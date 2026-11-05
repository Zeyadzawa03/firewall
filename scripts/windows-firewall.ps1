<#
    SentryFW - Windows firewall helper
    ==================================

    Bridge between the Node.js backend and Windows Defender Firewall with
    Advanced Security (the NetSecurity PowerShell module / Windows Filtering
    Platform).

    Contract
    --------
    * A single JSON request document is read from STDIN. No parameters are ever
      passed on the command line, so there is no interpolation point an attacker
      could reach even if validation upstream were bypassed.
    * A single JSON response document is written to STDOUT:
          { "ok": true,  "data": <result> }
          { "ok": false, "code": "<CODE>", "message": "...", "detail": "..." }
    * Exit code 0 on success, 1 on handled failure.

    Requests
    --------
      { "op": "probe" }
      { "op": "profiles" }
      { "op": "listManaged", "group": "SentryFW", "policyStore": "PersistentStore" }
      { "op": "listAll", "limit": 2000 }
      { "op": "apply",   "rule": { ... }, "group": "...", "policyStore": "..." }
      { "op": "remove",  "osName": "SentryFW_rule_x", "policyStore": "..." }
      { "op": "setEnabled", "osName": "...", "enabled": true, "policyStore": "..." }
      { "op": "removeGroup", "group": "SentryFW", "policyStore": "..." }

    The canonical rule shape it accepts (produced by src/firewall/rule-model.js):
      osName, displayName, description, direction (inbound|outbound),
      action (allow|deny), protocol (tcp|udp|icmp|icmpv6|any),
      srcAddress, dstAddress, srcPort, dstPort (specs, "any" allowed),
      iface, profiles (array), program, enabled (bool), group

    Address / port direction mapping (this is the part people get wrong):
      inbound  -> src = RemoteAddress/RemotePort, dst = LocalAddress/LocalPort
      outbound -> src = LocalAddress/LocalPort,   dst = RemoteAddress/RemotePort
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

function Write-Result {
    param([Parameter(Mandatory = $true)] $Data)
    $payload = [ordered]@{ ok = $true; data = $Data }
    [Console]::Out.Write(($payload | ConvertTo-Json -Depth 12 -Compress))
    exit 0
}

function Write-Failure {
    param(
        [string] $Code = 'PS_ERROR',
        [string] $Message = 'Unknown failure',
        [string] $Detail = ''
    )
    $payload = [ordered]@{ ok = $false; code = $Code; message = $Message; detail = $Detail }
    [Console]::Out.Write(($payload | ConvertTo-Json -Depth 6 -Compress))
    exit 1
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------- helpers ----

function Prop {
    <#
        Safe property read. CIM objects differ between Windows builds and
        StrictMode 2.0 turns a missing property into a terminating error, so all
        rule/filter properties are read through this helper.
    #>
    param($Object, [string] $Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    try {
        $p = $Object.PSObject.Properties[$Name]
        if ($null -eq $p) { return $Default }
        $v = $p.Value
        if ($null -eq $v) { return $Default }
        return $v
    } catch { return $Default }
}

function PropStr {
    param($Object, [string] $Name, [string] $Default = '')
    $v = Prop $Object $Name $null
    if ($null -eq $v) { return $Default }
    return "" + $v
}

function Convert-Spec {
    <# "any"/empty -> 'Any'; comma separated list -> string[] #>
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return 'Any' }
    $v = $Value.Trim()
    if ($v -ieq 'any') { return 'Any' }
    $parts = @($v.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    if ($parts.Count -eq 0) { return 'Any' }
    return $parts
}

function Convert-Protocol {
    param([string] $Value)
    switch (("" + $Value).ToLowerInvariant()) {
        'tcp'    { return 'TCP' }
        'udp'    { return 'UDP' }
        'icmp'   { return 'ICMPv4' }
        'icmpv6' { return 'ICMPv6' }
        default  { return 'Any' }
    }
}

function Convert-Profiles {
    param($Value)
    if ($null -eq $Value) { return 'Any' }
    $list = @($Value | ForEach-Object { ("" + $_).Trim() } | Where-Object { $_ -ne '' })
    if ($list.Count -eq 0) { return 'Any' }
    if ($list -contains 'Any') { return 'Any' }
    return ($list -join ',')
}

function Get-FilterIndex {
    <#
        Bulk-load the four filter object types once and index them by InstanceID.
        Doing this per-rule is O(n) PowerShell pipeline calls and takes minutes
        on a machine with ~1000 rules.

        Note: without elevation the bulk cmdlets return a partial set and emit
        access-denied errors for the remainder, so errors are suppressed and the
        caller falls back to per-rule enrichment for whatever is missing.
    #>
    param([string] $PolicyStore)

    $index = @{}
    function Add-To-Index($items, $key) {
        foreach ($item in $items) {
            $id = PropStr $item 'InstanceID'
            if (-not $id) { continue }
            if (-not $index.ContainsKey($id)) { $index[$id] = @{} }
            $index[$id][$key] = $item
        }
    }

    Add-To-Index (Get-NetFirewallPortFilter -PolicyStore $PolicyStore -ErrorAction SilentlyContinue) 'port'
    Add-To-Index (Get-NetFirewallAddressFilter -PolicyStore $PolicyStore -ErrorAction SilentlyContinue) 'address'
    Add-To-Index (Get-NetFirewallInterfaceFilter -PolicyStore $PolicyStore -ErrorAction SilentlyContinue) 'iface'
    Add-To-Index (Get-NetFirewallApplicationFilter -PolicyStore $PolicyStore -ErrorAction SilentlyContinue) 'app'
    return $index
}

function Add-RuleFilters {
    <#
        Per-rule enrichment. Slower than the bulk index but works without
        elevation, so it is used for the (small) managed rule set and as a
        bounded fallback elsewhere.
    #>
    param($Rule, $Index)

    $id = PropStr $Rule 'InstanceID'
    if (-not $id) { return }
    if (-not $Index.ContainsKey($id)) { $Index[$id] = @{} }
    $slot = $Index[$id]

    if (-not $slot.ContainsKey('port')) {
        try { $slot['port'] = ($Rule | Get-NetFirewallPortFilter -ErrorAction Stop) } catch { }
    }
    if (-not $slot.ContainsKey('address')) {
        try { $slot['address'] = ($Rule | Get-NetFirewallAddressFilter -ErrorAction Stop) } catch { }
    }
    if (-not $slot.ContainsKey('iface')) {
        try { $slot['iface'] = ($Rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop) } catch { }
    }
    if (-not $slot.ContainsKey('app')) {
        try { $slot['app'] = ($Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop) } catch { }
    }
}

function Join-Spec {
    param($Value)
    if ($null -eq $Value) { return 'any' }
    $list = @($Value | ForEach-Object { "" + $_ } | Where-Object { $_ -ne '' })
    if ($list.Count -eq 0) { return 'any' }
    if ($list.Count -eq 1 -and $list[0] -ieq 'Any') { return 'any' }
    return ($list -join ',')
}

function Convert-RuleToJson {
    param($Rule, $Index)

    $instanceId = PropStr $Rule 'InstanceID'
    $filters = $null
    if ($instanceId -and $Index.ContainsKey($instanceId)) { $filters = $Index[$instanceId] }

    $port = $null; $addr = $null; $iface = $null; $app = $null
    if ($filters) {
        if ($filters.ContainsKey('port')) { $port = $filters['port'] }
        if ($filters.ContainsKey('address')) { $addr = $filters['address'] }
        if ($filters.ContainsKey('iface')) { $iface = $filters['iface'] }
        if ($filters.ContainsKey('app')) { $app = $filters['app'] }
    }

    $direction = if ((PropStr $Rule 'Direction') -ieq 'Inbound') { 'inbound' } else { 'outbound' }
    $action = if ((PropStr $Rule 'Action') -ieq 'Block') { 'deny' } else { 'allow' }

    $localAddress  = Join-Spec (Prop $addr 'LocalAddress' $null)
    $remoteAddress = Join-Spec (Prop $addr 'RemoteAddress' $null)
    $localPort     = Join-Spec (Prop $port 'LocalPort' $null)
    $remotePort    = Join-Spec (Prop $port 'RemotePort' $null)
    $protocolRaw   = PropStr $port 'Protocol' 'Any'

    $protocol = switch ($protocolRaw.ToLowerInvariant()) {
        'tcp'    { 'tcp' }
        'udp'    { 'udp' }
        'icmpv4' { 'icmp' }
        '1'      { 'icmp' }
        'icmpv6' { 'icmpv6' }
        '58'     { 'icmpv6' }
        'any'    { 'any' }
        default  { $protocolRaw.ToLowerInvariant() }
    }

    if ($direction -eq 'inbound') {
        $src = $remoteAddress; $dst = $localAddress; $sport = $remotePort; $dport = $localPort
    } else {
        $src = $localAddress; $dst = $remoteAddress; $sport = $localPort; $dport = $remotePort
    }

    $ifaceAlias = Join-Spec (Prop $iface 'InterfaceAlias' $null)

    $program = ''
    $rawProgram = PropStr $app 'Program' ''
    if ($rawProgram -and $rawProgram -ne 'Any') { $program = $rawProgram }

    $profileText = PropStr $Rule 'Profile' 'Any'

    return [ordered]@{
        osName      = (PropStr $Rule 'Name')
        displayName = (PropStr $Rule 'DisplayName')
        description = (PropStr $Rule 'Description')
        group       = (PropStr $Rule 'Group')
        enabled     = ((PropStr $Rule 'Enabled') -ieq 'True')
        direction   = $direction
        action      = $action
        protocol    = $protocol
        srcAddress  = $src
        dstAddress  = $dst
        srcPort     = $sport
        dstPort     = $dport
        iface       = $ifaceAlias
        program     = $program
        profiles    = @(($profileText.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }))
        policyStore = (PropStr $Rule 'PolicyStoreSource')
    }
}

# ------------------------------------------------------------------- main ----

$raw = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($raw)) {
    Write-Failure -Code 'NO_INPUT' -Message 'No request document was supplied on stdin'
}

try {
    $req = $raw | ConvertFrom-Json
} catch {
    Write-Failure -Code 'BAD_INPUT' -Message 'Request document is not valid JSON' -Detail $_.Exception.Message
}

$op = "" + $req.op
$policyStore = 'PersistentStore'
if ($req.PSObject.Properties.Name -contains 'policyStore' -and $req.policyStore) {
    $candidate = "" + $req.policyStore
    if ($candidate -in @('PersistentStore', 'ActiveStore', 'RSOP', 'StaticServiceStore', 'ConfigurableServiceStore')) {
        $policyStore = $candidate
    }
}
$group = 'SentryFW'
if ($req.PSObject.Properties.Name -contains 'group' -and $req.group) {
    $group = ("" + $req.group) -replace '[^A-Za-z0-9 _.\-]', ''
    if ([string]::IsNullOrWhiteSpace($group)) { $group = 'SentryFW' }
}

if (-not (Get-Module -ListAvailable -Name NetSecurity)) {
    Write-Failure -Code 'NO_NETSECURITY' -Message 'The NetSecurity PowerShell module is not available on this system'
}

try {
    switch ($op) {

        'probe' {
            $svc = $null
            try { $svc = Get-Service -Name MpsSvc -ErrorAction Stop } catch { }
            Write-Result ([ordered]@{
                elevated       = (Test-Elevated)
                psVersion      = "" + $PSVersionTable.PSVersion
                netSecurity    = $true
                serviceName    = 'MpsSvc'
                serviceStatus  = if ($svc) { "" + $svc.Status } else { 'unknown' }
                policyStore    = $policyStore
                group          = $group
            })
        }

        'profiles' {
            $out = @()
            foreach ($p in Get-NetFirewallProfile -PolicyStore $policyStore) {
                $out += [ordered]@{
                    name                  = (PropStr $p 'Name')
                    enabled               = ((PropStr $p 'Enabled') -ieq 'True')
                    defaultInboundAction  = (PropStr $p 'DefaultInboundAction')
                    defaultOutboundAction = (PropStr $p 'DefaultOutboundAction')
                    logFileName           = (PropStr $p 'LogFileName')
                    logBlocked            = ((PropStr $p 'LogBlocked') -ieq 'True')
                    logAllowed            = ((PropStr $p 'LogAllowed') -ieq 'True')
                    logMaxSizeKilobytes   = [int](Prop $p 'LogMaxSizeKilobytes' 0)
                    notifyOnListen        = ((PropStr $p 'NotifyOnListen') -ieq 'True')
                }
            }
            Write-Result ([ordered]@{ profiles = @($out) })
        }

        'listManaged' {
            $rules = @(Get-NetFirewallRule -PolicyStore $policyStore -ErrorAction SilentlyContinue |
                       Where-Object { (PropStr $_ 'Group') -eq $group })
            if ($rules.Count -eq 0) {
                Write-Result ([ordered]@{ rules = @(); count = 0 })
            }
            # Managed set is small: enrich per rule so this works unelevated too.
            $index = @{}
            $out = @()
            foreach ($r in $rules) {
                Add-RuleFilters -Rule $r -Index $index
                $out += (Convert-RuleToJson -Rule $r -Index $index)
            }
            Write-Result ([ordered]@{ rules = @($out); count = $out.Count })
        }

        'listAll' {
            $limit = 2000
            if ($req.PSObject.Properties.Name -contains 'limit' -and $req.limit) {
                $limit = [int]$req.limit
                if ($limit -lt 1) { $limit = 1 }
                if ($limit -gt 5000) { $limit = 5000 }
            }
            $onlyEnabled = $false
            if ($req.PSObject.Properties.Name -contains 'onlyEnabled') { $onlyEnabled = [bool]$req.onlyEnabled }

            $all = @(Get-NetFirewallRule -PolicyStore $policyStore -ErrorAction SilentlyContinue)
            if ($onlyEnabled) { $all = @($all | Where-Object { (PropStr $_ 'Enabled') -ieq 'True' }) }
            $total = $all.Count
            $rules = @($all | Select-Object -First $limit)
            $index = Get-FilterIndex -PolicyStore $policyStore
            $out = @()
            $enriched = 0
            foreach ($r in $rules) {
                # Fill gaps left by an unelevated bulk read, bounded so a large
                # rule set cannot turn this into a multi-minute operation.
                $rid = PropStr $r 'InstanceID'
                if ($rid -and -not $index.ContainsKey($rid) -and $enriched -lt 150) {
                    Add-RuleFilters -Rule $r -Index $index
                    $enriched++
                }
                $out += (Convert-RuleToJson -Rule $r -Index $index)
            }
            Write-Result ([ordered]@{ rules = @($out); count = $out.Count; total = $total; truncated = ($total -gt $out.Count) })
        }

        'apply' {
            if (-not (Test-Elevated)) {
                Write-Failure -Code 'NOT_ELEVATED' -Message 'Creating or modifying firewall rules requires an elevated process'
            }
            $rule = $req.rule
            if ($null -eq $rule) { Write-Failure -Code 'BAD_INPUT' -Message 'apply requires a rule object' }

            $osName = "" + $rule.osName
            if ([string]::IsNullOrWhiteSpace($osName)) {
                Write-Failure -Code 'BAD_INPUT' -Message 'rule.osName is required'
            }

            $direction = if (("" + $rule.direction) -ieq 'outbound') { 'Outbound' } else { 'Inbound' }
            $action = if (("" + $rule.action) -ieq 'allow') { 'Allow' } else { 'Block' }
            $protocol = Convert-Protocol ("" + $rule.protocol)

            $src = Convert-Spec ("" + $rule.srcAddress)
            $dst = Convert-Spec ("" + $rule.dstAddress)
            $sport = Convert-Spec ("" + $rule.srcPort)
            $dport = Convert-Spec ("" + $rule.dstPort)

            if ($direction -eq 'Inbound') {
                $remoteAddress = $src; $localAddress = $dst; $remotePort = $sport; $localPort = $dport
            } else {
                $localAddress = $src; $remoteAddress = $dst; $localPort = $sport; $remotePort = $dport
            }

            $params = @{
                Name        = $osName
                DisplayName = if ($rule.displayName) { "" + $rule.displayName } else { $osName }
                Direction   = $direction
                Action      = $action
                Enabled     = if ($rule.enabled -eq $false) { 'False' } else { 'True' }
                Profile     = (Convert-Profiles $rule.profiles)
                Group       = $group
                PolicyStore = $policyStore
                ErrorAction = 'Stop'
            }
            if ($rule.description) { $params['Description'] = "" + $rule.description }
            if ($protocol -ne 'Any') { $params['Protocol'] = $protocol }
            if ($localAddress -ne 'Any') { $params['LocalAddress'] = $localAddress }
            if ($remoteAddress -ne 'Any') { $params['RemoteAddress'] = $remoteAddress }
            if ($protocol -eq 'TCP' -or $protocol -eq 'UDP') {
                if ($localPort -ne 'Any') { $params['LocalPort'] = $localPort }
                if ($remotePort -ne 'Any') { $params['RemotePort'] = $remotePort }
            }
            if ($rule.iface -and ("" + $rule.iface) -ne 'any') { $params['InterfaceAlias'] = "" + $rule.iface }
            if ($rule.program) { $params['Program'] = "" + $rule.program }

            # Replace semantics: remove any existing rule with this name first so
            # the resulting OS rule is an exact projection of the canonical rule.
            $existing = Get-NetFirewallRule -Name $osName -PolicyStore $policyStore -ErrorAction SilentlyContinue
            $replaced = $false
            if ($existing) {
                Remove-NetFirewallRule -Name $osName -PolicyStore $policyStore -ErrorAction Stop
                $replaced = $true
            }

            $created = New-NetFirewallRule @params

            Write-Result ([ordered]@{
                osName   = (PropStr $created 'Name' $osName)
                replaced = $replaced
                applied  = $true
                store    = $policyStore
            })
        }

        'remove' {
            if (-not (Test-Elevated)) {
                Write-Failure -Code 'NOT_ELEVATED' -Message 'Removing firewall rules requires an elevated process'
            }
            $osName = "" + $req.osName
            if ([string]::IsNullOrWhiteSpace($osName)) { Write-Failure -Code 'BAD_INPUT' -Message 'osName is required' }
            $existing = Get-NetFirewallRule -Name $osName -PolicyStore $policyStore -ErrorAction SilentlyContinue
            if (-not $existing) {
                Write-Result ([ordered]@{ osName = $osName; removed = $false; reason = 'not-present' })
            }
            Remove-NetFirewallRule -Name $osName -PolicyStore $policyStore -ErrorAction Stop
            Write-Result ([ordered]@{ osName = $osName; removed = $true })
        }

        'setEnabled' {
            if (-not (Test-Elevated)) {
                Write-Failure -Code 'NOT_ELEVATED' -Message 'Changing firewall rule state requires an elevated process'
            }
            $osName = "" + $req.osName
            if ([string]::IsNullOrWhiteSpace($osName)) { Write-Failure -Code 'BAD_INPUT' -Message 'osName is required' }
            $enabled = [bool]$req.enabled
            $existing = Get-NetFirewallRule -Name $osName -PolicyStore $policyStore -ErrorAction SilentlyContinue
            if (-not $existing) {
                Write-Failure -Code 'NOT_PRESENT' -Message "No OS firewall rule named '$osName'"
            }
            if ($enabled) {
                Enable-NetFirewallRule -Name $osName -PolicyStore $policyStore -ErrorAction Stop
            } else {
                Disable-NetFirewallRule -Name $osName -PolicyStore $policyStore -ErrorAction Stop
            }
            Write-Result ([ordered]@{ osName = $osName; enabled = $enabled })
        }

        'removeGroup' {
            if (-not (Test-Elevated)) {
                Write-Failure -Code 'NOT_ELEVATED' -Message 'Removing firewall rules requires an elevated process'
            }
            $rules = @(Get-NetFirewallRule -PolicyStore $policyStore -ErrorAction SilentlyContinue |
                       Where-Object { (PropStr $_ 'Group') -eq $group })
            $removed = 0
            foreach ($r in $rules) {
                Remove-NetFirewallRule -Name (PropStr $r 'Name') -PolicyStore $policyStore -ErrorAction SilentlyContinue
                $removed++
            }
            Write-Result ([ordered]@{ group = $group; removed = $removed })
        }

        default {
            Write-Failure -Code 'UNKNOWN_OP' -Message "Unsupported operation: '$op'"
        }
    }
} catch {
    $detail = ''
    try { $detail = "" + $_.Exception.Message } catch { }
    $code = 'PS_ERROR'
    if ($detail -match 'Access is denied' -or $detail -match 'requires elevation') { $code = 'NOT_ELEVATED' }
    if ($detail -match 'No MSFT_NetFirewallRule objects found') { $code = 'NOT_PRESENT' }
    Write-Failure -Code $code -Message "Windows firewall operation '$op' failed" -Detail $detail
}

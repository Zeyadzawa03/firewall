<#
    SentryFW - Windows network telemetry helper
    ===========================================

    Read-only. Collects interfaces, TCP/UDP endpoints and per-interface counters
    for the monitoring subsystem. Works without elevation; process names are best
    effort because a standard user cannot query every process owner.

    Contract: JSON request on STDIN -> JSON response on STDOUT.

      { "op": "interfaces" }
      { "op": "connections", "limit": 4000, "resolveProcess": true }
      { "op": "listeners", "limit": 2000, "resolveProcess": true }
      { "op": "stats" }
      { "op": "snapshot", "limit": 4000, "resolveProcess": true }
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

function Write-Result {
    param([Parameter(Mandatory = $true)] $Data)
    [Console]::Out.Write((([ordered]@{ ok = $true; data = $Data }) | ConvertTo-Json -Depth 10 -Compress))
    exit 0
}

function Write-Failure {
    param([string] $Code = 'PS_ERROR', [string] $Message = 'Unknown failure', [string] $Detail = '')
    [Console]::Out.Write((([ordered]@{ ok = $false; code = $Code; message = $Message; detail = $Detail }) | ConvertTo-Json -Depth 5 -Compress))
    exit 1
}

$script:ProcessCache = $null

function Prop {
    <#
        Safe property read. CIM/WMI objects do not expose the same properties on
        every Windows build (e.g. TCP connections lack InterfaceAlias on some
        systems), and StrictMode 2.0 turns a missing property into a terminating
        error. Everything below reads through this helper.
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

function PropNum {
    param($Object, [string] $Name, $Default = 0)
    $v = Prop $Object $Name $null
    if ($null -eq $v) { return $Default }
    try { return [double]$v } catch { return $Default }
}

function PropInt {
    param($Object, [string] $Name, [int] $Default = 0)
    $v = Prop $Object $Name $null
    if ($null -eq $v) { return $Default }
    try { return [int]$v } catch { return $Default }
}

function Get-ProcessMap {
    if ($null -ne $script:ProcessCache) { return $script:ProcessCache }
    $map = @{}
    try {
        foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
            if (-not $map.ContainsKey([int]$p.Id)) { $map[[int]$p.Id] = "" + $p.ProcessName }
        }
    } catch { }
    $script:ProcessCache = $map
    return $map
}

function Resolve-ProcessName {
    # NOTE: the parameter cannot be called $Pid - that is a read-only automatic
    # variable in PowerShell and binding to it throws under StrictMode.
    param([int] $ProcessId, [bool] $Resolve)
    if (-not $Resolve -or $ProcessId -le 0) { return '' }
    $map = Get-ProcessMap
    if ($map.ContainsKey($ProcessId)) { return $map[$ProcessId] }
    return ''
}

function Strip-Zone {
    param([string] $Address)
    if ([string]::IsNullOrEmpty($Address)) { return '' }
    $i = $Address.IndexOf('%')
    if ($i -ge 0) { return $Address.Substring(0, $i) }
    return $Address
}

function Get-Interfaces {
    $addressesByAlias = @{}
    try {
        foreach ($a in Get-NetIPAddress -ErrorAction SilentlyContinue) {
            $alias = PropStr $a 'InterfaceAlias'
            if (-not $addressesByAlias.ContainsKey($alias)) { $addressesByAlias[$alias] = @() }
            $addressesByAlias[$alias] += [ordered]@{
                address = (Strip-Zone (PropStr $a 'IPAddress'))
                family  = if ((PropStr $a 'AddressFamily') -eq 'IPv6') { 'ipv6' } else { 'ipv4' }
                prefix  = (PropInt $a 'PrefixLength' 0)
                state   = (PropStr $a 'AddressState')
                origin  = (PropStr $a 'PrefixOrigin')
            }
        }
    } catch { }

    $statsByAlias = @{}
    try {
        foreach ($s in Get-NetAdapterStatistics -ErrorAction SilentlyContinue) {
            $statsByAlias[(PropStr $s 'Name')] = $s
        }
    } catch { }

    $gatewayByIndex = @{}
    try {
        foreach ($r in (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
            $gatewayByIndex[(PropInt $r 'ifIndex' 0)] = (PropStr $r 'NextHop')
        }
    } catch { }

    $out = @()
    try {
        foreach ($ad in Get-NetAdapter -ErrorAction SilentlyContinue) {
            $alias = PropStr $ad 'Name'
            $st = $null
            if ($statsByAlias.ContainsKey($alias)) { $st = $statsByAlias[$alias] }
            $addrs = @()
            if ($addressesByAlias.ContainsKey($alias)) { $addrs = @($addressesByAlias[$alias]) }
            $ifIndex = PropInt $ad 'ifIndex' 0
            $gw = ''
            if ($gatewayByIndex.ContainsKey($ifIndex)) { $gw = $gatewayByIndex[$ifIndex] }

            $out += [ordered]@{
                name        = $alias
                description = (PropStr $ad 'InterfaceDescription')
                index       = $ifIndex
                status      = (PropStr $ad 'Status').ToLowerInvariant()
                mac         = (PropStr $ad 'MacAddress')
                linkSpeed   = (PropStr $ad 'LinkSpeed')
                mtu         = (PropInt $ad 'MtuSize' 0)
                type        = (PropStr $ad 'MediaType')
                virtual     = [bool](Prop $ad 'Virtual' $false)
                gateway     = $gw
                addresses   = @($addrs)
                rxBytes     = (PropNum $st 'ReceivedBytes' 0)
                txBytes     = (PropNum $st 'SentBytes' 0)
                rxPackets   = (PropNum $st 'ReceivedUnicastPackets' 0)
                txPackets   = (PropNum $st 'SentUnicastPackets' 0)
                rxDiscarded = (PropNum $st 'ReceivedDiscardedPackets' 0)
                txDiscarded = (PropNum $st 'OutboundDiscardedPackets' 0)
            }
        }
    } catch { }
    return @($out)
}

function Get-Connections {
    param([int] $Limit = 4000, [bool] $ResolveProcess = $true)

    $out = @()
    $total = 0
    try {
        $conns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
        $total = $conns.Count
        foreach ($c in ($conns | Select-Object -First $Limit)) {
            $ownerPid = PropInt $c 'OwningProcess' 0
            $created = ''
            $rawCreated = Prop $c 'CreationTime' $null
            if ($null -ne $rawCreated) {
                try { $created = ([datetime]$rawCreated).ToUniversalTime().ToString('o') } catch { }
            }
            $out += [ordered]@{
                protocol      = 'tcp'
                localAddress  = (Strip-Zone (PropStr $c 'LocalAddress'))
                localPort     = (PropInt $c 'LocalPort' 0)
                remoteAddress = (Strip-Zone (PropStr $c 'RemoteAddress'))
                remotePort    = (PropInt $c 'RemotePort' 0)
                state         = (PropStr $c 'State').ToLowerInvariant()
                pid           = $ownerPid
                process       = (Resolve-ProcessName -ProcessId $ownerPid -Resolve $ResolveProcess)
                iface         = (PropStr $c 'InterfaceAlias')
                createdAt     = $created
            }
        }
    } catch { }

    return [ordered]@{ connections = @($out); total = $total; truncated = ($total -gt $out.Count) }
}

function Get-Listeners {
    param([int] $Limit = 2000, [bool] $ResolveProcess = $true)

    $out = @()
    try {
        foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -First $Limit)) {
            $ownerPid = PropInt $c 'OwningProcess' 0
            $out += [ordered]@{
                protocol     = 'tcp'
                localAddress = (Strip-Zone (PropStr $c 'LocalAddress'))
                localPort    = (PropInt $c 'LocalPort' 0)
                pid          = $ownerPid
                process      = (Resolve-ProcessName -ProcessId $ownerPid -Resolve $ResolveProcess)
                iface        = (PropStr $c 'InterfaceAlias')
            }
        }
    } catch { }

    try {
        foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object -First $Limit)) {
            $ownerPid = PropInt $u 'OwningProcess' 0
            $out += [ordered]@{
                protocol     = 'udp'
                localAddress = (Strip-Zone (PropStr $u 'LocalAddress'))
                localPort    = (PropInt $u 'LocalPort' 0)
                pid          = $ownerPid
                process      = (Resolve-ProcessName -ProcessId $ownerPid -Resolve $ResolveProcess)
                iface        = ''
            }
        }
    } catch { }

    return @($out)
}

function Get-Stats {
    $tcpStates = @{}
    $total = 0
    try {
        foreach ($c in @(Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
            $state = (PropStr $c 'State' 'unknown').ToLowerInvariant()
            if (-not $tcpStates.ContainsKey($state)) { $tcpStates[$state] = 0 }
            $tcpStates[$state] = $tcpStates[$state] + 1
            $total++
        }
    } catch { }

    $udpCount = 0
    try { $udpCount = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue).Count } catch { }

    return [ordered]@{
        tcpTotal   = $total
        tcpByState = $tcpStates
        udpTotal   = $udpCount
        collectedAt = (Get-Date).ToUniversalTime().ToString('o')
    }
}

# ------------------------------------------------------------------- main ----

$raw = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($raw)) { Write-Failure -Code 'NO_INPUT' -Message 'No request document supplied on stdin' }

try { $req = $raw | ConvertFrom-Json } catch {
    Write-Failure -Code 'BAD_INPUT' -Message 'Request document is not valid JSON' -Detail $_.Exception.Message
}

$op = "" + $req.op
$limit = 4000
if ($req.PSObject.Properties.Name -contains 'limit' -and $req.limit) {
    $limit = [int]$req.limit
    if ($limit -lt 1) { $limit = 1 }
    if ($limit -gt 20000) { $limit = 20000 }
}
$resolveProcess = $true
if ($req.PSObject.Properties.Name -contains 'resolveProcess') { $resolveProcess = [bool]$req.resolveProcess }

try {
    switch ($op) {
        'interfaces' { Write-Result ([ordered]@{ interfaces = (Get-Interfaces) }) }
        'connections' { Write-Result (Get-Connections -Limit $limit -ResolveProcess $resolveProcess) }
        'listeners'  { Write-Result ([ordered]@{ listeners = (Get-Listeners -Limit $limit -ResolveProcess $resolveProcess) }) }
        'stats'      { Write-Result (Get-Stats) }
        'snapshot'   {
            $conns = Get-Connections -Limit $limit -ResolveProcess $resolveProcess
            Write-Result ([ordered]@{
                interfaces  = (Get-Interfaces)
                connections = $conns.connections
                total       = $conns.total
                truncated   = $conns.truncated
                listeners   = (Get-Listeners -Limit 2000 -ResolveProcess $resolveProcess)
                stats       = (Get-Stats)
            })
        }
        default { Write-Failure -Code 'UNKNOWN_OP' -Message "Unsupported operation: '$op'" }
    }
} catch {
    $detail = ''
    try { $detail = "" + $_.Exception.Message } catch { }
    Write-Failure -Code 'PS_ERROR' -Message "Network operation '$op' failed" -Detail $detail
}

// ============================================================
// FortiSIEM Rules, Reports, Threat Hunting, CMDB, Analytics
// ============================================================

KB.content['fsiem-rules'] = `
<h1><span class="h1-icon">⚙️</span> FortiSIEM Rules</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Rules are the detection engine of FortiSIEM. A rule watches the event stream in real-time and generates an incident when its conditions are met. Rules can be simple (single event matches condition) or complex (correlated across multiple events, devices, users, and time windows). FortiSIEM ships with 700+ pre-built rules covering common attack patterns and operational events.</p>
</div>

<div class="gui-path">RESOURCES <span class="gui-sep">›</span> Rules</div>

<h2 id="rule-types">Rule Types</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Type</th><th>Description</th><th>Example</th></tr>
</thead>
<tbody>
<tr><td><strong>Simple Threshold</strong></td><td>Single event matches condition X times in window</td><td>"5 failed logins in 60 seconds from same IP"</td></tr>
<tr><td><strong>Baseline Deviation</strong></td><td>Current value deviates from statistical baseline</td><td>"Outbound traffic 3x higher than 30-day average"</td></tr>
<tr><td><strong>Trend</strong></td><td>Value trending up or down beyond threshold</td><td>"Error rate increasing 50% over 15 minutes"</td></tr>
<tr><td><strong>Sequence</strong></td><td>Events A then B then C in order within window</td><td>"Recon → Exploit → Lateral Movement"</td></tr>
<tr><td><strong>Composite</strong></td><td>Combines multiple sub-rules with AND/OR logic</td><td>"Brute force AND account creation within 1 hour"</td></tr>
<tr><td><strong>Watch List</strong></td><td>Matches events against dynamic lists</td><td>"Any event from IOC IP feed"</td></tr>
</tbody>
</table>
</div>

<h2 id="rule-anatomy">Rule Anatomy</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Component</th><th>Description</th><th>Example</th></tr>
</thead>
<tbody>
<tr><td><strong>Conditions</strong></td><td>Event filter criteria (what events match)</td><td><code>eventType = "Failed-Login" AND srcIpAddr IN "External"</code></td></tr>
<tr><td><strong>Group By</strong></td><td>Aggregate per entity (who triggers)</td><td>Group by <code>srcIpAddr</code></td></tr>
<tr><td><strong>Threshold</strong></td><td>Count/value that triggers incident</td><td>COUNT > 10</td></tr>
<tr><td><strong>Time Window</strong></td><td>How long to count events</td><td>60 seconds</td></tr>
<tr><td><strong>Severity</strong></td><td>Incident severity when fired</td><td>High</td></tr>
<tr><td><strong>Clear Condition</strong></td><td>When to auto-close incident</td><td>No events for 300 seconds</td></tr>
<tr><td><strong>Actions</strong></td><td>What to do on trigger (notify, ticket)</td><td>Email SOC, create JIRA ticket</td></tr>
</tbody>
</table>
</div>

<h2 id="rule-creation">Creating Custom Rules</h2>

<div class="steps">
    <div class="step">
        <div class="step-title">Navigate to Rules</div>
        <p>Go to <strong>RESOURCES → Rules → Add Rule</strong>.</p>
    </div>
    <div class="step">
        <div class="step-title">Define Basic Info</div>
        <p>Set Name, Category, Subcategory, Severity, and Description. Severity must match the actual threat risk level — do not set everything to Critical.</p>
    </div>
    <div class="step">
        <div class="step-title">Set Conditions</div>
        <p>Click <strong>Conditions</strong> tab. Add Event Type filter and attribute filters. Use <strong>IN</strong> for multiple values, <strong>CONTAINS</strong> for partial match, <strong>NOT IN</strong> for exclusions.</p>
    </div>
    <div class="step">
        <div class="step-title">Configure Thresholds</div>
        <p>Set <strong>Group By</strong> attribute (srcIpAddr, user, hostName). Set <strong>Aggregate function</strong> (COUNT, SUM). Set <strong>threshold value</strong> and <strong>time window</strong>.</p>
    </div>
    <div class="step">
        <div class="step-title">Add Actions</div>
        <p>Configure notifications: email to SOC, Slack webhook, create ticket in JIRA/ServiceNow, run a script, or trigger a FortiGate remediation action.</p>
    </div>
    <div class="step">
        <div class="step-title">Test Rule</div>
        <p>Use <strong>Test</strong> button to validate against historical data. Verify it triggers correctly and doesn't produce false positives.</p>
    </div>
    <div class="step">
        <div class="step-title">Enable Rule</div>
        <p>Set Status to <strong>Active</strong>. Monitor for first 48 hours. Tune threshold if false positive rate is high.</p>
    </div>
</div>

<h2 id="builtin-rules">Key Built-in Rules to Enable</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Rule Name</th><th>Threat</th><th>Default Severity</th></tr>
</thead>
<tbody>
<tr><td>Brute Force Login - Same Source</td><td>Password spraying, brute force</td><td>High</td></tr>
<tr><td>Multiple Login Failures Followed by Success</td><td>Successful brute force</td><td>Critical</td></tr>
<tr><td>FortiGate: IPS Critical Alert</td><td>Exploit attempt</td><td>Critical</td></tr>
<tr><td>FortiGate: Malware Detected</td><td>Malware download</td><td>High</td></tr>
<tr><td>Outbound Traffic to Known C&C Servers</td><td>C2 communication, infection</td><td>Critical</td></tr>
<tr><td>Insider Threat: Data Exfiltration over HTTP</td><td>Data theft</td><td>High</td></tr>
<tr><td>Excessive Failed Firewall Logins</td><td>Firewall management attack</td><td>High</td></tr>
<tr><td>New Admin Account Created</td><td>Privilege escalation, persistence</td><td>Medium</td></tr>
<tr><td>VPN Login from Unusual Country</td><td>Account compromise</td><td>High</td></tr>
<tr><td>Lateral Movement via SMB/WMI</td><td>Lateral movement post-exploitation</td><td>Critical</td></tr>
<tr><td>FortiGate HA Failover</td><td>Network availability</td><td>Medium</td></tr>
<tr><td>Device Unreachable</td><td>Availability monitoring</td><td>Medium</td></tr>
</tbody>
</table>
</div>

<h2 id="rule-tuning">Rule Tuning</h2>

<div class="callout warning">
    <div class="callout-title">⚠️ Alert Fatigue</div>
    <p>Untuned rules create <strong>alert fatigue</strong> — when analysts see hundreds of daily false positives, they begin ignoring alerts. This is one of the top causes of missed real threats. Tune rules to achieve a <strong>false positive rate below 5%</strong> per rule.</p>
</div>

<div class="callout best-practice">
    <div class="callout-title">🎯 Rule Tuning Strategies</div>
    <p><strong>1. Whitelist known-good sources</strong> — exclude scanner IPs, monitoring tools, trusted jump hosts<br>
    <strong>2. Increase thresholds</strong> — if legitimate tools trigger 15 failures, set threshold to 25<br>
    <strong>3. Add time restrictions</strong> — fire only outside business hours<br>
    <strong>4. Refine Group By</strong> — group by user+srcIP instead of srcIP alone to reduce noise<br>
    <strong>5. Add business context</strong> — exclude known high-privilege service accounts from authentication failure rules</p>
</div>

<h2 id="custom-rules-examples">50+ Custom Rule Examples</h2>

<h3>🔴 Critical Threat Rules</h3>

<div class="code-block">
    <div class="code-header"><span>Rule — Ransomware File Extension Activity</span><button class="code-copy-btn">Copy</button></div>
    <pre><code>Rule: "Ransomware File Extension Activity"
Severity: Critical
Condition:
  Event Type: Windows-File-Access OR FortiGate-DLP
  Filter: fileName CONTAINS IN (".locked",".encrypted",".crypted",".crypt",
          ".locky",".wncry",".cerber")
Group By: hostName
Aggregate: COUNT > 5
Window: 60 seconds
Actions: Email SOC, Isolate Host (FortiGate automation), Create P1 Ticket</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Rule — Mimikatz / Credential Dumping</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Rule: "Credential Dumping Tool Detected"
Severity: Critical
Condition:
  Event Type: Windows-ProcessCreate OR Windows-Security
  Filter: processName IN ("mimikatz.exe","wce.exe","gsecdump.exe")
          OR (processName = "lsass.exe" AND parentProcess NOT IN 
             ("wininit.exe","services.exe","svchost.exe"))
          OR commandLine CONTAINS IN ("sekurlsa","lsadump","dcsync")
Group By: hostName, user
Aggregate: COUNT > 1
Window: 300 seconds
Actions: Critical email + isolate host + create incident</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Rule — Pass-the-Hash / Pass-the-Ticket</span><button class="code-copy-btn">Copy</button></div>
    <pre><code>Rule: "Pass-the-Hash Detected"
Severity: Critical
Condition:
  Event Type: Windows-Security (EventID 4624)
  Filter: logonType = "3" AND logonProcess = "NtLmSsp" 
          AND workstationName NOT IN "known-servers-list"
          AND targetDomain NOT IN "corp.local"
Group By: srcIpAddr, targetUser
Aggregate: COUNT > 3
Window: 300 seconds</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Rule — Impossible Travel / Login from Two Countries</span><button class="code-copy-btn">Copy</button></div>
    <pre><code>Rule: "Impossible Travel Login"
Severity: High
Type: Sequence
Conditions:
  Event A: SSL VPN Login SUCCESS from country = "USA"
  Event B: SSL VPN Login SUCCESS from country != "USA" 
           AND same user as Event A
Sequence: A then B
Time Between: A to B less than 60 minutes
Group By: user</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Rule — DNS Tunneling Detection</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Rule: "DNS Tunneling Suspected"
Severity: High
Condition:
  Event Type: FortiGate-DNS
  Filter: queryLength > 50 OR 
          (queryType = "TXT" AND rcvdBytes > 200)
Group By: srcIpAddr, dnsServerIp
Aggregate: COUNT > 30
Window: 5 minutes</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Rule — Wiper Malware / Mass File Deletion</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Rule: "Mass File Deletion (Wiper Malware)"
Severity: Critical
Condition:
  Event Type: Windows-File-Delete OR Windows-Security
  Filter: objectType = "File" AND eventType = "ObjectDeleted"
Group By: hostName, user
Aggregate: COUNT > 200
Window: 60 seconds
Actions: Immediate isolation + P0 ticket</code></pre>
</div>

<h3>🟡 High Priority Rules</h3>

<div class="code-block">
    <div class="code-header"><span>Rule — Off-Hours Admin Access</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Rule: "Admin Access Outside Business Hours"
Severity: High
Condition:
  Event Type: FortiGate-Admin-Login OR Windows-Admin-Logon
  Filter: eventTime.hour NOT IN "08-18" OR
          eventTime.dayOfWeek IN "Saturday,Sunday"
  AND user IN "Administrators,Domain-Admins"
Group By: user, srcIpAddr
Aggregate: COUNT > 1
Window: 600 seconds</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Rule — PowerShell Empire / Encoded Commands</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Rule: "Obfuscated PowerShell Execution"
Severity: High
Condition:
  Event Type: Windows-ProcessCreate
  Filter: processName = "powershell.exe"
          AND commandLine CONTAINS IN ("-enc","-EncodedCommand",
          "IEX","Invoke-Expression","DownloadString",
          "WebClient","bypass","hidden","-nop")
Group By: hostName, user
Aggregate: COUNT > 1
Window: 300 seconds</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Rule — Service Account Login Anomaly</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Rule: "Service Account Interactive Login"
Severity: High
Condition:
  Event Type: Windows-Security (EventID 4624)
  Filter: user IN "ServiceAccounts-Group"
          AND logonType IN ("2","10")  # Interactive or RemoteInteractive
Group By: user, srcIpAddr
Aggregate: COUNT > 1
Window: 3600 seconds</code></pre>
</div>
`;

KB.content['fsiem-reports'] = `
<h1><span class="h1-icon">📄</span> Reports</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>FortiSIEM reports transform raw security data into structured documents for compliance audits, executive summaries, operational reviews, and board presentations. Reports can be scheduled, automatically emailed, and generated in PDF, HTML, or CSV formats.</p>
</div>

<div class="gui-path">ANALYTICS <span class="gui-sep">›</span> Reports</div>

<h2 id="report-categories">Report Categories</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Category</th><th>Key Reports</th><th>Audience</th><th>Schedule</th></tr>
</thead>
<tbody>
<tr><td><strong>Compliance</strong></td><td>PCI DSS, HIPAA, SOX, ISO 27001, NIST CSF</td><td>Compliance, Auditors</td><td>Monthly</td></tr>
<tr><td><strong>Executive</strong></td><td>Security Posture Summary, Risk Trends</td><td>CISO, Board</td><td>Weekly/Monthly</td></tr>
<tr><td><strong>SOC Operations</strong></td><td>Incident SLA, MTTR/MTTD, Alert Volume</td><td>SOC Manager</td><td>Weekly</td></tr>
<tr><td><strong>Threat Detection</strong></td><td>Top Threats, Attack Trends, IOC Hits</td><td>Threat Team</td><td>Daily</td></tr>
<tr><td><strong>Network</strong></td><td>Top Talkers, Bandwidth, Availability</td><td>NOC</td><td>Daily</td></tr>
<tr><td><strong>User Activity</strong></td><td>Auth Activity, VPN Usage, Access Anomalies</td><td>HR, Legal, Security</td><td>Weekly</td></tr>
<tr><td><strong>Asset</strong></td><td>New Devices, Vulnerability Summary, Patch Status</td><td>IT, Security</td><td>Weekly</td></tr>
</tbody>
</table>
</div>

<h2 id="pci-reports">PCI DSS Report Coverage</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>PCI DSS Requirement</th><th>FortiSIEM Report</th></tr>
</thead>
<tbody>
<tr><td>Req 7: Restrict access to need-to-know</td><td>User Access Rights Report, Policy Changes</td></tr>
<tr><td>Req 8: Identify and authenticate access</td><td>Failed Authentication Report, MFA Usage</td></tr>
<tr><td>Req 10: Track and monitor all access</td><td>Privileged User Activity, Log Integrity Report</td></tr>
<tr><td>Req 10.5: Secure audit trails</td><td>Log Collection Status, Log Gaps Report</td></tr>
<tr><td>Req 11: Regularly test security systems</td><td>Vulnerability Scan Tracking, IDS Alert Report</td></tr>
<tr><td>Req 12: Security policy maintenance</td><td>Configuration Change Report</td></tr>
</tbody>
</table>
</div>

<h2 id="create-report">Creating Custom Reports</h2>

<div class="steps">
    <div class="step">
        <div class="step-title">Create Report Template</div>
        <p>Go to <strong>ANALYTICS → Reports → Add Report</strong>. Choose from template or start blank. Set title, description, and categories.</p>
    </div>
    <div class="step">
        <div class="step-title">Add Report Sections</div>
        <p>Each section is powered by a saved search query. Add as many sections as needed: Summary tables, trend charts, top-N lists, etc.</p>
    </div>
    <div class="step">
        <div class="step-title">Configure Schedule</div>
        <p>Set: frequency (daily/weekly/monthly), time, recipient email addresses, report format (PDF/HTML/CSV).</p>
    </div>
    <div class="step">
        <div class="step-title">Set Time Scope</div>
        <p>Relative (Last 7 days) or fixed period. For compliance reports, use fixed calendar periods (Last Month).</p>
    </div>
</div>
`;

KB.content['fsiem-threat-hunting'] = `
<h1><span class="h1-icon">🎯</span> Threat Hunting</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What Is Threat Hunting</div>
    <p>Threat hunting is the <strong>proactive</strong> search for hidden threats that have evaded automated detection. Unlike reactive alert-driven security, hunters start with a hypothesis ("I think an attacker may be doing X") and actively search for evidence. FortiSIEM is a powerful threat hunting platform because of its broad visibility, long retention, and flexible search engine.</p>
</div>

<h2 id="hunting-methodology">Hunting Methodology</h2>

<div class="mermaid-wrapper">
<div class="mermaid">
flowchart LR
    A["Hypothesis\n(Threat Intelligence\nor Intuition)"] --> B["Data Collection\n(Define search scope)"]
    B --> C["Pattern Analysis\n(Search & correlate)"]
    C --> D{Anomaly Found?}
    D -- Yes --> E["Deep Dive\n(Pivot & expand)"]
    D -- No --> F["Refine Hypothesis\nor Close"]
    E --> G{Confirmed Threat?}
    G -- Yes --> H["Incident Response\n+ Rule Creation"]
    G -- No --> F
    style H fill:#ef4444,color:#fff
    style A fill:#3b82f6,color:#fff
</div>
<div class="mermaid-caption">Threat Hunting Cycle — Hypothesis-driven investigation</div>
</div>

<h2 id="hunting-frameworks">Hunting Frameworks</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Framework</th><th>Description</th><th>Use in FortiSIEM</th></tr>
</thead>
<tbody>
<tr><td><strong>MITRE ATT&amp;CK</strong></td><td>Knowledge base of adversary TTPs</td><td>Map FortiSIEM rules to ATT&amp;CK techniques, identify gaps</td></tr>
<tr><td><strong>Pyramid of Pain</strong></td><td>IOC detection difficulty hierarchy</td><td>Prioritize TTPs and tools over IPs/hashes (harder to evade)</td></tr>
<tr><td><strong>PEAK Framework</strong></td><td>Prepare-Execute-Act-Keynote hunt cycle</td><td>Structure hunts systematically with documentation</td></tr>
<tr><td><strong>F3EAD</strong></td><td>Find-Fix-Finish-Exploit-Analyze-Disseminate</td><td>Military-derived hunt cycle for SOC operations</td></tr>
</tbody>
</table>
</div>

<h2 id="hunt-examples">50+ Threat Hunting Queries</h2>

<h3>🔴 Initial Access (MITRE T1190, T1078, T1133)</h3>

<div class="code-block">
    <div class="code-header"><span>Hunt — VPN Logins from New Countries</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Hypothesis: Attacker obtained user credentials and logging in via SSL VPN

Hunt Query:
Event Type: FortiGate-VPN, FortiGate-SSL-VPN
Filter: action = "accept" AND eventType = "ssl-login"
        AND user != "svc-*"  # Exclude service accounts
Group By: user, srcCountry
Display: user, srcIpAddr, srcCountry, eventTime, duration

Pivot: For users logging from unusual country, check:
- Were credentials recently changed?
- Any recent phishing reports for that user?
- What did they access after login?
- Normal working hours?</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Hunt — Successful Login after Multiple Failures</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Hypothesis: Brute force succeeded and attacker accessed systems

Hunt Query:
Step 1 - Find accounts with 5+ failures in 1 hour:
  Event Type: Authentication
  Filter: eventType CONTAINS "Failed-Login"
  Group By: user, srcIpAddr
  Aggregate: COUNT > 5 in 3600s

Step 2 - Check if those accounts then logged in successfully:
  Event Type: Authentication
  Filter: eventType CONTAINS "Login-Success"
         AND user IN [results from step 1]
         AND eventTime > [first failure time]
  Display: user, srcIpAddr, hostName, eventTime</code></pre>
</div>

<h3>🟠 Execution (MITRE T1059, T1204)</h3>

<div class="code-block">
    <div class="code-header"><span>Hunt — Suspicious Process Executions</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Hypothesis: Malware or attacker executing tools on endpoints

Hunt Query:
Event Type: Windows-ProcessCreate (Sysmon EventID 1)
Filter: parentProcess IN ("winword.exe","excel.exe","outlook.exe",
        "powerpnt.exe","acrord32.exe","chrome.exe","iexplore.exe")
        AND processName IN ("cmd.exe","powershell.exe","wscript.exe",
        "cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe",
        "certutil.exe","bitsadmin.exe")
Display: eventTime, hostName, user, parentProcess, processName, commandLine
Sort: eventTime DESC</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Hunt — LOLBins (Living off the Land)</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Hypothesis: Attacker using built-in Windows tools to avoid detection

Hunt Query:
Event Type: Windows-ProcessCreate
Filter: processName IN ("certutil.exe","bitsadmin.exe","msiexec.exe",
        "regsvr32.exe","regasm.exe","mshta.exe","wmic.exe",
        "cmstp.exe","msbuild.exe","installutil.exe")
        AND (commandLine CONTAINS "http" OR commandLine CONTAINS "ftp"
        OR commandLine CONTAINS "urlcache" OR commandLine CONTAINS "/transfer")
Display: eventTime, hostName, user, processName, commandLine, parentProcess</code></pre>
</div>

<h3>🟡 Persistence (MITRE T1547, T1053, T1543)</h3>

<div class="code-block">
    <div class="code-header"><span>Hunt — Scheduled Task Creation</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Hypothesis: Attacker created scheduled tasks for persistence

Hunt Query:
Event Type: Windows-Security (EventID 4698) OR Windows-ProcessCreate
Filter: (processName = "schtasks.exe" AND commandLine CONTAINS "/create")
        OR eventType = "ScheduledTask-Created"
Display: eventTime, hostName, user, taskName, taskCommand, commandLine
Exclude: taskName IN "known-legit-tasks"
Sort: eventTime DESC</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Hunt — New Services Created</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Hypothesis: Malware installed as Windows service for persistence

Hunt Query:
Event Type: Windows-Security (EventID 4697) OR Windows-System (EventID 7045)
Filter: eventType IN ("Service-Installed","New-Service-Created")
        AND serviceStartType = "AutoStart"
Display: eventTime, hostName, user, serviceName, serviceFile, serviceStartType
Exclude: serviceName IN KnownServices-Watchlist
Sort: eventTime DESC</code></pre>
</div>

<h3>🔵 Lateral Movement (MITRE T1021, T1075, T1550)</h3>

<div class="code-block">
    <div class="code-header"><span>Hunt — Abnormal SMB Traffic (Internal)</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Hypothesis: Attacker moving laterally via SMB

Hunt Query:
Event Type: FortiGate-Traffic, Windows-Security
Filter: destPort = "445" AND srcIpAddr IN "10.0.0.0/8"
        AND destIpAddr IN "10.0.0.0/8"
        AND srcIpAddr != destIpAddr
Group By: srcIpAddr
Aggregate: COUNT(DISTINCT destIpAddr) as UniqueTargets
Having: UniqueTargets > 10
Sort: UniqueTargets DESC
Time: Last 2 Hours</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Hunt — RDP from Non-IT Sources</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Hypothesis: Attacker using RDP for lateral movement from compromised user workstations

Hunt Query:
Event Type: FortiGate-Traffic, Windows-Security (EventID 4624)
Filter: destPort = "3389"
        AND srcIpAddr IN "Workstations-VLAN"  # Not from IT subnets
        AND destIpAddr IN "Servers-VLAN"
Group By: srcIpAddr, destIpAddr, user
Aggregate: COUNT > 3
Time: Last 24 Hours</code></pre>
</div>

<h3>🟣 Exfiltration (MITRE T1041, T1048, T1567)</h3>

<div class="code-block">
    <div class="code-header"><span>Hunt — Large HTTPS Uploads</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Hypothesis: Data being exfiltrated via HTTPS to unknown destinations

Hunt Query:
Event Type: FortiGate-Traffic
Filter: destPort IN "443,8443" AND action = "accept"
        AND destIpAddr NOT IN KnownCloud-IPs  # Exclude O365, Google, etc.
        AND srcIpAddr IN "10.0.0.0/8"
Group By: srcIpAddr, destIpAddr, destCountry
Aggregate: SUM(sentBytes) as TotalSent
Having: TotalSent > 52428800  # 50 MB
Sort: TotalSent DESC
Time: Last 24 Hours</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Hunt — DNS TXT Record Abuse</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Hypothesis: Data exfiltration via DNS TXT records (common malware technique)

Hunt Query:
Event Type: FortiGate-DNS
Filter: queryType = "TXT" AND rcvdBytes > 500
Group By: srcIpAddr, dnsQuery, dnsServerIp
Aggregate: COUNT > 20
Time: Last 4 Hours</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Hunt — FTP Uploads to External</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Hypothesis: Attacker exfiltrating via FTP

Hunt Query:
Event Type: FortiGate-Traffic, FortiGate-AppControl
Filter: (destPort IN "20,21" OR appName CONTAINS "FTP")
        AND action = "accept"
        AND destIpAddr NOT IN "10.0.0.0/8"
Group By: srcIpAddr, destIpAddr
Aggregate: SUM(sentBytes) as Sent
Sort: Sent DESC
Time: Last 24 Hours</code></pre>
</div>

<h3>⚫ Command & Control (MITRE T1071, T1090, T1219)</h3>

<div class="code-block">
    <div class="code-header"><span>Hunt — Beaconing Detection</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Hypothesis: Infected host beaconing to C2 server at regular intervals

Hunt Query:
Event Type: FortiGate-Traffic
Filter: action = "accept" AND destIpAddr NOT IN "10.0.0.0/8"
        AND destPort NOT IN "80,443,53"
        AND sentBytes BETWEEN "100-5000"  # Small regular packets typical of C2
Group By: srcIpAddr, destIpAddr, destPort
Aggregate: COUNT as Connections, STDDEV(eventTime_interval) as Variance
Having: Connections > 30 AND Variance < 60  # Regular timing = low variance
Sort: Connections DESC</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Hunt — Non-Standard Port HTTPS</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Hypothesis: Malware using HTTPS on non-standard ports to evade web proxies

Hunt Query:
Event Type: FortiGate-Traffic, FortiGate-AppControl
Filter: appName = "SSL" AND destPort NOT IN "443,8443,8080"
        AND action = "accept"
        AND destIpAddr NOT IN "10.0.0.0/8"
Group By: srcIpAddr, destIpAddr, destPort
Aggregate: COUNT as Sessions, SUM(sentBytes) as Sent
Sort: Sessions DESC
Time: Last 24 Hours</code></pre>
</div>

<h2 id="hunting-tips">Threat Hunting Tips</h2>

<ul class="checklist">
    <li><span class="check checked">✓</span> Start every hunt with a clear hypothesis — don't hunt blindly</li>
    <li><span class="check checked">✓</span> Use MITRE ATT&amp;CK to identify technique-based hypotheses</li>
    <li><span class="check checked">✓</span> Build baselines first — anomaly hunting requires knowing what "normal" looks like</li>
    <li><span class="check checked">✓</span> Pivot aggressively — each finding should lead to new search dimensions</li>
    <li><span class="check checked">✓</span> Document every hunt — what you searched, what you found, what actions you took</li>
    <li><span class="check checked">✓</span> Convert successful hunts into rules — automate future detection</li>
    <li><span class="check checked">✓</span> Hunt where you have least visibility — attackers exploit blind spots</li>
    <li><span class="check checked">✓</span> Always hunt after a major threat report or CVE announcement</li>
    <li><span class="check checked">✓</span> Set aside dedicated hunting time — not just incident response</li>
</ul>
`;

KB.content['fsiem-cmdb'] = `
<h1><span class="h1-icon">📚</span> CMDB (Configuration Management Database)</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>The FortiSIEM CMDB is an auto-populated inventory of all discovered devices, their attributes, relationships, and business context. It enriches every event with asset information: what device is this? Who owns it? How critical is it? What vulnerabilities does it have? This context is critical for alert triage and prioritization.</p>
</div>

<div class="gui-path">CMDB <span class="gui-sep">›</span> Devices</div>

<h2 id="cmdb-attributes">Key CMDB Attributes</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Attribute</th><th>Description</th><th>Use in SIEM</th></tr>
</thead>
<tbody>
<tr><td><strong>Device Type</strong></td><td>Router, Switch, Firewall, Server, Workstation</td><td>Filter events by device category</td></tr>
<tr><td><strong>Criticality</strong></td><td>Critical, High, Medium, Low</td><td>Prioritize incidents affecting critical assets</td></tr>
<tr><td><strong>Owner/Contact</strong></td><td>Business owner, IT contact</td><td>Who to notify for incidents</td></tr>
<tr><td><strong>Location</strong></td><td>Site, building, rack, VLAN</td><td>Geographic correlation</td></tr>
<tr><td><strong>Business Unit</strong></td><td>Finance, HR, IT, Sales</td><td>Role-based reporting</td></tr>
<tr><td><strong>OS Version</strong></td><td>Windows 10, Ubuntu 22.04</td><td>Vulnerability correlation</td></tr>
<tr><td><strong>Running Services</strong></td><td>IIS, Apache, MSSQL</td><td>Attack surface analysis</td></tr>
<tr><td><strong>Open Vulnerabilities</strong></td><td>CVEs from scanner integration</td><td>Risk-weighted alert prioritization</td></tr>
</tbody>
</table>
</div>

<h2 id="cmdb-enrichment">CMDB for Alert Enrichment</h2>

<p>Every FortiSIEM alert is automatically enriched with CMDB data. When an alert fires for <code>srcIpAddr = 10.10.50.100</code>, the analyst immediately sees:</p>
<ul>
<li>Hostname: <code>FINANCE-SRV-01</code></li>
<li>Device Type: <code>Windows Server 2022</code></li>
<li>Criticality: <code>Critical</code></li>
<li>Owner: <code>finance-it@company.com</code></li>
<li>Open Vulnerabilities: <code>3 Critical, 7 High</code></li>
<li>Business Unit: <code>Finance</code></li>
</ul>
<p>This context transforms an IP address into an actionable, prioritized incident.</p>
`;

KB.content['fsiem-analytics'] = `
<h1><span class="h1-icon">📊</span> Analytics & UEBA</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>FortiSIEM Analytics uses machine learning and statistical modeling to build behavioral baselines for users, entities (devices), and networks. It detects deviations that rule-based systems miss — because attackers who mimic normal behavior evade threshold rules but deviate from statistical baselines.</p>
</div>

<div class="gui-path">ANALYTICS <span class="gui-sep">›</span> UEBA</div>

<h2 id="ueba-baselines">What UEBA Baselines</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Entity</th><th>Baseline Metrics</th><th>Anomaly Detected</th></tr>
</thead>
<tbody>
<tr><td><strong>User</strong></td><td>Login times, locations, accessed resources, data volume</td><td>Login at 3 AM, from new country, accessing finance files</td></tr>
<tr><td><strong>Host</strong></td><td>Outbound connections, processes run, network peers</td><td>Server suddenly connecting to 50 new IPs</td></tr>
<tr><td><strong>Network</strong></td><td>Interface utilization, protocol mix, peer IPs</td><td>500% increase in DNS traffic on WAN link</td></tr>
<tr><td><strong>Application</strong></td><td>Normal error rates, response times, user counts</td><td>Login error rate spikes from 1% to 40%</td></tr>
</tbody>
</table>
</div>

<h2 id="ueba-risk-score">UEBA Risk Scoring</h2>

<p>Each user and entity has a dynamic <strong>Risk Score (0-100)</strong>:</p>
<ul>
<li><strong>0-30</strong>: Normal activity</li>
<li><strong>31-60</strong>: Elevated — worth monitoring</li>
<li><strong>61-80</strong>: High — investigate soon</li>
<li><strong>81-100</strong>: Critical — immediate investigation</li>
</ul>

<p>Risk scores accumulate over time based on anomalies and decay as behavior returns to normal.</p>

<div class="gui-path">ANALYTICS <span class="gui-sep">›</span> UEBA <span class="gui-sep">›</span> User Risk</div>
`;

KB.content['fsiem-automation'] = `
<h1><span class="h1-icon">🤖</span> FortiSIEM Automation & SOAR</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>FortiSIEM includes a built-in SOAR (Security Orchestration, Automation, and Response) engine that automates repetitive analyst tasks: sending notifications, creating tickets, enriching incidents with threat intel lookups, and triggering remediation actions on integrated security controls.</p>
</div>

<div class="gui-path">RESOURCES <span class="gui-sep">›</span> Incident Notification</div>

<h2 id="automation-types">Automation Types</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Action Type</th><th>Description</th><th>Integration</th></tr>
</thead>
<tbody>
<tr><td><strong>Email Notification</strong></td><td>Alert SOC team with incident details</td><td>SMTP server</td></tr>
<tr><td><strong>Ticket Creation</strong></td><td>Auto-create incidents in ticketing system</td><td>JIRA, ServiceNow, Remedy, Zendesk</td></tr>
<tr><td><strong>Slack/Teams Alert</strong></td><td>Post incident to SOC channel</td><td>Webhook URL</td></tr>
<tr><td><strong>Script Execution</strong></td><td>Run custom Python/Bash/PowerShell script</td><td>Local or remote execution</td></tr>
<tr><td><strong>FortiGate Integration</strong></td><td>Block IP, quarantine host, update address group</td><td>FortiGate REST API</td></tr>
<tr><td><strong>Threat Intel Lookup</strong></td><td>Enrich incident with VirusTotal, Shodan, AbuseIPDB</td><td>REST APIs</td></tr>
<tr><td><strong>FortiDeceptor</strong></td><td>Deploy deception assets in affected segment</td><td>FortiDeceptor API</td></tr>
</tbody>
</table>
</div>

<h2 id="playbook-examples">Playbook Examples</h2>

<div class="code-block">
    <div class="code-header"><span>Playbook — Malware Detection Response</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Trigger: Rule "FortiGate Malware Detected" fires

Step 1: Enrich incident
  - Lookup srcIpAddr in CMDB → Get hostname, owner, criticality
  - Lookup hash in VirusTotal → Get malware family, detection count
  - Lookup IP in Threat Intel → Check if known C2

Step 2: Notify
  - Email: soc@company.com with full incident details
  - Slack: #soc-alerts channel with summary + link
  - If criticality = "Critical": Page on-call analyst via PagerDuty

Step 3: Contain (if auto-approved)
  - FortiGate API: Add srcIpAddr to "Quarantine" address group
  - FortiGate API: Block all outbound from srcIpAddr except DNS
  - FortiNAC API: Quarantine network port

Step 4: Create Ticket
  - ServiceNow: Create P2 ticket with all enrichment data
  - Assign to: Malware Response Team
  - SLA: 4 hours for initial containment</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Playbook — Brute Force Response</span><button class="code-copy-btn">Copy</button></div>
    <pre><code">Trigger: Rule "External Brute Force" fires (20+ failures in 5 min)

Step 1: Enrich
  - AbuseIPDB lookup on srcIpAddr → Check abuse confidence score
  - Geolocation lookup → Country, ASN, ISP
  - Check if IP is in existing blocklist

Step 2: Auto-Block (if AbuseIPDB confidence > 50%)
  - FortiGate API: Add srcIpAddr to "Auto-Blocked-Brute-Force" address group
  - FortiGate API: Block rule at top of policy table
  - Log: "IP auto-blocked at [timestamp] due to brute force"

Step 3: Notify
  - Email: security-team@company.com
  - Slack: #security-incidents
  - Include: IP, country, service targeted, block action taken

Step 4: Check Account Status
  - If target user = admin account: Escalate to Critical immediately
  - If account locked: Note in ticket
  - If login SUCCEEDED before block: Escalate to "Account Compromise" playbook</code></pre>
</div>

<h2 id="fortigate-integration">FortiSIEM ↔ FortiGate Integration</h2>

<p>FortiSIEM can programmatically control FortiGate via REST API:</p>

<div class="code-block">
    <div class="code-header"><span>Python — FortiGate REST API from FortiSIEM</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># FortiSIEM custom action — block IP on FortiGate</span>
<span class="keyword">import</span> requests
<span class="keyword">import</span> json

FG_IP = <span class="string">"10.0.0.1"</span>
API_KEY = <span class="string">"your-api-key"</span>

<span class="keyword">def</span> block_ip(ip_to_block):
    headers = {<span class="string">"Authorization"</span>: f<span class="string">"Bearer {API_KEY}"</span>, <span class="string">"Content-Type"</span>: <span class="string">"application/json"</span>}
    
    <span class="comment"># Add IP to existing address group</span>
    url = f<span class="string">"https://{FG_IP}/api/v2/cmdb/firewall/addrgrp/SIEM-Auto-Block"</span>
    
    <span class="comment"># Get current members</span>
    current = requests.get(url, headers=headers, verify=<span class="keyword">False</span>).json()
    members = current[<span class="string">"results"</span>][0][<span class="string">"member"</span>]
    
    <span class="comment"># Create address object for the IP</span>
    addr_url = f<span class="string">"https://{FG_IP}/api/v2/cmdb/firewall/address"</span>
    addr_data = {<span class="string">"name"</span>: f<span class="string">"SIEM-Block-{ip_to_block}"</span>, <span class="string">"type"</span>: <span class="string">"ipmask"</span>,
                 <span class="string">"subnet"</span>: f<span class="string">"{ip_to_block}/32"</span>}
    requests.post(addr_url, json=addr_data, headers=headers, verify=<span class="keyword">False</span>)
    
    <span class="comment"># Add to group</span>
    members.append({<span class="string">"name"</span>: f<span class="string">"SIEM-Block-{ip_to_block}"</span>})
    requests.put(url, json={<span class="string">"member"</span>: members}, headers=headers, verify=<span class="keyword">False</span>)
    
    <span class="keyword">return</span> f<span class="string">"IP {ip_to_block} blocked on FortiGate"</span></code></pre>
</div>
`;

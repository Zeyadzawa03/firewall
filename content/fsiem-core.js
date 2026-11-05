// ============================================================
// FortiSIEM — Complete Documentation
// Covers: Architecture, Device Management, Dashboards,
//         Event Management, Searches, Rules, Reports,
//         CMDB, Analytics, Threat Detection, Automation
// ============================================================

KB.content['fsiem-overview'] = `
<h1><span class="h1-icon">🛡️</span> FortiSIEM Overview</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What Is FortiSIEM</div>
    <p>FortiSIEM (formerly AccelOps) is Fortinet's enterprise Security Information and Event Management (SIEM) platform. It provides: multi-vendor log collection and correlation, UEBA (User and Entity Behavior Analytics), CMDB asset management, real-time threat detection via rules, incident management, compliance reporting, network performance monitoring, and security automation via SOAR.</p>
</div>

<h2 id="fsiem-capabilities">Core Capabilities</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Capability</th><th>Description</th><th>Business Value</th></tr>
</thead>
<tbody>
<tr><td><strong>Log Management</strong></td><td>Collect, parse, normalize, store logs from 300+ vendors</td><td>Single pane of glass for all logs</td></tr>
<tr><td><strong>Event Correlation</strong></td><td>Rule engine correlates events across devices/time</td><td>Detect multi-stage attacks</td></tr>
<tr><td><strong>UEBA</strong></td><td>Baseline user/entity behavior, detect anomalies</td><td>Insider threat, compromised account detection</td></tr>
<tr><td><strong>CMDB</strong></td><td>Auto-discover and inventory all network assets</td><td>Complete asset visibility</td></tr>
<tr><td><strong>Incident Management</strong></td><td>Case management, ticket integration, playbooks</td><td>Structured SOC response</td></tr>
<tr><td><strong>Compliance</strong></td><td>Pre-built reports: PCI-DSS, HIPAA, SOX, ISO 27001, GDPR</td><td>Automated compliance evidence</td></tr>
<tr><td><strong>NOC/Network Monitoring</strong></td><td>SNMP polling, availability monitoring, performance metrics</td><td>IT operations visibility</td></tr>
<tr><td><strong>SOAR</strong></td><td>Playbooks, notification, ticketing, enrichment automation</td><td>Reduce MTTR, automate repetitive tasks</td></tr>
</tbody>
</table>
</div>

<h2 id="fsiem-architecture">Architecture</h2>

<div class="mermaid-wrapper">
<div class="mermaid">
graph TD
    subgraph Sources["Log Sources"]
        FG["FortiGate"]
        AD["Active Directory"]
        FW["Firewalls (multi-vendor)"]
        OS["Linux/Windows Servers"]
        VPN["VPN Concentrators"]
        CLOUD["Cloud: AWS/Azure/GCP"]
    end

    subgraph Collectors["Collector Layer"]
        COL1["Collector\n(Remote Site 1)"]
        COL2["Collector\n(Remote Site 2)"]
    end

    subgraph Core["FortiSIEM Core"]
        SUP["Supervisor\n(UI, DB, Correlation)"]
        WRK1["Worker\n(Query Processing)"]
        WRK2["Worker\n(Query Processing)"]
        ES["EventDB\n(ClickHouse/NFS)"]
    end

    FG & AD & FW --> COL1
    OS & VPN & CLOUD --> COL2
    COL1 & COL2 --> SUP
    SUP --> ES
    SUP <--> WRK1
    SUP <--> WRK2
    WRK1 & WRK2 --> ES

    style SUP fill:#ee3124,color:#fff
    style ES fill:#1e293b,color:#e2e8f0
</div>
<div class="mermaid-caption">FortiSIEM Architecture — Supervisor, Workers, Collectors, EventDB</div>
</div>

<h2 id="fsiem-components">Component Roles</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Component</th><th>Role</th><th>When to Deploy</th></tr>
</thead>
<tbody>
<tr><td><strong>Supervisor</strong></td><td>Master node: GUI, rule engine, CMDB, correlation, scheduling</td><td>Always — 1 per deployment</td></tr>
<tr><td><strong>Worker</strong></td><td>Scale-out query processing and event parsing</td><td>High EPS environments (&gt;5,000 EPS)</td></tr>
<tr><td><strong>Collector</strong></td><td>Receives logs from remote sites, forwards to Supervisor</td><td>Remote offices, DMZ segments, cloud</td></tr>
<tr><td><strong>EventDB</strong></td><td>Distributed time-series database (ClickHouse or NFS)</td><td>All deployments — storage layer</td></tr>
</tbody>
</table>
</div>

<h2 id="fsiem-deployment-sizing">Deployment Sizing</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Deployment Size</th><th>EPS</th><th>Architecture</th><th>Storage (90 days)</th></tr>
</thead>
<tbody>
<tr><td><strong>Small</strong></td><td>&lt;2,000</td><td>Supervisor only (all-in-one)</td><td>2-5 TB</td></tr>
<tr><td><strong>Medium</strong></td><td>2,000-10,000</td><td>Supervisor + 2 Workers</td><td>5-20 TB</td></tr>
<tr><td><strong>Large</strong></td><td>10,000-50,000</td><td>Supervisor + 4+ Workers + Collectors</td><td>20-100 TB</td></tr>
<tr><td><strong>Enterprise</strong></td><td>&gt;50,000</td><td>HA Supervisor + 8+ Workers + Multi-Collectors</td><td>100+ TB NFS/SAN</td></tr>
</tbody>
</table>
</div>
`;

KB.content['fsiem-device-management'] = `
<h1><span class="h1-icon">🖥️</span> Device Management</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Device Management in FortiSIEM is where you register, configure, and manage all monitored devices. FortiSIEM can auto-discover devices via SNMP sweeps, or you can manually add them. Each device has credentials, a monitoring profile, and collection parameters.</p>
</div>

<div class="gui-path">ADMIN <span class="gui-sep">›</span> Setup <span class="gui-sep">›</span> Credentials</div>
<div class="gui-path">ADMIN <span class="gui-sep">›</span> Setup <span class="gui-sep">›</span> Discovery</div>
<div class="gui-path">CMDB <span class="gui-sep">›</span> Devices</div>

<h2 id="add-devices">Adding Devices</h2>

<h3>Step 1: Define Credentials</h3>
<p>Go to <strong>ADMIN → Setup → Credentials</strong> and create credential profiles for each device type:</p>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Device Type</th><th>Protocol</th><th>Credential Type</th><th>Notes</th></tr>
</thead>
<tbody>
<tr><td>FortiGate</td><td>SNMP + Syslog</td><td>SNMPv2c community or SNMPv3</td><td>Enable SNMP on device interface</td></tr>
<tr><td>Windows Server</td><td>WMI</td><td>Domain admin credentials</td><td>WMI must be enabled</td></tr>
<tr><td>Linux Server</td><td>SSH</td><td>SSH username + key or password</td><td>Sudo access for full monitoring</td></tr>
<tr><td>Active Directory</td><td>LDAP</td><td>Service account read-only</td><td>LDAPS recommended</td></tr>
<tr><td>Network Switches</td><td>SNMP + SSH</td><td>SNMPv3 + SSH credentials</td><td>One credential set per vendor type</td></tr>
<tr><td>AWS</td><td>REST API</td><td>IAM Access Key + Secret</td><td>Read-only IAM policy recommended</td></tr>
<tr><td>VMware</td><td>REST API</td><td>vCenter API user</td><td>Read-only role on vCenter</td></tr>
</tbody>
</table>
</div>

<h3>Step 2: Run Discovery</h3>
<div class="gui-path">ADMIN <span class="gui-sep">›</span> Setup <span class="gui-sep">›</span> Discovery <span class="gui-sep">›</span> New Discovery</div>

<p>Configure:</p>
<ul>
<li><strong>IP Range</strong>: Target subnet (e.g., 10.0.0.0/24)</li>
<li><strong>Credential</strong>: Select matching credentials</li>
<li><strong>Collector</strong>: Which collector handles this network</li>
<li><strong>Discovery Method</strong>: SNMP, WMI, SSH, Ping</li>
</ul>

<h3>Step 3: Verify in CMDB</h3>
<div class="gui-path">CMDB <span class="gui-sep">›</span> Devices <span class="gui-sep">›</span> All Devices</div>

<p>After discovery, each device appears with:</p>
<ul>
<li>Device type, vendor, and model</li>
<li>IP address, hostname, and location</li>
<li>Monitoring status (green/yellow/red)</li>
<li>Last event time</li>
</ul>

<h2 id="log-sources">Log Source Configuration</h2>

<h3>Syslog Configuration (FortiGate)</h3>
<div class="callout best-practice">
    <div class="callout-title">🎯 FortiSIEM Syslog Settings</div>
    <p>On FortiGate, configure syslog to FortiSIEM Collector IP:<br>
    • Format: <strong>CEF or Default</strong><br>
    • Port: <strong>514 UDP</strong> (or 514/TCP for reliable)<br>
    • Facility: <strong>local7</strong><br>
    • Severity: <strong>information</strong> (catch all levels)<br>
    FortiSIEM auto-identifies FortiGate syslog and maps it correctly.</p>
</div>

<h3>Agent-Based Collection (Windows)</h3>
<p>FortiSIEM provides a Windows Agent for:</p>
<ul>
<li>Windows Event Log collection (Security, System, Application)</li>
<li>Log file monitoring (IIS, application logs)</li>
<li>WMI performance data</li>
<li>File integrity monitoring</li>
</ul>

<div class="gui-path">ADMIN <span class="gui-sep">›</span> Setup <span class="gui-sep">›</span> Windows Agent</div>

<h2 id="monitoring-profiles">Monitoring Profiles</h2>

<p>Monitoring profiles define what FortiSIEM collects from each device type: SNMP OIDs for performance, log categories, application-specific monitoring, file monitoring patterns.</p>

<div class="gui-path">ADMIN <span class="gui-sep">›</span> Device Support <span class="gui-sep">›</span> Monitoring Profiles</div>
`;

KB.content['fsiem-dashboard'] = `
<h1><span class="h1-icon">📊</span> Dashboards</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>FortiSIEM dashboards provide real-time and historical visual intelligence about your security posture, network performance, and event trends. They are customizable, role-based, and support multiple widget types: summary, charts, tables, maps, and metric displays.</p>
</div>

<div class="gui-path">DASHBOARD <span class="gui-sep">›</span> Summary</div>

<h2 id="dashboard-types">Dashboard Types</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Dashboard</th><th>Audience</th><th>Key Widgets</th></tr>
</thead>
<tbody>
<tr><td><strong>Executive Summary</strong></td><td>CISO, Management</td><td>Risk score trend, incident count, top threats, compliance status</td></tr>
<tr><td><strong>SOC Operations</strong></td><td>SOC Analysts</td><td>Real-time events, open incidents, MITRE ATT&amp;CK coverage, top attackers</td></tr>
<tr><td><strong>Network Operations</strong></td><td>NOC Team</td><td>Device availability, interface utilization, top talkers, bandwidth</td></tr>
<tr><td><strong>FortiGate Security</strong></td><td>Firewall Admin</td><td>Top denied IPs, AV detections, IPS blocks, VPN activity</td></tr>
<tr><td><strong>Threat Intelligence</strong></td><td>Threat Analysts</td><td>IOC matches, C2 communications, geo-attack map, malware families</td></tr>
<tr><td><strong>User Activity</strong></td><td>SOC/HR</td><td>Authentication events, VPN logins, data access, anomalous users</td></tr>
<tr><td><strong>Compliance</strong></td><td>Compliance Team</td><td>PCI/HIPAA/SOX control status, failed controls, last audit</td></tr>
</tbody>
</table>
</div>

<h2 id="dashboard-creation">Creating Custom Dashboards</h2>

<div class="steps">
    <div class="step">
        <div class="step-title">Create Dashboard</div>
        <p><strong>Dashboard → My Dashboard → Add Dashboard</strong>. Give it a name, description, and set refresh interval.</p>
    </div>
    <div class="step">
        <div class="step-title">Add Widgets</div>
        <p>Click <strong>Add Widget</strong>. Choose widget type: Summary, Chart (pie/bar/line/area), Table, Map, or Sparkline.</p>
    </div>
    <div class="step">
        <div class="step-title">Configure Widget Query</div>
        <p>Each widget is powered by a saved query or rule. Select the data source, time range, filters, and grouping.</p>
    </div>
    <div class="step">
        <div class="step-title">Set Thresholds (for gauges)</div>
        <p>Configure warning/critical thresholds for metric widgets. These color-code the display red/yellow/green.</p>
    </div>
    <div class="step">
        <div class="step-title">Share Dashboard</div>
        <p>Share with user roles or specific users. Set as default for specific roles.</p>
    </div>
</div>

<h2 id="key-widgets">Key Widgets to Build</h2>

<ul class="checklist">
    <li><span class="check checked">✓</span> <strong>Top Source IPs by Event Count</strong> — identify noisy or malicious sources</li>
    <li><span class="check checked">✓</span> <strong>Event Severity Distribution</strong> — pie chart of critical/high/medium/low</li>
    <li><span class="check checked">✓</span> <strong>FortiGate Blocked Traffic Trend</strong> — bar chart over 7 days</li>
    <li><span class="check checked">✓</span> <strong>Top Denied Destinations (External)</strong> — outbound connection attempts</li>
    <li><span class="check checked">✓</span> <strong>VPN User Activity</strong> — who connected, when, from where</li>
    <li><span class="check checked">✓</span> <strong>Incident Open/Close Rate</strong> — SOC operational metric</li>
    <li><span class="check checked">✓</span> <strong>Device Availability Map</strong> — geographic or rack view</li>
    <li><span class="check checked">✓</span> <strong>MITRE ATT&amp;CK Heat Map</strong> — technique coverage</li>
</ul>
`;

KB.content['fsiem-event-management'] = `
<h1><span class="h1-icon">⚡</span> Event Management</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Event Management in FortiSIEM handles the complete lifecycle of security incidents: detection by rules, enrichment with CMDB/threat intel data, alert generation, incident creation, case assignment, investigation, and resolution tracking. It is the core SOC workflow engine.</p>
</div>

<div class="gui-path">INCIDENTS <span class="gui-sep">›</span> List View</div>

<h2 id="event-lifecycle">Incident Lifecycle</h2>

<div class="mermaid-wrapper">
<div class="mermaid">
flowchart LR
    A["Raw Events\n(Syslog/SNMP/API)"] --> B["Parsing &\nNormalization"]
    B --> C["Rule Engine\nCorrelation"]
    C --> D["Incident Created\n(New)"]
    D --> E["Enrichment\nCMDB + Threat Intel"]
    E --> F["Alert / Notification\nEmail/Slack/Ticket"]
    F --> G["Analyst Assignment\n(Assigned)"]
    G --> H["Investigation\n(In Progress)"]
    H --> I{Verdict}
    I -- True Positive --> J["Containment &\nRemediation"]
    I -- False Positive --> K["Tune Rule\n(Closed/FP)"]
    J --> L["Incident Closed\nRoot Cause Documented"]
    style D fill:#ef4444,color:#fff
    style L fill:#10b981,color:#fff
</div>
<div class="mermaid-caption">Incident Lifecycle — Detection to Closure</div>
</div>

<h2 id="incident-states">Incident States</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>State</th><th>Meaning</th><th>Who Sets It</th></tr>
</thead>
<tbody>
<tr><td><strong>New</strong></td><td>Auto-created by rule, not yet reviewed</td><td>System</td></tr>
<tr><td><strong>Active</strong></td><td>Rule still firing (ongoing threat)</td><td>System</td></tr>
<tr><td><strong>Assigned</strong></td><td>Assigned to an analyst</td><td>Analyst/Manager</td></tr>
<tr><td><strong>In Progress</strong></td><td>Investigation underway</td><td>Analyst</td></tr>
<tr><td><strong>Waiting</strong></td><td>Awaiting external action (change, vendor, user)</td><td>Analyst</td></tr>
<tr><td><strong>Closed</strong></td><td>Resolved and documented</td><td>Analyst</td></tr>
<tr><td><strong>System Closed</strong></td><td>Auto-closed after inactivity timeout</td><td>System</td></tr>
</tbody>
</table>
</div>

<h2 id="incident-management">Working Incidents</h2>

<h3>Triage Checklist</h3>
<ul class="checklist">
    <li><span class="check checked">✓</span> Check incident severity and rule name — understand what triggered it</li>
    <li><span class="check checked">✓</span> Review the triggering events — click "Events" tab in incident</li>
    <li><span class="check checked">✓</span> Check affected device in CMDB — is it critical? Who owns it?</li>
    <li><span class="check checked">✓</span> Review source IP reputation — internal? External? Known bad?</li>
    <li><span class="check checked">✓</span> Check user attribution (if applicable) via LDAP/FSSO</li>
    <li><span class="check checked">✓</span> Look at similar incidents for this host in past 30 days</li>
    <li><span class="check checked">✓</span> Determine: False Positive, True Positive, or Needs Investigation</li>
    <li><span class="check checked">✓</span> Document findings in incident comments</li>
    <li><span class="check checked">✓</span> Set appropriate state and assignee</li>
</ul>

<h2 id="incident-enrichment">Event Enrichment</h2>

<p>FortiSIEM automatically enriches events with context:</p>
<ul>
<li><strong>CMDB data</strong>: Device owner, location, criticality, business unit</li>
<li><strong>IP reputation</strong>: Threat intel feed lookup (Fortinet Threat Intelligence)</li>
<li><strong>User data</strong>: Username from FSSO/LDAP based on source IP</li>
<li><strong>Geographic location</strong>: Country/city based on IP</li>
<li><strong>Vulnerability data</strong>: Known CVEs on affected host</li>
</ul>
`;

KB.content['fsiem-searches'] = `
<h1><span class="h1-icon">🔍</span> FortiSIEM Searches</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>FortiSIEM's search engine allows you to query the EventDB for any combination of event attributes. Searches are the foundation for: ad-hoc investigations, threat hunting, creating rules, building dashboard widgets, generating reports, and building saved queries for reuse.</p>
</div>

<div class="gui-path">ANALYTICS <span class="gui-sep">›</span> Events</div>

<h2 id="search-interface">Search Interface Overview</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Component</th><th>Description</th></tr>
</thead>
<tbody>
<tr><td><strong>Event Type</strong></td><td>Filter by parsed event types (e.g., "FortiGate-Traffic-Deny")</td></tr>
<tr><td><strong>Time Range</strong></td><td>Relative (last 1h, 24h, 7d) or absolute (specific dates)</td></tr>
<tr><td><strong>Filter Criteria</strong></td><td>Attribute-value conditions (srcIpAddr=10.0.0.100 AND action=drop)</td></tr>
<tr><td><strong>Display Fields</strong></td><td>Select which attributes to show in results</td></tr>
<tr><td><strong>Group By</strong></td><td>Aggregate results by attribute (srcIpAddr, user, country)</td></tr>
<tr><td><strong>Aggregate Function</strong></td><td>COUNT, SUM, AVG, MIN, MAX on numeric fields</td></tr>
<tr><td><strong>Sort By</strong></td><td>Order results by any field</td></tr>
</tbody>
</table>
</div>

<h2 id="search-examples">50+ FortiSIEM Search Examples</h2>

<h3>🔴 Security / Threat Detection</h3>

<div class="code-block">
    <div class="code-header"><span>Search — Firewall Denied Traffic to External</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Find all outbound denied traffic from internal hosts</span>
Event Type: FortiGate-Traffic
Filter: action = "deny" AND srcIpAddr IN "10.0.0.0/8,192.168.0.0/16" 
        AND destIpAddr NOT IN "10.0.0.0/8"
Group By: srcIpAddr, destIpAddr
Aggregate: COUNT(Matched Events) as Hits
Sort: Hits DESC
Time: Last 24 Hours</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — IPS Critical Events</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Critical IPS detections</span>
Event Type: FortiGate-IPS
Filter: eventSeverity = "Critical"
Display: eventTime, srcIpAddr, destIpAddr, eventType, signature, action
Sort: eventTime DESC
Time: Last 7 Days</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — Brute Force / Multiple Auth Failures</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Authentication failures — group by source to find brute force</span>
Event Type: Authentication
Filter: eventSeverity IN ("High","Medium") AND eventType CONTAINS "Login-Failed"
Group By: srcIpAddr, destIpAddr, user
Aggregate: COUNT(Matched Events) as Attempts
Having: Attempts > 10
Sort: Attempts DESC
Time: Last 1 Hour</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — Malware / AV Detections</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># AV detections across all devices</span>
Event Type: FortiGate-AV, FortiMail-AV, Windows-Defender
Filter: action IN ("blocked","quarantined","detected")
Display: eventTime, srcIpAddr, hostName, malwareName, virusName, fileName, url
Sort: eventTime DESC
Time: Last 24 Hours</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — Port Scan Detection</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Detect port scanning: one source, many destination ports</span>
Event Type: FortiGate-Traffic
Filter: action = "deny" AND srcIpAddr IN "10.0.0.0/8"
Group By: srcIpAddr, destIpAddr
Aggregate: COUNT(DISTINCT destPort) as Ports
Having: Ports > 20
Sort: Ports DESC
Time: Last 1 Hour</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — Large Data Transfer (Exfiltration)</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Detect large outbound transfers (potential exfiltration)</span>
Event Type: FortiGate-Traffic
Filter: action = "accept" AND destCountry NOT IN "US,UK,DE" 
        AND srcIpAddr IN "10.0.0.0/8"
Group By: srcIpAddr, destIpAddr, destCountry
Aggregate: SUM(sentBytes) as TotalBytes
Having: TotalBytes > 104857600  <span class="comment"># 100 MB</span>
Sort: TotalBytes DESC
Time: Last 24 Hours</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — C2 Beaconing (Regular Intervals)</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Detect potential C2 beaconing: same IP, regular small connections</span>
Event Type: FortiGate-Traffic
Filter: action = "accept" AND destIpAddr NOT IN "10.0.0.0/8" 
        AND sentBytes < 10000
Group By: srcIpAddr, destIpAddr, destPort
Aggregate: COUNT(Matched Events) as Connections, 
           SUM(sentBytes) as TotalSent
Having: Connections > 50
Sort: Connections DESC
Time: Last 24 Hours</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — SSL VPN Failed Logins</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># SSL VPN authentication failures by source IP</span>
Event Type: FortiGate-VPN
Filter: eventType = "ssl-vpn-auth-failed"
Group By: srcIpAddr, user
Aggregate: COUNT(Matched Events) as Failures
Having: Failures > 5
Sort: Failures DESC
Time: Last 1 Hour</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — Admin Configuration Changes</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Detect configuration changes on network devices</span>
Event Type: FortiGate-Event
Filter: eventType CONTAINS "config-change" OR eventType CONTAINS "admin"
Display: eventTime, hostName, user, srcIpAddr, eventType, msg
Sort: eventTime DESC
Time: Last 7 Days</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — Geo-Blocked Traffic Attempts</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Traffic blocked from geo-restricted countries</span>
Event Type: FortiGate-Traffic
Filter: action = "deny" AND srcCountry IN "RU,KP,IR,CN"
Group By: srcCountry, destIpAddr, destPort
Aggregate: COUNT(Matched Events) as Hits
Sort: Hits DESC
Time: Last 24 Hours</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — New/Unknown Applications Detected</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Detect newly seen applications (potential shadow IT)</span>
Event Type: FortiGate-AppControl
Filter: action = "allowed" 
        AND appName NOT IN "Chrome,Firefox,Teams,Office365,DNS,HTTPS"
Group By: appName, srcIpAddr, user
Aggregate: COUNT(Matched Events) as Count
Sort: Count DESC
Time: Last 7 Days</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — Lateral Movement Detection</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Detect lateral movement: internal-to-internal scanning</span>
Event Type: FortiGate-Traffic
Filter: action = "deny" AND srcIpAddr IN "10.0.0.0/8" 
        AND destIpAddr IN "10.0.0.0/8"
        AND destPort IN "22,23,445,3389,5985,5986,1433,3306"
Group By: srcIpAddr, destIpAddr, destPort
Aggregate: COUNT(Matched Events) as Hits
Having: Hits > 5
Sort: Hits DESC
Time: Last 2 Hours</code></pre>
</div>

<h3>🟡 Network Operations</h3>

<div class="code-block">
    <div class="code-header"><span>Search — Top Bandwidth Users</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Identify top bandwidth consumers</span>
Event Type: FortiGate-Traffic
Filter: action = "accept"
Group By: srcIpAddr, user
Aggregate: SUM(sentBytes + recvBytes) as TotalBytes
Sort: TotalBytes DESC
Limit: 20
Time: Last 24 Hours</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — VPN User Activity Summary</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Daily VPN activity by user</span>
Event Type: FortiGate-VPN
Filter: eventType IN ("ssl-login","ssl-logout","tunnel-up","tunnel-down")
Display: eventTime, user, srcIpAddr, srcCountry, duration, sentBytes
Sort: eventTime DESC
Time: Last 7 Days</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — Device Availability</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Devices that have been unreachable</span>
Event Type: PH_DEV_MON_CRIT_INTF_DOWN
Display: eventTime, hostName, ipAddr, intfName, downReason
Sort: eventTime DESC
Time: Last 24 Hours</code></pre>
</div>

<h3>🟢 Compliance</h3>

<div class="code-block">
    <div class="code-header"><span>Search — Privileged Access Activity</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Track privileged user activity (PCI DSS Req 10.2)</span>
Event Type: Windows-Security
Filter: eventType IN ("Windows-Admin-Logon","Windows-Privilege-Use")
Display: eventTime, user, srcIpAddr, hostName, logonType, processName
Sort: eventTime DESC
Time: Last 24 Hours</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — Account Lockout Events</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Account lockouts (EventID 4740)</span>
Event Type: Windows-Account-Lockout
Display: eventTime, targetUser, srcIpAddr, callerComputer
Group By: targetUser
Aggregate: COUNT(Matched Events) as Lockouts
Sort: Lockouts DESC
Time: Last 24 Hours</code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>Search — User Created/Modified (IAM Changes)</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># User account changes (PCI DSS, SOX)</span>
Event Type: Windows-Security
Filter: eventType IN ("Windows-User-Create","Windows-User-Delete",
        "Windows-Group-Member-Add","Windows-Password-Changed")
Display: eventTime, user, targetUser, hostName, groupName
Sort: eventTime DESC
Time: Last 24 Hours</code></pre>
</div>
`;

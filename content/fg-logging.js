// ============================================================
// FortiGate Logging — Traffic, Event, UTM, VPN, Debug Commands
// ============================================================

KB.content['fg-logging'] = `
<h1><span class="h1-icon">📋</span> Logging Overview</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>FortiGate logging captures every security and operational event: traffic flows, UTM detections, VPN connections, admin logins, system events, and more. Logs are the foundation of security monitoring, incident response, compliance, and troubleshooting. Without proper logging, you are operating blind.</p>
</div>

<div class="gui-path">Log &amp; Report <span class="gui-sep">›</span> Log Settings</div>

<h2 id="log-destinations">Log Destinations</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Destination</th><th>Retention</th><th>Performance Impact</th><th>Best For</th></tr>
</thead>
<tbody>
<tr><td><strong>Local Disk</strong></td><td>Days to weeks (limited by disk)</td><td>Low-Medium</td><td>Immediate access, small deployments</td></tr>
<tr><td><strong>FortiAnalyzer</strong></td><td>Months to years</td><td>Very Low (async)</td><td>Enterprise, compliance, SOC analytics</td></tr>
<tr><td><strong>FortiCloud</strong></td><td>7-365 days (license dependent)</td><td>Very Low</td><td>Small/medium with no on-prem FAZ</td></tr>
<tr><td><strong>Syslog</strong></td><td>Depends on SIEM</td><td>Low</td><td>Integration with SIEM (FortiSIEM, Splunk, QRadar)</td></tr>
<tr><td><strong>Memory (RAM)</strong></td><td>Minutes only (volatile)</td><td>None</td><td>Real-time CLI viewing only — not for production</td></tr>
</tbody>
</table>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Log Settings Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># ===== LOCAL DISK LOGGING =====</span>
<span class="keyword">config</span> log disk setting
    <span class="keyword">set</span> status enable
    <span class="keyword">set</span> severity information      <span class="comment"># Minimum severity to log</span>
    <span class="keyword">set</span> max-policy-packet-capture-size 100
    <span class="keyword">set</span> roll-schedule weekly
    <span class="keyword">set</span> roll-time 00:00
    <span class="keyword">set</span> upload enable
    <span class="keyword">set</span> uploadtype ftp
    <span class="keyword">set</span> uploadip "10.0.0.100"
    <span class="keyword">set</span> uploaduser "loguser"
    <span class="keyword">set</span> uploadpass <span class="string">"FTPPass!"</span>
<span class="keyword">end</span>

<span class="comment"># ===== FORTIANALYZER LOGGING =====</span>
<span class="keyword">config</span> log fortianalyzer setting
    <span class="keyword">set</span> status enable
    <span class="keyword">set</span> server "10.0.0.200"        <span class="comment"># FAZ IP</span>
    <span class="keyword">set</span> source-ip 10.0.0.1
    <span class="keyword">set</span> upload-option realtime     <span class="comment"># realtime | 1-minute | 5-minute</span>
    <span class="keyword">set</span> reliable enable            <span class="comment"># TCP-based reliable delivery</span>
    <span class="keyword">set</span> enc-algorithm high         <span class="comment"># Encrypt log traffic to FAZ</span>
    <span class="keyword">set</span> ssl-min-proto-version tls1-2
    <span class="keyword">set</span> conn-timeout 10
    <span class="keyword">set</span> monitor-keepalive-period 5
<span class="keyword">end</span>

<span class="comment"># ===== SYSLOG =====</span>
<span class="keyword">config</span> log syslogd setting
    <span class="keyword">set</span> status enable
    <span class="keyword">set</span> server "10.0.0.150"        <span class="comment"># SIEM syslog receiver</span>
    <span class="keyword">set</span> port 514
    <span class="keyword">set</span> mode udp                   <span class="comment"># udp | tcp | reliable (TLS)</span>
    <span class="keyword">set</span> format default             <span class="comment"># default | csv | cef | rfc5424</span>
    <span class="keyword">set</span> facility local7
    <span class="keyword">set</span> source-ip 10.0.0.1
<span class="keyword">end</span>

<span class="comment"># Multiple syslog servers (syslogd2, syslogd3, syslogd4)</span>
<span class="keyword">config</span> log syslogd2 setting
    <span class="keyword">set</span> status enable
    <span class="keyword">set</span> server "10.0.0.151"        <span class="comment"># Backup SIEM</span>
    <span class="keyword">set</span> port 514
    <span class="keyword">set</span> mode reliable              <span class="comment"># TLS syslog</span>
    <span class="keyword">set</span> format cef                 <span class="comment"># Common Event Format for some SIEMs</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="log-filters">Log Filters</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Log Filter Settings</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Filter what gets sent to FortiAnalyzer</span>
<span class="keyword">config</span> log fortianalyzer filter
    <span class="keyword">set</span> severity information
    <span class="keyword">set</span> traffic enable
    <span class="keyword">set</span> web enable
    <span class="keyword">set</span> antivirus enable
    <span class="keyword">set</span> ips enable
    <span class="keyword">set</span> app-ctrl enable
    <span class="keyword">set</span> email enable
    <span class="keyword">set</span> voip enable
    <span class="keyword">set</span> dns enable
    <span class="keyword">set</span> ssh enable
    <span class="keyword">set</span> ssl enable
    <span class="keyword">set</span> forward-traffic enable
    <span class="keyword">set</span> local-traffic enable        <span class="comment"># Log management traffic</span>
    <span class="keyword">set</span> sniffer-traffic disable     <span class="comment"># Don't log sniffer captures</span>
    <span class="keyword">set</span> anomaly enable
    <span class="keyword">set</span> voip enable
<span class="keyword">end</span></code></pre>
</div>

<h2 id="log-categories">Log Categories</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Category</th><th>CLI Name</th><th>What It Contains</th><th>Must Log?</th></tr>
</thead>
<tbody>
<tr><td><strong>Traffic</strong></td><td>forward-traffic</td><td>Every allowed/denied session (src, dst, bytes, policy)</td><td>✅ Always</td></tr>
<tr><td><strong>UTM/Security</strong></td><td>utm</td><td>AV detections, IPS blocks, web filter events, app control</td><td>✅ Always</td></tr>
<tr><td><strong>Event</strong></td><td>event</td><td>Admin logins, config changes, HA events, VPN events</td><td>✅ Always</td></tr>
<tr><td><strong>VPN</strong></td><td>event (vpn subtype)</td><td>SSL VPN/IPSec connect/disconnect, auth failures</td><td>✅ Always</td></tr>
<tr><td><strong>System</strong></td><td>event (system subtype)</td><td>Firmware changes, conserve mode, daemon crashes</td><td>✅ Always</td></tr>
<tr><td><strong>Local Traffic</strong></td><td>local-traffic</td><td>Traffic TO FortiGate (management, DNS, OSPF)</td><td>⚠️ Recommended</td></tr>
<tr><td><strong>Multicast</strong></td><td>multicast-traffic</td><td>Multicast streams</td><td>❌ Usually not needed</td></tr>
<tr><td><strong>Sniffer</strong></td><td>sniffer-traffic</td><td>Packets from diagnostic captures</td><td>❌ Never in production</td></tr>
</tbody>
</table>
</div>

<h2 id="log-viewing-cli">Viewing Logs via CLI</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Log Viewing Commands</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Set filter — category</span>
<span class="command">execute log filter category traffic</span>
<span class="comment"># Categories: traffic | utm | event | dns | dlp | emailfilter | ssh</span>

<span class="comment"># Filter by IP</span>
<span class="command">execute log filter field srcip 10.0.0.100</span>

<span class="comment"># Filter by time</span>
<span class="command">execute log filter start-time 2024-01-15 08:00:00</span>
<span class="command">execute log filter end-time 2024-01-15 18:00:00</span>

<span class="comment"># Display last 100 log entries</span>
<span class="command">execute log display</span>

<span class="comment"># Filter UTM logs by threat name</span>
<span class="command">execute log filter category utm</span>
<span class="command">execute log filter field action blocked</span>
<span class="command">execute log display</span>

<span class="comment"># Event logs — admin changes</span>
<span class="command">execute log filter category event</span>
<span class="command">execute log filter field subtype system</span>
<span class="command">execute log display</span>

<span class="comment"># VPN event logs</span>
<span class="command">execute log filter category event</span>
<span class="command">execute log filter field subtype vpn</span>
<span class="command">execute log display</span>

<span class="comment"># Reset filters</span>
<span class="command">execute log filter reset</span></code></pre>
</div>

<h2 id="log-best-practices">Logging Best Practices</h2>

<ul class="checklist">
    <li><span class="check checked">✓</span> Log to FortiAnalyzer — local disk alone is insufficient for enterprise</li>
    <li><span class="check checked">✓</span> Enable logging on ALL firewall policies — both accept and deny</li>
    <li><span class="check checked">✓</span> Enable implicit deny logging for unauthorized traffic detection</li>
    <li><span class="check checked">✓</span> Use reliable (TCP) syslog transport to prevent log loss</li>
    <li><span class="check checked">✓</span> Send logs to SIEM (FortiSIEM/Splunk) for correlation</li>
    <li><span class="check checked">✓</span> Monitor disk usage — full disk stops logging</li>
    <li><span class="check checked">✓</span> Set log retention policy per compliance requirements (PCI: 1yr, HIPAA: 6yr)</li>
    <li><span class="check checked">✓</span> Always log admin logins and configuration changes</li>
</ul>
`;

KB.content['fg-traffic-logs'] = `
<h1><span class="h1-icon">📊</span> Traffic Logs</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Traffic logs record information about every network session that passes through the FortiGate. They capture source/destination IP, ports, protocol, action (allow/deny), bytes transferred, duration, policy ID, and NAT information. Traffic logs are the primary data source for network visibility and incident response.</p>
</div>

<div class="gui-path">Log &amp; Report <span class="gui-sep">›</span> Traffic</div>

<h2 id="traffic-log-fields">Key Traffic Log Fields</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Field</th><th>Description</th><th>Use in Investigation</th></tr>
</thead>
<tbody>
<tr><td><code>srcip</code></td><td>Source IP address (pre-NAT)</td><td>Identify originating host</td></tr>
<tr><td><code>dstip</code></td><td>Destination IP address (pre-DNAT)</td><td>Identify target</td></tr>
<tr><td><code>srcport</code></td><td>Source port</td><td>Ephemeral vs well-known port analysis</td></tr>
<tr><td><code>dstport</code></td><td>Destination port</td><td>Service identification</td></tr>
<tr><td><code>proto</code></td><td>Protocol number (6=TCP, 17=UDP, 1=ICMP)</td><td>Protocol analysis</td></tr>
<tr><td><code>action</code></td><td>accept | deny | drop | close</td><td>Was traffic allowed?</td></tr>
<tr><td><code>policyid</code></td><td>Policy ID that matched</td><td>Which rule allowed/denied</td></tr>
<tr><td><code>sentbyte</code></td><td>Bytes sent from source</td><td>Data exfiltration detection</td></tr>
<tr><td><code>rcvdbyte</code></td><td>Bytes received by source</td><td>Download volume</td></tr>
<tr><td><code>duration</code></td><td>Session duration in seconds</td><td>Long-duration sessions = potential C2</td></tr>
<tr><td><code>tranip</code></td><td>Translated (NAT) source IP</td><td>Post-SNAT IP</td></tr>
<tr><td><code>tranport</code></td><td>Translated source port</td><td>Post-SNAT port</td></tr>
<tr><td><code>devname</code></td><td>FortiGate device name</td><td>Multi-device environments</td></tr>
<tr><td><code>user</code></td><td>Authenticated username (FSSO/SSL VPN)</td><td>User attribution</td></tr>
<tr><td><code>app</code></td><td>Application identified by App Control</td><td>Application visibility</td></tr>
</tbody>
</table>
</div>
`;

KB.content['fg-fortianalyzer'] = `
<h1><span class="h1-icon">📈</span> FortiAnalyzer Integration</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>FortiAnalyzer (FAZ) is Fortinet's centralized log management and analytics platform. It collects logs from multiple FortiGate firewalls, runs correlation, generates compliance reports, and provides SOC dashboards. It is the recommended log destination for any enterprise deployment.</p>
</div>

<div class="gui-path">Security Fabric <span class="gui-sep">›</span> Fabric Connectors <span class="gui-sep">›</span> Logging &amp; Analytics</div>

<div class="code-block">
    <div class="code-header"><span>CLI — FortiAnalyzer Integration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Configure FAZ connection</span>
<span class="keyword">config</span> log fortianalyzer setting
    <span class="keyword">set</span> status enable
    <span class="keyword">set</span> server "10.0.0.200"
    <span class="keyword">set</span> reliable enable
    <span class="keyword">set</span> enc-algorithm high
    <span class="keyword">set</span> upload-option realtime
    <span class="keyword">set</span> psksecret <span class="string">"FAZ-PSK-Secret!"</span>
<span class="keyword">end</span>

<span class="comment"># Verify FAZ connection</span>
<span class="command">diagnose test application fgtlogd 5</span>
<span class="command">diagnose log test</span>

<span class="comment"># Check log send queue</span>
<span class="command">diagnose test application fgtlogd 6</span>

<span class="comment"># FAZ reachability test</span>
<span class="command">execute ping 10.0.0.200</span>
<span class="command">execute telnet 10.0.0.200 514</span>

<span class="comment"># Authorize FortiGate on FAZ (run on FAZ):</span>
<span class="comment"># Device Manager → Unregistered Devices → Authorize</span></code></pre>
</div>

<div class="callout best-practice">
    <div class="callout-title">🎯 FAZ Deployment Best Practices</div>
    <p>• Use <strong>reliable (TCP) log transport</strong> — UDP can lose logs under load<br>
    • Enable <strong>log encryption</strong> — logs contain sensitive data<br>
    • Size FAZ storage for <strong>90-day minimum</strong> retention (compliance often requires more)<br>
    • Enable <strong>realtime upload</strong> for FortiGates in production — never batch-upload for security logs<br>
    • Configure FAZ HA for critical environments — single FAZ is a log loss risk</p>
</div>
`;

KB.content['fg-security-fabric'] = `
<h1><span class="h1-icon">🧩</span> Security Fabric</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>The Fortinet Security Fabric is an architecture that interconnects Fortinet products (FortiGate, FortiAnalyzer, FortiManager, FortiClient, FortiAP, FortiSwitch, FortiSandbox, FortiSIEM) into a single, coordinated security platform. Fabric members share telemetry, threat intelligence, and enable automated response.</p>
</div>

<div class="gui-path">Security Fabric <span class="gui-sep">›</span> Fabric Connectors</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Security Fabric Root Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Configure root FortiGate (HQ firewall)</span>
<span class="keyword">config</span> system csf
    <span class="keyword">set</span> status enable
    <span class="keyword">set</span> upstream-ip ""             <span class="comment"># Empty = this is the root</span>
    <span class="keyword">set</span> upstream-port 8013
    <span class="keyword">set</span> group-name "Corp-Security-Fabric"
    <span class="keyword">set</span> group-password <span class="string">"Fabric!PSK"</span>
    <span class="keyword">set</span> fabric-object-unification enable
    <span class="keyword">set</span> fortianalyzer-name "FAZ-Primary"
    <span class="keyword">config</span> trusted-list
        <span class="keyword">edit</span> "Branch1-FG"
            <span class="keyword">set</span> serial "FGT60XXXXXXXXXX"
            <span class="keyword">set</span> action accept
        <span class="keyword">next</span>
    <span class="keyword">end</span>
<span class="keyword">end</span>

<span class="comment"># Downstream FortiGate (branch) configuration</span>
<span class="keyword">config</span> system csf
    <span class="keyword">set</span> status enable
    <span class="keyword">set</span> upstream-ip "10.0.0.1"     <span class="comment"># Root FortiGate IP</span>
    <span class="keyword">set</span> upstream-port 8013
    <span class="keyword">set</span> group-name "Corp-Security-Fabric"
    <span class="keyword">set</span> group-password <span class="string">"Fabric!PSK"</span>
<span class="keyword">end</span>

<span class="comment"># Fabric status</span>
<span class="command">get system csf</span>
<span class="command">diagnose sys csf list</span></code></pre>
</div>

<h2 id="security-rating">Security Rating</h2>

<p>The Security Rating feature scans your FortiGate configuration against Fortinet best practices and assigns a score (0-100). It identifies configuration weaknesses and provides remediation guidance.</p>

<div class="gui-path">Security Fabric <span class="gui-sep">›</span> Security Rating</div>

<div class="callout best-practice">
    <div class="callout-title">🎯 Security Rating Target</div>
    <p>Aim for a Security Rating of <strong>80+</strong> in production environments. Critical findings (red) should be remediated immediately. High findings (orange) should be addressed within 30 days. Review and improve the rating quarterly.</p>
</div>
`;

// ============================================================
// FortiGate Dashboard — Complete Documentation
// ============================================================

KB.content['fg-dashboard'] = `
<h1><span class="h1-icon">📊</span> FortiGate Dashboard</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What Is It</div>
    <p>The FortiGate Dashboard is the <strong>landing page</strong> after login. It provides a real-time, at-a-glance overview of system health, security events, network traffic, license status, and administrator sessions. It is the single-pane-of-glass for operational awareness.</p>
</div>

<div class="callout best-practice">
    <div class="callout-title">🎯 Why It Exists</div>
    <p>Operators need immediate situational awareness. The Dashboard answers: Is the device healthy? Is there an active threat? Are there connectivity issues? Are my licenses valid? Without this, you'd need to run multiple CLI commands or navigate several pages.</p>
</div>

<h2 id="gui-location">GUI Location</h2>
<div class="gui-path">Dashboard <span class="gui-sep">›</span> Status</div>
<div class="gui-path">Dashboard <span class="gui-sep">›</span> Network</div>
<div class="gui-path">Dashboard <span class="gui-sep">›</span> Security</div>
<div class="gui-path">Dashboard <span class="gui-sep">›</span> Users & Devices</div>

<h2 id="dashboard-types">Dashboard Pages</h2>

<p>FortiGate provides several built-in dashboard views. Each can be customized by adding, removing, or rearranging widgets.</p>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Dashboard</th><th>Purpose</th><th>Key Widgets</th><th>When to Use</th></tr>
</thead>
<tbody>
<tr><td><strong>Status</strong></td><td>System health overview</td><td>System Info, Licenses, HA Status, Resource Usage, Alerts</td><td>Daily check / first look after login</td></tr>
<tr><td><strong>Network</strong></td><td>Interface and traffic overview</td><td>Interface Bandwidth, Routing Table, SD-WAN, DHCP</td><td>Network troubleshooting / monitoring</td></tr>
<tr><td><strong>Security</strong></td><td>Threat landscape</td><td>Top Threats, FortiSandbox, Botnet, Top Sources</td><td>Security incident awareness</td></tr>
<tr><td><strong>Users & Devices</strong></td><td>Connected clients</td><td>Active Users, Top Users by Bandwidth, FortiClient</td><td>User-based troubleshooting</td></tr>
</tbody>
</table>
</div>

<h2 id="status-widgets">Status Dashboard Widgets</h2>

<h3 id="system-information">System Information Widget</h3>

<p>Displays critical system details at a glance.</p>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Field</th><th>Description</th><th>What to Watch For</th></tr>
</thead>
<tbody>
<tr><td><strong>Hostname</strong></td><td>Device hostname</td><td>Ensure it follows naming convention</td></tr>
<tr><td><strong>Serial Number</strong></td><td>Unique device identifier</td><td>Needed for RMA and licensing</td></tr>
<tr><td><strong>Firmware Version</strong></td><td>FortiOS version running</td><td>Check for known CVEs. Stay on recommended path</td></tr>
<tr><td><strong>System Time</strong></td><td>Current date/time and timezone</td><td>Must be accurate — affects logs, certs, VPN</td></tr>
<tr><td><strong>Uptime</strong></td><td>Time since last reboot</td><td>Unexpected reboots indicate issues</td></tr>
<tr><td><strong>HA Status</strong></td><td>Active/Standby/Standalone</td><td>Ensure HA sync is healthy</td></tr>
<tr><td><strong>Operation Mode</strong></td><td>NAT or Transparent</td><td>Must match network design</td></tr>
<tr><td><strong>VDOM Mode</strong></td><td>Enabled/Disabled</td><td>Multi-tenant requires VDOMs</td></tr>
</tbody>
</table>
</div>

<h4>CLI Equivalent</h4>
<div class="code-block">
    <div class="code-header"><span>FortiOS CLI</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># System information</span>
<span class="command">get system status</span>

<span class="comment"># Detailed hardware info</span>
<span class="command">get hardware status</span>

<span class="comment"># System performance (CPU/memory)</span>
<span class="command">get system performance status</span>

<span class="comment"># Uptime</span>
<span class="command">get system performance status | grep Uptime</span>

<span class="comment"># Serial number</span>
<span class="command">get system status | grep Serial</span>

<span class="comment"># Firmware version</span>
<span class="command">get system status | grep Version</span></code></pre>
</div>

<h3 id="license-widget">License Information Widget</h3>

<p>Shows the status of all FortiGuard licenses and subscriptions.</p>

<div class="table-wrapper">
<table>
<thead>
<tr><th>License</th><th>Purpose</th><th>Impact if Expired</th></tr>
</thead>
<tbody>
<tr><td><strong>FortiCare Support</strong></td><td>Hardware/software support & firmware downloads</td><td>No firmware updates, no TAC support</td></tr>
<tr><td><strong>AntiVirus</strong></td><td>AV signature updates</td><td>Signatures stop updating — new malware undetected</td></tr>
<tr><td><strong>IPS</strong></td><td>Intrusion prevention signatures</td><td>No new vulnerability coverage</td></tr>
<tr><td><strong>Web Filtering</strong></td><td>URL categorization database</td><td>Categories become stale, new sites uncategorized</td></tr>
<tr><td><strong>Application Control</strong></td><td>App signature database</td><td>New apps undetected</td></tr>
<tr><td><strong>FortiSandbox</strong></td><td>Cloud/on-prem sandboxing</td><td>No zero-day analysis</td></tr>
<tr><td><strong>Industrial Security</strong></td><td>ICS/SCADA signatures</td><td>OT environments unprotected</td></tr>
<tr><td><strong>SSL Inspection</strong></td><td>Deep inspection CA management</td><td>Reduced HTTPS visibility</td></tr>
</tbody>
</table>
</div>

<div class="callout warning">
    <div class="callout-title">⚠️ Common Mistake</div>
    <p>Many engineers ignore license expiration warnings. When <strong>FortiGuard AV/IPS</strong> licenses expire, the FortiGate <strong>continues enforcing the last downloaded signatures</strong> but no longer receives updates. In high-threat environments, this creates a growing blind spot within days.</p>
</div>

<h4>CLI Equivalent</h4>
<div class="code-block">
    <div class="code-header"><span>FortiOS CLI</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># View all licenses</span>
<span class="command">get system fortiguard-service status</span>

<span class="comment"># Check FortiGuard connectivity</span>
<span class="command">diagnose autoupdate status</span>
<span class="command">diagnose autoupdate versions</span>

<span class="comment"># Force FortiGuard update check</span>
<span class="command">execute update-now</span></code></pre>
</div>

<h3 id="resource-usage">Resource Usage Widget</h3>

<p>Displays real-time CPU, memory, session count, and disk usage.</p>

<div class="callout danger">
    <div class="callout-title">🚨 Performance Thresholds</div>
    <p><strong>CPU &gt; 80%</strong> sustained — investigate immediately. Check <code>diagnose sys top</code> for offending processes.<br>
    <strong>Memory &gt; 80%</strong> sustained — risk of session drops. Check conserve mode status.<br>
    <strong>Sessions near max</strong> — new connections may be dropped. Review session table for anomalies.</p>
</div>

<div class="code-block">
    <div class="code-header"><span>Performance Monitoring CLI</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Real-time CPU and memory</span>
<span class="command">get system performance status</span>

<span class="comment"># Top processes by CPU</span>
<span class="command">diagnose sys top 2 20</span>
<span class="comment"># (updates every 2 seconds, shows 20 processes)</span>

<span class="comment"># Session count</span>
<span class="command">diagnose sys session stat</span>

<span class="comment"># Check conserve mode</span>
<span class="command">diagnose hardware sysinfo conserve</span>

<span class="comment"># Memory usage breakdown</span>
<span class="command">diagnose hardware sysinfo memory</span>

<span class="comment"># Disk usage</span>
<span class="command">diagnose sys flash list</span>
<span class="command">execute disk list</span></code></pre>
</div>

<h3 id="alerts-widget">Alert Messages Console</h3>

<p>Real-time alerts about system events: HA failovers, interface status changes, configuration changes, firmware upgrade availability, and security events.</p>

<div class="callout tip">
    <div class="callout-title">💡 Best Practice</div>
    <p>Configure <strong>Alert Email</strong> or <strong>SNMP traps</strong> for critical alerts. Don't rely solely on the Dashboard — nobody watches it 24/7.</p>
</div>

<div class="code-block">
    <div class="code-header"><span>Alert Configuration CLI</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Configure alert email</span>
<span class="keyword">config</span> alertemail setting
    <span class="keyword">set</span> username "firewall-alerts@company.com"
    <span class="keyword">set</span> mailto1 "noc@company.com"
    <span class="keyword">set</span> filter-mode threshold
    <span class="keyword">set</span> HA-logs enable
    <span class="keyword">set</span> configuration-changes-logs enable
    <span class="keyword">set</span> violation-traffic-logs enable
<span class="keyword">end</span></code></pre>
</div>

<h2 id="network-dashboard">Network Dashboard</h2>

<h3 id="interface-bandwidth">Interface Bandwidth Widget</h3>

<p>Real-time throughput graphs per interface. Shows inbound/outbound traffic in bps. Critical for capacity planning and detecting anomalies like DDoS or data exfiltration.</p>

<div class="code-block">
    <div class="code-header"><span>Interface Statistics CLI</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Interface statistics</span>
<span class="command">get hardware nic port1</span>

<span class="comment"># Real-time interface throughput</span>
<span class="command">diagnose netlink interface list port1</span>

<span class="comment"># Aggregate interface stats</span>
<span class="command">fnsysctl cat /proc/net/dev</span>

<span class="comment"># Top talkers by interface</span>
<span class="command">diagnose sys session stat</span></code></pre>
</div>

<h3 id="routing-table-widget">Routing Table Widget</h3>

<p>Displays the active routing table with next-hop, metric, and interface. Equivalent to <code>get router info routing-table all</code>.</p>

<h3 id="sd-wan-widget">SD-WAN Status Widget</h3>

<p>If SD-WAN is configured, shows member health status, SLA metrics (latency, jitter, packet loss), and active rules.</p>

<h2 id="security-dashboard">Security Dashboard</h2>

<h3 id="top-threats">Top Threats Widget</h3>
<p>Aggregated view of detected threats across all UTM profiles: AV detections, IPS signatures triggered, web filter blocks, application control violations.</p>

<h3 id="botnet-activity">Botnet Activity Widget</h3>
<p>Displays outbound connections to known botnet C2 servers. A non-zero count here requires <strong>immediate investigation</strong> — it indicates an infected host in your network.</p>

<div class="callout danger">
    <div class="callout-title">🚨 Security Risk</div>
    <p>If Botnet Activity shows active connections, <strong>do not ignore this</strong>. It means a device on your network is communicating with a known command-and-control server. Immediately identify the source IP, isolate the device, and investigate.</p>
</div>

<h2 id="custom-dashboards">Customizing Dashboards</h2>

<h3 id="add-widgets">Adding Widgets</h3>

<div class="steps">
    <div class="step">
        <div class="step-title">Open Dashboard Settings</div>
        <p>Navigate to <strong>Dashboard</strong> and click the <strong>+ Add Widget</strong> button (or the gear icon).</p>
    </div>
    <div class="step">
        <div class="step-title">Select Widget Type</div>
        <p>Choose from: System Information, License, Resource Usage, Session Rate, Bandwidth, Top Sources, Top Destinations, Threat Map, Log Rate, Interface Bandwidth, etc.</p>
    </div>
    <div class="step">
        <div class="step-title">Configure Widget</div>
        <p>Set title, time range, refresh interval, and any filters. Some widgets allow specific interface or VDOM selection.</p>
    </div>
    <div class="step">
        <div class="step-title">Arrange Layout</div>
        <p>Drag and drop widgets to arrange the layout. Resize by dragging widget edges.</p>
    </div>
</div>

<div class="callout tip">
    <div class="callout-title">💡 Pro Tip</div>
    <p>Create a custom <strong>"SOC View"</strong> dashboard with: Top Threats, Botnet Activity, Failed VPN Logins, Top Denied Sources, and Session Rate. Pin it for your security team. Each admin can have their own dashboard configuration.</p>
</div>

<h2 id="cli-dashboard">CLI-Based Monitoring</h2>

<p>For engineers who prefer CLI or need to monitor via SSH/console:</p>

<div class="code-block">
    <div class="code-header"><span>Complete CLI Dashboard Equivalent</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># ===== SYSTEM STATUS =====</span>
<span class="command">get system status</span>
<span class="command">get system performance status</span>

<span class="comment"># ===== INTERFACES =====</span>
<span class="command">get hardware nic</span>
<span class="command">diagnose netlink interface list</span>

<span class="comment"># ===== SESSIONS =====</span>
<span class="command">diagnose sys session stat</span>
<span class="command">diagnose sys session full-stat</span>

<span class="comment"># ===== ROUTING =====</span>
<span class="command">get router info routing-table all</span>

<span class="comment"># ===== HA =====</span>
<span class="command">get system ha status</span>
<span class="command">diagnose sys ha status</span>

<span class="comment"># ===== FORTIGUARD =====</span>
<span class="command">diagnose autoupdate status</span>
<span class="command">diagnose autoupdate versions</span>

<span class="comment"># ===== LOGS (LAST 10) =====</span>
<span class="command">execute log filter category event</span>
<span class="command">execute log display</span>

<span class="comment"># ===== REAL-TIME TRAFFIC =====</span>
<span class="command">diagnose sys top 1 50</span>

<span class="comment"># ===== VPN STATUS =====</span>
<span class="command">get vpn ssl monitor</span>
<span class="command">get vpn ipsec tunnel summary</span></code></pre>
</div>

<h2 id="troubleshooting-dashboard">Troubleshooting</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Problem</th><th>Possible Cause</th><th>Solution</th></tr>
</thead>
<tbody>
<tr><td>Dashboard not loading</td><td>Browser cache, HTTPS issue</td><td>Clear cache, try different browser, check management HTTPS settings</td></tr>
<tr><td>Widgets show "No Data"</td><td>Logging not enabled, VDOM context wrong</td><td>Enable logging in policies, check VDOM selection in GUI</td></tr>
<tr><td>High CPU shown on dashboard</td><td>IPS/AV heavy processing, DDoS, debug running</td><td>Check <code>diagnose sys top</code>, disable any running debugs</td></tr>
<tr><td>License shows "Expired"</td><td>License not renewed, DNS issue</td><td>Renew license, verify DNS (<code>exec ping update.fortiguard.net</code>)</td></tr>
<tr><td>Incorrect time shown</td><td>NTP misconfigured</td><td>Check NTP config: <code>diagnose sys ntp status</code></td></tr>
</tbody>
</table>
</div>

<h2 id="dashboard-best-practices">Best Practices</h2>

<ul class="checklist">
    <li><span class="check checked">✓</span> Review Dashboard daily — make it your first check</li>
    <li><span class="check checked">✓</span> Configure SNMP/email alerts for critical metrics — don't rely on manual checks</li>
    <li><span class="check checked">✓</span> Monitor license expiry proactively — set calendar reminders 30 days before</li>
    <li><span class="check checked">✓</span> Create role-specific dashboards — NOC vs SOC have different needs</li>
    <li><span class="check checked">✓</span> Keep system time accurate — NTP must be working</li>
    <li><span class="check checked">✓</span> Investigate any Botnet Activity immediately — it's never a false positive for the connection itself</li>
    <li><span class="check checked">✓</span> Set up FortiAnalyzer for historical dashboard data — local logging has limited retention</li>
</ul>

<h2 id="dashboard-faq">FAQ</h2>

<details>
    <summary>Can each admin have a different dashboard layout?</summary>
    <div class="details-content">
        <p>Yes. Dashboard widget configurations are stored per-administrator. Each admin profile can have its own customized view. This is per-VDOM if VDOMs are enabled.</p>
    </div>
</details>

<details>
    <summary>How often do dashboard widgets refresh?</summary>
    <div class="details-content">
        <p>Most widgets auto-refresh every <strong>5-60 seconds</strong> depending on the widget type. The refresh interval can be configured per widget. Some real-time widgets (like bandwidth) update every second.</p>
    </div>
</details>

<details>
    <summary>Can I access the dashboard via API?</summary>
    <div class="details-content">
        <p>Yes. The FortiGate REST API provides endpoints for all dashboard data. Use <code>GET /api/v2/monitor/system/status</code> for system info, <code>GET /api/v2/monitor/system/resource/usage</code> for resource stats. Full API documentation is available via <code>https://&lt;fortigate&gt;/api/v2/cmdb</code>.</p>
    </div>
</details>

<details>
    <summary>What is the difference between "Dashboard" and "FortiView"?</summary>
    <div class="details-content">
        <p><strong>Dashboard</strong> provides system-level widgets (health, licenses, resources). <strong>FortiView</strong> provides traffic-level analytics (top sources, top destinations, top applications, threat map). FortiView is the SOC analyst's primary tool; Dashboard is the admin's operational view.</p>
    </div>
</details>
`;

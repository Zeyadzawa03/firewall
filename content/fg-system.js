// ============================================================
// FortiGate System — Complete Documentation
// Covers: System Settings, Interfaces, Zones, VDOMs, Administrators,
//         Certificates, DNS, NTP, SNMP, HA, Firmware, Automation, FortiGuard
// ============================================================

KB.content['fg-system'] = `
<h1><span class="h1-icon">⚙️</span> System Settings</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ Overview</div>
    <p>System Settings is the foundation of FortiGate configuration. It controls the device identity, operational mode, admin access, and global parameters that affect every other feature. Misconfiguration here can lock you out, break routing, or create security gaps.</p>
</div>

<div class="gui-path">System <span class="gui-sep">›</span> Settings</div>

<h2 id="hostname">Hostname & Device Identity</h2>

<p>The hostname appears in logs, SNMP, HA, syslog headers, CLI prompt, and FortiManager. Use a naming convention that encodes location, role, and sequence.</p>

<div class="code-block">
    <div class="code-header"><span>CLI — Set Hostname</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system global
    <span class="keyword">set</span> hostname "FG-DC1-FW01"
    <span class="keyword">set</span> timezone 04  <span class="comment"># Check timezone table</span>
    <span class="keyword">set</span> gui-theme mariner  <span class="comment"># Dark blue theme</span>
<span class="keyword">end</span></code></pre>
</div>

<div class="callout best-practice">
    <div class="callout-title">🎯 Naming Convention</div>
    <p>Use a standard format: <code>[VENDOR]-[LOCATION]-[ROLE][SEQ]</code><br>
    Examples: <code>FG-NYC-FW01</code>, <code>FG-LDN-EDGE02</code>, <code>FG-DC1-CORE01</code><br>
    This makes log analysis and multi-device management significantly easier.</p>
</div>

<h2 id="operation-mode">Operation Mode</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Mode</th><th>Layer</th><th>When to Use</th><th>When NOT to Use</th></tr>
</thead>
<tbody>
<tr><td><strong>NAT Mode</strong> (default)</td><td>Layer 3</td><td>Standard deployments, routing between subnets, internet edge</td><td>When you need transparent inline inspection</td></tr>
<tr><td><strong>Transparent Mode</strong></td><td>Layer 2</td><td>Inline IPS/IDS without changing network topology, bridge mode</td><td>When you need NAT, VPN termination, or DHCP server</td></tr>
</tbody>
</table>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Change Operation Mode</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># WARNING: Changing mode resets interface IPs and policies!</span>
<span class="keyword">config</span> system settings
    <span class="keyword">set</span> opmode transparent
    <span class="keyword">set</span> manageip 10.0.1.1/24  <span class="comment"># Required in transparent mode</span>
    <span class="keyword">set</span> gateway 10.0.1.254
<span class="keyword">end</span></code></pre>
</div>

<div class="callout danger">
    <div class="callout-title">🚨 Warning</div>
    <p>Switching between NAT and Transparent mode <strong>deletes all firewall policies and resets interface configurations</strong>. Always back up the config before changing operation mode. Plan a maintenance window.</p>
</div>

<h2 id="inspection-mode">Inspection Mode</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Mode</th><th>How It Works</th><th>Performance</th><th>Best For</th></tr>
</thead>
<tbody>
<tr><td><strong>Flow-Based</strong></td><td>Single-pass DPI engine. Inspects packets as they flow through</td><td>Higher throughput, lower latency</td><td>High-performance environments, most deployments</td></tr>
<tr><td><strong>Proxy-Based</strong></td><td>Buffers entire content (file/page) before inspection</td><td>Lower throughput, higher latency</td><td>Maximum security: full file reconstruction, replacement messages</td></tr>
</tbody>
</table>
</div>

<div class="callout tip">
    <div class="callout-title">💡 Best Practice</div>
    <p>Use <strong>Flow-Based</strong> as default. Switch to <strong>Proxy-Based</strong> only for specific policies that need advanced features like: HTTPS replacement messages, complete file reassembly, ICAP integration, or explicit web proxy. In FortiOS 7.x, most features work in both modes.</p>
</div>

<h2 id="admin-timeout">Administrator Settings</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Global Admin Settings</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system global
    <span class="keyword">set</span> admintimeout 30          <span class="comment"># Admin idle timeout (minutes)</span>
    <span class="keyword">set</span> admin-https-pki-required enable  <span class="comment"># Require cert-based admin auth</span>
    <span class="keyword">set</span> admin-sport 8443          <span class="comment"># Change default HTTPS port</span>
    <span class="keyword">set</span> admin-ssh-port 2222       <span class="comment"># Change default SSH port</span>
    <span class="keyword">set</span> admin-server-cert "self-sign"
    <span class="keyword">set</span> admin-concurrent enable    <span class="comment"># Allow multiple admin sessions</span>
    <span class="keyword">set</span> admin-lockout-threshold 3  <span class="comment"># Lock after 3 failed attempts</span>
    <span class="keyword">set</span> admin-lockout-duration 300 <span class="comment"># Lockout duration (seconds)</span>
    <span class="keyword">set</span> strong-crypto enable       <span class="comment"># Enforce strong ciphers</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="gui-customization">GUI Customization</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — GUI Settings</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system global
    <span class="keyword">set</span> gui-theme mariner    <span class="comment"># Options: jade, neutrino, mariner, graphite, melongene, retro, dark-matter, onyx, eclipse</span>
    <span class="keyword">set</span> gui-date-format yyyy-MM-dd
    <span class="keyword">set</span> gui-display-hostname enable
    <span class="keyword">set</span> gui-firmware-upgrade-warning enable
    <span class="keyword">set</span> gui-fortigate-cloud-sandbox enable
    <span class="keyword">set</span> gui-lines-per-page 50
<span class="keyword">end</span></code></pre>
</div>
`;

// ============================================================
// INTERFACES
// ============================================================
KB.content['fg-interfaces'] = `
<h1><span class="h1-icon">🔌</span> Interfaces</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Interfaces are the network connection points of FortiGate. Every packet enters and exits through an interface. They define IP addressing, VLANs, security zones, administrative access, DHCP services, and link-level parameters. Correct interface configuration is foundational — everything else depends on it.</p>
</div>

<div class="gui-path">Network <span class="gui-sep">›</span> Interfaces</div>

<h2 id="interface-types">Interface Types</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Type</th><th>Description</th><th>Use Case</th><th>CLI Object</th></tr>
</thead>
<tbody>
<tr><td><strong>Physical</strong></td><td>Hardware ports (port1, port2, wan1, etc.)</td><td>Direct connections to switches, routers, ISPs</td><td><code>config system interface</code></td></tr>
<tr><td><strong>VLAN</strong></td><td>802.1Q tagged sub-interface on a physical port</td><td>Network segmentation (servers, users, guests)</td><td><code>config system interface</code> with <code>type vlan</code></td></tr>
<tr><td><strong>Aggregate (LAG)</strong></td><td>Link Aggregation Group (802.3ad LACP or static)</td><td>Bandwidth aggregation, redundancy</td><td><code>config system interface</code> with <code>type aggregate</code></td></tr>
<tr><td><strong>Loopback</strong></td><td>Virtual interface with no physical port</td><td>BGP router-id, management access, source IP for services</td><td><code>config system interface</code> with <code>type loopback</code></td></tr>
<tr><td><strong>Tunnel</strong></td><td>Virtual interface for VPN tunnels</td><td>IPSec VPN, GRE tunnel endpoints</td><td>Auto-created with VPN config</td></tr>
<tr><td><strong>Software Switch</strong></td><td>Bridge multiple physical ports</td><td>LAN switch functionality (small offices)</td><td><code>config system switch-interface</code></td></tr>
<tr><td><strong>Hardware Switch</strong></td><td>Hardware-accelerated bridge</td><td>Built-in switch ports on desktop models</td><td><code>config system virtual-switch</code></td></tr>
<tr><td><strong>WiFi (SSID)</strong></td><td>Wireless interface (FortiAP integration)</td><td>Wireless LAN access</td><td><code>config wireless-controller vap</code></td></tr>
<tr><td><strong>SD-WAN</strong></td><td>Virtual interface for SD-WAN zone</td><td>SD-WAN rules reference this</td><td><code>config system sdwan</code></td></tr>
</tbody>
</table>
</div>

<h2 id="interface-config">Interface Configuration</h2>

<h3 id="physical-interface">Physical Interface</h3>

<div class="code-block">
    <div class="code-header"><span>CLI — Physical Interface</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system interface
    <span class="keyword">edit</span> "port1"
        <span class="keyword">set</span> alias "WAN-ISP1"
        <span class="keyword">set</span> mode static
        <span class="keyword">set</span> ip 203.0.113.2/30
        <span class="keyword">set</span> allowaccess ping https ssh snmp fgfm
        <span class="keyword">set</span> role wan
        <span class="keyword">set</span> speed auto  <span class="comment"># auto, 1000full, 10000full, etc.</span>
        <span class="keyword">set</span> mtu-override enable
        <span class="keyword">set</span> mtu 1500
        <span class="keyword">set</span> description "Primary ISP - Provider XYZ"
        <span class="keyword">set</span> estimated-upstream-bandwidth 100000   <span class="comment"># kbps</span>
        <span class="keyword">set</span> estimated-downstream-bandwidth 100000
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h3 id="vlan-interface">VLAN Interface</h3>

<div class="code-block">
    <div class="code-header"><span>CLI — VLAN Interface</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system interface
    <span class="keyword">edit</span> "VLAN100-Servers"
        <span class="keyword">set</span> vdom "root"
        <span class="keyword">set</span> type vlan
        <span class="keyword">set</span> vlanid 100
        <span class="keyword">set</span> interface "port3"   <span class="comment"># Parent physical interface</span>
        <span class="keyword">set</span> ip 10.10.100.1/24
        <span class="keyword">set</span> allowaccess ping https
        <span class="keyword">set</span> role lan
        <span class="keyword">set</span> device-identification enable
        <span class="keyword">set</span> description "Server VLAN"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h3 id="lag-interface">Aggregate / LAG Interface</h3>

<div class="code-block">
    <div class="code-header"><span>CLI — LAG with LACP</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system interface
    <span class="keyword">edit</span> "LAG-CORE"
        <span class="keyword">set</span> type aggregate
        <span class="keyword">set</span> member "port5" "port6"
        <span class="keyword">set</span> ip 10.0.0.1/30
        <span class="keyword">set</span> allowaccess ping
        <span class="keyword">set</span> lacp-mode active     <span class="comment"># active, passive, static</span>
        <span class="keyword">set</span> lacp-ha-slave enable  <span class="comment"># Important for HA</span>
        <span class="keyword">set</span> lacp-speed fast       <span class="comment"># fast (1s) or slow (30s)</span>
        <span class="keyword">set</span> min-links 1
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h3 id="loopback-interface">Loopback Interface</h3>

<div class="code-block">
    <div class="code-header"><span>CLI — Loopback</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system interface
    <span class="keyword">edit</span> "Loopback0"
        <span class="keyword">set</span> type loopback
        <span class="keyword">set</span> ip 10.255.255.1/32
        <span class="keyword">set</span> allowaccess ping
        <span class="keyword">set</span> description "BGP Router-ID / Management"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="admin-access">Administrative Access</h2>

<p>The <code>allowaccess</code> setting controls which management protocols are permitted on each interface. This is critical for security.</p>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Protocol</th><th>Port</th><th>When to Enable</th><th>Security Note</th></tr>
</thead>
<tbody>
<tr><td><code>https</code></td><td>443 (or custom)</td><td>GUI management</td><td>Never on WAN unless restricted by source IP</td></tr>
<tr><td><code>ssh</code></td><td>22 (or custom)</td><td>CLI management</td><td>Never on WAN unless restricted</td></tr>
<tr><td><code>ping</code></td><td>ICMP</td><td>Monitoring, troubleshooting</td><td>Generally safe, useful for health checks</td></tr>
<tr><td><code>snmp</code></td><td>161 (UDP)</td><td>NMS monitoring</td><td>Use SNMPv3, restrict source</td></tr>
<tr><td><code>http</code></td><td>80</td><td><strong>Never</strong></td><td>Plaintext — always use HTTPS instead</td></tr>
<tr><td><code>telnet</code></td><td>23</td><td><strong>Never</strong></td><td>Plaintext — always use SSH instead</td></tr>
<tr><td><code>fgfm</code></td><td>541</td><td>FortiManager management</td><td>Only on interfaces facing FortiManager</td></tr>
<tr><td><code>ftm</code></td><td>Various</td><td>FortiToken Mobile push</td><td>Only if using FortiToken</td></tr>
<tr><td><code>radius-acct</code></td><td>1813</td><td>RADIUS accounting</td><td>Only on interfaces facing NAS devices</td></tr>
<tr><td><code>fabric</code></td><td>8013,8014</td><td>Security Fabric</td><td>Only between Fabric members</td></tr>
</tbody>
</table>
</div>

<div class="callout danger">
    <div class="callout-title">🚨 Security Risk: WAN Interface Access</div>
    <p><strong>NEVER enable HTTPS/SSH on WAN interfaces without restricting by trusted source IP</strong>. This is the #1 attack vector for FortiGate compromises. Use <code>trusted hosts</code> on admin accounts and/or local-in policies to restrict management access.</p>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Restrict Admin Access by Source</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Method 1: Trusted hosts on admin account</span>
<span class="keyword">config</span> system admin
    <span class="keyword">edit</span> "admin"
        <span class="keyword">set</span> trusthost1 10.0.0.0/8
        <span class="keyword">set</span> trusthost2 192.168.1.0/24
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Method 2: Local-in policy (more granular)</span>
<span class="keyword">config</span> firewall local-in-policy
    <span class="keyword">edit</span> 1
        <span class="keyword">set</span> intf "port1"
        <span class="keyword">set</span> srcaddr "Management-Hosts"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "HTTPS" "SSH"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> schedule "always"
    <span class="keyword">next</span>
    <span class="keyword">edit</span> 2
        <span class="keyword">set</span> intf "port1"
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "HTTPS" "SSH"
        <span class="keyword">set</span> action deny
        <span class="keyword">set</span> schedule "always"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="interface-roles">Interface Roles</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Role</th><th>Effect</th><th>When to Use</th></tr>
</thead>
<tbody>
<tr><td><strong>WAN</strong></td><td>Shows in WAN-related widgets, SD-WAN candidate</td><td>Interfaces connected to ISPs or upstream routers</td></tr>
<tr><td><strong>LAN</strong></td><td>Shows device detection, DHCP options</td><td>Internal network interfaces</td></tr>
<tr><td><strong>DMZ</strong></td><td>Similar to LAN with DMZ-specific display</td><td>Demilitarized zone interfaces</td></tr>
<tr><td><strong>Undefined</strong></td><td>No special treatment</td><td>Tunnel interfaces, transit links</td></tr>
</tbody>
</table>
</div>

<h2 id="dhcp-on-interface">DHCP on Interfaces</h2>

<p>Each LAN/DMZ interface can run a DHCP server or relay.</p>

<div class="code-block">
    <div class="code-header"><span>CLI — DHCP Server on Interface</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system dhcp server
    <span class="keyword">edit</span> 1
        <span class="keyword">set</span> interface "VLAN100-Servers"
        <span class="keyword">set</span> default-gateway 10.10.100.1
        <span class="keyword">set</span> netmask 255.255.255.0
        <span class="keyword">set</span> dns-server1 10.10.100.10
        <span class="keyword">set</span> dns-server2 8.8.8.8
        <span class="keyword">set</span> lease-time 86400  <span class="comment"># seconds (24 hours)</span>
        <span class="keyword">set</span> domain "corp.local"
        <span class="keyword">config</span> ip-range
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> start-ip 10.10.100.100
                <span class="keyword">set</span> end-ip 10.10.100.200
            <span class="keyword">next</span>
        <span class="keyword">end</span>
        <span class="keyword">config</span> reserved-address
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> ip 10.10.100.50
                <span class="keyword">set</span> mac 00:11:22:33:44:55
                <span class="keyword">set</span> description "Print Server"
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="interface-diagnostics">Interface Diagnostics</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Interface Diagnostics</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># View interface status</span>
<span class="command">get hardware nic port1</span>

<span class="comment"># Interface statistics (packets, errors, drops)</span>
<span class="command">diagnose netlink interface list port1</span>

<span class="comment"># Check SFP/transceiver details</span>
<span class="command">get hardware npu np6 port-list</span>

<span class="comment"># View ARP table for an interface</span>
<span class="command">get system arp | grep port1</span>

<span class="comment"># Clear interface statistics</span>
<span class="command">diagnose netlink interface clear port1</span>

<span class="comment"># Check DHCP leases</span>
<span class="command">execute dhcp lease-list</span>

<span class="comment"># Interface speed/duplex negotiation</span>
<span class="command">get hardware nic port1 | grep Speed</span></code></pre>
</div>

<h2 id="interface-best-practices">Best Practices</h2>

<ul class="checklist">
    <li><span class="check checked">✓</span> Always set meaningful aliases and descriptions on every interface</li>
    <li><span class="check checked">✓</span> Never enable HTTP or Telnet — use HTTPS and SSH only</li>
    <li><span class="check checked">✓</span> Disable administrative access on WAN interfaces or restrict to trusted IPs</li>
    <li><span class="check checked">✓</span> Use VLAN interfaces for network segmentation instead of separate physical ports</li>
    <li><span class="check checked">✓</span> Set appropriate interface roles (WAN/LAN/DMZ) for proper GUI categorization</li>
    <li><span class="check checked">✓</span> Use LAG (LACP) for critical uplinks — provides both bandwidth and redundancy</li>
    <li><span class="check checked">✓</span> Configure estimated bandwidth on WAN interfaces for accurate SD-WAN and traffic shaping</li>
    <li><span class="check checked">✓</span> Enable device identification on LAN interfaces for visibility</li>
</ul>
`;

// ============================================================
// ZONES
// ============================================================
KB.content['fg-zones'] = `
<h1><span class="h1-icon">📦</span> Zones</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>A Zone groups multiple interfaces into a single logical entity for firewall policy purposes. Instead of creating policies for each interface pair, you create one policy referencing the zone. Zones also control intra-zone traffic (traffic between interfaces within the same zone).</p>
</div>

<div class="gui-path">Network <span class="gui-sep">›</span> Interfaces <span class="gui-sep">›</span> Create New <span class="gui-sep">›</span> Zone</div>

<h2 id="why-zones">Why Use Zones</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Without Zones</th><th>With Zones</th></tr>
</thead>
<tbody>
<tr><td>Policy: VLAN10 → WAN1, VLAN10 → WAN2</td><td>Policy: LAN-Zone → WAN-Zone (1 policy)</td></tr>
<tr><td>Policy: VLAN20 → WAN1, VLAN20 → WAN2</td><td>Automatically covers all members</td></tr>
<tr><td>4+ policies needed</td><td>1 policy covers all combinations</td></tr>
<tr><td>Adding a new VLAN = new policies</td><td>Adding a new VLAN = add to zone (no policy change)</td></tr>
</tbody>
</table>
</div>

<h2 id="zone-config">Configuration</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Create Zones</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system zone
    <span class="keyword">edit</span> "LAN-Zone"
        <span class="keyword">set</span> intrazone allow  <span class="comment"># Allow traffic BETWEEN zone members</span>
        <span class="keyword">set</span> interface "VLAN10-Users" "VLAN20-Servers" "VLAN30-Printers"
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "WAN-Zone"
        <span class="keyword">set</span> intrazone deny   <span class="comment"># Block traffic between WANs</span>
        <span class="keyword">set</span> interface "port1" "port2"
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "DMZ-Zone"
        <span class="keyword">set</span> intrazone deny
        <span class="keyword">set</span> interface "VLAN50-DMZ-Web" "VLAN51-DMZ-Mail"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<div class="callout warning">
    <div class="callout-title">⚠️ Intrazone Traffic</div>
    <p><strong>Intrazone = allow</strong> means traffic flows freely between zone members WITHOUT a policy. This is convenient but creates a <strong>security blind spot</strong> — no logging, no UTM inspection. For segmented environments, set intrazone to <strong>deny</strong> and create explicit policies if needed.</p>
</div>

<div class="callout danger">
    <div class="callout-title">🚨 Cannot Undo Easily</div>
    <p>Once an interface is in a zone, <strong>all policies must reference the zone, not the interface</strong>. You cannot mix zone-based and interface-based policies. Removing an interface from a zone requires deleting all policies referencing that zone first.</p>
</div>
`;

// ============================================================
// VDOMs
// ============================================================
KB.content['fg-vdoms'] = `
<h1><span class="h1-icon">🏗️</span> Virtual Domains (VDOMs)</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>VDOMs (Virtual Domains) partition a single physical FortiGate into multiple <strong>independent virtual firewalls</strong>. Each VDOM has its own interfaces, routing table, firewall policies, VPN, and administrators. It's like running multiple FortiGates on one box.</p>
</div>

<div class="gui-path">System <span class="gui-sep">›</span> Settings <span class="gui-sep">›</span> Virtual Domains</div>

<h2 id="vdom-use-cases">When to Use VDOMs</h2>

<ul>
<li><strong>Multi-Tenant</strong>: Service providers hosting multiple customers on one FortiGate</li>
<li><strong>Department Isolation</strong>: Completely separate security domains for different business units</li>
<li><strong>Management vs. Data Plane</strong>: Separate management traffic from production traffic</li>
<li><strong>Compliance</strong>: PCI-DSS requiring network segmentation with separate firewall contexts</li>
</ul>

<h2 id="vdom-when-not">When NOT to Use VDOMs</h2>

<ul>
<li>Simple segmentation — use VLANs and zones instead</li>
<li>Small offices — VDOMs add operational complexity</li>
<li>When you don't have the license (some models limit VDOM count)</li>
<li>When a single routing table is sufficient</li>
</ul>

<h2 id="vdom-types">VDOM Types</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Type</th><th>Description</th><th>Use Case</th></tr>
</thead>
<tbody>
<tr><td><strong>Admin VDOM</strong></td><td>Handles FortiGuard updates, NTP, DNS, SNMP, management traffic</td><td>Always exists (usually "root"). One per FortiGate.</td></tr>
<tr><td><strong>Traffic VDOM</strong></td><td>Handles user/production traffic</td><td>Each customer/tenant gets their own Traffic VDOM</td></tr>
</tbody>
</table>
</div>

<h2 id="vdom-config">Configuration</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Enable VDOMs and Create</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Enable VDOM mode</span>
<span class="keyword">config</span> system global
    <span class="keyword">set</span> vdom-mode multi-vdom
<span class="keyword">end</span>
<span class="comment"># WARNING: System will reboot!</span>

<span class="comment"># Create a VDOM</span>
<span class="keyword">config</span> vdom
    <span class="keyword">edit</span> "CustomerA"
<span class="keyword">end</span>

<span class="comment"># Assign interface to VDOM</span>
<span class="keyword">config</span> global
<span class="keyword">config</span> system interface
    <span class="keyword">edit</span> "port3"
        <span class="keyword">set</span> vdom "CustomerA"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Configure within a VDOM</span>
<span class="keyword">config</span> vdom
    <span class="keyword">edit</span> "CustomerA"
        <span class="keyword">config</span> system settings
            <span class="keyword">set</span> opmode nat
        <span class="keyword">end</span>
        <span class="keyword">config</span> router static
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> gateway 10.1.1.1
                <span class="keyword">set</span> device "port3"
            <span class="keyword">next</span>
        <span class="keyword">end</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="inter-vdom-link">Inter-VDOM Links</h2>

<p>For traffic between VDOMs, you need <strong>Inter-VDOM Links</strong> — virtual Ethernet cables connecting two VDOMs internally.</p>

<div class="code-block">
    <div class="code-header"><span>CLI — Inter-VDOM Link</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> global
<span class="keyword">config</span> system vdom-link
    <span class="keyword">edit</span> "root-to-custA"
    <span class="keyword">next</span>
<span class="keyword">end</span>
<span class="comment"># This creates two interfaces: root-to-custA0 (in root) and root-to-custA1 (in CustomerA)</span>

<span class="comment"># Assign IPs</span>
<span class="keyword">config</span> system interface
    <span class="keyword">edit</span> "root-to-custA0"
        <span class="keyword">set</span> vdom "root"
        <span class="keyword">set</span> ip 10.255.0.1/30
        <span class="keyword">set</span> allowaccess ping
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "root-to-custA1"
        <span class="keyword">set</span> vdom "CustomerA"
        <span class="keyword">set</span> ip 10.255.0.2/30
        <span class="keyword">set</span> allowaccess ping
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<div class="callout best-practice">
    <div class="callout-title">🎯 Best Practice</div>
    <p>Use <strong>NPU VDOM Links</strong> (available on newer models) instead of standard VDOM links. NPU links are hardware-accelerated and provide significantly better performance for inter-VDOM traffic.</p>
</div>
`;

// ============================================================
// ADMINISTRATORS
// ============================================================
KB.content['fg-administrators'] = `
<h1><span class="h1-icon">👤</span> Administrators</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Administrator accounts control who can manage the FortiGate and what they can do. FortiGate supports local accounts, remote authentication (LDAP/RADIUS/TACACS+), admin profiles for RBAC, two-factor authentication, and trusted host restrictions.</p>
</div>

<div class="gui-path">System <span class="gui-sep">›</span> Administrators</div>

<h2 id="admin-profiles">Admin Profiles (RBAC)</h2>

<p>Admin profiles define what an administrator can see and do. FortiGate has built-in profiles and supports custom ones.</p>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Built-in Profile</th><th>Access Level</th><th>Use Case</th></tr>
</thead>
<tbody>
<tr><td><strong>super_admin</strong></td><td>Full read-write to everything including global settings</td><td>Only for initial setup and emergency</td></tr>
<tr><td><strong>prof_admin</strong></td><td>Full read-write within assigned VDOMs</td><td>VDOM-level administrator</td></tr>
<tr><td><strong>super_admin_readonly</strong></td><td>Read-only to everything</td><td>Audit, monitoring, SOC</td></tr>
</tbody>
</table>
</div>

<h3>Custom Admin Profile</h3>

<div class="code-block">
    <div class="code-header"><span>CLI — Custom Admin Profile</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system accprofile
    <span class="keyword">edit</span> "NOC-Operator"
        <span class="keyword">set</span> secfabgrp read
        <span class="keyword">set</span> ftviewgrp read
        <span class="keyword">set</span> authgrp none
        <span class="keyword">set</span> sysgrp read
        <span class="keyword">set</span> netgrp none
        <span class="keyword">set</span> loggrp read
        <span class="keyword">set</span> fwgrp read
        <span class="keyword">set</span> vpngrp read
        <span class="keyword">set</span> utmgrp none
        <span class="keyword">set</span> wanoptgrp none
        <span class="keyword">set</span> wifi none
        <span class="keyword">set</span> admintimeout 15
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="create-admin">Creating Administrators</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Create Local Admin with 2FA</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system admin
    <span class="keyword">edit</span> "john.doe"
        <span class="keyword">set</span> accprofile "prof_admin"
        <span class="keyword">set</span> vdom "root"
        <span class="keyword">set</span> password <span class="string">"C0mpl3x!P@ss"</span>
        <span class="keyword">set</span> two-factor fortitoken
        <span class="keyword">set</span> fortitoken <span class="string">"FTK1234567890"</span>
        <span class="keyword">set</span> email-to "john.doe@company.com"
        <span class="keyword">set</span> trusthost1 10.0.0.0/8
        <span class="keyword">set</span> trusthost2 192.168.1.0/24
        <span class="keyword">set</span> gui-default-dashboard-template "status"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<div class="callout danger">
    <div class="callout-title">🚨 Security Hardening Requirements</div>
    <p><strong>1.</strong> Change the default admin password IMMEDIATELY after deployment<br>
    <strong>2.</strong> Configure <code>trusthost</code> on EVERY admin account — restrict to management networks<br>
    <strong>3.</strong> Enable two-factor authentication for ALL admin accounts<br>
    <strong>4.</strong> Create named accounts for each person — never share the default "admin" account<br>
    <strong>5.</strong> Disable the default "admin" account after creating named super_admin accounts<br>
    <strong>6.</strong> Set <code>admin-lockout-threshold</code> to 3-5 attempts</p>
</div>

<h2 id="admin-diagnostics">Diagnostics</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Admin Session Monitoring</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># View current admin sessions</span>
<span class="command">get system info admin status</span>

<span class="comment"># View admin login history</span>
<span class="command">execute log filter category event</span>
<span class="command">execute log filter field subtype system</span>
<span class="command">execute log display</span>

<span class="comment"># Disconnect an admin session</span>
<span class="command">execute disconnect-admin-session &lt;session-id&gt;</span></code></pre>
</div>
`;

// ============================================================
// CERTIFICATES
// ============================================================
KB.content['fg-certificates'] = `
<h1><span class="h1-icon">📜</span> Certificates</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Certificates on FortiGate are used for: SSL VPN portal, admin HTTPS, SSL deep inspection, IPSec VPN authentication, SAML, and FortiGuard communication. Proper certificate management prevents browser warnings, inspection failures, and authentication issues.</p>
</div>

<div class="gui-path">System <span class="gui-sep">›</span> Certificates</div>

<h2 id="cert-types">Certificate Types</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Type</th><th>Purpose</th><th>Example</th></tr>
</thead>
<tbody>
<tr><td><strong>Local Certificate</strong></td><td>FortiGate's own identity cert (for services it hosts)</td><td>SSL VPN portal, admin HTTPS, SAML IdP</td></tr>
<tr><td><strong>CA Certificate</strong></td><td>Certificate Authority cert for verifying others</td><td>SSL deep inspection CA, LDAPS trust</td></tr>
<tr><td><strong>Remote Certificate</strong></td><td>Peer certificate for IPSec auth</td><td>Site-to-site VPN with cert auth</td></tr>
<tr><td><strong>CRL</strong></td><td>Certificate Revocation List</td><td>Checking if a cert has been revoked</td></tr>
</tbody>
</table>
</div>

<h2 id="ssl-inspection-cert">SSL Deep Inspection CA</h2>

<div class="callout warning">
    <div class="callout-title">⚠️ Critical for SSL Inspection</div>
    <p>SSL deep inspection requires a CA certificate that your endpoints trust. By default, FortiGate uses "Fortinet_CA_SSL". You <strong>must</strong> deploy this CA to all endpoints via GPO/MDM, or replace it with your enterprise CA. Otherwise, users get certificate warnings on every HTTPS site.</p>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Import Certificate</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Generate CSR</span>
<span class="command">execute vpn certificate local generate rsa 2048 "CN=vpn.company.com,O=Company,C=US"</span>

<span class="comment"># Import signed certificate</span>
<span class="command">execute vpn certificate local import tftp &lt;filename&gt; &lt;tftp-server-ip&gt;</span>

<span class="comment"># Import CA certificate</span>
<span class="command">execute vpn certificate ca import tftp &lt;filename&gt; &lt;tftp-server-ip&gt;</span>

<span class="comment"># View certificates</span>
<span class="command">get vpn certificate local</span>
<span class="command">get vpn certificate ca</span></code></pre>
</div>
`;

// ============================================================
// DNS
// ============================================================
KB.content['fg-dns'] = `
<h1><span class="h1-icon">🌐</span> DNS Settings</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>DNS settings configure which DNS servers the <strong>FortiGate itself</strong> uses for name resolution. This affects FortiGuard connectivity, FQDN objects, SSL inspection certificate validation, syslog FQDN targets, and any CLI command using hostnames. This is NOT the DNS that user traffic uses (that's handled by DNS Filter or DHCP settings).</p>
</div>

<div class="gui-path">Network <span class="gui-sep">›</span> DNS</div>

<h2 id="dns-config">Configuration</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — DNS Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system dns
    <span class="keyword">set</span> primary 8.8.8.8
    <span class="keyword">set</span> secondary 8.8.4.4
    <span class="keyword">set</span> protocol cleartext dot doh
    <span class="keyword">set</span> ssl-certificate "Fortinet_Factory"
    <span class="keyword">set</span> dns-over-tls enforce  <span class="comment"># Use DoT</span>
    <span class="keyword">set</span> source-ip 0.0.0.0    <span class="comment"># Auto-select</span>
    <span class="keyword">set</span> interface "port1"      <span class="comment"># Force DNS out specific interface</span>
    <span class="keyword">set</span> cache-notfound-responses disable
<span class="keyword">end</span></code></pre>
</div>

<div class="callout tip">
    <div class="callout-title">💡 Best Practice</div>
    <p>Use <strong>DNS over TLS (DoT)</strong> or <strong>DNS over HTTPS (DoH)</strong> for FortiGate's own DNS to prevent DNS hijacking. Point to your internal DNS if FortiGate needs to resolve internal FQDNs (e.g., LDAP server names, FortiAnalyzer hostnames).</p>
</div>

<h2 id="dns-database">DNS Database (FortiGate as DNS Server)</h2>

<p>FortiGate can act as a DNS server for clients, providing local DNS resolution.</p>

<div class="code-block">
    <div class="code-header"><span>CLI — DNS Database</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system dns-database
    <span class="keyword">edit</span> "corp.local"
        <span class="keyword">set</span> domain "corp.local"
        <span class="keyword">set</span> type master
        <span class="keyword">set</span> view shadow
        <span class="keyword">set</span> ttl 600
        <span class="keyword">set</span> authoritative enable
        <span class="keyword">config</span> dns-entry
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> hostname "portal"
                <span class="keyword">set</span> type A
                <span class="keyword">set</span> ip 10.10.10.100
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="dns-diagnostics">Diagnostics</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — DNS Troubleshooting</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Test DNS resolution from FortiGate</span>
<span class="command">execute ping update.fortiguard.net</span>
<span class="command">execute nslookup name update.fortiguard.net</span>

<span class="comment"># Check DNS server status</span>
<span class="command">diagnose test application dnsproxy 1</span>

<span class="comment"># DNS cache</span>
<span class="command">diagnose test application dnsproxy 6</span>  <span class="comment"># Display cache</span>
<span class="command">diagnose test application dnsproxy 7</span>  <span class="comment"># Clear cache</span>

<span class="comment"># DNS debug</span>
<span class="command">diagnose debug application dnsproxy -1</span>
<span class="command">diagnose debug enable</span></code></pre>
</div>
`;

// ============================================================
// NTP
// ============================================================
KB.content['fg-ntp'] = `
<h1><span class="h1-icon">🕐</span> NTP (Network Time Protocol)</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>NTP synchronizes the FortiGate's system clock with authoritative time servers. Accurate time is <strong>critical</strong> for: log correlation, certificate validation, scheduled policies, session timeouts, TOTP 2FA, and forensic analysis.</p>
</div>

<div class="gui-path">System <span class="gui-sep">›</span> Settings <span class="gui-sep">›</span> NTP</div>

<div class="callout danger">
    <div class="callout-title">🚨 Why Time Accuracy Matters</div>
    <p><strong>Wrong time = broken security:</strong><br>
    • Certificates appear expired or not yet valid<br>
    • FortiToken OTP codes won't validate (TOTP is time-based)<br>
    • Log timestamps become unreliable for incident response<br>
    • Scheduled policies trigger at wrong times<br>
    • Kerberos authentication fails (max 5-minute clock skew)</p>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — NTP Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system ntp
    <span class="keyword">set</span> ntpsync enable
    <span class="keyword">set</span> type custom
    <span class="keyword">set</span> syncinterval 60  <span class="comment"># minutes</span>
    <span class="keyword">config</span> ntpserver
        <span class="keyword">edit</span> 1
            <span class="keyword">set</span> server "0.pool.ntp.org"
        <span class="keyword">next</span>
        <span class="keyword">edit</span> 2
            <span class="keyword">set</span> server "1.pool.ntp.org"
        <span class="keyword">next</span>
    <span class="keyword">end</span>
    <span class="keyword">set</span> source-ip 0.0.0.0
    <span class="keyword">set</span> interface "port1"
<span class="keyword">end</span>

<span class="comment"># Verification</span>
<span class="command">diagnose sys ntp status</span>
<span class="command">execute date</span></code></pre>
</div>
`;

// ============================================================
// SNMP
// ============================================================
KB.content['fg-snmp'] = `
<h1><span class="h1-icon">📡</span> SNMP</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>SNMP (Simple Network Management Protocol) enables external NMS tools (PRTG, Zabbix, LibreNMS, SolarWinds, Nagios) to monitor FortiGate health metrics: CPU, memory, sessions, interface stats, HA status, VPN tunnels, and more. FortiGate supports SNMPv1/v2c/v3 and can send SNMP traps.</p>
</div>

<div class="gui-path">System <span class="gui-sep">›</span> SNMP</div>

<h2 id="snmp-versions">SNMP Versions</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Version</th><th>Security</th><th>Recommendation</th></tr>
</thead>
<tbody>
<tr><td><strong>v1/v2c</strong></td><td>Community string (plaintext)</td><td>Use only on isolated management VLANs</td></tr>
<tr><td><strong>v3</strong></td><td>Username + Auth (SHA) + Privacy (AES)</td><td><strong>Recommended</strong> — encrypted and authenticated</td></tr>
</tbody>
</table>
</div>

<h2 id="snmp-config">Configuration</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — SNMPv2c Community</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system snmp community
    <span class="keyword">edit</span> 1
        <span class="keyword">set</span> name "MonitorOnly"
        <span class="keyword">set</span> status enable
        <span class="keyword">set</span> query-v2c-status enable
        <span class="keyword">set</span> trap-v2c-status enable
        <span class="keyword">config</span> hosts
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> ip 10.0.0.50/32  <span class="comment"># NMS server IP</span>
            <span class="keyword">next</span>
        <span class="keyword">end</span>
        <span class="keyword">set</span> events cpu-high mem-low intf-ip ha-switch</span>
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — SNMPv3 User (Recommended)</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system snmp user
    <span class="keyword">edit</span> "snmpv3-monitor"
        <span class="keyword">set</span> status enable
        <span class="keyword">set</span> security-level auth-priv
        <span class="keyword">set</span> auth-proto sha256
        <span class="keyword">set</span> auth-pwd <span class="string">"Auth$ecure!2024"</span>
        <span class="keyword">set</span> priv-proto aes256
        <span class="keyword">set</span> priv-pwd <span class="string">"Priv$ecure!2024"</span>
        <span class="keyword">set</span> queries enable
        <span class="keyword">set</span> query-port 161
        <span class="keyword">set</span> traps enable
        <span class="keyword">set</span> notify-hosts 10.0.0.50
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="snmp-sysinfo">SNMP System Info</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — SNMP System Information</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system snmp sysinfo
    <span class="keyword">set</span> status enable
    <span class="keyword">set</span> description "FortiGate DC1 Primary Firewall"
    <span class="keyword">set</span> contact-info "noc@company.com"
    <span class="keyword">set</span> location "DataCenter 1, Rack A3"
<span class="keyword">end</span></code></pre>
</div>

<h2 id="snmp-oids">Key FortiGate SNMP OIDs</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Metric</th><th>OID</th><th>Description</th></tr>
</thead>
<tbody>
<tr><td>CPU Usage</td><td><code>.1.3.6.1.4.1.12356.101.4.1.3.0</code></td><td>Current CPU usage percentage</td></tr>
<tr><td>Memory Usage</td><td><code>.1.3.6.1.4.1.12356.101.4.1.4.0</code></td><td>Current memory usage percentage</td></tr>
<tr><td>Session Count</td><td><code>.1.3.6.1.4.1.12356.101.4.1.8.0</code></td><td>Active session count</td></tr>
<tr><td>Disk Usage</td><td><code>.1.3.6.1.4.1.12356.101.4.1.6.0</code></td><td>Disk usage percentage</td></tr>
<tr><td>HA State</td><td><code>.1.3.6.1.4.1.12356.101.13.2.1.1.0</code></td><td>HA cluster member state</td></tr>
<tr><td>Serial Number</td><td><code>.1.3.6.1.4.1.12356.100.1.1.1.0</code></td><td>Device serial number</td></tr>
<tr><td>Firmware Version</td><td><code>.1.3.6.1.4.1.12356.101.4.1.1.0</code></td><td>Running firmware version</td></tr>
<tr><td>VPN Tunnel Up</td><td><code>.1.3.6.1.4.1.12356.101.12.2.2.1.20</code></td><td>IPSec tunnel status</td></tr>
</tbody>
</table>
</div>
`;

// ============================================================
// HA
// ============================================================
KB.content['fg-ha'] = `
<h1><span class="h1-icon">🔄</span> High Availability (HA)</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>FortiGate High Availability (HA) clusters two or more FortiGate units to provide <strong>failover redundancy</strong> and/or <strong>load balancing</strong>. If the primary unit fails, the secondary takes over within seconds, maintaining all sessions, VPN tunnels, and firewall state.</p>
</div>

<div class="gui-path">System <span class="gui-sep">›</span> HA</div>

<h2 id="ha-modes">HA Modes</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Mode</th><th>How It Works</th><th>Best For</th><th>Limitation</th></tr>
</thead>
<tbody>
<tr><td><strong>Active-Passive (A-P)</strong></td><td>Primary handles all traffic; secondary is hot standby</td><td>Most deployments, predictable failover</td><td>Secondary hardware sits idle</td></tr>
<tr><td><strong>Active-Active (A-A)</strong></td><td>All units process traffic; primary distributes sessions</td><td>High-throughput environments</td><td>More complex, asymmetric routing risks</td></tr>
</tbody>
</table>
</div>

<h2 id="ha-config">Configuration</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — HA Active-Passive Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system ha
    <span class="keyword">set</span> mode a-p                   <span class="comment"># a-p or a-a</span>
    <span class="keyword">set</span> group-name "DC1-FW-Cluster"
    <span class="keyword">set</span> group-id 1
    <span class="keyword">set</span> password <span class="string">"H@Cl5terK3y!"</span>
    <span class="keyword">set</span> hbdev "port7" 50 "port8" 100  <span class="comment"># Heartbeat interfaces with priority</span>
    <span class="keyword">set</span> session-pickup enable        <span class="comment"># Sync sessions for seamless failover</span>
    <span class="keyword">set</span> session-pickup-connectionless enable
    <span class="keyword">set</span> session-pickup-delay enable
    <span class="keyword">set</span> override disable              <span class="comment"># Don't auto-preempt</span>
    <span class="keyword">set</span> priority 200                  <span class="comment"># Higher = more likely to be primary</span>
    <span class="keyword">set</span> monitor "port1" "port2" "port3"  <span class="comment"># Monitored interfaces</span>
    <span class="keyword">set</span> ha-mgmt-status enable
    <span class="keyword">config</span> ha-mgmt-interfaces
        <span class="keyword">edit</span> 1
            <span class="keyword">set</span> interface "port10"
            <span class="keyword">set</span> gateway 10.0.99.1
        <span class="keyword">next</span>
    <span class="keyword">end</span>
<span class="keyword">end</span></code></pre>
</div>

<div class="callout warning">
    <div class="callout-title">⚠️ Critical HA Requirements</div>
    <p>• Both units <strong>must be identical model and firmware</strong><br>
    • Heartbeat link should be a <strong>dedicated interface</strong> (not shared with data traffic)<br>
    • Use <strong>two heartbeat links</strong> for redundancy (if one cable fails, HA still works)<br>
    • Heartbeat interfaces should be <strong>directly connected</strong> (crossover cable) or on an isolated VLAN<br>
    • The HA password must match on both units</p>
</div>

<h2 id="ha-diagnostics">HA Diagnostics</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — HA Monitoring & Troubleshooting</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># HA status overview</span>
<span class="command">get system ha status</span>

<span class="comment"># Detailed HA diagnostics</span>
<span class="command">diagnose sys ha status</span>

<span class="comment"># HA checksum (config sync verification)</span>
<span class="command">diagnose sys ha checksum cluster</span>

<span class="comment"># View HA history (failover events)</span>
<span class="command">diagnose sys ha history read</span>

<span class="comment"># Force failover (testing)</span>
<span class="command">diagnose sys ha reset-uptime</span>

<span class="comment"># Check session sync status</span>
<span class="command">diagnose sys ha dump-by vcluster</span>

<span class="comment"># Run command on secondary unit</span>
<span class="command">execute ha manage 1</span>  <span class="comment"># Connect to secondary</span></code></pre>
</div>

<h2 id="ha-troubleshooting">Common HA Issues</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Issue</th><th>Cause</th><th>Resolution</th></tr>
</thead>
<tbody>
<tr><td>Split-brain (both active)</td><td>Heartbeat link failure</td><td>Check heartbeat cables, ensure dedicated link</td></tr>
<tr><td>Config out of sync</td><td>Changes made on secondary directly</td><td><code>diagnose sys ha checksum recalculate</code></td></tr>
<tr><td>Unexpected failover</td><td>Monitored interface flap, high CPU</td><td>Check <code>diagnose sys ha history read</code></td></tr>
<tr><td>Slow failover</td><td>Many sessions, session sync overwhelmed</td><td>Tune session-pickup-delay, check heartbeat bandwidth</td></tr>
</tbody>
</table>
</div>
`;

// ============================================================
// FIRMWARE
// ============================================================
KB.content['fg-firmware'] = `
<h1><span class="h1-icon">💾</span> Firmware Management</h1>

<div class="gui-path">System <span class="gui-sep">›</span> Firmware</div>

<div class="callout info">
    <div class="callout-title">ℹ️ Overview</div>
    <p>Firmware management covers upgrading, downgrading, and maintaining FortiOS versions. Fortinet releases updates in three tracks: <strong>Feature Release</strong> (new features), <strong>Mature Release</strong> (stability fixes), and <strong>Long-Term Support</strong> (critical fixes only).</p>
</div>

<div class="callout danger">
    <div class="callout-title">🚨 Critical Rules for Firmware Upgrades</div>
    <p><strong>1.</strong> ALWAYS follow the <strong>Fortinet Recommended Upgrade Path</strong> — never skip versions<br>
    <strong>2.</strong> ALWAYS back up the config BEFORE upgrading<br>
    <strong>3.</strong> ALWAYS read the Release Notes for known issues<br>
    <strong>4.</strong> NEVER upgrade production during business hours without a maintenance window<br>
    <strong>5.</strong> Test on a non-production unit first if possible</p>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Firmware Operations</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Check current firmware</span>
<span class="command">get system status</span>

<span class="comment"># Backup configuration before upgrade</span>
<span class="command">execute backup config tftp &lt;filename&gt; &lt;tftp-server-ip&gt;</span>
<span class="command">execute backup config ftp &lt;filename&gt; &lt;ftp-server-ip&gt;</span>

<span class="comment"># Upload firmware from TFTP</span>
<span class="command">execute restore image tftp &lt;filename&gt; &lt;tftp-server-ip&gt;</span>

<span class="comment"># Upload firmware from USB</span>
<span class="command">execute usb-disk list</span>
<span class="command">execute restore image usb &lt;filename&gt;</span>

<span class="comment"># Check firmware integrity</span>
<span class="command">diagnose hardware deviceinfo disk</span>

<span class="comment"># Dual-boot partition (rollback)</span>
<span class="command">diagnose sys flash list</span>
<span class="command">execute set-next-reboot secondary</span>  <span class="comment"># Boot from backup partition</span></code></pre>
</div>
`;

// ============================================================
// AUTOMATION
// ============================================================
KB.content['fg-automation'] = `
<h1><span class="h1-icon">🤖</span> Automation Stitches</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Automation Stitches combine <strong>Triggers</strong> (events) with <strong>Actions</strong> (responses) to automate operational and security tasks without human intervention. Think of them as FortiGate's built-in SOAR capability.</p>
</div>

<div class="gui-path">Security Fabric <span class="gui-sep">›</span> Automation</div>

<h2 id="automation-examples">Common Automation Examples</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Trigger</th><th>Action</th><th>Use Case</th></tr>
</thead>
<tbody>
<tr><td>Compromised Host Detected</td><td>Quarantine host + Send Email</td><td>Automatic containment of infected devices</td></tr>
<tr><td>HA Failover</td><td>Send Email + Webhook to Slack</td><td>NOC alerting for failover events</td></tr>
<tr><td>High CPU (&gt;90%)</td><td>Send SNMP Trap + Email</td><td>Performance incident detection</td></tr>
<tr><td>VPN Tunnel Down</td><td>Send Email + Run CLI Script</td><td>Auto-attempt tunnel re-establishment</td></tr>
<tr><td>Configuration Change</td><td>Send Email + Backup Config</td><td>Change tracking and auto-backup</td></tr>
<tr><td>FortiGuard License Expiry</td><td>Send Email</td><td>Proactive license renewal alerting</td></tr>
<tr><td>Login Failed (3+ times)</td><td>Ban IP + Send Email</td><td>Brute-force protection</td></tr>
</tbody>
</table>
</div>

<h2 id="stitch-config">Configuration Example</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Automation Stitch</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Trigger: Compromised host detected</span>
<span class="keyword">config</span> system automation-trigger
    <span class="keyword">edit</span> "Compromised-Host-Trigger"
        <span class="keyword">set</span> event-type compromised-host
        <span class="keyword">set</span> description "Trigger when IPS/AV detects compromised endpoint"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Action: Send email notification</span>
<span class="keyword">config</span> system automation-action
    <span class="keyword">edit</span> "Email-SOC-Team"
        <span class="keyword">set</span> action-type email
        <span class="keyword">set</span> email-to "soc@company.com"
        <span class="keyword">set</span> email-subject "ALERT: Compromised Host Detected on %%log.srcip%%"
        <span class="keyword">set</span> message "Host %%log.srcip%% has been flagged as compromised.\\nAction: Quarantined.\\nDevice: %%log.devname%%\\nTime: %%log.date%% %%log.time%%"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Action: Quarantine the host</span>
<span class="keyword">config</span> system automation-action
    <span class="keyword">edit</span> "Quarantine-Host"
        <span class="keyword">set</span> action-type quarantine
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Stitch: Combine trigger + actions</span>
<span class="keyword">config</span> system automation-stitch
    <span class="keyword">edit</span> "Auto-Quarantine-Compromised"
        <span class="keyword">set</span> trigger "Compromised-Host-Trigger"
        <span class="keyword">set</span> status enable
        <span class="keyword">config</span> actions
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> action "Quarantine-Host"
                <span class="keyword">set</span> required enable
            <span class="keyword">next</span>
            <span class="keyword">edit</span> 2
                <span class="keyword">set</span> action "Email-SOC-Team"
                <span class="keyword">set</span> delay 0
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>
`;

// ============================================================
// FORTIGUARD
// ============================================================
KB.content['fg-fortiguard'] = `
<h1><span class="h1-icon">🔒</span> FortiGuard Services</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>FortiGuard is Fortinet's cloud-based threat intelligence and security update service. It delivers real-time updates for AV signatures, IPS rules, web filter categories, application signatures, IP reputation, anti-botnet, and more. Without FortiGuard, your FortiGate operates on stale data.</p>
</div>

<div class="gui-path">System <span class="gui-sep">›</span> FortiGuard</div>

<h2 id="fg-connectivity">FortiGuard Connectivity</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — FortiGuard Configuration & Diagnostics</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Check FortiGuard connectivity</span>
<span class="command">diagnose autoupdate status</span>

<span class="comment"># View all update versions/dates</span>
<span class="command">diagnose autoupdate versions</span>

<span class="comment"># Force immediate update</span>
<span class="command">execute update-now</span>

<span class="comment"># Test connectivity to FortiGuard</span>
<span class="command">execute ping update.fortiguard.net</span>
<span class="command">execute ping guard.fortinet.com</span>
<span class="command">execute telnet service.fortiguard.net 443</span>

<span class="comment"># FortiGuard server list and rating</span>
<span class="command">diagnose debug rating</span>

<span class="comment"># Configure update source</span>
<span class="keyword">config</span> system fortiguard
    <span class="keyword">set</span> port 443
    <span class="keyword">set</span> protocol https
    <span class="keyword">set</span> auto-join-forticloud enable
    <span class="keyword">set</span> update-server-location automatic
    <span class="keyword">set</span> sandbox-region ""
    <span class="keyword">set</span> antispam-force-off disable
    <span class="keyword">set</span> webfilter-force-off disable
<span class="keyword">end</span></code></pre>
</div>

<div class="callout warning">
    <div class="callout-title">⚠️ FortiGuard Not Updating?</div>
    <p>Common causes:<br>
    • <strong>DNS resolution failure</strong> — FortiGate can't resolve <code>update.fortiguard.net</code><br>
    • <strong>Firewall blocking outbound</strong> — Ensure TCP 443 and UDP 53/8888 are allowed<br>
    • <strong>Proxy blocking</strong> — If behind a proxy, configure FortiGuard to use proxy<br>
    • <strong>License expired</strong> — Updates stop when FortiCare or specific service licenses expire<br>
    • <strong>Wrong source interface</strong> — FortiGuard traffic exits the wrong interface</p>
</div>
`;

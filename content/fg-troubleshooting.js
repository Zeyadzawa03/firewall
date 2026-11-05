// ============================================================
// FortiGate Troubleshooting — Master Reference
// ============================================================

KB.content['fg-troubleshooting'] = `
<h1><span class="h1-icon">🔧</span> FortiGate Troubleshooting</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ Overview</div>
    <p>This section covers systematic troubleshooting methodology and the complete toolkit of FortiGate diagnostic commands. Effective troubleshooting requires a methodical approach: identify symptoms, isolate the layer, gather evidence, apply fixes, and verify resolution.</p>
</div>

<h2 id="troubleshooting-methodology">Troubleshooting Methodology</h2>

<div class="mermaid-wrapper">
<div class="mermaid">
flowchart TD
    A["🔴 Problem Reported"] --> B["Define the Problem\n- What is failing?\n- Since when?\n- What changed?"]
    B --> C["Identify Scope\n- Single user? All users?\n- Specific destination?\n- All destinations?"]
    C --> D["Layer Analysis"]
    D --> D1["L1/L2: Link up? ARP?"]
    D --> D2["L3: Route exists? Ping?"]
    D --> D3["L4: Policy match? Session?"]
    D --> D4["L7: UTM blocking? NAT correct?"]
    D1 & D2 & D3 & D4 --> E["Apply Fix"]
    E --> F["Verify Resolution"]
    F --> G["Document Root Cause"]
    style A fill:#ef4444,color:#fff
    style G fill:#10b981,color:#fff
</div>
<div class="mermaid-caption">Systematic Troubleshooting Flow</div>
</div>

<h2 id="layer-by-layer">Layer-by-Layer Checks</h2>

<h3>Layer 1/2 — Physical & Data Link</h3>
<div class="code-block">
    <div class="code-header"><span>CLI — L1/L2 Checks</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Interface physical status</span>
<span class="command">get hardware nic port1</span>

<span class="comment"># Interface statistics (errors, drops, collisions)</span>
<span class="command">diagnose netlink interface list port1</span>

<span class="comment"># ARP table</span>
<span class="command">get system arp</span>
<span class="command">get system arp | grep 10.0.0.1</span>

<span class="comment"># Check if interface is up</span>
<span class="command">diagnose hardware deviceinfo nic port1</span>

<span class="comment"># Check SFP transceiver info</span>
<span class="command">diagnose hardware deviceinfo nic port1 | grep -i sfp</span></code></pre>
</div>

<h3>Layer 3 — Network</h3>
<div class="code-block">
    <div class="code-header"><span>CLI — L3 Checks</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Routing table</span>
<span class="command">get router info routing-table all</span>

<span class="comment"># Specific route lookup</span>
<span class="command">get router info routing-table details 8.8.8.8</span>

<span class="comment"># Ping from FortiGate</span>
<span class="command">execute ping 8.8.8.8</span>

<span class="comment"># Ping from specific interface</span>
<span class="command">execute ping-options source 10.0.0.1</span>
<span class="command">execute ping 8.8.8.8</span>

<span class="comment"># Traceroute</span>
<span class="command">execute traceroute 8.8.8.8</span>

<span class="comment"># Neighbor Discovery / ARP</span>
<span class="command">diagnose ip arp list</span></code></pre>
</div>

<h3>Layer 4 — Session / Firewall</h3>
<div class="code-block">
    <div class="code-header"><span>CLI — L4/Policy Checks</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Session lookup</span>
<span class="command">diagnose sys session filter src 10.0.0.100</span>
<span class="command">diagnose sys session filter dst 8.8.8.8</span>
<span class="command">diagnose sys session list</span>

<span class="comment"># Policy lookup</span>
<span class="command">diagnose firewall iprope lookup 10.0.0.100 8.8.8.8 6 1024 80</span>

<span class="comment"># Debug flow (the most powerful tool)</span>
<span class="command">diagnose debug flow filter saddr 10.0.0.100</span>
<span class="command">diagnose debug flow trace start 20</span>
<span class="command">diagnose debug enable</span></code></pre>
</div>

<h3>Layer 7 — Application / UTM</h3>
<div class="code-block">
    <div class="code-header"><span>CLI — L7/UTM Checks</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Check AV engine</span>
<span class="command">diagnose test application scanunitd 1</span>

<span class="comment"># Check IPS engine</span>
<span class="command">diagnose test application ips 1</span>

<span class="comment"># Web filter proxy</span>
<span class="command">diagnose test application urlfilter 1</span>

<span class="comment"># Application identification</span>
<span class="command">diagnose test application appfw 1</span>

<span class="comment"># Debug AV</span>
<span class="command">diagnose debug application scanunitd -1</span>

<span class="comment"># Debug web filter</span>
<span class="command">diagnose debug application proxyd -1</span></code></pre>
</div>

<h2 id="common-issues">Common Issues & Solutions</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Problem</th><th>Quick Check</th><th>Solution</th></tr>
</thead>
<tbody>
<tr><td>Can't access internet</td><td><code>get router info routing-table all | grep 0.0.0.0</code></td><td>Add default route or fix ISP link</td></tr>
<tr><td>Policy not matching</td><td>Debug flow trace</td><td>Check interface/zone assignment, source/dst order</td></tr>
<tr><td>NAT not working</td><td><code>diagnose sys session filter</code> → check tranip</td><td>Verify NAT enabled on policy, IP pool configured</td></tr>
<tr><td>VPN tunnel down</td><td><code>get vpn ipsec tunnel summary</code></td><td>Check Phase 1/2 proposals, PSK, DPD settings</td></tr>
<tr><td>Slow performance</td><td><code>get system performance status</code></td><td>Check CPU/memory, NP offload, session count</td></tr>
<tr><td>FortiGuard not updating</td><td><code>diagnose autoupdate status</code></td><td>Check DNS, port 443 outbound, license</td></tr>
<tr><td>Admin locked out</td><td>Console access needed</td><td>Console → reset via maintainer account or factory reset</td></tr>
<tr><td>High CPU</td><td><code>diagnose sys top</code></td><td>Identify process, check IPS signatures, offload</td></tr>
</tbody>
</table>
</div>

<h2 id="performance-diagnostics">Performance Diagnostics</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Performance Commands</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># System performance overview</span>
<span class="command">get system performance status</span>

<span class="comment"># CPU usage per process</span>
<span class="command">diagnose sys top</span>
<span class="command">diagnose sys top-summary</span>

<span class="comment"># Memory usage</span>
<span class="command">diagnose hardware sysinfo memory</span>

<span class="comment"># Session statistics</span>
<span class="command">diagnose sys session stat</span>

<span class="comment"># Interface bandwidth utilization</span>
<span class="command">diagnose netlink interface list</span>

<span class="comment"># Hardware NPU status</span>
<span class="command">diagnose npu np6 session list</span>
<span class="command">diagnose npu np6 sse status</span>

<span class="comment"># Conserve mode check (memory overload)</span>
<span class="command">diagnose hardware sysinfo conserve</span></code></pre>
</div>

<h2 id="packet-capture">Packet Capture</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Packet Sniffer</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Basic packet capture</span>
<span class="comment"># Syntax: diagnose sniffer packet &lt;interface&gt; &lt;filter&gt; &lt;verbose&gt; &lt;count&gt; &lt;tsformat&gt;</span>

<span class="comment"># Capture on specific interface, specific host</span>
<span class="command">diagnose sniffer packet port1 "host 10.0.0.100" 4 100 a</span>

<span class="comment"># Capture on all interfaces</span>
<span class="command">diagnose sniffer packet any "host 8.8.8.8" 4 50</span>

<span class="comment"># Capture specific port</span>
<span class="command">diagnose sniffer packet port1 "port 443" 4 100</span>

<span class="comment"># Capture TCP SYN/RST (connection issues)</span>
<span class="command">diagnose sniffer packet any "tcp[tcpflags] & tcp-syn != 0" 4 100</span>

<span class="comment"># Verbose levels:</span>
<span class="comment"># 1 = just packet header</span>
<span class="comment"># 2 = header + hex data</span>
<span class="comment"># 3 = header with interface name</span>
<span class="comment"># 4 = all above with interface name (most useful)</span>
<span class="comment"># 6 = raw hex</span>

<span class="comment"># Capture to file (for Wireshark)</span>
<span class="command">diagnose sniffer packet port1 "host 10.0.0.100" 6 200 a >> /tmp/capture.pcap</span>
<span class="comment"># Then download via GUI: Network → Packet Capture</span></code></pre>
</div>
`;

KB.content['fg-cli-reference'] = `
<h1><span class="h1-icon">💻</span> CLI Reference</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ CLI Overview</div>
    <p>The FortiGate CLI provides complete configuration and diagnostic access. Every action possible in the GUI can be done via CLI plus many diagnostic and debug capabilities that don't have GUI equivalents. Mastering the CLI is essential for enterprise administration.</p>
</div>

<h2 id="cli-navigation">CLI Navigation</h2>

<div class="code-block">
    <div class="code-header"><span>CLI Navigation Basics</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Help</span>
<span class="command">?</span>                          <span class="comment"># Context-sensitive help</span>
<span class="command">get ?</span>                      <span class="comment"># Show all get sub-commands</span>

<span class="comment"># Config navigation</span>
<span class="command">config system interface</span>   <span class="comment"># Enter config context</span>
<span class="command">edit port1</span>                 <span class="comment"># Edit specific entry</span>
<span class="command">show</span>                       <span class="comment"># Show current config</span>
<span class="command">get</span>                        <span class="comment"># Show current values</span>
<span class="command">next</span>                       <span class="comment"># Save and move to next entry</span>
<span class="command">end</span>                        <span class="comment"># Save and exit context</span>
<span class="command">abort</span>                      <span class="comment"># Discard changes and exit</span>

<span class="comment"># View running config</span>
<span class="command">show full-configuration</span>   <span class="comment"># Show everything including defaults</span>
<span class="command">show</span>                       <span class="comment"># Show changed-from-default config only</span>
<span class="command">show | grep "set port"</span>     <span class="comment"># Filter config output</span>

<span class="comment"># Execute commands</span>
<span class="command">execute ping 8.8.8.8</span>
<span class="command">execute reboot</span>
<span class="command">execute shutdown</span>
<span class="command">execute factoryreset</span>      <span class="comment"># ⚠️ DANGER: Wipes config!</span>

<span class="comment"># Backup/Restore</span>
<span class="command">execute backup config tftp backup.cfg 10.0.0.50</span>
<span class="command">execute restore config tftp backup.cfg 10.0.0.50</span></code></pre>
</div>

<h2 id="essential-commands">Essential Commands Reference</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Task</th><th>Command</th></tr>
</thead>
<tbody>
<tr><td>System status</td><td><code>get system status</code></td></tr>
<tr><td>Performance</td><td><code>get system performance status</code></td></tr>
<tr><td>Interface status</td><td><code>get system interface</code></td></tr>
<tr><td>Routing table</td><td><code>get router info routing-table all</code></td></tr>
<tr><td>ARP table</td><td><code>get system arp</code></td></tr>
<tr><td>Active sessions</td><td><code>diagnose sys session stat</code></td></tr>
<tr><td>BGP summary</td><td><code>get router info bgp summary</code></td></tr>
<tr><td>OSPF neighbors</td><td><code>get router info ospf neighbor</code></td></tr>
<tr><td>VPN tunnels</td><td><code>get vpn ipsec tunnel summary</code></td></tr>
<tr><td>SSL VPN users</td><td><code>get vpn ssl monitor</code></td></tr>
<tr><td>HA status</td><td><code>get system ha status</code></td></tr>
<tr><td>Process top</td><td><code>diagnose sys top</code></td></tr>
<tr><td>FortiGuard status</td><td><code>diagnose autoupdate status</code></td></tr>
<tr><td>NTP sync</td><td><code>diagnose sys ntp status</code></td></tr>
<tr><td>DNS test</td><td><code>execute nslookup name google.com</code></td></tr>
<tr><td>Policy hit count</td><td><code>diagnose firewall policy hitcount</code></td></tr>
<tr><td>Debug enable</td><td><code>diagnose debug enable</code></td></tr>
<tr><td>Debug disable</td><td><code>diagnose debug disable</code></td></tr>
<tr><td>Debug reset</td><td><code>diagnose debug reset</code></td></tr>
</tbody>
</table>
</div>
`;

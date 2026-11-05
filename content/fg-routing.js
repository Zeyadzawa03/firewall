// ============================================================
// FortiGate Routing — Static, Policy, BGP, OSPF, RIP, ECMP, SD-WAN
// ============================================================

KB.content['fg-static-routes'] = `
<h1><span class="h1-icon">📍</span> Static Routes</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Static routes manually define the path that traffic takes to reach a destination network. They are the simplest routing mechanism — no protocol overhead, fully predictable, but require manual updates when topology changes. Static routes are the backbone of most FortiGate deployments.</p>
</div>

<div class="gui-path">Network <span class="gui-sep">›</span> Static Routes</div>

<h2 id="route-anatomy">Route Anatomy</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Field</th><th>Description</th><th>Notes</th></tr>
</thead>
<tbody>
<tr><td><strong>Destination</strong></td><td>Target network (subnet or host)</td><td>0.0.0.0/0 = default route</td></tr>
<tr><td><strong>Gateway</strong></td><td>Next-hop IP address</td><td>Must be reachable on the specified interface</td></tr>
<tr><td><strong>Interface</strong></td><td>Egress interface</td><td>Required. Gateway must be on this interface's subnet</td></tr>
<tr><td><strong>Distance</strong></td><td>Administrative distance (1-255)</td><td>Lower = higher priority. Default: 10 for static</td></tr>
<tr><td><strong>Priority</strong></td><td>Tie-breaking within same distance</td><td>Lower = higher priority</td></tr>
<tr><td><strong>Weight</strong></td><td>ECMP load sharing weight</td><td>Higher = more traffic in ECMP</td></tr>
<tr><td><strong>Status</strong></td><td>Enable/Disable route</td><td>Disabled routes stay in config but not in RIB</td></tr>
<tr><td><strong>Comments</strong></td><td>Description</td><td>Always document why the route exists</td></tr>
</tbody>
</table>
</div>

<h2 id="static-config">Configuration</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Static Routes</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> router static
    <span class="comment"># Default route (internet gateway)</span>
    <span class="keyword">edit</span> 1
        <span class="keyword">set</span> dst 0.0.0.0/0
        <span class="keyword">set</span> gateway 203.0.113.1
        <span class="keyword">set</span> device "port1"
        <span class="keyword">set</span> distance 10
        <span class="keyword">set</span> comment "Primary ISP default route"
    <span class="keyword">next</span>

    <span class="comment"># Backup default route (higher distance = lower priority)</span>
    <span class="keyword">edit</span> 2
        <span class="keyword">set</span> dst 0.0.0.0/0
        <span class="keyword">set</span> gateway 198.51.100.1
        <span class="keyword">set</span> device "port2"
        <span class="keyword">set</span> distance 20
        <span class="keyword">set</span> comment "Backup ISP default route"
    <span class="keyword">next</span>

    <span class="comment"># Specific host route</span>
    <span class="keyword">edit</span> 3
        <span class="keyword">set</span> dst 192.168.50.100/32
        <span class="keyword">set</span> gateway 10.0.0.1
        <span class="keyword">set</span> device "port3"
        <span class="keyword">set</span> comment "Management server"
    <span class="keyword">next</span>

    <span class="comment"># Null route (blackhole for bogons)</span>
    <span class="keyword">edit</span> 4
        <span class="keyword">set</span> dst 10.200.0.0/16
        <span class="keyword">set</span> blackhole enable
        <span class="keyword">set</span> distance 254
        <span class="keyword">set</span> comment "Blackhole for unused internal space"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="route-verification">Verification Commands</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Route Verification</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># View active routing table</span>
<span class="command">get router info routing-table all</span>

<span class="comment"># View only static routes</span>
<span class="command">get router info routing-table static</span>

<span class="comment"># Route lookup for specific destination</span>
<span class="command">get router info routing-table details 8.8.8.8</span>

<span class="comment"># All configured routes (including disabled)</span>
<span class="command">show router static</span>

<span class="comment"># Policy route check</span>
<span class="command">get router info routing-table all | grep 0.0.0.0</span>

<span class="comment"># Test connectivity via specific gateway</span>
<span class="command">execute ping-options source 10.0.0.1</span>
<span class="command">execute ping 8.8.8.8</span></code></pre>
</div>

<div class="mermaid-wrapper">
<div class="mermaid">
graph LR
    A["Incoming Packet<br/>Dest: 8.8.8.8"] --> B{"Policy Route<br/>Match?"}
    B -- Yes --> C["Use Policy Route<br/>Gateway"]
    B -- No --> D{"Routing Table<br/>Lookup"}
    D --> E{"Specific Route<br/>/24 or more?"}
    E -- Yes --> F["Use Specific Route"]
    E -- No --> G{"Default Route<br/>0.0.0.0/0?"}
    G -- Yes --> H["Use Default Route"]
    G -- No --> I["Drop: No Route"]
    style I fill:#ef4444,color:#fff
    style H fill:#10b981,color:#fff
    style F fill:#10b981,color:#fff
</div>
<div class="mermaid-caption">Static Route Decision Flow — Longest Prefix Match</div>
</div>

<h2 id="ecmp-routes">ECMP (Equal-Cost Multi-Path)</h2>

<div class="callout info">
    <div class="callout-title">ℹ️ ECMP</div>
    <p>When two routes have the <strong>same destination, same distance, and same priority</strong>, FortiGate installs both in the routing table and load-balances traffic across them. This is ECMP — providing both bandwidth aggregation and redundancy.</p>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — ECMP Routes</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> router static
    <span class="comment"># Both routes same distance/priority = ECMP</span>
    <span class="keyword">edit</span> 1
        <span class="keyword">set</span> dst 0.0.0.0/0
        <span class="keyword">set</span> gateway 203.0.113.1
        <span class="keyword">set</span> device "port1"
        <span class="keyword">set</span> distance 10
        <span class="keyword">set</span> weight 100    <span class="comment"># Controls share of traffic</span>
    <span class="keyword">next</span>
    <span class="keyword">edit</span> 2
        <span class="keyword">set</span> dst 0.0.0.0/0
        <span class="keyword">set</span> gateway 198.51.100.1
        <span class="keyword">set</span> device "port2"
        <span class="keyword">set</span> distance 10
        <span class="keyword">set</span> weight 100
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Configure ECMP load-balancing method</span>
<span class="keyword">config</span> router setting
    <span class="keyword">set</span> ip-ecmp-mode src-dst-ip-based  
    <span class="comment"># Options: src-ip-based | dst-ip-based | src-dst-ip-based | usage-based | weight-based</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="route-troubleshooting-static">Troubleshooting Static Routes</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Symptom</th><th>Cause</th><th>Fix</th></tr>
</thead>
<tbody>
<tr><td>Route not in routing table</td><td>Interface down, gateway unreachable</td><td>Check interface status, ping gateway</td></tr>
<tr><td>Traffic going wrong path</td><td>Wrong distance or more-specific route</td><td><code>get router info routing-table details &lt;IP&gt;</code></td></tr>
<tr><td>No ECMP load sharing</td><td>Different distances, or ECMP disabled</td><td>Ensure same distance, check <code>ip-ecmp-mode</code></td></tr>
<tr><td>Default route missing</td><td>ISP link down, route not configured</td><td>Verify physical link, ping gateway</td></tr>
<tr><td>Asymmetric routing</td><td>Separate ingress/egress paths</td><td>Use policy routes or SD-WAN to force symmetry</td></tr>
</tbody>
</table>
</div>
`;

KB.content['fg-policy-routes'] = `
<h1><span class="h1-icon">🔀</span> Policy Routes</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Policy Routes (also called Policy-Based Routing or PBR) allow you to override the normal routing table decisions based on packet attributes: source IP, destination IP, source interface, ToS/DSCP, or protocol. They are evaluated <strong>before</strong> the routing table lookup.</p>
</div>

<div class="gui-path">Network <span class="gui-sep">›</span> Policy Routes</div>

<h2 id="policy-route-when">When to Use Policy Routes</h2>

<ul>
<li><strong>Multi-ISP routing</strong>: Route specific department traffic (Finance) via ISP1, others via ISP2</li>
<li><strong>VoIP path control</strong>: Force voice traffic through low-latency link</li>
<li><strong>Management traffic separation</strong>: Route management traffic through dedicated link</li>
<li><strong>Asymmetric flow correction</strong>: Force return traffic out the same interface it came in</li>
</ul>

<div class="code-block">
    <div class="code-header"><span>CLI — Policy Route Examples</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> router policy
    <span class="comment"># Route Finance VLAN traffic via ISP2</span>
    <span class="keyword">edit</span> 1
        <span class="keyword">set</span> input-device "VLAN10-Finance"
        <span class="keyword">set</span> src 10.10.10.0/24
        <span class="keyword">set</span> dst 0.0.0.0/0
        <span class="keyword">set</span> protocol 0  <span class="comment"># All protocols</span>
        <span class="keyword">set</span> gateway 198.51.100.1
        <span class="keyword">set</span> output-device "port2"
        <span class="keyword">set</span> comments "Finance VLAN → ISP2"
    <span class="keyword">next</span>

    <span class="comment"># Route VoIP (RTP/SIP) via low-latency ISP</span>
    <span class="keyword">edit</span> 2
        <span class="keyword">set</span> input-device "VLAN20-Voice"
        <span class="keyword">set</span> src 10.20.0.0/24
        <span class="keyword">set</span> dst 0.0.0.0/0
        <span class="keyword">set</span> protocol 17  <span class="comment"># UDP (used by RTP)</span>
        <span class="keyword">set</span> start-port 16384
        <span class="keyword">set</span> end-port 32768
        <span class="keyword">set</span> gateway 203.0.113.1
        <span class="keyword">set</span> output-device "port1"
        <span class="keyword">set</span> comments "VoIP RTP → Low-Latency ISP"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Verify policy routes</span>
<span class="command">get router info routing-table all | head</span>
<span class="command">diagnose firewall proute list</span>
<span class="command">diagnose ip router policy list</span></code></pre>
</div>

<div class="callout warning">
    <div class="callout-title">⚠️ Policy Route Pitfalls</div>
    <p>• Policy routes are matched <strong>before NAT</strong> — use pre-NAT source IPs<br>
    • Policy routes <strong>bypass SD-WAN rules</strong> — they are mutually exclusive with SD-WAN on same traffic<br>
    • Always have a <strong>return path</strong> — if you policy-route outbound, ensure return traffic uses same ISP<br>
    • Policy routes don't appear in the routing table display — use <code>diagnose firewall proute list</code></p>
</div>
`;

KB.content['fg-bgp'] = `
<h1><span class="h1-icon">🌍</span> BGP (Border Gateway Protocol)</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>BGP is the routing protocol of the internet. FortiGate supports both <strong>eBGP</strong> (peering with ISPs, upstream routers) and <strong>iBGP</strong> (peering within your AS for route reflection). BGP is used when you need dynamic route exchange with ISPs, for multi-homing, or for SD-WAN overlay control.</p>
</div>

<div class="gui-path">Network <span class="gui-sep">›</span> BGP</div>

<h2 id="bgp-config">BGP Configuration</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — BGP eBGP Peering with ISP</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> router bgp
    <span class="keyword">set</span> as 65001          <span class="comment"># Your AS number</span>
    <span class="keyword">set</span> router-id 10.255.255.1
    <span class="keyword">set</span> ibgp-multipath enable
    <span class="keyword">set</span> ebgp-multipath enable
    <span class="keyword">set</span> graceful-restart enable

    <span class="keyword">config</span> neighbor
        <span class="keyword">edit</span> "203.0.113.1"
            <span class="keyword">set</span> remote-as 64512       <span class="comment"># ISP AS number</span>
            <span class="keyword">set</span> description "ISP1-BGP-Peer"
            <span class="keyword">set</span> ebgp-multihop-ttl 2
            <span class="keyword">set</span> next-hop-self enable   <span class="comment"># For iBGP redistribution</span>
            <span class="keyword">set</span> password <span class="string">"BgpAuth!Key"</span>  <span class="comment"># MD5 authentication</span>
            <span class="keyword">set</span> soft-reconfiguration enable
            <span class="keyword">set</span> route-map-in "ISP1-IN"
            <span class="keyword">set</span> route-map-out "ISP1-OUT"
        <span class="keyword">next</span>
    <span class="keyword">end</span>

    <span class="keyword">config</span> network
        <span class="keyword">edit</span> 1
            <span class="keyword">set</span> prefix 10.0.0.0/8    <span class="comment"># Advertise your prefix</span>
        <span class="keyword">next</span>
    <span class="keyword">end</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="bgp-diagnostics">BGP Diagnostics</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — BGP Monitoring</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># BGP summary (neighbors and state)</span>
<span class="command">get router info bgp summary</span>

<span class="comment"># BGP neighbors detail</span>
<span class="command">get router info bgp neighbors</span>
<span class="command">get router info bgp neighbors 203.0.113.1 detail</span>

<span class="comment"># BGP routing table</span>
<span class="command">get router info bgp table</span>

<span class="comment"># Routes received from peer</span>
<span class="command">get router info bgp neighbors 203.0.113.1 received-routes</span>

<span class="comment"># Routes advertised to peer</span>
<span class="command">get router info bgp neighbors 203.0.113.1 advertised-routes</span>

<span class="comment"># Clear BGP session (soft reset)</span>
<span class="command">execute router clear bgp all soft</span>
<span class="command">execute router clear bgp neighbor 203.0.113.1 soft</span>

<span class="comment"># BGP debug</span>
<span class="command">diagnose ip router bgp level info</span>
<span class="command">diagnose ip router bgp all enable</span>
<span class="command">diagnose debug enable</span></code></pre>
</div>
`;

KB.content['fg-ospf'] = `
<h1><span class="h1-icon">🔗</span> OSPF (Open Shortest Path First)</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>OSPF is a link-state IGP (Interior Gateway Protocol) used for internal network routing. FortiGate supports OSPFv2 (IPv4) and OSPFv3 (IPv6). OSPF is ideal for enterprise campus networks where you need fast convergence and automatic routing updates.</p>
</div>

<div class="gui-path">Network <span class="gui-sep">›</span> OSPF</div>

<div class="code-block">
    <div class="code-header"><span>CLI — OSPF Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> router ospf
    <span class="keyword">set</span> router-id 10.255.255.1
    <span class="keyword">set</span> auto-cost-ref-bandwidth 10000  <span class="comment"># 10 Gbps reference for cost calc</span>
    <span class="keyword">set</span> default-information-originate always  <span class="comment"># Originate default route</span>
    <span class="keyword">set</span> default-metric 10

    <span class="keyword">config</span> area
        <span class="keyword">edit</span> "0.0.0.0"    <span class="comment"># Backbone area</span>
            <span class="keyword">set</span> type regular
        <span class="keyword">next</span>
        <span class="keyword">edit</span> "0.0.0.1"    <span class="comment"># Stub area</span>
            <span class="keyword">set</span> type stub
            <span class="keyword">set</span> stub-type no-summary
        <span class="keyword">next</span>
    <span class="keyword">end</span>

    <span class="keyword">config</span> ospf-interface
        <span class="keyword">edit</span> "core-link"
            <span class="keyword">set</span> interface "port3"
            <span class="keyword">set</span> area "0.0.0.0"
            <span class="keyword">set</span> cost 10
            <span class="keyword">set</span> hello-interval 10
            <span class="keyword">set</span> dead-interval 40
            <span class="keyword">set</span> network-type point-to-point
            <span class="keyword">set</span> md5-key 1 <span class="string">"OspfKey!2024"</span>
        <span class="keyword">next</span>
    <span class="keyword">end</span>

    <span class="keyword">config</span> network
        <span class="keyword">edit</span> 1
            <span class="keyword">set</span> prefix 10.0.0.0/24
            <span class="keyword">set</span> area "0.0.0.0"
        <span class="keyword">next</span>
    <span class="keyword">end</span>
<span class="keyword">end</span>

<span class="comment"># OSPF diagnostics</span>
<span class="command">get router info ospf status</span>
<span class="command">get router info ospf neighbor</span>
<span class="command">get router info ospf database</span>
<span class="command">get router info ospf interface</span>
<span class="command">diagnose ip router ospf all enable</span></code></pre>
</div>
`;

KB.content['fg-sdwan'] = `
<h1><span class="h1-icon">📶</span> SD-WAN</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>FortiGate SD-WAN is an intelligent WAN management feature that dynamically routes traffic across multiple WAN links based on real-time link quality metrics: latency, jitter, packet loss, and bandwidth utilization. It replaces static failover with <strong>application-aware, SLA-driven path selection</strong>.</p>
</div>

<div class="gui-path">Network <span class="gui-sep">›</span> SD-WAN</div>

<h2 id="sdwan-components">SD-WAN Components</h2>

<div class="mermaid-wrapper">
<div class="mermaid">
graph TD
    A["SD-WAN Zone"] --> B["Members<br/>(WAN Interfaces)"]
    A --> C["Performance SLA<br/>(Health Checks)"]
    A --> D["SD-WAN Rules<br/>(Traffic Steering)"]
    B --> B1["ISP1 - port1"]
    B --> B2["ISP2 - port2"]
    B --> B3["MPLS - port3"]
    C --> C1["Latency Target"]
    C --> C2["Jitter Target"]
    C --> C3["Packet Loss %"]
    D --> D1["VoIP → Low Latency ISP"]
    D --> D2["Video → High BW ISP"]
    D --> D3["All Other → ECMP"]
    style A fill:#1e293b,color:#e2e8f0
    style D1 fill:#10b981,color:#fff
    style D2 fill:#3b82f6,color:#fff
</div>
<div class="mermaid-caption">SD-WAN Architecture — Components and Traffic Flow</div>
</div>

<h2 id="sdwan-config">Configuration</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — SD-WAN Complete Setup</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> system sdwan
    <span class="keyword">set</span> status enable

    <span class="comment"># === ZONE ===</span>
    <span class="keyword">config</span> zone
        <span class="keyword">edit</span> "virtual-wan-link"
        <span class="keyword">next</span>
    <span class="keyword">end</span>

    <span class="comment"># === MEMBERS (WAN interfaces) ===</span>
    <span class="keyword">config</span> members
        <span class="keyword">edit</span> 1
            <span class="keyword">set</span> interface "port1"
            <span class="keyword">set</span> zone "virtual-wan-link"
            <span class="keyword">set</span> gateway 203.0.113.1
            <span class="keyword">set</span> priority 10          <span class="comment"># Lower = preferred</span>
            <span class="keyword">set</span> cost 0
            <span class="keyword">set</span> volume-ratio 50      <span class="comment"># 50% of ECMP traffic</span>
        <span class="keyword">next</span>
        <span class="keyword">edit</span> 2
            <span class="keyword">set</span> interface "port2"
            <span class="keyword">set</span> zone "virtual-wan-link"
            <span class="keyword">set</span> gateway 198.51.100.1
            <span class="keyword">set</span> priority 10
            <span class="keyword">set</span> volume-ratio 50
        <span class="keyword">next</span>
        <span class="keyword">edit</span> 3
            <span class="keyword">set</span> interface "port3"   <span class="comment"># MPLS</span>
            <span class="keyword">set</span> zone "virtual-wan-link"
            <span class="keyword">set</span> priority 20         <span class="comment"># Lower priority (backup)</span>
        <span class="keyword">next</span>
    <span class="keyword">end</span>

    <span class="comment"># === PERFORMANCE SLA (Health Checks) ===</span>
    <span class="keyword">config</span> health-check
        <span class="keyword">edit</span> "Internet-SLA"
            <span class="keyword">set</span> server "8.8.8.8" "1.1.1.1"
            <span class="keyword">set</span> protocol ping
            <span class="keyword">set</span> interval 500       <span class="comment"># ms between probes</span>
            <span class="keyword">set</span> failtime 3          <span class="comment"># failures to mark member down</span>
            <span class="keyword">set</span> recoverytime 3      <span class="comment"># successes to mark member up</span>
            <span class="keyword">set</span> members 1 2 3
            <span class="keyword">config</span> sla
                <span class="keyword">edit</span> 1
                    <span class="keyword">set</span> latency-threshold 100   <span class="comment"># ms</span>
                    <span class="keyword">set</span> jitter-threshold 20     <span class="comment"># ms</span>
                    <span class="keyword">set</span> packetloss-threshold 1  <span class="comment"># percent</span>
                <span class="keyword">next</span>
            <span class="keyword">end</span>
        <span class="keyword">next</span>
        <span class="keyword">edit</span> "VoIP-SLA"
            <span class="keyword">set</span> server "voip-provider.com"
            <span class="keyword">set</span> protocol udp-echo
            <span class="keyword">set</span> port 5060
            <span class="keyword">set</span> interval 300
            <span class="keyword">set</span> members 1 2
            <span class="keyword">config</span> sla
                <span class="keyword">edit</span> 1
                    <span class="keyword">set</span> latency-threshold 50
                    <span class="keyword">set</span> jitter-threshold 10
                    <span class="keyword">set</span> packetloss-threshold 0.5
                <span class="keyword">next</span>
            <span class="keyword">end</span>
        <span class="keyword">next</span>
    <span class="keyword">end</span>

    <span class="comment"># === SD-WAN RULES (Traffic Steering) ===</span>
    <span class="keyword">config</span> service
        <span class="comment"># Rule 1: Route VoIP via best-quality link</span>
        <span class="keyword">edit</span> 1
            <span class="keyword">set</span> name "VoIP-Quality"
            <span class="keyword">set</span> mode sla                <span class="comment"># SLA-based selection</span>
            <span class="keyword">set</span> protocol 17
            <span class="keyword">set</span> start-port 5060
            <span class="keyword">set</span> end-port 5061
            <span class="keyword">set</span> src "all"
            <span class="keyword">set</span> health-check "VoIP-SLA"
            <span class="keyword">config</span> sla
                <span class="keyword">edit</span> 1
                    <span class="keyword">set</span> health-check "VoIP-SLA"
                    <span class="keyword">set</span> id 1
                <span class="keyword">next</span>
            <span class="keyword">end</span>
            <span class="keyword">config</span> priority-members
                <span class="keyword">edit</span> 1
                    <span class="keyword">set</span> seq-num 1  <span class="comment"># ISP1 preferred</span>
                <span class="keyword">next</span>
                <span class="keyword">edit</span> 2
                    <span class="keyword">set</span> seq-num 2  <span class="comment"># ISP2 backup</span>
                <span class="keyword">next</span>
            <span class="keyword">end</span>
        <span class="keyword">next</span>

        <span class="comment"># Rule 2: Balanced internet traffic (ECMP)</span>
        <span class="keyword">edit</span> 2
            <span class="keyword">set</span> name "General-Internet"
            <span class="keyword">set</span> mode load-balance
            <span class="keyword">set</span> load-balance-mode volume-based
            <span class="keyword">set</span> src "all"
            <span class="keyword">set</span> health-check "Internet-SLA"
            <span class="keyword">config</span> priority-members
                <span class="keyword">edit</span> 1
                    <span class="keyword">set</span> seq-num 1
                <span class="keyword">next</span>
                <span class="keyword">edit</span> 2
                    <span class="keyword">set</span> seq-num 2
                <span class="keyword">next</span>
            <span class="keyword">end</span>
        <span class="keyword">next</span>
    <span class="keyword">end</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="sdwan-monitor">Monitoring & Diagnostics</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — SD-WAN Monitoring</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># SD-WAN member status and metrics</span>
<span class="command">diagnose sys sdwan health-check status</span>

<span class="comment"># SD-WAN rule matching</span>
<span class="command">diagnose sys sdwan service</span>

<span class="comment"># Detailed per-member statistics</span>
<span class="command">diagnose sys sdwan member</span>

<span class="comment"># SD-WAN routing table</span>
<span class="command">get router info routing-table all | grep virtual</span>

<span class="comment"># Real-time SLA metrics</span>
<span class="command">diagnose sys sdwan intf-sla-log ISP1</span>

<span class="comment"># Session distribution across members</span>
<span class="command">diagnose firewall session-group list</span></code></pre>
</div>

<h2 id="sdwan-best-practices">Best Practices</h2>

<ul class="checklist">
    <li><span class="check checked">✓</span> Always configure Performance SLA health checks — SD-WAN without them is blind</li>
    <li><span class="check checked">✓</span> Use application-aware rules (Internet Service objects) instead of port-based rules</li>
    <li><span class="check checked">✓</span> Set appropriate SLA thresholds per application type (VoIP needs tighter jitter/latency than HTTP)</li>
    <li><span class="check checked">✓</span> Monitor SD-WAN health in FortiManager or FortiAnalyzer for historical trending</li>
    <li><span class="check checked">✓</span> Test failover manually — never assume it works in production</li>
    <li><span class="check checked">✓</span> Configure estimated bandwidth on members for accurate volume-based load balancing</li>
</ul>
`;

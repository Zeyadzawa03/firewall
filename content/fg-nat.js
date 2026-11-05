// ============================================================
// FortiGate NAT — Source NAT, Destination NAT, VIP, Central NAT, Hairpin
// ============================================================

KB.content['fg-nat'] = `
<h1><span class="h1-icon">🔄</span> NAT (Network Address Translation)</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>NAT translates IP addresses and ports as packets pass through the firewall. FortiGate supports multiple NAT methods: Source NAT for outbound traffic, Destination NAT (VIP) for inbound access to internal servers, Central NAT for centralized policy, and Hairpin NAT for internal-to-VIP access.</p>
</div>

<h2 id="nat-order">NAT Processing Order</h2>

<div class="mermaid-wrapper">
<div class="mermaid">
flowchart LR
    A["Packet In"] --> B["DNAT / VIP\n(Destination changes)"]
    B --> C["Policy Lookup\n(Uses post-DNAT dst)"]
    C --> D["SNAT\n(Source changes)"]
    D --> E["Packet Out"]
    style B fill:#3b82f6,color:#fff
    style D fill:#10b981,color:#fff
</div>
<div class="mermaid-caption">NAT Order: DNAT applied before policy lookup; SNAT applied after</div>
</div>

<h2 id="source-nat">Source NAT (SNAT)</h2>

<div class="callout info">
    <div class="callout-title">ℹ️ What Is SNAT</div>
    <p>Source NAT translates the <strong>source IP address</strong> of outgoing packets. Used when internal devices with private IPs need to access the internet. The firewall replaces the private source IP with a public IP.</p>
</div>

<h3 id="snat-types">SNAT Types</h3>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Type</th><th>How It Works</th><th>When to Use</th></tr>
</thead>
<tbody>
<tr><td><strong>Outgoing Interface IP</strong></td><td>All traffic appears to come from the interface's IP</td><td>Simple setups with single ISP IP</td></tr>
<tr><td><strong>IP Pool - Overload</strong></td><td>Many-to-one or many-to-few PAT (Port Address Translation)</td><td>Large LAN behind few public IPs</td></tr>
<tr><td><strong>IP Pool - One-to-One</strong></td><td>Each internal IP maps to a unique public IP</td><td>Servers needing consistent public IP</td></tr>
<tr><td><strong>IP Pool - Fixed Port Range</strong></td><td>Assigns specific port ranges per internal IP</td><td>Compliance, forensics, log tracing</td></tr>
<tr><td><strong>IP Pool - Port Block Allocation</strong></td><td>Pre-allocates port blocks per client</td><td>Carrier-grade NAT (CGNAT)</td></tr>
</tbody>
</table>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — IP Pool Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Overload pool (PAT)</span>
<span class="keyword">config</span> firewall ippool
    <span class="keyword">edit</span> "ISP1-Overload-Pool"
        <span class="keyword">set</span> type overload
        <span class="keyword">set</span> startip 203.0.113.10
        <span class="keyword">set</span> endip 203.0.113.20
        <span class="keyword">set</span> source-startip 0.0.0.0
        <span class="keyword">set</span> source-endip 0.0.0.0
        <span class="keyword">set</span> arp-reply enable
        <span class="keyword">set</span> comments "ISP1 public IPs for SNAT"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># One-to-one pool</span>
<span class="keyword">config</span> firewall ippool
    <span class="keyword">edit</span> "Server-1to1-Pool"
        <span class="keyword">set</span> type one-to-one
        <span class="keyword">set</span> startip 203.0.113.50
        <span class="keyword">set</span> endip 203.0.113.59
        <span class="keyword">set</span> comments "1-to-1 NAT for server farm"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Use pool in policy</span>
<span class="keyword">config</span> firewall policy
    <span class="keyword">edit</span> 1
        <span class="keyword">set</span> nat enable
        <span class="keyword">set</span> ippool enable
        <span class="keyword">set</span> poolname "ISP1-Overload-Pool"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="destination-nat">Destination NAT (DNAT) — Virtual IPs</h2>

<div class="callout info">
    <div class="callout-title">ℹ️ What Is DNAT</div>
    <p>Destination NAT (implemented via <strong>Virtual IPs / VIPs</strong>) translates the <strong>destination IP</strong> of incoming packets. Used to publish internal servers to the internet: the firewall receives traffic on a public IP and forwards it to an internal server.</p>
</div>

<div class="callout warning">
    <div class="callout-title">⚠️ Critical: VIP in Policy</div>
    <p>When using a VIP, you <strong>MUST</strong> reference the VIP object in the firewall policy destination. DO NOT use the real server IP. The VIP replaces the external IP before policy lookup — the policy sees the VIP, not the real server.</p>
</div>

<h3 id="vip-types">VIP Types</h3>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Type</th><th>Translation</th><th>Use Case</th></tr>
</thead>
<tbody>
<tr><td><strong>Static NAT</strong></td><td>External IP → Internal IP (all ports)</td><td>Full server exposure</td></tr>
<tr><td><strong>Port Forwarding</strong></td><td>External IP:Port → Internal IP:Port</td><td>Expose specific services only (recommended)</td></tr>
<tr><td><strong>Load Balance</strong></td><td>External IP → Multiple internal IPs</td><td>Built-in server load balancing</td></tr>
<tr><td><strong>Server Load Balance (Full NAT)</strong></td><td>Full SNAT+DNAT for server health monitoring</td><td>Enterprise server farms</td></tr>
</tbody>
</table>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — VIP Configuration Examples</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># ===== Static NAT VIP =====</span>
<span class="keyword">config</span> firewall vip
    <span class="keyword">edit</span> "Web-Server-VIP"
        <span class="keyword">set</span> type static-nat
        <span class="keyword">set</span> extip 203.0.113.10      <span class="comment"># Public IP</span>
        <span class="keyword">set</span> extintf "port1"          <span class="comment"># WAN interface</span>
        <span class="keyword">set</span> mappedip "10.10.50.10"   <span class="comment"># Internal server IP</span>
        <span class="keyword">set</span> arp-reply enable
        <span class="keyword">set</span> portforward disable
        <span class="keyword">set</span> comments "Web server static NAT"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># ===== Port Forwarding VIP (Recommended) =====</span>
<span class="keyword">config</span> firewall vip
    <span class="keyword">edit</span> "HTTPS-to-WebServer"
        <span class="keyword">set</span> type static-nat
        <span class="keyword">set</span> extip 203.0.113.10
        <span class="keyword">set</span> extintf "port1"
        <span class="keyword">set</span> mappedip "10.10.50.10"
        <span class="keyword">set</span> portforward enable
        <span class="keyword">set</span> protocol tcp
        <span class="keyword">set</span> extport 443
        <span class="keyword">set</span> mappedport 443
        <span class="keyword">set</span> nat-source-vip enable  <span class="comment"># Required for session tracking</span>
        <span class="keyword">set</span> comments "HTTPS only to web server"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># ===== Load Balancing VIP =====</span>
<span class="keyword">config</span> firewall vip
    <span class="keyword">edit</span> "LB-WebFarm"
        <span class="keyword">set</span> type loadbalance
        <span class="keyword">set</span> extip 203.0.113.20
        <span class="keyword">set</span> extintf "port1"
        <span class="keyword">set</span> ldb-method round-robin  <span class="comment"># round-robin | least-session | source | hash</span>
        <span class="keyword">set</span> portforward enable
        <span class="keyword">set</span> protocol tcp
        <span class="keyword">set</span> extport 443
        <span class="keyword">set</span> mappedport 443
        <span class="keyword">set</span> monitor "http-monitor"
        <span class="keyword">config</span> realservers
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> ip 10.10.50.11
                <span class="keyword">set</span> port 443
                <span class="keyword">set</span> max-connections 1000
                <span class="keyword">set</span> weight 10
            <span class="keyword">next</span>
            <span class="keyword">edit</span> 2
                <span class="keyword">set</span> ip 10.10.50.12
                <span class="keyword">set</span> port 443
                <span class="keyword">set</span> max-connections 1000
                <span class="keyword">set</span> weight 10
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Policy to allow inbound access to VIP</span>
<span class="keyword">config</span> firewall policy
    <span class="keyword">edit</span> 100
        <span class="keyword">set</span> name "Inbound-HTTPS-to-WebServer"
        <span class="keyword">set</span> srcintf "WAN-Zone"
        <span class="keyword">set</span> dstintf "DMZ-Zone"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "HTTPS-to-WebServer"  <span class="comment"># VIP object!</span>
        <span class="keyword">set</span> service "HTTPS"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> utm-status enable
        <span class="keyword">set</span> ips-sensor "DMZ-IPS-Profile"
        <span class="keyword">set</span> ssl-ssh-profile "deep-inspection"
        <span class="keyword">set</span> logtraffic all
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="central-nat">Central NAT</h2>

<div class="callout info">
    <div class="callout-title">ℹ️ What Is Central NAT</div>
    <p>Central NAT moves NAT configuration out of individual firewall policies into a <strong>dedicated NAT table</strong>. This provides a centralized view of all NAT rules and allows NAT changes without touching firewall policies. Available in FortiOS 6.4+.</p>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Enable Central NAT</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Enable Central NAT (cannot coexist with policy-based NAT)</span>
<span class="keyword">config</span> system settings
    <span class="keyword">set</span> central-nat enable
<span class="keyword">end</span>

<span class="comment"># Central SNAT rule</span>
<span class="keyword">config</span> firewall central-snat-map
    <span class="keyword">edit</span> 1
        <span class="keyword">set</span> srcintf "VLAN10-HR"
        <span class="keyword">set</span> dstintf "WAN-Zone"
        <span class="keyword">set</span> orig-addr "HR-Subnet"
        <span class="keyword">set</span> dst-addr "all"
        <span class="keyword">set</span> protocol 0
        <span class="keyword">set</span> nat enable
        <span class="keyword">set</span> nat-ippool "ISP1-Pool"
        <span class="keyword">set</span> comments "HR outbound SNAT"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Central DNAT rule</span>
<span class="keyword">config</span> firewall central-dnat
    <span class="keyword">edit</span> 1
        <span class="keyword">set</span> name "WebServer-DNAT"
        <span class="keyword">set</span> type dnat
        <span class="keyword">set</span> orig-addr "WebServer-VIP-External"
        <span class="keyword">set</span> mapped-addr "WebServer-Internal"
        <span class="keyword">set</span> protocol tcp
        <span class="keyword">set</span> orig-port 443
        <span class="keyword">set</span> mapped-port 443
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="hairpin-nat">Hairpin NAT (NAT Reflection)</h2>

<div class="callout info">
    <div class="callout-title">ℹ️ What Is Hairpin NAT</div>
    <p>Hairpin NAT (also called NAT reflection or NAT loopback) solves a specific problem: when internal clients try to reach an internal server using its <strong>external/public IP</strong> (the VIP). Without hairpin NAT, this traffic would fail because the response would go directly to the internal client, bypassing the firewall.</p>
</div>

<div class="mermaid-wrapper">
<div class="mermaid">
flowchart TD
    C["Internal Client\n10.0.0.100"] -->|"DNS: server.com → 203.0.113.10\nConnect to 203.0.113.10:443"| FW
    FW["FortiGate\nHairpin NAT"] -->|"DNAT: 203.0.113.10 → 10.10.50.10\nSNAT: 10.0.0.100 → FortiGate IP"| S["Web Server\n10.10.50.10"]
    S --> FW
    FW --> C
    style FW fill:#1e293b,color:#e2e8f0
    style C fill:#3b82f6,color:#fff
    style S fill:#10b981,color:#fff
</div>
<div class="mermaid-caption">Hairpin NAT — Internal traffic via public VIP</div>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Hairpin NAT Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Step 1: VIP already configured (WebServer-VIP)</span>

<span class="comment"># Step 2: Create hairpin policy (LAN → LAN, dst = VIP)</span>
<span class="keyword">config</span> firewall policy
    <span class="keyword">edit</span> 200
        <span class="keyword">set</span> name "Hairpin-LAN-to-WebServer"
        <span class="keyword">set</span> srcintf "LAN-Zone"
        <span class="keyword">set</span> dstintf "LAN-Zone"    <span class="comment"># Same zone! Traffic stays internal</span>
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "HTTPS-to-WebServer"  <span class="comment"># VIP object</span>
        <span class="keyword">set</span> service "HTTPS"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> nat enable            <span class="comment"># REQUIRED! SNAT to FortiGate IP</span>
        <span class="keyword">set</span> comments "Hairpin NAT - internal clients to VIP"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<div class="callout warning">
    <div class="callout-title">⚠️ Hairpin NAT Limitation</div>
    <p>With hairpin NAT enabled (NAT = yes on the policy), the server sees the FortiGate's IP as the source of all connections, not the real client IP. This breaks server-side logging and access control by IP. Consider using <strong>split-horizon DNS</strong> instead: configure your internal DNS to return the server's private IP for its FQDN.</p>
</div>

<h2 id="nat-diagnostics">NAT Diagnostics</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — NAT Diagnostics</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># View NAT table (active SNAT translations)</span>
<span class="command">diagnose sys session list | grep -A10 "proto_state"</span>

<span class="comment"># Check IP pool utilization</span>
<span class="command">diagnose firewall ippool list</span>
<span class="command">diagnose firewall ippool-usage</span>

<span class="comment"># VIP list and match</span>
<span class="command">diagnose firewall vip list</span>

<span class="comment"># Test NAT translation</span>
<span class="command">diagnose firewall iprope lookup 10.0.0.100 8.8.8.8 6 0 80</span>

<span class="comment"># Central NAT table</span>
<span class="command">diagnose firewall central-nat list</span></code></pre>
</div>
`;

KB.content['fg-vip'] = `
<h1><span class="h1-icon">🔄</span> Virtual IPs (VIP) & VIP Groups</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ Overview</div>
    <p>VIPs are the FortiGate implementation of Destination NAT. A VIP object maps an external IP/port to an internal server IP/port. VIP Groups bundle multiple VIPs for policy simplification. They are essential for any inbound service publication.</p>
</div>

<div class="gui-path">Policy &amp; Objects <span class="gui-sep">›</span> Virtual IPs</div>

<h2 id="vip-group">VIP Groups</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — VIP Group</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> firewall vipgrp
    <span class="keyword">edit</span> "DMZ-Servers-VIPs"
        <span class="keyword">set</span> interface "port1"
        <span class="keyword">set</span> member "HTTPS-to-WebServer" "SMTP-to-MailServer" "SSH-to-BastionHost"
        <span class="keyword">set</span> comments "All published DMZ services"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="vip-best-practices">VIP Best Practices</h2>

<ul class="checklist">
    <li><span class="check checked">✓</span> Always use port forwarding VIPs — limit exposure to specific ports only</li>
    <li><span class="check checked">✓</span> Apply IPS + SSL Inspection profiles to all inbound VIP policies</li>
    <li><span class="check checked">✓</span> Never publish unnecessary services — disable management protocols</li>
    <li><span class="check checked">✓</span> Use VIP groups for policies covering multiple published services</li>
    <li><span class="check checked">✓</span> Enable ARP reply on VIPs so FortiGate answers ARP for public IPs</li>
    <li><span class="check checked">✓</span> Log all inbound traffic to VIPs — critical for incident response</li>
    <li><span class="check checked">✓</span> Consider split-horizon DNS to avoid hairpin NAT complexity</li>
</ul>
`;

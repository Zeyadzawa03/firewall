// ============================================================
// FortiGate VPN — SSL VPN & IPSec VPN
// ============================================================

KB.content['fg-ssl-vpn'] = `
<h1><span class="h1-icon">🔒</span> SSL VPN</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>SSL VPN provides remote access to corporate resources over HTTPS (TLS 1.2/1.3). Users connect via a web browser (web mode) or a FortiClient agent (tunnel mode). It's the most common remote access solution for enterprise users because it works through firewalls and proxies without needing special ports.</p>
</div>

<div class="gui-path">VPN <span class="gui-sep">›</span> SSL-VPN Settings</div>
<div class="gui-path">VPN <span class="gui-sep">›</span> SSL-VPN Portals</div>

<h2 id="ssl-vpn-modes">Access Modes</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Mode</th><th>How It Works</th><th>Client Needed</th><th>Network Access</th></tr>
</thead>
<tbody>
<tr><td><strong>Web Mode</strong></td><td>Browser-based portal. Reverse proxy for web apps, RDP, SSH</td><td>Just a browser</td><td>Limited — only web applications</td></tr>
<tr><td><strong>Tunnel Mode</strong></td><td>Virtual NIC on client. Full IP-layer tunnel</td><td>FortiClient required</td><td>Full network access (like being on LAN)</td></tr>
<tr><td><strong>Split Tunnel</strong></td><td>Only corporate traffic goes through VPN; internet direct</td><td>FortiClient</td><td>Corporate subnets via VPN, internet direct</td></tr>
<tr><td><strong>Full Tunnel</strong></td><td>ALL traffic through VPN (internet too)</td><td>FortiClient</td><td>All traffic via corporate</td></tr>
</tbody>
</table>
</div>

<h2 id="ssl-vpn-config">Configuration</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — SSL VPN Complete Setup</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># ===== PORTAL CONFIGURATION =====</span>
<span class="keyword">config</span> vpn ssl web portal
    <span class="keyword">edit</span> "Corporate-Portal"
        <span class="keyword">set</span> tunnel-mode enable
        <span class="keyword">set</span> web-mode enable
        <span class="keyword">set</span> ip-mode range
        <span class="keyword">set</span> split-tunneling enable         <span class="comment"># Split tunnel — only corporate routes</span>
        <span class="keyword">set</span> split-tunneling-routing-address "Internal-Networks"
        <span class="keyword">set</span> ipv4-start-ip 10.100.0.10
        <span class="keyword">set</span> ipv4-end-ip 10.100.0.200
        <span class="keyword">set</span> ipv4-netmask 255.255.255.0
        <span class="keyword">set</span> dns-server1 10.0.0.10
        <span class="keyword">set</span> dns-server2 10.0.0.11
        <span class="keyword">set</span> dns-suffix "corp.local"
        <span class="keyword">set</span> wins-server1 0.0.0.0
        <span class="keyword">set</span> keep-alive enable
        <span class="keyword">set</span> auto-connect enable          <span class="comment"># FortiClient auto-connects</span>
        <span class="keyword">set</span> save-password enable
        <span class="keyword">config</span> bookmark-group
            <span class="keyword">edit</span> "Internal-Tools"
                <span class="keyword">config</span> bookmarks
                    <span class="keyword">edit</span> "Intranet"
                        <span class="keyword">set</span> apptype http
                        <span class="keyword">set</span> url "http://intranet.corp.local"
                    <span class="keyword">next</span>
                    <span class="keyword">edit</span> "RDP-Jump"
                        <span class="keyword">set</span> apptype rdp
                        <span class="keyword">set</span> host "10.10.10.50"
                        <span class="keyword">set</span> port 3389
                    <span class="keyword">next</span>
                <span class="keyword">end</span>
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>

    <span class="keyword">edit</span> "Guest-Portal"
        <span class="keyword">set</span> web-mode enable
        <span class="keyword">set</span> tunnel-mode disable         <span class="comment"># Web mode only for guests</span>
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># ===== SSL VPN SETTINGS =====</span>
<span class="keyword">config</span> vpn ssl settings
    <span class="keyword">set</span> servercert "ssl-vpn-cert"    <span class="comment"># Must be trusted by clients!</span>
    <span class="keyword">set</span> tunnel-ip-pools "SSLVPN-IP-Pool"
    <span class="keyword">set</span> tunnel-ipv6-pools ""
    <span class="keyword">set</span> dns-server1 10.0.0.10
    <span class="keyword">set</span> dns-server2 10.0.0.11
    <span class="keyword">set</span> dns-suffix "corp.local"
    <span class="keyword">set</span> port 443
    <span class="keyword">set</span> dtls-tunnel enable           <span class="comment"># Faster UDP-based DTLS tunnel</span>
    <span class="keyword">set</span> reqclientcert disable        <span class="comment"># Enable for cert-based auth</span>
    <span class="keyword">set</span> idle-timeout 300
    <span class="keyword">set</span> auth-timeout 43200           <span class="comment"># 12 hours</span>
    <span class="keyword">set</span> login-attempt-limit 3
    <span class="keyword">set</span> login-block-time 60
    <span class="keyword">config</span> authentication-rule
        <span class="keyword">edit</span> 1
            <span class="keyword">set</span> groups "VPN-Users-AD"
            <span class="keyword">set</span> portal "Corporate-Portal"
            <span class="keyword">set</span> client-cert disable
        <span class="keyword">next</span>
        <span class="keyword">edit</span> 2
            <span class="keyword">set</span> groups "VPN-Guests"
            <span class="keyword">set</span> portal "Guest-Portal"
        <span class="keyword">next</span>
    <span class="keyword">end</span>
<span class="keyword">end</span>

<span class="comment"># ===== FIREWALL POLICY FOR SSL VPN =====</span>
<span class="keyword">config</span> firewall policy
    <span class="keyword">edit</span> 200
        <span class="keyword">set</span> name "SSLVPN-to-Internal"
        <span class="keyword">set</span> srcintf "ssl.root"           <span class="comment"># SSL VPN virtual interface</span>
        <span class="keyword">set</span> dstintf "LAN-Zone"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "SSLVPN-IP-Pool"     <span class="comment"># VPN client IP pool</span>
        <span class="keyword">set</span> dstaddr "Internal-Networks"
        <span class="keyword">set</span> service "ALL"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> groups "VPN-Users-AD"        <span class="comment"># Identity-based</span>
        <span class="keyword">set</span> utm-status enable
        <span class="keyword">set</span> ips-sensor "Corporate-IPS"
        <span class="keyword">set</span> logtraffic all
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="ssl-vpn-monitor">Monitoring</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — SSL VPN Monitoring</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Active SSL VPN sessions</span>
<span class="command">get vpn ssl monitor</span>

<span class="comment"># Detailed session info</span>
<span class="command">diagnose vpn ssl list</span>

<span class="comment"># SSL VPN statistics</span>
<span class="command">diagnose vpn ssl statistics</span>

<span class="comment"># Kill a specific session</span>
<span class="command">diagnose vpn ssl del-tunnel &lt;tunnel-id&gt;</span>

<span class="comment"># IP pool usage</span>
<span class="command">diagnose firewall ippool list</span></code></pre>
</div>

<h2 id="ssl-vpn-troubleshooting">Troubleshooting</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Problem</th><th>Cause</th><th>Solution</th></tr>
</thead>
<tbody>
<tr><td>Login page not accessible</td><td>Port blocked, certificate error</td><td>Check port 443 open on WAN, verify certificate</td></tr>
<tr><td>Authentication fails</td><td>LDAP/RADIUS unreachable, wrong group</td><td>Test LDAP: <code>diagnose test authserver ldap</code></td></tr>
<tr><td>Tunnel connects but no access</td><td>Missing firewall policy, wrong route</td><td>Check ssl.root policy, add routes</td></tr>
<tr><td>Slow speeds</td><td>Full tunnel routing all traffic</td><td>Enable split tunneling</td></tr>
<tr><td>Certificate warning</td><td>Self-signed cert or untrusted CA</td><td>Install proper cert or deploy CA to clients</td></tr>
<tr><td>FortiClient can't connect</td><td>DTLS blocked, proxy interference</td><td>Test with DTLS disabled: <code>set dtls-tunnel disable</code></td></tr>
</tbody>
</table>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — SSL VPN Debug</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># SSL VPN debug</span>
<span class="command">diagnose debug application sslvpn -1</span>
<span class="command">diagnose debug enable</span>

<span class="comment"># Test LDAP authentication</span>
<span class="command">diagnose test authserver ldap Corp-LDAP johndoe Password123</span>

<span class="comment"># Test RADIUS authentication</span>
<span class="command">diagnose test authserver radius Corp-RADIUS johndoe Password123</span>

<span class="comment"># SSL VPN log</span>
<span class="command">execute log filter category event</span>
<span class="command">execute log filter field subtype vpn</span>
<span class="command">execute log display</span></code></pre>
</div>
`;

KB.content['fg-ipsec-vpn'] = `
<h1><span class="h1-icon">🔐</span> IPSec VPN</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>IPSec VPN creates encrypted tunnels at the IP layer (Layer 3). Used for site-to-site connections (branch to HQ, multi-site enterprise, cloud connectivity) and remote access. FortiGate supports IKEv1 and IKEv2 for key exchange, with ESP encryption and AH/HMAC authentication.</p>
</div>

<div class="gui-path">VPN <span class="gui-sep">›</span> IPsec Tunnels</div>

<h2 id="ike-phases">IKE Phases Explained</h2>

<div class="mermaid-wrapper">
<div class="mermaid">
sequenceDiagram
    participant A as FortiGate A (Initiator)
    participant B as FortiGate B (Responder)

    Note over A,B: Phase 1 — IKE SA (Management Channel)
    A->>B: IKE_SA_INIT: DH Group, Encryption, Hash proposals
    B->>A: IKE_SA_INIT Response: Selected proposal + DH Public Key
    A->>B: IKE_AUTH: Identity + Certificate/PSK
    B->>A: IKE_AUTH Response: Authenticated + IKE SA Established

    Note over A,B: Phase 2 — Child SA (Data Tunnel)
    A->>B: CREATE_CHILD_SA: Traffic selectors (subnets), ESP proposals
    B->>A: CREATE_CHILD_SA Response: Child SA Established
    Note over A,B: IPSec Tunnel Active — Data flows encrypted
</div>
<div class="mermaid-caption">IKEv2 Exchange — Phase 1 (IKE SA) then Phase 2 (Child SA)</div>
</div>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Phase</th><th>Purpose</th><th>IKEv1 Name</th><th>IKEv2 Name</th></tr>
</thead>
<tbody>
<tr><td><strong>Phase 1</strong></td><td>Authenticate peers, establish encrypted management channel</td><td>Main Mode / Aggressive Mode</td><td>IKE_SA_INIT + IKE_AUTH</td></tr>
<tr><td><strong>Phase 2</strong></td><td>Negotiate IPSec SAs for actual data encryption</td><td>Quick Mode</td><td>CREATE_CHILD_SA</td></tr>
</tbody>
</table>
</div>

<h2 id="site-to-site">Site-to-Site IPSec VPN</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Site-to-Site IKEv2 VPN</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># ===== PHASE 1 (IKE SA) =====</span>
<span class="keyword">config</span> vpn ipsec phase1-interface
    <span class="keyword">edit</span> "VPN-HQ-to-Branch1"
        <span class="keyword">set</span> interface "port1"            <span class="comment"># WAN interface</span>
        <span class="keyword">set</span> ike-version 2                <span class="comment"># IKEv2 (preferred)</span>
        <span class="keyword">set</span> keylife 28800               <span class="comment"># seconds (8 hours)</span>
        <span class="keyword">set</span> peertype any
        <span class="keyword">set</span> remote-gw 198.51.100.10     <span class="comment"># Branch WAN IP</span>
        <span class="keyword">set</span> proposal aes256-sha256 aes256-sha512   <span class="comment"># Encryption-Hash</span>
        <span class="keyword">set</span> dhgrp 14 19 20              <span class="comment"># DH Group 14=2048bit, 19=ECP256, 20=ECP384</span>
        <span class="keyword">set</span> authmethod psk              <span class="comment"># Pre-shared key</span>
        <span class="keyword">set</span> psksecret <span class="string">"Str0ng!VPN-PSK-2024#"</span>
        <span class="keyword">set</span> dead-peer-detection enable  <span class="comment"># DPD for failover</span>
        <span class="keyword">set</span> dpd-retrycount 3
        <span class="keyword">set</span> dpd-retryinterval 20
        <span class="keyword">set</span> auto-negotiate enable
        <span class="keyword">set</span> net-device disable
        <span class="keyword">set</span> mode-cfg disable
        <span class="keyword">set</span> comments "HQ to Branch1 - 198.51.100.10"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># ===== PHASE 2 (IPSec SA) =====</span>
<span class="keyword">config</span> vpn ipsec phase2-interface
    <span class="keyword">edit</span> "VPN-HQ-to-Branch1-P2"
        <span class="keyword">set</span> phase1name "VPN-HQ-to-Branch1"
        <span class="keyword">set</span> proposal aes256-sha256 aes256gcm
        <span class="keyword">set</span> dhgrp 14 19              <span class="comment"># PFS DH group</span>
        <span class="keyword">set</span> pfs enable              <span class="comment"># Perfect Forward Secrecy</span>
        <span class="keyword">set</span> keylifeseconds 3600     <span class="comment"># 1 hour</span>
        <span class="keyword">set</span> src-subnet 10.0.0.0/8  <span class="comment"># HQ networks</span>
        <span class="keyword">set</span> dst-subnet 10.10.0.0/16 <span class="comment"># Branch networks</span>
        <span class="keyword">set</span> auto-negotiate enable
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># ===== ROUTE THROUGH VPN =====</span>
<span class="keyword">config</span> router static
    <span class="keyword">edit</span> 100
        <span class="keyword">set</span> dst 10.10.0.0/16
        <span class="keyword">set</span> device "VPN-HQ-to-Branch1"
        <span class="keyword">set</span> comment "Route to Branch1 via IPSec VPN"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># ===== FIREWALL POLICIES =====</span>
<span class="keyword">config</span> firewall policy
    <span class="comment"># HQ to Branch</span>
    <span class="keyword">edit</span> 300
        <span class="keyword">set</span> name "HQ-to-Branch1"
        <span class="keyword">set</span> srcintf "LAN-Zone"
        <span class="keyword">set</span> dstintf "VPN-HQ-to-Branch1"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "HQ-Networks"
        <span class="keyword">set</span> dstaddr "Branch1-Networks"
        <span class="keyword">set</span> service "ALL"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> logtraffic all
    <span class="keyword">next</span>

    <span class="comment"># Branch to HQ</span>
    <span class="keyword">edit</span> 301
        <span class="keyword">set</span> name "Branch1-to-HQ"
        <span class="keyword">set</span> srcintf "VPN-HQ-to-Branch1"
        <span class="keyword">set</span> dstintf "LAN-Zone"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "Branch1-Networks"
        <span class="keyword">set</span> dstaddr "HQ-Networks"
        <span class="keyword">set</span> service "ALL"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> logtraffic all
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="ipsec-monitoring">Monitoring & Diagnostics</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — IPSec Monitoring</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Tunnel status</span>
<span class="command">get vpn ipsec tunnel summary</span>
<span class="command">get vpn ipsec tunnel name VPN-HQ-to-Branch1</span>

<span class="comment"># Detailed tunnel information</span>
<span class="command">diagnose vpn tunnel list</span>
<span class="command">diagnose vpn tunnel list name VPN-HQ-to-Branch1</span>

<span class="comment"># IKE SA status</span>
<span class="command">diagnose vpn ike status</span>
<span class="command">diagnose vpn ike gateway list</span>

<span class="comment"># ESP SA status</span>
<span class="command">diagnose vpn ike ipcomp list</span>

<span class="comment"># Bring tunnel up manually</span>
<span class="command">diagnose vpn tunnel up VPN-HQ-to-Branch1</span>

<span class="comment"># Force DPD (test peer reachability)</span>
<span class="command">diagnose vpn ike dpd VPN-HQ-to-Branch1</span>

<span class="comment"># IKE debug</span>
<span class="command">diagnose debug application ike -1</span>
<span class="command">diagnose debug enable</span>
<span class="comment"># Check output, then:</span>
<span class="command">diagnose debug disable</span></code></pre>
</div>

<h2 id="ipsec-troubleshooting">Common IPSec Errors & Solutions</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Error / Symptom</th><th>Root Cause</th><th>Solution</th></tr>
</thead>
<tbody>
<tr><td>Phase 1 fails: "No proposal chosen"</td><td>Encryption/hash/DH group mismatch</td><td>Verify proposals match on both sides</td></tr>
<tr><td>Phase 1 fails: "Authentication failed"</td><td>PSK mismatch or cert issue</td><td>Verify PSK characters, check for spaces</td></tr>
<tr><td>Phase 2 fails: "No matching traffic"</td><td>Traffic selectors (subnets) mismatch</td><td>Ensure src-subnet/dst-subnet match both ends</td></tr>
<tr><td>Tunnel up but no traffic</td><td>Missing route, wrong policy, NAT interference</td><td>Check static routes, firewall policies, NAT exemption</td></tr>
<tr><td>Tunnel drops frequently</td><td>DPD misconfigured, flapping link, MTU issue</td><td>Check DPD settings, set MSS clamping</td></tr>
<tr><td>Asymmetric routing</td><td>Return traffic takes different path</td><td>Add static routes or policy routes</td></tr>
<tr><td>NAT-T issues</td><td>NAT device in path blocking ESP</td><td>Enable NAT-T (UDP 4500): <code>set nattraversal enable</code></td></tr>
</tbody>
</table>
</div>

<div class="callout tip">
    <div class="callout-title">💡 IKEv2 vs IKEv1</div>
    <p>Always use <strong>IKEv2</strong> for new deployments:<br>
    • Fewer round-trips (faster setup)<br>
    • Built-in NAT traversal<br>
    • Better mobility support (MOBIKE)<br>
    • More secure (no Aggressive Mode PSK hash exposure)<br>
    • Only use IKEv1 for legacy interoperability with old equipment</p>
</div>
`;

KB.content['fg-vpn-troubleshooting'] = `
<h1><span class="h1-icon">🔧</span> VPN Troubleshooting</h1>

<h2 id="vpn-debug-methodology">Debug Methodology</h2>

<div class="steps">
    <div class="step">
        <div class="step-title">Check Basic Connectivity</div>
        <p>Can the FortiGate reach the remote peer? <code>execute ping &lt;remote-peer-IP&gt;</code>. Check if UDP 500 and UDP 4500 are not blocked by upstream firewall.</p>
    </div>
    <div class="step">
        <div class="step-title">Check Phase 1</div>
        <p>Run <code>diagnose vpn ike status</code>. Look for established IKE SAs. If Phase 1 fails, run IKE debug: <code>diagnose debug application ike -1</code></p>
    </div>
    <div class="step">
        <div class="step-title">Check Phase 2</div>
        <p>Run <code>diagnose vpn tunnel list</code>. If Phase 1 is up but Phase 2 isn't, check traffic selectors (subnets) on both sides.</p>
    </div>
    <div class="step">
        <div class="step-title">Check Routes</div>
        <p><code>get router info routing-table all | grep &lt;remote-subnet&gt;</code>. The remote subnet must have a route pointing to the VPN tunnel interface.</p>
    </div>
    <div class="step">
        <div class="step-title">Check Firewall Policies</div>
        <p>Verify policies exist: LAN → VPN tunnel (for outbound) and VPN tunnel → LAN (for inbound). Both directions required.</p>
    </div>
    <div class="step">
        <div class="step-title">Check NAT Exemption</div>
        <p>If you have NAT policies, VPN traffic must be excluded. Check Central SNAT or policy-level NAT settings.</p>
    </div>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — VPN Comprehensive Debug</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Complete VPN diagnostic script</span>

<span class="comment"># 1. Tunnel summary</span>
<span class="command">get vpn ipsec tunnel summary</span>
<span class="command">get vpn ssl monitor</span>

<span class="comment"># 2. IKE debug (run, try to connect, then disable)</span>
<span class="command">diagnose debug reset</span>
<span class="command">diagnose debug application ike 255</span>
<span class="command">diagnose debug enable</span>
<span class="comment"># Trigger VPN connection</span>
<span class="command">diagnose vpn tunnel up VPN-HQ-to-Branch1</span>
<span class="comment"># Wait 30 seconds, then:</span>
<span class="command">diagnose debug disable</span>

<span class="comment"># 3. Route check</span>
<span class="command">get router info routing-table all | grep 10.10</span>

<span class="comment"># 4. Session check</span>
<span class="command">diagnose sys session filter daddr 10.10.0.0</span>
<span class="command">diagnose sys session list</span>

<span class="comment"># 5. Packet capture on VPN interface</span>
<span class="command">diagnose sniffer packet port1 "host 198.51.100.10 and (port 500 or port 4500)" 4 0</span></code></pre>
</div>
`;

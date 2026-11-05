// ============================================================
// FortiGate Real-World Enterprise Scenarios
// Complete end-to-end deployment scenarios with CLI configs,
// topology diagrams, and architectural decisions
// ============================================================

KB.content['fg-scenarios'] = `
<h1><span class="h1-icon">🏢</span> Real-World Enterprise Scenarios</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ How to Use This Section</div>
    <p>Each scenario is a complete, deployable configuration covering a specific enterprise use case. They are designed to be adapted to your environment. All IP ranges use RFC 5737 documentation addresses — replace them with your actual addressing before deployment.</p>
</div>

<div class="tabs">
    <div class="tab-buttons">
        <button class="tab-btn active" data-tab="dmz">DMZ Architecture</button>
        <button class="tab-btn" data-tab="vpn-hub">VPN Hub-and-Spoke</button>
        <button class="tab-btn" data-tab="segmentation">Network Segmentation</button>
        <button class="tab-btn" data-tab="ha">HA Deployment</button>
        <button class="tab-btn" data-tab="remote-access">Remote Access</button>
        <button class="tab-btn" data-tab="mssp">MSSP Multi-Tenant</button>
    </div>

    <div class="tab-content active" data-tab="dmz">
        <h2 id="dmz-scenario">Scenario 1: Enterprise DMZ with Published Services</h2>

        <div class="callout best-practice">
            <div class="callout-title">🎯 Scenario Overview</div>
            <p><strong>Use Case:</strong> A company needs to publish web, mail, and remote access services to the internet while keeping internal servers isolated.<br>
            <strong>Architecture:</strong> Three-interface FortiGate: WAN → DMZ → LAN<br>
            <strong>Goal:</strong> Publish HTTPS, SMTP, and SSH Bastion from DMZ; allow LAN to internet; block DMZ-to-LAN direct access</p>
        </div>

        <h3 id="dmz-topology">Topology</h3>

        <div class="mermaid-wrapper">
        <div class="mermaid">
graph LR
    INET["🌐 Internet"] -->|"203.0.113.x/30"| FW["FortiGate\nFG-DC1-FW01"]
    FW -->|"VLAN50 10.50.0.1/24"| DMZ["DMZ Zone\n10.50.0.0/24"]
    FW -->|"VLAN10 10.10.0.1/24"| LAN["LAN Zone\n10.10.0.0/22"]
    DMZ --> WEB["Web Server\n10.50.0.10"]
    DMZ --> MAIL["Mail Server\n10.50.0.20"]
    DMZ --> JUMP["Jump Server\n10.50.0.30"]
    style FW fill:#ee3124,color:#fff
    style DMZ fill:#1e293b,color:#e2e8f0
    style LAN fill:#1e293b,color:#e2e8f0
        </div>
        <div class="mermaid-caption">DMZ Architecture — Three-Zone FortiGate Design</div>
        </div>

        <h3>Interface Configuration</h3>
        <div class="code-block">
            <div class="code-header"><span>CLI — Interface Setup</span><button class="code-copy-btn">Copy</button></div>
            <pre><code><span class="comment"># WAN Interface (ISP)</span>
<span class="keyword">config</span> system interface
    <span class="keyword">edit</span> "port1"
        <span class="keyword">set</span> alias "WAN-ISP1"
        <span class="keyword">set</span> mode static
        <span class="keyword">set</span> ip 203.0.113.2/30
        <span class="keyword">set</span> allowaccess ping
        <span class="keyword">set</span> role wan
        <span class="keyword">set</span> description "Primary ISP - Provider XYZ"
    <span class="keyword">next</span>

    <span class="comment"># DMZ Interface — dedicated physical port or VLAN</span>
    <span class="keyword">edit</span> "VLAN50-DMZ"
        <span class="keyword">set</span> type vlan
        <span class="keyword">set</span> vlanid 50
        <span class="keyword">set</span> interface "port3"
        <span class="keyword">set</span> ip 10.50.0.1/24
        <span class="keyword">set</span> allowaccess ping https  <span class="comment"># HTTPS for management only</span>
        <span class="keyword">set</span> role dmz
        <span class="keyword">set</span> device-identification enable
        <span class="keyword">set</span> description "DMZ Segment"
    <span class="keyword">next</span>

    <span class="comment"># LAN Interface</span>
    <span class="keyword">edit</span> "VLAN10-LAN"
        <span class="keyword">set</span> type vlan
        <span class="keyword">set</span> vlanid 10
        <span class="keyword">set</span> interface "port3"
        <span class="keyword">set</span> ip 10.10.0.1/24
        <span class="keyword">set</span> allowaccess ping https ssh
        <span class="keyword">set</span> role lan
        <span class="keyword">set</span> device-identification enable
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
        </div>

        <h3>VIPs for Published Services</h3>
        <div class="code-block">
            <div class="code-header"><span>CLI — VIP Definitions</span><button class="code-copy-btn">Copy</button></div>
            <pre><code><span class="keyword">config</span> firewall vip
    <span class="comment"># HTTPS to web server (port-forward only port 443)</span>
    <span class="keyword">edit</span> "VIP-HTTPS-WebServer"
        <span class="keyword">set</span> type static-nat
        <span class="keyword">set</span> extip 203.0.113.2     <span class="comment"># Public IP (WAN IP itself, or additional IP)</span>
        <span class="keyword">set</span> extintf "port1"
        <span class="keyword">set</span> mappedip "10.50.0.10"
        <span class="keyword">set</span> portforward enable
        <span class="keyword">set</span> protocol tcp
        <span class="keyword">set</span> extport 443
        <span class="keyword">set</span> mappedport 443
        <span class="keyword">set</span> arp-reply enable
        <span class="keyword">set</span> comments "HTTPS to DMZ Web Server"
    <span class="keyword">next</span>

    <span class="comment"># SMTP to mail server</span>
    <span class="keyword">edit</span> "VIP-SMTP-MailServer"
        <span class="keyword">set</span> type static-nat
        <span class="keyword">set</span> extip 203.0.113.10    <span class="comment"># Additional public IP for mail</span>
        <span class="keyword">set</span> extintf "port1"
        <span class="keyword">set</span> mappedip "10.50.0.20"
        <span class="keyword">set</span> portforward enable
        <span class="keyword">set</span> protocol tcp
        <span class="keyword">set</span> extport 25
        <span class="keyword">set</span> mappedport 25
        <span class="keyword">set</span> arp-reply enable
        <span class="keyword">set</span> comments "SMTP inbound to mail relay"
    <span class="keyword">next</span>

    <span class="comment"># SSH Bastion (non-standard port for security)</span>
    <span class="keyword">edit</span> "VIP-SSH-Bastion"
        <span class="keyword">set</span> type static-nat
        <span class="keyword">set</span> extip 203.0.113.2
        <span class="keyword">set</span> extintf "port1"
        <span class="keyword">set</span> mappedip "10.50.0.30"
        <span class="keyword">set</span> portforward enable
        <span class="keyword">set</span> protocol tcp
        <span class="keyword">set</span> extport 2222           <span class="comment"># Non-standard SSH port</span>
        <span class="keyword">set</span> mappedport 22
        <span class="keyword">set</span> arp-reply enable
        <span class="keyword">set</span> comments "SSH bastion host"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
        </div>

        <h3>Firewall Policies</h3>
        <div class="code-block">
            <div class="code-header"><span>CLI — DMZ Policy Set (in order)</span><button class="code-copy-btn">Copy</button></div>
            <pre><code><span class="keyword">config</span> firewall policy
    <span class="comment"># ===== INBOUND: Internet → DMZ =====</span>

    <span class="comment"># Policy 1: Allow HTTPS to web server</span>
    <span class="keyword">edit</span> 1
        <span class="keyword">set</span> name "Inbound-HTTPS-WebServer"
        <span class="keyword">set</span> srcintf "port1"
        <span class="keyword">set</span> dstintf "VLAN50-DMZ"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "VIP-HTTPS-WebServer"
        <span class="keyword">set</span> service "HTTPS"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> utm-status enable
        <span class="keyword">set</span> ips-sensor "DMZ-IPS-Profile"
        <span class="keyword">set</span> ssl-ssh-profile "deep-inspection"
        <span class="keyword">set</span> av-profile "DMZ-AV"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "HTTPS inbound — IPS + SSL inspection"
    <span class="keyword">next</span>

    <span class="comment"># Policy 2: Allow SMTP inbound</span>
    <span class="keyword">edit</span> 2
        <span class="keyword">set</span> name "Inbound-SMTP-MailServer"
        <span class="keyword">set</span> srcintf "port1"
        <span class="keyword">set</span> dstintf "VLAN50-DMZ"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "VIP-SMTP-MailServer"
        <span class="keyword">set</span> service "SMTP"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> utm-status enable
        <span class="keyword">set</span> av-profile "DMZ-AV"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "SMTP relay inbound"
    <span class="keyword">next</span>

    <span class="comment"># Policy 3: SSH bastion (restricted source — your IP only)</span>
    <span class="keyword">edit</span> 3
        <span class="keyword">set</span> name "Inbound-SSH-Bastion"
        <span class="keyword">set</span> srcintf "port1"
        <span class="keyword">set</span> dstintf "VLAN50-DMZ"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "Admin-PublicIPs"   <span class="comment"># Restrict to known admin IPs</span>
        <span class="keyword">set</span> dstaddr "VIP-SSH-Bastion"
        <span class="keyword">set</span> service "SSH"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "SSH bastion — restricted to admin IPs"
    <span class="keyword">next</span>

    <span class="comment"># ===== DMZ → INTERNET (for updates, etc.) =====</span>

    <span class="comment"># Policy 4: Allow DMZ servers to reach internet (limited)</span>
    <span class="keyword">edit</span> 4
        <span class="keyword">set</span> name "DMZ-to-Internet-Updates"
        <span class="keyword">set</span> srcintf "VLAN50-DMZ"
        <span class="keyword">set</span> dstintf "port1"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "DMZ-Servers"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "HTTP" "HTTPS" "DNS"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> nat enable
        <span class="keyword">set</span> utm-status enable
        <span class="keyword">set</span> web-filter-profile "DMZ-WebFilter"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "DMZ outbound for updates only — web filtered"
    <span class="keyword">next</span>

    <span class="comment"># ===== LAN → INTERNET =====</span>

    <span class="comment"># Policy 5: LAN users internet access</span>
    <span class="keyword">edit</span> 5
        <span class="keyword">set</span> name "LAN-to-Internet"
        <span class="keyword">set</span> srcintf "VLAN10-LAN"
        <span class="keyword">set</span> dstintf "port1"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "HTTP" "HTTPS" "DNS" "SMTP" "SMTPS"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> nat enable
        <span class="keyword">set</span> utm-status enable
        <span class="keyword">set</span> profile-group "Corporate-UTM"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "Standard LAN internet access"
    <span class="keyword">next</span>

    <span class="comment"># ===== LAN → DMZ (admin access to servers) =====</span>

    <span class="comment"># Policy 6: IT admins can SSH/RDP to DMZ servers</span>
    <span class="keyword">edit</span> 6
        <span class="keyword">set</span> name "IT-to-DMZ-Admin"
        <span class="keyword">set</span> srcintf "VLAN10-LAN"
        <span class="keyword">set</span> dstintf "VLAN50-DMZ"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "IT-Admin-Subnet"
        <span class="keyword">set</span> dstaddr "DMZ-Servers"
        <span class="keyword">set</span> service "SSH" "RDP" "HTTPS"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "IT admin access to DMZ servers"
    <span class="keyword">next</span>

    <span class="comment"># ===== DMZ → LAN: BLOCKED (DMZ cannot initiate to LAN) =====</span>

    <span class="comment"># Policy 7: Explicit deny DMZ to LAN (with logging)</span>
    <span class="keyword">edit</span> 7
        <span class="keyword">set</span> name "DMZ-to-LAN-DENY"
        <span class="keyword">set</span> srcintf "VLAN50-DMZ"
        <span class="keyword">set</span> dstintf "VLAN10-LAN"
        <span class="keyword">set</span> action deny
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "ALL"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> logtraffic all         <span class="comment"># Log ALL deny — detect compromise</span>
        <span class="keyword">set</span> comments "DMZ cannot initiate to LAN — if logged, investigate immediately"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
        </div>

        <div class="callout danger">
            <div class="callout-title">🚨 Critical DMZ Rule</div>
            <p>Policy 7 (DMZ→LAN deny) must be <strong>above any allow-all or zone-allow policies</strong>. If a DMZ server is compromised, this prevents lateral movement into the LAN. Always log all DMZ-to-LAN denies and alert on them — any such traffic indicates a potential breach.</p>
        </div>
    </div>

    <div class="tab-content" data-tab="vpn-hub">
        <h2 id="vpn-hub-scenario">Scenario 2: VPN Hub-and-Spoke (HQ + Branch Offices)</h2>

        <div class="callout best-practice">
            <div class="callout-title">🎯 Scenario Overview</div>
            <p><strong>Use Case:</strong> Multi-site enterprise with HQ FortiGate serving as IPSec VPN hub. Branch offices have FortiGate spokes connecting back to HQ.<br>
            <strong>Architecture:</strong> IPSec with IKEv2, dynamic routing via OSPF over VPN tunnels<br>
            <strong>Goal:</strong> Branches access HQ resources and internet via hub; centralized security inspection</p>
        </div>

        <div class="mermaid-wrapper">
        <div class="mermaid">
graph TD
    HQ["HQ FortiGate\n(Hub)\n203.0.113.2"] -->|IPSec Tunnel| B1["Branch 1\n(Spoke)\n198.51.100.10"]
    HQ -->|IPSec Tunnel| B2["Branch 2\n(Spoke)\n198.51.100.20"]
    HQ -->|IPSec Tunnel| B3["Branch 3\n(Spoke)\n198.51.100.30"]
    HQ -->|"Direct"| INET["🌐 Internet"]
    B1 --> LAN1["Branch 1 LAN\n10.1.0.0/24"]
    B2 --> LAN2["Branch 2 LAN\n10.2.0.0/24"]
    B3 --> LAN3["Branch 3 LAN\n10.3.0.0/24"]
    HQ --> HQLAN["HQ LAN\n10.0.0.0/22"]
    style HQ fill:#ee3124,color:#fff
        </div>
        <div class="mermaid-caption">Hub-and-Spoke VPN — HQ as Central IPSec Hub</div>
        </div>

        <h3>HQ Hub Configuration</h3>
        <div class="code-block">
            <div class="code-header"><span>CLI — HQ Hub IPSec Phase 1 (Dynamic, accepts all spokes)</span><button class="code-copy-btn">Copy</button></div>
            <pre><code><span class="comment"># ===== HQ HUB: IPSec Phase 1 (accepts dynamic spoke connections) =====</span>
<span class="keyword">config</span> vpn ipsec phase1-interface
    <span class="keyword">edit</span> "HUB-VPN-P1"
        <span class="keyword">set</span> type dynamic          <span class="comment"># Accept any spoke IP</span>
        <span class="keyword">set</span> interface "port1"     <span class="comment"># WAN interface</span>
        <span class="keyword">set</span> ike-version 2
        <span class="keyword">set</span> peertype any
        <span class="keyword">set</span> mode-cfg enable        <span class="comment"># Push IP config to spokes</span>
        <span class="keyword">set</span> proposal aes256-sha256
        <span class="keyword">set</span> dhgrp 14 21            <span class="comment"># DH Groups 14 (2048-bit) and 21 (521-bit ECC)</span>
        <span class="keyword">set</span> psk "Hub-Spoke-PSK-2024!"
        <span class="keyword">set</span> dpd on-idle
        <span class="keyword">set</span> dpd-retrycount 3
        <span class="keyword">set</span> dpd-retryinterval 10
        <span class="keyword">set</span> comments "Hub-and-Spoke VPN Termination"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># ===== HQ HUB: IPSec Phase 2 =====</span>
<span class="keyword">config</span> vpn ipsec phase2-interface
    <span class="keyword">edit</span> "HUB-VPN-P2"
        <span class="keyword">set</span> phase1name "HUB-VPN-P1"
        <span class="keyword">set</span> proposal aes256gcm aes256-sha256
        <span class="keyword">set</span> pfs enable
        <span class="keyword">set</span> dhgrp 14 21
        <span class="keyword">set</span> replay enable
        <span class="keyword">set</span> auto-negotiate enable
        <span class="keyword">set</span> keylifeseconds 3600
        <span class="keyword">set</span> comments "Hub Phase 2"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
        </div>

        <div class="code-block">
            <div class="code-header"><span>CLI — Branch Spoke Configuration (repeat per branch with unique IDs)</span><button class="code-copy-btn">Copy</button></div>
            <pre><code><span class="comment"># ===== BRANCH SPOKE: Phase 1 =====</span>
<span class="keyword">config</span> vpn ipsec phase1-interface
    <span class="keyword">edit</span> "SPOKE-to-HUB-P1"
        <span class="keyword">set</span> type static          <span class="comment"># Spoke has fixed HQ IP as remote</span>
        <span class="keyword">set</span> interface "port1"
        <span class="keyword">set</span> ike-version 2
        <span class="keyword">set</span> peertype any
        <span class="keyword">set</span> remote-gw 203.0.113.2  <span class="comment"># HQ Hub WAN IP</span>
        <span class="keyword">set</span> mode-cfg enable
        <span class="keyword">set</span> proposal aes256-sha256
        <span class="keyword">set</span> dhgrp 14 21
        <span class="keyword">set</span> psk "Hub-Spoke-PSK-2024!"
        <span class="keyword">set</span> dpd on-idle
        <span class="keyword">set</span> dpd-retrycount 3
        <span class="keyword">set</span> add-route enable       <span class="comment"># Auto-add routes via VPN</span>
        <span class="keyword">set</span> comments "Spoke connection to HQ Hub"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># ===== OSPF over VPN (for dynamic routing) =====</span>
<span class="keyword">config</span> router ospf
    <span class="keyword">set</span> router-id 10.1.255.1     <span class="comment"># Unique per branch</span>
    <span class="keyword">set</span> default-information-originate enable
    <span class="keyword">config</span> ospf-interface
        <span class="keyword">edit</span> "SPOKE-to-HUB-P1"
            <span class="keyword">set</span> interface "SPOKE-to-HUB-P1"
            <span class="keyword">set</span> area "0.0.0.0"
            <span class="keyword">set</span> network-type point-to-point
            <span class="keyword">set</span> cost 10
        <span class="keyword">next</span>
        <span class="keyword">edit</span> "branch-lan"
            <span class="keyword">set</span> interface "LAN"
            <span class="keyword">set</span> area "0.0.0.0"
        <span class="keyword">next</span>
    <span class="keyword">end</span>
    <span class="keyword">config</span> network
        <span class="keyword">edit</span> 1
            <span class="keyword">set</span> prefix 10.1.0.0/24   <span class="comment"># This branch's LAN</span>
            <span class="keyword">set</span> area "0.0.0.0"
        <span class="keyword">next</span>
    <span class="keyword">end</span>
<span class="keyword">end</span></code></pre>
        </div>

        <div class="code-block">
            <div class="code-header"><span>CLI — VPN Policies (HQ Hub)</span><button class="code-copy-btn">Copy</button></div>
            <pre><code><span class="keyword">config</span> firewall policy
    <span class="comment"># Allow spokes to reach HQ LAN</span>
    <span class="keyword">edit</span> 10
        <span class="keyword">set</span> name "VPN-Spokes-to-HQ-LAN"
        <span class="keyword">set</span> srcintf "HUB-VPN-P1"
        <span class="keyword">set</span> dstintf "VLAN10-LAN"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "Branch-Networks"  <span class="comment"># 10.1.0.0/8 address group</span>
        <span class="keyword">set</span> dstaddr "HQ-LAN"
        <span class="keyword">set</span> service "ALL"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> utm-status enable
        <span class="keyword">set</span> ips-sensor "Branch-IPS"
        <span class="keyword">set</span> logtraffic all
    <span class="keyword">next</span>

    <span class="comment"># Allow spoke-to-spoke via hub (hairpin)</span>
    <span class="keyword">edit</span> 11
        <span class="keyword">set</span> name "VPN-Spoke-to-Spoke"
        <span class="keyword">set</span> srcintf "HUB-VPN-P1"
        <span class="keyword">set</span> dstintf "HUB-VPN-P1"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "Branch-Networks"
        <span class="keyword">set</span> dstaddr "Branch-Networks"
        <span class="keyword">set</span> service "ALL"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "Branch-to-branch via hub"
    <span class="keyword">next</span>

    <span class="comment"># Allow spokes to reach internet via HQ (centralized inspection)</span>
    <span class="keyword">edit</span> 12
        <span class="keyword">set</span> name "VPN-Spokes-Internet-via-HQ"
        <span class="keyword">set</span> srcintf "HUB-VPN-P1"
        <span class="keyword">set</span> dstintf "port1"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "Branch-Networks"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "HTTP" "HTTPS" "DNS"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> nat enable
        <span class="keyword">set</span> utm-status enable
        <span class="keyword">set</span> profile-group "Branch-UTM"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "Branch internet via HQ — centralized UTM"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
        </div>

        <div class="callout tip">
            <div class="callout-title">💡 Hub-and-Spoke Best Practice</div>
            <p>Route all branch internet traffic through the HQ hub for centralized UTM inspection. This increases bandwidth use at HQ but ensures consistent security policy enforcement across all sites. Use SD-WAN at each branch to balance between VPN and local breakout for trusted services like Microsoft 365.</p>
        </div>
    </div>

    <div class="tab-content" data-tab="segmentation">
        <h2 id="segmentation-scenario">Scenario 3: Enterprise Network Segmentation (8 VLANs)</h2>

        <div class="callout best-practice">
            <div class="callout-title">🎯 Scenario Overview</div>
            <p><strong>Use Case:</strong> Segment a flat corporate network into isolated VLANs for different departments and functions.<br>
            <strong>Architecture:</strong> FortiGate as inter-VLAN router with strict east-west policies<br>
            <strong>Goal:</strong> Users can only reach what they need; IoT devices cannot reach any IT infrastructure</p>
        </div>

        <h3>VLAN Design</h3>
        <div class="table-wrapper">
        <table>
        <thead>
        <tr><th>VLAN</th><th>Name</th><th>Subnet</th><th>Purpose</th><th>Internet</th><th>Cross-VLAN Access</th></tr>
        </thead>
        <tbody>
        <tr><td><strong>10</strong></td><td>Corporate-Users</td><td>10.10.0.0/22</td><td>Domain-joined workstations</td><td>✅ Filtered</td><td>Servers VLAN 20, Printers VLAN 60</td></tr>
        <tr><td><strong>20</strong></td><td>Servers</td><td>10.20.0.0/24</td><td>Application servers</td><td>✅ Limited</td><td>None initiated</td></tr>
        <tr><td><strong>30</strong></td><td>IT-Management</td><td>10.30.0.0/24</td><td>IT admin workstations</td><td>✅ Filtered</td><td>All VLANs (read-only rules)</td></tr>
        <tr><td><strong>40</strong></td><td>Guest-WiFi</td><td>10.40.0.0/24</td><td>Visitor wireless</td><td>✅ Unrestricted</td><td>None</td></tr>
        <tr><td><strong>50</strong></td><td>Voice-VoIP</td><td>10.50.0.0/24</td><td>IP phones</td><td>❌ No</td><td>SIP server in VLAN 20 only</td></tr>
        <tr><td><strong>60</strong></td><td>Printers</td><td>10.60.0.0/24</td><td>Network printers</td><td>❌ No</td><td>Corporate users only</td></tr>
        <tr><td><strong>70</strong></td><td>IoT</td><td>10.70.0.0/24</td><td>Smart devices, cameras</td><td>✅ Limited (allow list only)</td><td>None</td></tr>
        <tr><td><strong>80</strong></td><td>OT-SCADA</td><td>10.80.0.0/24</td><td>Industrial systems</td><td>❌ No</td><td>Fully isolated</td></tr>
        </tbody>
        </table>
        </div>

        <div class="code-block">
            <div class="code-header"><span>CLI — VLAN Interfaces (trunk port to core switch)</span><button class="code-copy-btn">Copy</button></div>
            <pre><code><span class="keyword">config</span> system interface
    <span class="keyword">edit</span> "VLAN10-Corp"
        <span class="keyword">set</span> type vlan
        <span class="keyword">set</span> vlanid 10
        <span class="keyword">set</span> interface "port4"   <span class="comment"># Trunk to core switch</span>
        <span class="keyword">set</span> ip 10.10.0.1/22
        <span class="keyword">set</span> allowaccess ping
        <span class="keyword">set</span> role lan
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "VLAN20-Servers"
        <span class="keyword">set</span> type vlan
        <span class="keyword">set</span> vlanid 20
        <span class="keyword">set</span> interface "port4"
        <span class="keyword">set</span> ip 10.20.0.1/24
        <span class="keyword">set</span> allowaccess ping
        <span class="keyword">set</span> role lan
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "VLAN30-IT-Mgmt"
        <span class="keyword">set</span> type vlan
        <span class="keyword">set</span> vlanid 30
        <span class="keyword">set</span> interface "port4"
        <span class="keyword">set</span> ip 10.30.0.1/24
        <span class="keyword">set</span> allowaccess ping https ssh
        <span class="keyword">set</span> role lan
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "VLAN40-Guest"
        <span class="keyword">set</span> type vlan
        <span class="keyword">set</span> vlanid 40
        <span class="keyword">set</span> interface "port4"
        <span class="keyword">set</span> ip 10.40.0.1/24
        <span class="keyword">set</span> allowaccess ping
        <span class="keyword">set</span> role lan
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "VLAN70-IoT"
        <span class="keyword">set</span> type vlan
        <span class="keyword">set</span> vlanid 70
        <span class="keyword">set</span> interface "port4"
        <span class="keyword">set</span> ip 10.70.0.1/24
        <span class="keyword">set</span> allowaccess ping
        <span class="keyword">set</span> role lan
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "VLAN80-OT"
        <span class="keyword">set</span> type vlan
        <span class="keyword">set</span> vlanid 80
        <span class="keyword">set</span> interface "port4"
        <span class="keyword">set</span> ip 10.80.0.1/24
        <span class="keyword">set</span> allowaccess ping
        <span class="keyword">set</span> role undefined    <span class="comment"># OT/SCADA — special handling</span>
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
        </div>

        <div class="code-block">
            <div class="code-header"><span>CLI — Segmentation Policies (key rules)</span><button class="code-copy-btn">Copy</button></div>
            <pre><code><span class="keyword">config</span> firewall policy
    <span class="comment"># ====== GUEST NETWORK: Internet only, NO cross-VLAN ======</span>
    <span class="keyword">edit</span> 40
        <span class="keyword">set</span> name "Guest-Internet-Only"
        <span class="keyword">set</span> srcintf "VLAN40-Guest"
        <span class="keyword">set</span> dstintf "port1"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "HTTP" "HTTPS" "DNS"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> nat enable
        <span class="keyword">set</span> utm-status enable
        <span class="keyword">set</span> web-filter-profile "Guest-Safe-Search"
        <span class="keyword">set</span> logtraffic all
    <span class="keyword">next</span>

    <span class="comment"># DENY: Guest to any internal VLAN</span>
    <span class="keyword">edit</span> 41
        <span class="keyword">set</span> name "Guest-to-Internal-DENY"
        <span class="keyword">set</span> srcintf "VLAN40-Guest"
        <span class="keyword">set</span> dstintf "VLAN10-Corp" "VLAN20-Servers" "VLAN30-IT-Mgmt"
        <span class="keyword">set</span> action deny
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "ALL"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> logtraffic all
    <span class="keyword">next</span>

    <span class="comment"># ====== IoT: Only allow specific cloud destinations ======</span>
    <span class="keyword">edit</span> 70
        <span class="keyword">set</span> name "IoT-AllowList-Internet"
        <span class="keyword">set</span> srcintf "VLAN70-IoT"
        <span class="keyword">set</span> dstintf "port1"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "IoT-AllowedCloud-FQDNs"  <span class="comment"># Specific vendor cloud endpoints</span>
        <span class="keyword">set</span> service "HTTPS"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> nat enable
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "IoT devices — allow list ONLY"
    <span class="keyword">next</span>

    <span class="comment"># IoT: Deny everything else (including internal networks)</span>
    <span class="keyword">edit</span> 71
        <span class="keyword">set</span> name "IoT-Deny-All-Else"
        <span class="keyword">set</span> srcintf "VLAN70-IoT"
        <span class="keyword">set</span> dstintf "ANY"
        <span class="keyword">set</span> action deny
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "ALL"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "IoT fully isolated — deny all except above"
    <span class="keyword">next</span>

    <span class="comment"># ====== OT/SCADA: Fully isolated — nothing in, nothing out ======</span>
    <span class="keyword">edit</span> 80
        <span class="keyword">set</span> name "OT-Deny-All-Outbound"
        <span class="keyword">set</span> srcintf "VLAN80-OT"
        <span class="keyword">set</span> dstintf "ANY"
        <span class="keyword">set</span> action deny
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "ALL"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "OT/SCADA: NO external communication — air gap policy"
    <span class="keyword">next</span>
    <span class="keyword">edit</span> 81
        <span class="keyword">set</span> name "OT-Deny-All-Inbound"
        <span class="keyword">set</span> srcintf "ANY"
        <span class="keyword">set</span> dstintf "VLAN80-OT"
        <span class="keyword">set</span> action deny
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "ALL"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "OT/SCADA: block all inbound — alert on any match"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
        </div>
    </div>

    <div class="tab-content" data-tab="ha">
        <h2 id="ha-scenario">Scenario 4: Active-Passive High Availability</h2>

        <div class="callout best-practice">
            <div class="callout-title">🎯 Scenario Overview</div>
            <p><strong>Use Case:</strong> Mission-critical environment requiring sub-second failover with session preservation.<br>
            <strong>Architecture:</strong> Two identical FortiGate models in A-P HA with dedicated heartbeat link<br>
            <strong>Goal:</strong> Zero-downtime failover; both units synchronized; automated failback</p>
        </div>

        <div class="mermaid-wrapper">
        <div class="mermaid">
graph LR
    ISP["ISP Router"] -->|"WAN"| FG1["FG-01 (Active)\nPrimary"]
    ISP -->|"WAN"| FG2["FG-02 (Standby)\nSecondary"]
    FG1 <-->|"HA Heartbeat\n(dedicated port)"| FG2
    FG1 <-->|"HA Data Sync"| FG2
    FG1 -->|"LAN"| SW["Core Switch"]
    FG2 -->|"LAN"| SW
    SW --> SERVERS["Internal Servers"]
    style FG1 fill:#10b981,color:#fff
    style FG2 fill:#64748b,color:#fff
        </div>
        <div class="mermaid-caption">Active-Passive HA — Dedicated heartbeat link, session sync</div>
        </div>

        <div class="code-block">
            <div class="code-header"><span>CLI — HA Configuration (run on BOTH units — priority differs)</span><button class="code-copy-btn">Copy</button></div>
            <pre><code><span class="comment"># ===== On FG-01 (Primary — higher priority) =====</span>
<span class="keyword">config</span> system ha
    <span class="keyword">set</span> group-id 1
    <span class="keyword">set</span> group-name "DC-HA-Cluster"
    <span class="keyword">set</span> mode a-p               <span class="comment"># Active-Passive</span>
    <span class="keyword">set</span> password "HA-Cluster-PSK-2024!"
    <span class="keyword">set</span> hbdev "port6" 50       <span class="comment"># Heartbeat on port6, priority 50</span>
    <span class="keyword">set</span> hbdev "port7" 40       <span class="comment"># Backup heartbeat on port7</span>
    <span class="keyword">set</span> session-sync-dev "port6"
    <span class="keyword">set</span> priority 200           <span class="comment"># Higher = Primary (FG-01)</span>
    <span class="keyword">set</span> route-ttl 10
    <span class="keyword">set</span> route-wait 0
    <span class="keyword">set</span> route-hold 10
    <span class="keyword">set</span> sync-config enable     <span class="comment"># Sync config from primary to secondary</span>
    <span class="keyword">set</span> ha-mgmt-status enable  <span class="comment"># Independent management interface</span>
    <span class="keyword">set</span> override enable        <span class="comment"># Return to primary after recovery</span>
    <span class="keyword">set</span> override-wait-time 300 <span class="comment"># Wait 5 min before returning to primary</span>
    <span class="keyword">config</span> ha-mgmt-interfaces
        <span class="keyword">edit</span> 1
            <span class="keyword">set</span> interface "mgmt1"
            <span class="keyword">set</span> dst 0.0.0.0/0
            <span class="keyword">set</span> gateway 10.0.255.1
        <span class="keyword">next</span>
    <span class="keyword">end</span>
    <span class="keyword">set</span> monitor "port1" "port2" "port3"  <span class="comment"># Monitor these — failover if any down</span>
<span class="keyword">end</span>

<span class="comment"># ===== On FG-02 (Secondary — lower priority) =====</span>
<span class="comment"># Same config but: set priority 100</span></code></pre>
        </div>

        <div class="code-block">
            <div class="code-header"><span>CLI — HA Monitoring & Diagnostics</span><button class="code-copy-btn">Copy</button></div>
            <pre><code><span class="comment"># HA cluster status</span>
<span class="command">get system ha status</span>

<span class="comment"># Detailed HA diagnostics</span>
<span class="command">diagnose sys ha status</span>
<span class="command">diagnose sys ha dump-by sid</span>

<span class="comment"># Check config sync status</span>
<span class="command">diagnose sys ha checksum show</span>
<span class="command">diagnose sys ha checksum recalculate</span>

<span class="comment"># Force failover (for testing — use on ACTIVE unit)</span>
<span class="command">diagnose sys ha reset-uptime</span>

<span class="comment"># View sessions being synced</span>
<span class="command">diagnose sys session stat | grep sess</span>

<span class="comment"># Expected output for healthy HA:</span>
<span class="output">FG-01 # get system ha status
Model: FortiGate-1000D
HA Health Status: OK
Cluster Uptime: 30 days 14:22:11

Member[0]: FG-01 (Master)
  HA-Role: Master
  Monitored Interfaces: port1(up) port2(up) port3(up)
  Sessions: 24531

Member[1]: FG-02 (Slave)
  HA-Role: Slave
  Monitored Interfaces: port1(up) port2(up) port3(up)
  Sessions: 24531</span></code></pre>
        </div>

        <ul class="checklist">
            <li><span class="check checked">✓</span> Use identical hardware models — hardware differences prevent HA formation</li>
            <li><span class="check checked">✓</span> Use a dedicated switch or crossover cable for the heartbeat link</li>
            <li><span class="check checked">✓</span> Configure management IP on each unit separately (ha-mgmt-interface) for independent CLI access</li>
            <li><span class="check checked">✓</span> Enable interface monitoring on all critical interfaces</li>
            <li><span class="check checked">✓</span> Test failover monthly — manually trigger and measure failover time</li>
            <li><span class="check checked">✓</span> After failover, always check <code>get system ha status</code> to confirm recovery</li>
        </ul>
    </div>

    <div class="tab-content" data-tab="remote-access">
        <h2 id="remote-access-scenario">Scenario 5: Secure Remote Access (SSL VPN + MFA)</h2>

        <div class="callout best-practice">
            <div class="callout-title">🎯 Scenario Overview</div>
            <p><strong>Use Case:</strong> Remote workforce needing secure, MFA-protected access to internal resources.<br>
            <strong>Architecture:</strong> SSL VPN in tunnel mode with FortiToken Cloud MFA + LDAP group-based access control<br>
            <strong>Goal:</strong> Users authenticate with domain credentials + MFA token; access only assigned resources</p>
        </div>

        <div class="code-block">
            <div class="code-header"><span>CLI — SSL VPN with LDAP + FortiToken MFA</span><button class="code-copy-btn">Copy</button></div>
            <pre><code><span class="comment"># Step 1: LDAP Server</span>
<span class="keyword">config</span> user ldap
    <span class="keyword">edit</span> "Corp-AD"
        <span class="keyword">set</span> server "dc01.corp.local"
        <span class="keyword">set</span> secondary-server "dc02.corp.local"
        <span class="keyword">set</span> cnid "sAMAccountName"
        <span class="keyword">set</span> dn "DC=corp,DC=local"
        <span class="keyword">set</span> type regular
        <span class="keyword">set</span> username "CN=FG-SVC-LDAP,OU=SvcAccts,DC=corp,DC=local"
        <span class="keyword">set</span> password "ServicePassword!"
        <span class="keyword">set</span> port 636
        <span class="keyword">set</span> secure ldaps
        <span class="keyword">set</span> group-member-check user-attr
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Step 2: User Groups (mapped to AD groups)</span>
<span class="keyword">config</span> user group
    <span class="keyword">edit</span> "VPN-AllUsers"
        <span class="keyword">set</span> member "Corp-AD"
        <span class="keyword">config</span> match
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> server-name "Corp-AD"
                <span class="keyword">set</span> group-name "CN=VPN-Users,OU=Groups,DC=corp,DC=local"
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "VPN-IT-Admins"
        <span class="keyword">set</span> member "Corp-AD"
        <span class="keyword">config</span> match
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> server-name "Corp-AD"
                <span class="keyword">set</span> group-name "CN=IT-Admins,OU=Groups,DC=corp,DC=local"
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Step 3: SSL VPN Portal (tunnel mode)</span>
<span class="keyword">config</span> vpn ssl web portal
    <span class="keyword">edit</span> "corp-tunnel"
        <span class="keyword">set</span> tunnel-mode enable
        <span class="keyword">set</span> web-mode disable        <span class="comment"># Full tunnel, no clientless</span>
        <span class="keyword">set</span> ip-pools "SSLVPN-Pool"
        <span class="keyword">set</span> dns-server1 10.10.0.10
        <span class="keyword">set</span> dns-server2 10.10.0.11
        <span class="keyword">set</span> dns-suffix "corp.local"
        <span class="keyword">set</span> split-tunneling enable  <span class="comment"># Only corporate traffic via VPN</span>
        <span class="keyword">config</span> split-dns
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> domains "corp.local"
                <span class="keyword">set</span> dns-server1 10.10.0.10
            <span class="keyword">next</span>
        <span class="keyword">end</span>
        <span class="keyword">set</span> ipv4-split-include "Internal-Networks"
        <span class="keyword">set</span> user-bookmark enable
        <span class="keyword">set</span> user-subnets enable
        <span class="keyword">set</span> forticlient-download enable
    <span class="keyword">next</span>

    <span class="comment"># Restricted portal for contractors — web-mode only</span>
    <span class="keyword">edit</span> "contractor-webmode"
        <span class="keyword">set</span> tunnel-mode disable
        <span class="keyword">set</span> web-mode enable
        <span class="keyword">set</span> display-bookmark enable
        <span class="keyword">config</span> bookmark-group
            <span class="keyword">edit</span> "Allowed-Apps"
                <span class="keyword">config</span> bookmarks
                    <span class="keyword">edit</span> "ServiceDesk"
                        <span class="keyword">set</span> url "https://helpdesk.corp.local"
                        <span class="keyword">set</span> type https
                    <span class="keyword">next</span>
                <span class="keyword">end</span>
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Step 4: SSL VPN Settings</span>
<span class="keyword">config</span> vpn ssl settings
    <span class="keyword">set</span> status enable
    <span class="keyword">set</span> servercert "vpn.corp.com-cert"   <span class="comment"># Trusted cert — no warnings</span>
    <span class="keyword">set</span> port 443
    <span class="keyword">set</span> source-interface "port1"
    <span class="keyword">set</span> source-address "all"
    <span class="keyword">set</span> default-portal "corp-tunnel"
    <span class="keyword">set</span> algorithm high
    <span class="keyword">set</span> login-timeout 30
    <span class="keyword">set</span> idle-timeout 300             <span class="comment"># 5 min idle disconnect</span>
    <span class="keyword">set</span> dtls-tunnel enable           <span class="comment"># DTLS for better performance</span>
    <span class="keyword">set</span> dtls-hello-timeout 10
    <span class="keyword">set</span> tunnel-connect-without-reauth disable
    <span class="keyword">config</span> authentication-rule
        <span class="comment"># Rule 1: IT Admins get full tunnel portal</span>
        <span class="keyword">edit</span> 1
            <span class="keyword">set</span> groups "VPN-IT-Admins"
            <span class="keyword">set</span> portal "corp-tunnel"
        <span class="keyword">next</span>
        <span class="comment"># Rule 2: Regular users get standard tunnel</span>
        <span class="keyword">edit</span> 2
            <span class="keyword">set</span> groups "VPN-AllUsers"
            <span class="keyword">set</span> portal "corp-tunnel"
        <span class="keyword">next</span>
    <span class="keyword">end</span>
<span class="keyword">end</span>

<span class="comment"># Step 5: Enable FortiToken Cloud MFA on LDAP users</span>
<span class="comment"># FortiToken Cloud is configured in FortiGate settings</span>
<span class="keyword">config</span> user ldap
    <span class="keyword">edit</span> "Corp-AD"
        <span class="keyword">set</span> two-factor fortitoken-cloud
        <span class="keyword">set</span> email-from "no-reply@corp.local"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
        </div>

        <div class="code-block">
            <div class="code-header"><span>CLI — SSL VPN Firewall Policy</span><button class="code-copy-btn">Copy</button></div>
            <pre><code><span class="comment"># IP Pool for VPN clients</span>
<span class="keyword">config</span> firewall ippool
    <span class="keyword">edit</span> "SSLVPN-Pool"
        <span class="keyword">set</span> type overload
        <span class="keyword">set</span> startip 10.99.0.1
        <span class="keyword">set</span> endip 10.99.0.254
        <span class="keyword">set</span> comments "SSL VPN client IP range"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="keyword">config</span> firewall policy
    <span class="comment"># Allow VPN users to reach internal resources</span>
    <span class="keyword">edit</span> 100
        <span class="keyword">set</span> name "SSLVPN-to-LAN"
        <span class="keyword">set</span> srcintf "ssl.root"         <span class="comment"># SSL VPN virtual interface</span>
        <span class="keyword">set</span> dstintf "VLAN10-LAN" "VLAN20-Servers"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "SSLVPN-Pool"
        <span class="keyword">set</span> dstaddr "Internal-Networks"
        <span class="keyword">set</span> service "ALL"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> utm-status enable
        <span class="keyword">set</span> ips-sensor "Remote-Access-IPS"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> groups "VPN-AllUsers" "VPN-IT-Admins"
        <span class="keyword">set</span> comments "SSL VPN users access internal resources"
    <span class="keyword">next</span>

    <span class="comment"># Allow VPN users internet split-tunnel (optional)</span>
    <span class="comment"># If using full-tunnel, route internet via VPN too:</span>
    <span class="keyword">edit</span> 101
        <span class="keyword">set</span> name "SSLVPN-to-Internet"
        <span class="keyword">set</span> srcintf "ssl.root"
        <span class="keyword">set</span> dstintf "port1"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "SSLVPN-Pool"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "HTTP" "HTTPS" "DNS"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> nat enable
        <span class="keyword">set</span> utm-status enable
        <span class="keyword">set</span> profile-group "Remote-User-UTM"
        <span class="keyword">set</span> logtraffic all
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
        </div>
    </div>

    <div class="tab-content" data-tab="mssp">
        <h2 id="mssp-scenario">Scenario 6: MSSP Multi-Tenant with VDOMs</h2>

        <div class="callout best-practice">
            <div class="callout-title">🎯 Scenario Overview</div>
            <p><strong>Use Case:</strong> Managed Security Service Provider hosting multiple customers on a single FortiGate with complete isolation.<br>
            <strong>Architecture:</strong> Multi-VDOM FortiGate — one VDOM per customer + global management VDOM<br>
            <strong>Goal:</strong> Each customer is fully isolated; customer admins can only see their own VDOM</p>
        </div>

        <div class="code-block">
            <div class="code-header"><span>CLI — MSSP VDOM Setup</span><button class="code-copy-btn">Copy</button></div>
            <pre><code><span class="comment"># Step 1: Enable multi-VDOM mode (causes reboot!)</span>
<span class="keyword">config</span> system global
    <span class="keyword">set</span> vdom-mode multi-vdom
<span class="keyword">end</span>

<span class="comment"># Step 2: Create customer VDOMs</span>
<span class="keyword">config</span> vdom
    <span class="keyword">edit</span> "CustomerA"
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "CustomerB"
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "CustomerC"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Step 3: Assign interfaces to VDOMs</span>
<span class="keyword">config</span> global
<span class="keyword">config</span> system interface
    <span class="keyword">edit</span> "port5"
        <span class="keyword">set</span> vdom "CustomerA"
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "VLAN100-CustA-WAN"
        <span class="keyword">set</span> type vlan
        <span class="keyword">set</span> vlanid 100
        <span class="keyword">set</span> interface "port2"
        <span class="keyword">set</span> vdom "CustomerA"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Step 4: Customer admin accounts (restricted to their VDOM)</span>
<span class="keyword">config</span> system admin
    <span class="keyword">edit</span> "customerA-admin"
        <span class="keyword">set</span> accprofile "prof_admin"  <span class="comment"># Full control within VDOM</span>
        <span class="keyword">set</span> vdom "CustomerA"
        <span class="keyword">set</span> password "CustomerA-Admin-Pass!"
        <span class="keyword">set</span> two-factor fortitoken-cloud
        <span class="keyword">set</span> email-to "admin@customerA.com"
        <span class="keyword">set</span> trusthost1 203.0.113.50/32  <span class="comment"># Customer's management IP</span>
        <span class="keyword">set</span> comments "CustomerA designated admin"
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "customerA-readonly"
        <span class="keyword">set</span> accprofile "super_admin_readonly"
        <span class="keyword">set</span> vdom "CustomerA"
        <span class="keyword">set</span> password "CustomerA-RO-Pass!"
        <span class="keyword">set</span> comments "CustomerA read-only for audits"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Step 5: Configure within Customer A VDOM</span>
<span class="keyword">config</span> vdom
    <span class="keyword">edit</span> "CustomerA"
        <span class="keyword">config</span> system settings
            <span class="keyword">set</span> opmode nat
            <span class="keyword">set</span> gui-default-policyid 0
        <span class="keyword">end</span>
        <span class="keyword">config</span> router static
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> dst 0.0.0.0/0
                <span class="keyword">set</span> gateway 203.0.113.1
                <span class="keyword">set</span> device "VLAN100-CustA-WAN"
            <span class="keyword">next</span>
        <span class="keyword">end</span>
        <span class="comment"># Customer-specific policies configured here...</span>
<span class="keyword">end</span>

<span class="comment"># Step 6: MSSP operator — super admin managing all VDOMs</span>
<span class="keyword">config</span> system admin
    <span class="keyword">edit</span> "mssp-operator"
        <span class="keyword">set</span> accprofile "super_admin"  <span class="comment"># Global admin — sees all VDOMs</span>
        <span class="keyword">set</span> password "MSSP-Global-Admin-Pass!"
        <span class="keyword">set</span> two-factor fortitoken-cloud
        <span class="keyword">set</span> email-to "ops@mssp.com"
        <span class="keyword">set</span> trusthost1 10.0.0.0/8    <span class="comment"># Only from MSSP management network</span>
        <span class="keyword">set</span> comments "MSSP global operations team"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
        </div>

        <div class="callout tip">
            <div class="callout-title">💡 MSSP Operational Tips</div>
            <p>• Use <strong>FortiManager</strong> to centrally manage all VDOMs across multiple FortiGates — essential for MSSP scale<br>
            • Set up <strong>per-VDOM log forwarding</strong> to separate FortiSIEM tenants or FortiAnalyzer ADOMs<br>
            • Use <strong>NPU VDOM links</strong> for inter-VDOM traffic (better performance than standard VDOM links)<br>
            • Each customer VDOM gets its own license allocation — be aware of per-VDOM user count limits</p>
        </div>
    </div>
</div>

<h2 id="scenario-checklist">Pre-Deployment Checklist</h2>

<ul class="checklist">
    <li><span class="check checked">✓</span> <strong>Backup config</strong> before any major change — <code>execute backup config tftp backup.cfg 10.0.0.50</code></li>
    <li><span class="check checked">✓</span> <strong>Test in staging</strong> first — never test policies directly in production</li>
    <li><span class="check checked">✓</span> <strong>Document every policy</strong> — name, comments, ticket number, business justification</li>
    <li><span class="check checked">✓</span> <strong>Enable logging</strong> on every policy — both allow and deny</li>
    <li><span class="check checked">✓</span> <strong>Monitor hit counts</strong> after deployment — zero hits after 30 days = candidate for removal</li>
    <li><span class="check checked">✓</span> <strong>Review implicit deny logs</strong> — blocked traffic from legitimate hosts = missing policy</li>
    <li><span class="check checked">✓</span> <strong>Test failover</strong> (for HA scenarios) in a scheduled maintenance window</li>
    <li><span class="check checked">✓</span> <strong>Verify VPN connectivity</strong> from multiple client locations after deployment</li>
    <li><span class="check checked">✓</span> <strong>Run Security Rating</strong> post-deployment — target 80+ score</li>
</ul>
`;

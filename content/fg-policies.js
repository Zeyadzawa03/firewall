// ============================================================
// FortiGate Firewall Policies — Deep Dive
// The most critical section of any FortiGate deployment
// ============================================================

KB.content['fg-policies'] = `
<h1><span class="h1-icon">🧱</span> Firewall Policies</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Firewall policies are the <strong>core decision engine</strong> of FortiGate. Every packet that transits the firewall is matched against policies in sequence. The first matching policy determines what happens: allow, deny, inspect, NAT, log. Without policies, the implicit deny at the end blocks all traffic.</p>
</div>

<div class="gui-path">Policy &amp; Objects <span class="gui-sep">›</span> Firewall Policy</div>

<h2 id="policy-anatomy">Policy Anatomy</h2>

<p>A FortiGate firewall policy is a rule with these components:</p>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Field</th><th>Description</th><th>Options</th><th>Notes</th></tr>
</thead>
<tbody>
<tr><td><strong>Name</strong></td><td>Policy identifier</td><td>String</td><td>Make it descriptive: "HR-Internet-Allow"</td></tr>
<tr><td><strong>From (Source Interface/Zone)</strong></td><td>Ingress interface</td><td>Interface, Zone, Any</td><td>Matched first — must match incoming interface</td></tr>
<tr><td><strong>To (Destination Interface/Zone)</strong></td><td>Egress interface</td><td>Interface, Zone, Any</td><td>Traffic direction matters</td></tr>
<tr><td><strong>Source</strong></td><td>Source IP/user/device</td><td>Address, Group, Geography, Internet Service</td><td>Can be user/group for identity-based policies</td></tr>
<tr><td><strong>Destination</strong></td><td>Destination IP</td><td>Address, Group, Geography, Internet Service, FQDN</td><td>For DNAT/VIP, use the VIP object here</td></tr>
<tr><td><strong>Service</strong></td><td>Protocol/port</td><td>Service, Service Group, Application</td><td>Use specific services — avoid "ALL" in production</td></tr>
<tr><td><strong>Schedule</strong></td><td>When policy is active</td><td>always, specific time/day</td><td>Useful for business-hours access control</td></tr>
<tr><td><strong>Action</strong></td><td>What to do</td><td>Accept, Deny, IPSec</td><td>No "reject" — drop is silent</td></tr>
<tr><td><strong>NAT</strong></td><td>Source NAT</td><td>Enable/Disable, IP Pool</td><td>For outbound internet, enable + select pool or outgoing IP</td></tr>
<tr><td><strong>Security Profiles</strong></td><td>UTM inspection</td><td>AV, IPS, Web Filter, App Control, etc.</td><td>Only applies when Action = Accept</td></tr>
<tr><td><strong>Log</strong></td><td>Log settings</td><td>All sessions, UTM events, No log</td><td><strong>Always log at minimum UTM + denied traffic</strong></td></tr>
<tr><td><strong>Comments</strong></td><td>Documentation</td><td>Text</td><td>Document business purpose, ticket number, date</td></tr>
</tbody>
</table>
</div>

<h2 id="policy-packet-flow">Policy Matching Order</h2>

<div class="mermaid-wrapper">
<div class="mermaid">
flowchart TD
    A["New Packet Arrives"] --> B["Interface Match\n(From/To)"]
    B --> C["Source IP/User Match"]
    C --> D["Destination IP Match"]
    D --> E["Service Match\n(Protocol/Port)"]
    E --> F["Schedule Active?"]
    F -- Yes --> G{"Action?"}
    F -- No --> H["Next Policy ↓"]
    G -- Accept --> I["Apply NAT"]
    G -- Deny --> J["Drop Packet\nLog if configured"]
    I --> K["Apply Security Profiles\nAV, IPS, Web Filter..."]
    K --> L["Forward Packet\nCreate Session"]
    H --> M["Next Policy in Table"]
    M --> N{"Matched?"}
    N -- Yes --> B
    N -- No --> O["Implicit Deny\n(Last Rule)\nDrop + Log if enabled"]
    style J fill:#ef4444,color:#fff
    style O fill:#ef4444,color:#fff
    style L fill:#10b981,color:#fff
</div>
<div class="mermaid-caption">Firewall Policy Processing — Sequential Match from Top to Bottom</div>
</div>

<h2 id="create-policy">Creating a Firewall Policy</h2>

<h3>GUI Method</h3>
<div class="steps">
    <div class="step">
        <div class="step-title">Navigate to Policy List</div>
        <p>Go to <strong>Policy &amp; Objects → Firewall Policy</strong>. Click <strong>Create New</strong>.</p>
    </div>
    <div class="step">
        <div class="step-title">Set Interfaces</div>
        <p>Set <strong>Incoming Interface</strong> (source zone/interface) and <strong>Outgoing Interface</strong> (destination zone/interface). These define traffic direction.</p>
    </div>
    <div class="step">
        <div class="step-title">Define Source and Destination</div>
        <p>Add source address objects (subnets, FQDN, users). Add destination address objects. Use existing objects or create inline. Prefer specific addresses over "all".</p>
    </div>
    <div class="step">
        <div class="step-title">Set Service and Schedule</div>
        <p>Select services (HTTP, HTTPS, DNS, etc.). Set schedule (usually "always"). Avoid using "ALL" service.</p>
    </div>
    <div class="step">
        <div class="step-title">Set Action and NAT</div>
        <p>Action = Accept (or Deny). For outbound internet policies, enable NAT. Choose between outgoing interface IP or an IP pool.</p>
    </div>
    <div class="step">
        <div class="step-title">Apply Security Profiles</div>
        <p>Enable desired UTM profiles: Antivirus, IPS, Application Control, Web Filter, SSL Inspection, etc.</p>
    </div>
    <div class="step">
        <div class="step-title">Configure Logging</div>
        <p>At minimum: enable <strong>UTM Logs</strong>. For sensitive policies: enable <strong>All Sessions</strong>. Set log destination (FortiAnalyzer, local disk, syslog).</p>
    </div>
</div>

<h3 id="cli-policy">CLI Method</h3>

<div class="code-block">
    <div class="code-header"><span>CLI — Create Firewall Policy</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> firewall policy
    <span class="keyword">edit</span> 0  <span class="comment"># 0 = auto-assign next ID</span>
        <span class="keyword">set</span> name "HR-Internet-Allow"
        <span class="keyword">set</span> uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        <span class="keyword">set</span> srcintf "VLAN10-HR"
        <span class="keyword">set</span> dstintf "WAN-Zone"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "HR-Users-Subnet"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> service "HTTP" "HTTPS" "DNS"
        <span class="keyword">set</span> utm-status enable
        <span class="keyword">set</span> profile-type group
        <span class="keyword">set</span> profile-group "Corporate-UTM-Profile"
        <span class="keyword">set</span> nat enable
        <span class="keyword">set</span> ippool enable
        <span class="keyword">set</span> poolname "ISP1-Pool"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> logtraffic-start enable
        <span class="keyword">set</span> auto-asic-offload enable
        <span class="keyword">set</span> comments "HR department internet access - Ticket #INC001234"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="policy-management">Policy Management Operations</h2>

<h3>Move Policy</h3>
<div class="code-block">
    <div class="code-header"><span>CLI — Move Policy</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Move policy 5 before policy 2</span>
<span class="command">config firewall policy</span>
<span class="command">move 5 before 2</span>
<span class="command">end</span>

<span class="comment"># Move policy 5 after policy 10</span>
<span class="command">config firewall policy</span>
<span class="command">move 5 after 10</span>
<span class="command">end</span></code></pre>
</div>

<h3>Clone Policy</h3>
<div class="code-block">
    <div class="code-header"><span>CLI — Clone Policy</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># GUI: Right-click policy → Clone</span>
<span class="comment"># CLI: Copy the config and edit</span>
<span class="command">show firewall policy 5</span>
<span class="comment"># Copy output, then create new policy with same settings + modifications</span></code></pre>
</div>

<h3>Disable/Enable Policy</h3>
<div class="code-block">
    <div class="code-header"><span>CLI — Disable Policy</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> firewall policy
    <span class="keyword">edit</span> 5
        <span class="keyword">set</span> status disable
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="policy-order">Policy Order — The Golden Rules</h2>

<div class="callout warning">
    <div class="callout-title">⚠️ Policy Order is Critical</div>
    <p>FortiGate matches policies <strong>top to bottom</strong>. The first match wins. Order matters.</p>
</div>

<div class="callout best-practice">
    <div class="callout-title">🎯 Recommended Policy Order</div>
    <ol>
        <li><strong>Block Lists first</strong> — Known bad IPs, threat feeds, IOCs</li>
        <li><strong>Authentication policies</strong> — Force captive portal or user auth</li>
        <li><strong>Most specific rules</strong> — Narrow source+destination before broad</li>
        <li><strong>Application-specific rules</strong> — VoIP, video, critical apps</li>
        <li><strong>Department access rules</strong> — HR, Finance, IT, Guests</li>
        <li><strong>Deny rules</strong> — Explicit deny with logging</li>
        <li><strong>General internet access</strong> — Broadest allow (if any)</li>
        <li>Implicit Deny (automatically last)</li>
    </ol>
</div>

<h2 id="shadow-policies">Shadow Policies</h2>

<div class="callout warning">
    <div class="callout-title">⚠️ What Is a Shadow Policy?</div>
    <p>A shadow policy is a policy that can <strong>never be matched</strong> because a more general (broader) policy above it already catches all traffic. Shadow policies are a common misconfiguration in enterprise firewalls.</p>
</div>

<p><strong>Example of shadow policy:</strong></p>
<div class="code-block">
    <div class="code-header"><span>Shadow Policy Example</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Policy 1 (line 5): LAN → WAN, src=all, dst=all, service=ALL → ACCEPT</span>
<span class="comment"># Policy 2 (line 6): LAN → WAN, src=HR-Subnet, dst=Social-Media → DENY</span>
<span class="comment"># Policy 2 is a SHADOW — it can never match because Policy 1 catches everything first!</span>

<span class="comment"># FIX: Move the deny rule ABOVE the broad allow rule</span>
<span class="command">config firewall policy</span>
<span class="command">move 6 before 5</span>
<span class="command">end</span></code></pre>
</div>

<h3>Find Shadow Policies via GUI</h3>
<div class="gui-path">Policy &amp; Objects <span class="gui-sep">›</span> Firewall Policy <span class="gui-sep">›</span> Search/Filter <span class="gui-sep">›</span> Show Shadow Policies</div>

<h2 id="implicit-deny">Implicit Deny</h2>

<div class="callout info">
    <div class="callout-title">ℹ️ The Implicit Deny Rule</div>
    <p>FortiGate has an invisible <strong>last rule</strong> that denies all traffic not matched by any explicit policy. This is the "default deny" principle. It cannot be disabled or deleted. You can enable logging on it via:</p>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Enable Implicit Deny Logging</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> log setting
    <span class="keyword">set</span> implicit-deny-traffic enable
<span class="keyword">end</span></code></pre>
</div>

<h2 id="hit-counts">Hit Counts</h2>

<p>Hit counts show how many sessions matched each policy. Zero hits on a policy for a long time may indicate it's unused (candidate for cleanup). High hits confirm it's actively used.</p>

<div class="code-block">
    <div class="code-header"><span>CLI — Hit Counts</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># View all policies with hit counts</span>
<span class="command">show firewall policy | grep -A5 "edit"</span>

<span class="comment"># Policy hit count per policy ID</span>
<span class="command">diagnose firewall policy hitcount</span>

<span class="comment"># Reset hit counters</span>
<span class="command">diagnose firewall policy reset-hitcount</span>

<span class="comment"># Per-policy statistics</span>
<span class="command">diagnose firewall policy list</span></code></pre>
</div>

<h2 id="policy-lookup">Policy Lookup Tool</h2>

<p>The Policy Lookup tool shows which policy would match for a given source, destination, and service combination.</p>

<div class="gui-path">Policy &amp; Objects <span class="gui-sep">›</span> Firewall Policy <span class="gui-sep">›</span> Policy Lookup</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Policy Lookup Equivalent</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Policy lookup for specific traffic</span>
<span class="command">diagnose firewall iprope lookup 10.0.0.100 8.8.8.8 6 1024 80</span>
<span class="comment"># Format: src-ip dst-ip protocol src-port dst-port</span>

<span class="comment"># Debug packet flow to see policy matching</span>
<span class="command">diagnose debug flow filter addr 10.0.0.100</span>
<span class="command">diagnose debug flow filter daddr 8.8.8.8</span>
<span class="command">diagnose debug flow show function-name enable</span>
<span class="command">diagnose debug flow trace start 20</span>
<span class="command">diagnose debug enable</span></code></pre>
</div>

<h2 id="identity-policies">Identity-Based Policies</h2>

<p>Identity-based policies match on authenticated user/group identities rather than (or in addition to) IP addresses. Requires FSSO, LDAP, or local user authentication.</p>

<div class="code-block">
    <div class="code-header"><span>CLI — Identity-Based Policy</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> firewall policy
    <span class="keyword">edit</span> 10
        <span class="keyword">set</span> name "Finance-Users-Internet"
        <span class="keyword">set</span> srcintf "LAN-Zone"
        <span class="keyword">set</span> dstintf "WAN-Zone"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "HTTP" "HTTPS"
        <span class="keyword">set</span> schedule "Business-Hours"
        <span class="comment"># Identity matching</span>
        <span class="keyword">set</span> groups "Finance-AD-Group"  <span class="comment"># FSSO/LDAP group</span>
        <span class="keyword">set</span> utm-status enable
        <span class="keyword">set</span> profile-group "Finance-UTM"
        <span class="keyword">set</span> nat enable
        <span class="keyword">set</span> logtraffic all
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="internet-services-policy">Internet Services in Policies</h2>

<p>Internet Service objects (ISDB) contain pre-built, continuously updated lists of IPs associated with major services (Microsoft 365, Google, AWS, etc.). Use them instead of maintaining IP lists manually.</p>

<div class="code-block">
    <div class="code-header"><span>CLI — Policy with Internet Services</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> firewall policy
    <span class="keyword">edit</span> 20
        <span class="keyword">set</span> name "Allow-Microsoft365"
        <span class="keyword">set</span> srcintf "LAN-Zone"
        <span class="keyword">set</span> dstintf "WAN-Zone"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> internet-service enable
        <span class="keyword">set</span> internet-service-name "Microsoft-Office365" "Microsoft-Teams"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> nat enable
        <span class="keyword">set</span> comments "Allow M365 + Teams - bypass web filter"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="policy-best-practices">Best Practices</h2>

<ul class="checklist">
    <li><span class="check checked">✓</span> Use descriptive names and comments — include ticket numbers</li>
    <li><span class="check checked">✓</span> Follow least-privilege — deny by default, allow explicitly</li>
    <li><span class="check checked">✓</span> Never use "ALL" service in production — specify what's actually needed</li>
    <li><span class="check checked">✓</span> Enable logging on ALL accept policies and ALL deny policies</li>
    <li><span class="check checked">✓</span> Apply security profiles on all outbound internet policies</li>
    <li><span class="check checked">✓</span> Review hit counts quarterly — remove zero-hit policies</li>
    <li><span class="check checked">✓</span> Use address objects — never hardcode IPs directly in policies</li>
    <li><span class="check checked">✓</span> Enable implicit deny logging to detect unauthorized traffic</li>
    <li><span class="check checked">✓</span> Document policy intent in the "Comments" field</li>
    <li><span class="check checked">✓</span> Use ISDB for cloud services instead of manual IP maintenance</li>
</ul>

<h2 id="policy-troubleshooting">Troubleshooting Policy Issues</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Symptom</th><th>Possible Cause</th><th>Debug Step</th></tr>
</thead>
<tbody>
<tr><td>Traffic blocked unexpectedly</td><td>Wrong policy order, missing route, interface mismatch</td><td><code>diagnose debug flow trace start 10</code></td></tr>
<tr><td>Traffic allowed when should be denied</td><td>Shadow policy, wrong interface in policy</td><td>Check Policy Lookup tool</td></tr>
<tr><td>UTM not triggering</td><td>Inspection mode mismatch, SSL not inspected</td><td>Check profile assignment and SSL inspection</td></tr>
<tr><td>Policy matches but session fails</td><td>NAT issue, route issue, server-side reject</td><td>Packet capture on both sides</td></tr>
<tr><td>VPN traffic not matching</td><td>VPN interface not in policy, tunnel down</td><td>Check VPN status and policy interface</td></tr>
</tbody>
</table>
</div>
`;

KB.content['fg-packet-flow'] = `
<h1><span class="h1-icon">📦</span> FortiGate Packet Processing Flow</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ Why This Matters</div>
    <p>Understanding the exact sequence in which FortiGate processes packets is essential for troubleshooting. It tells you: where does NAT apply? When are policies evaluated? In what order do security profiles run? This knowledge is what separates junior admins from senior engineers.</p>
</div>

<h2 id="ingress-to-egress">Complete Packet Flow</h2>

<div class="mermaid-wrapper">
<div class="mermaid">
flowchart TD
    A["📥 Packet Arrives on Ingress Interface"] --> B["NIC / Hardware Driver"]
    B --> C["DoS Policy Check"]
    C --> D{DoS Match?}
    D -- Deny --> DROP1["DROP 🔴"]
    D -- Pass --> E["IPSec / SSL VPN Decryption\n(if encrypted)"]
    E --> F["Ingress Interface Policy\n(Local-in for mgmt traffic)"]
    F --> G["Routing Lookup\n(DNAT / VIP check first!)"]
    G --> H["DNAT / VIP Applied\n(Pre-routing NAT)"]
    H --> I["Policy Lookup\n(Interface + Src + Dst + Service)"]
    I --> J{Policy Action?}
    J -- Deny --> LOG1["Log → DROP 🔴"]
    J -- Accept --> K["SNAT Check\n(Policy NAT or Central NAT)"]
    K --> L["Session Created in Table"]
    L --> M["Security Profile Pipeline"]
    M --> M1["AV Scan"]
    M1 --> M2["IPS Inspection"]
    M2 --> M3["App Control"]
    M3 --> M4["Web Filter / DNS Filter"]
    M4 --> M5["SSL Inspection\n(if encrypted)"]
    M5 --> N["NP/CP Hardware Offload\n(if eligible)"]
    N --> O["Egress Interface"]
    O --> P["📤 Packet Forwarded"]
    style DROP1 fill:#ef4444,color:#fff
    style LOG1 fill:#ef4444,color:#fff
    style P fill:#10b981,color:#fff
    style A fill:#1e293b,color:#e2e8f0
</div>
<div class="mermaid-caption">FortiGate Complete Packet Processing Pipeline</div>
</div>

<h2 id="key-processing-points">Key Processing Points</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>#</th><th>Stage</th><th>What Happens</th><th>Troubleshooting Command</th></tr>
</thead>
<tbody>
<tr><td>1</td><td><strong>DoS Policy</strong></td><td>Rate limiting, flood protection checked before anything else</td><td><code>diagnose dos-attack list</code></td></tr>
<tr><td>2</td><td><strong>Decryption</strong></td><td>IPSec or SSL VPN decrypts packet, presents inner IP to engine</td><td><code>diagnose vpn tunnel list</code></td></tr>
<tr><td>3</td><td><strong>DNAT / VIP</strong></td><td>Destination NAT applied BEFORE policy lookup — destination changes</td><td><code>diagnose firewall vip list</code></td></tr>
<tr><td>4</td><td><strong>Policy Match</strong></td><td>Policy table scanned top-to-bottom for first match</td><td><code>diagnose debug flow trace start 10</code></td></tr>
<tr><td>5</td><td><strong>SNAT</strong></td><td>Source NAT applied after policy match — source IP changes for outbound</td><td><code>diagnose firewall ippool list</code></td></tr>
<tr><td>6</td><td><strong>Session Creation</strong></td><td>Session entry added to session table for stateful tracking</td><td><code>diagnose sys session list</code></td></tr>
<tr><td>7</td><td><strong>UTM Inspection</strong></td><td>Security profiles applied in pipeline: AV → IPS → AppCtrl → WebFilter</td><td><code>diagnose debug application ips -1</code></td></tr>
<tr><td>8</td><td><strong>Hardware Offload</strong></td><td>Eligible sessions offloaded to NP6/NP7 ASICs for line-rate forwarding</td><td><code>diagnose npu np6 session list</code></td></tr>
</tbody>
</table>
</div>

<div class="callout warning">
    <div class="callout-title">⚠️ Critical: DNAT before Policy Lookup</div>
    <p>This is the most commonly misunderstood point. <strong>DNAT (VIP) is applied BEFORE the firewall policy is evaluated</strong>. This means:<br>
    • In your firewall policy, you must use the <strong>VIP object</strong> as the destination (not the real server IP)<br>
    • The policy destination is the <strong>translated IP</strong> as it appears after DNAT<br>
    • If you write a policy with the server's real IP as destination, it will NOT match</p>
</div>

<h2 id="session-table">Session Table</h2>

<p>The session table is FortiGate's state database. Every allowed TCP, UDP, and ICMP flow has an entry. Sessions expire based on timeouts. The session table is key to stateful inspection.</p>

<div class="code-block">
    <div class="code-header"><span>CLI — Session Table Analysis</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># View session statistics</span>
<span class="command">diagnose sys session stat</span>

<span class="comment"># Show all sessions (careful — can be millions)</span>
<span class="command">diagnose sys session list</span>

<span class="comment"># Filter sessions by source IP</span>
<span class="command">diagnose sys session filter src 10.0.0.100</span>
<span class="command">diagnose sys session list</span>

<span class="comment"># Filter sessions by destination</span>
<span class="command">diagnose sys session filter dst 8.8.8.8</span>
<span class="command">diagnose sys session list</span>

<span class="comment"># Filter by protocol</span>
<span class="command">diagnose sys session filter proto 6</span>  <span class="comment"># TCP=6, UDP=17, ICMP=1</span>
<span class="command">diagnose sys session list</span>

<span class="comment"># Filter by policy ID</span>
<span class="command">diagnose sys session filter policy 5</span>
<span class="command">diagnose sys session list</span>

<span class="comment"># Clear all sessions (DANGEROUS in production!)</span>
<span class="command">diagnose sys session clear</span>

<span class="comment"># Clear specific session filter</span>
<span class="command">diagnose sys session filter src 10.0.0.100</span>
<span class="command">diagnose sys session clear</span>

<span class="comment"># Session detail example output:</span>
<span class="output">session info: proto=6 proto_state=01 duration=45 expire=3595 timeout=3600
  policyid=5 pol_uuid=xxx flag=00000000 flag2=00000000
  sentbyte=2340 rcvdbyte=8920 sentpkt=15 landmarking=0
  src=10.0.0.100 dst=8.8.8.8 src_port=54321 dst_port=443
  pos/(before,after)=0/(0,0)
  state=log may_dirty f00
  npu_state=00000000</span></code></pre>
</div>

<h2 id="debug-flow">Debug Flow</h2>

<p>Debug flow is the most powerful FortiGate troubleshooting tool. It shows packet-by-packet processing through the entire pipeline.</p>

<div class="code-block">
    <div class="code-header"><span>CLI — Debug Flow Step by Step</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Step 1: Clear any existing debugs</span>
<span class="command">diagnose debug reset</span>
<span class="command">diagnose debug flow filter clear</span>

<span class="comment"># Step 2: Set filter (narrow scope!)</span>
<span class="command">diagnose debug flow filter addr 10.0.0.100</span>
<span class="comment"># Or filter by both src and dst:</span>
<span class="command">diagnose debug flow filter saddr 10.0.0.100</span>
<span class="command">diagnose debug flow filter daddr 8.8.8.8</span>
<span class="command">diagnose debug flow filter port 443</span>

<span class="comment"># Step 3: Enable verbose output</span>
<span class="command">diagnose debug flow show function-name enable</span>
<span class="command">diagnose debug flow show iprope enable</span>

<span class="comment"># Step 4: Start trace (capture 50 packets)</span>
<span class="command">diagnose debug flow trace start 50</span>

<span class="comment"># Step 5: Enable debug output</span>
<span class="command">diagnose debug enable</span>

<span class="comment"># NOW generate the traffic from the source!</span>

<span class="comment"># Step 6: When done, ALWAYS disable debug!</span>
<span class="command">diagnose debug flow trace stop</span>
<span class="command">diagnose debug disable</span>
<span class="command">diagnose debug reset</span>

<span class="comment"># === INTERPRETING OUTPUT ===</span>
<span class="output">id=20085 trace_id=1 func=print_pkt_detail line=5484 msg="vd-root:0 received a packet(proto=6, 10.0.0.100:54321->8.8.8.8:443) tun_id=0.0.0.0 tun_id6=:: from port3. flag [S], seq 123456, ack 0, win 65535"
<span class="comment"># ↑ Packet received on port3</span>
id=20085 trace_id=1 func=resolve_ip_tuple_fast line=5617 msg="Find an existing session, id-00001234, original direction"
<span class="comment"># ↑ Existing session found</span>
id=20085 trace_id=1 func=iprope_in_check line=183 msg="check failed on policy 0, drop"
<span class="comment"># ↑ Dropped by policy 0 (implicit deny)</span></span></code></pre>
</div>

<div class="callout danger">
    <div class="callout-title">🚨 Debug Safety Rules</div>
    <p><strong>Always disable debug after use!</strong> Running <code>diagnose debug enable</code> with no filter on a busy firewall will generate millions of lines and can cause performance degradation. Always set a specific filter before enabling. Always <code>diagnose debug disable</code> when done.</p>
</div>
`;

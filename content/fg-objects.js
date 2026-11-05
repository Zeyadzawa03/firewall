// ============================================================
// FortiGate Objects — Addresses, Services, Schedules, ISDB, Threat Feeds
// ============================================================

KB.content['fg-addresses'] = `
<h1><span class="h1-icon">📍</span> Address Objects</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Address objects are named representations of IP addresses, subnets, FQDNs, wildcard FQDNs, geography, or MAC addresses. Using objects instead of raw IPs in policies makes them readable, reusable, and easy to update — change the object once and all policies update automatically.</p>
</div>

<div class="gui-path">Policy &amp; Objects <span class="gui-sep">›</span> Addresses</div>

<h2 id="address-types">Address Types</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Type</th><th>Example</th><th>Use Case</th></tr>
</thead>
<tbody>
<tr><td><strong>Subnet</strong></td><td>10.0.0.0/8</td><td>Network segments, VLANs</td></tr>
<tr><td><strong>IP Range</strong></td><td>10.0.0.100-200</td><td>DHCP ranges, server pools</td></tr>
<tr><td><strong>FQDN</strong></td><td>*.microsoft.com</td><td>Cloud services with dynamic IPs</td></tr>
<tr><td><strong>Wildcard FQDN</strong></td><td>*.office.com</td><td>Microsoft 365, CDNs</td></tr>
<tr><td><strong>Geography</strong></td><td>Country: Russia</td><td>Geo-blocking by country</td></tr>
<tr><td><strong>MAC Address</strong></td><td>00:11:22:33:44:55</td><td>IoT device control by MAC</td></tr>
<tr><td><strong>Dynamic (Fabric)</strong></td><td>EMS tags, FortiNAC</td><td>Zero-trust endpoint identity</td></tr>
<tr><td><strong>Internet Service</strong></td><td>Office365.Exchange</td><td>Cloud service IPs from Fortinet DB</td></tr>
</tbody>
</table>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Address Object Examples</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> firewall address
    <span class="comment"># Subnet</span>
    <span class="keyword">edit</span> "HR-VLAN"
        <span class="keyword">set</span> type ipmask
        <span class="keyword">set</span> subnet 10.10.10.0/24
        <span class="keyword">set</span> color 3
        <span class="keyword">set</span> comment "HR Department VLAN"
    <span class="keyword">next</span>

    <span class="comment"># IP Range</span>
    <span class="keyword">edit</span> "DHCP-Pool-Guests"
        <span class="keyword">set</span> type iprange
        <span class="keyword">set</span> start-ip 192.168.100.100
        <span class="keyword">set</span> end-ip 192.168.100.200
        <span class="keyword">set</span> comment "Guest DHCP range"
    <span class="keyword">next</span>

    <span class="comment"># FQDN</span>
    <span class="keyword">edit</span> "Microsoft-Teams-FQDN"
        <span class="keyword">set</span> type fqdn
        <span class="keyword">set</span> fqdn "*.teams.microsoft.com"
        <span class="keyword">set</span> comment "MS Teams FQDN"
    <span class="keyword">next</span>

    <span class="comment"># Geography - block country</span>
    <span class="keyword">edit</span> "Geo-Russia"
        <span class="keyword">set</span> type geography
        <span class="keyword">set</span> country "RU"
        <span class="keyword">set</span> comment "Russia geo-block"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Address Groups</span>
<span class="keyword">config</span> firewall addrgrp
    <span class="keyword">edit</span> "Internal-Networks"
        <span class="keyword">set</span> member "HR-VLAN" "Finance-VLAN" "IT-VLAN"
        <span class="keyword">set</span> comment "All internal VLANs"
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "Blocked-Countries"
        <span class="keyword">set</span> member "Geo-Russia" "Geo-NorthKorea" "Geo-Iran"
        <span class="keyword">set</span> comment "Geoblocked countries"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="address-best-practices">Address Object Best Practices</h2>

<ul class="checklist">
    <li><span class="check checked">✓</span> Use a consistent naming convention: [Location]-[VLAN/Role]-[Type]</li>
    <li><span class="check checked">✓</span> Never use raw IPs in policies — always use named objects</li>
    <li><span class="check checked">✓</span> Use FQDN objects for cloud services with dynamic IPs</li>
    <li><span class="check checked">✓</span> Use Geography objects for geo-blocking instead of maintaining IP lists</li>
    <li><span class="check checked">✓</span> Color-code objects by type (subnets = blue, FQDNs = green, etc.)</li>
    <li><span class="check checked">✓</span> Add comments explaining what the object represents and who owns it</li>
</ul>
`;

KB.content['fg-services'] = `
<h1><span class="h1-icon">🔧</span> Services & Service Groups</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ Overview</div>
    <p>Service objects define the protocol and port combination allowed in a policy. FortiGate has hundreds of pre-defined services. You can create custom services for non-standard ports. Service groups bundle multiple services for policy simplicity.</p>
</div>

<div class="gui-path">Policy &amp; Objects <span class="gui-sep">›</span> Services</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Custom Services</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> firewall service custom
    <span class="comment"># Custom TCP service</span>
    <span class="keyword">edit</span> "SAP-Application"
        <span class="keyword">set</span> protocol TCP
        <span class="keyword">set</span> tcp-portrange 3200-3299 8000 8080
        <span class="keyword">set</span> comment "SAP Dispatcher and Web GUI ports"
    <span class="keyword">next</span>

    <span class="comment"># Custom UDP service</span>
    <span class="keyword">edit</span> "Custom-Syslog"
        <span class="keyword">set</span> protocol UDP
        <span class="keyword">set</span> udp-portrange 5514
        <span class="keyword">set</span> comment "Custom syslog port"
    <span class="keyword">next</span>

    <span class="comment"># ICMP custom</span>
    <span class="keyword">edit</span> "ICMP-Echo"
        <span class="keyword">set</span> protocol ICMP
        <span class="keyword">set</span> icmptype 8
        <span class="keyword">set</span> comment "Ping (ICMP Echo)"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Service Groups</span>
<span class="keyword">config</span> firewall service group
    <span class="keyword">edit</span> "Web-Services"
        <span class="keyword">set</span> member "HTTP" "HTTPS" "HTTP_8080" "HTTPS_8443"
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "Email-Services"
        <span class="keyword">set</span> member "SMTP" "SMTPS" "IMAP" "IMAPS" "POP3" "POP3S"
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "Corp-Apps"
        <span class="keyword">set</span> member "SAP-Application" "Custom-Syslog" "DNS" "NTP"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>
`;

KB.content['fg-schedules'] = `
<h1><span class="h1-icon">📅</span> Schedules</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Schedules define time windows during which a firewall policy is active. They allow you to create time-based access control: allow social media only during lunch hours, block all internet after business hours, enable guest Wi-Fi only on weekdays.</p>
</div>

<div class="gui-path">Policy &amp; Objects <span class="gui-sep">›</span> Schedules</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Schedule Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Recurring schedule (business hours)</span>
<span class="keyword">config</span> firewall schedule recurring
    <span class="keyword">edit</span> "Business-Hours"
        <span class="keyword">set</span> day monday tuesday wednesday thursday friday
        <span class="keyword">set</span> start 08:00
        <span class="keyword">set</span> end 18:00
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "Lunch-Break"
        <span class="keyword">set</span> day monday tuesday wednesday thursday friday
        <span class="keyword">set</span> start 12:00
        <span class="keyword">set</span> end 13:00
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "Weekends-Only"
        <span class="keyword">set</span> day saturday sunday
        <span class="keyword">set</span> start 00:00
        <span class="keyword">set</span> end 23:59
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># One-time schedule (maintenance window)</span>
<span class="keyword">config</span> firewall schedule onetime
    <span class="keyword">edit</span> "Maintenance-Window-Jan"
        <span class="keyword">set</span> start 01/15/2025 22:00
        <span class="keyword">set</span> end 01/16/2025 02:00
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>
`;

KB.content['fg-isdb'] = `
<h1><span class="h1-icon">🌍</span> Internet Service Database (ISDB)</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>The Internet Service Database (ISDB) is a Fortinet-maintained database of IP address ranges, ports, and protocols associated with thousands of internet services: Microsoft 365, Google, AWS, Azure, Netflix, Salesforce, etc. FortiGate downloads updates from FortiGuard and uses ISDB objects in policies and SD-WAN rules.</p>
</div>

<div class="gui-path">Policy &amp; Objects <span class="gui-sep">›</span> Internet Service Database</div>

<h2 id="isdb-benefits">Why Use ISDB</h2>

<ul>
<li><strong>No manual IP maintenance</strong>: Cloud providers change IPs constantly. ISDB updates automatically.</li>
<li><strong>Application awareness</strong>: Not just IPs — includes port/protocol combinations specific to each service</li>
<li><strong>SD-WAN integration</strong>: Route Microsoft Teams traffic via low-latency link, Netflix via high-bandwidth</li>
<li><strong>SSL bypass</strong>: Create policies to bypass SSL inspection for trusted cloud services</li>
</ul>

<div class="code-block">
    <div class="code-header"><span>CLI — ISDB in Policy</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Policy using ISDB (destination)</span>
<span class="keyword">config</span> firewall policy
    <span class="keyword">edit</span> 50
        <span class="keyword">set</span> name "Allow-M365-bypass-SSL"
        <span class="keyword">set</span> srcintf "LAN-Zone"
        <span class="keyword">set</span> dstintf "WAN-Zone"
        <span class="keyword">set</span> action accept
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> internet-service enable
        <span class="keyword">set</span> internet-service-name "Microsoft-Office365"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> nat enable
        <span class="comment"># No SSL inspection for M365 — bypass for performance</span>
        <span class="keyword">set</span> ssl-ssh-profile "no-inspection"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "M365 bypass — Fortinet ISDB managed IPs"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># View ISDB entries</span>
<span class="command">show firewall internet-service-name | grep Microsoft</span>
<span class="command">diagnose internet-service info id 65537</span></code></pre>
</div>
`;

KB.content['fg-threat-feeds'] = `
<h1><span class="h1-icon">⚠️</span> Threat Feeds</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Threat Feeds are <strong>external, dynamically-updating IP/domain/URL blocklists</strong> that FortiGate downloads and applies in real-time. They can be used in firewall policies and web filter profiles to block IPs/domains associated with malware, botnets, C2 servers, ransomware infrastructure, or internal threat intelligence.</p>
</div>

<div class="gui-path">Security Fabric <span class="gui-sep">›</span> Threat Feeds</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Threat Feed Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># External threat feed (IP blocklist from URL)</span>
<span class="keyword">config</span> system external-resource
    <span class="keyword">edit</span> "Emerging-Threats-IPs"
        <span class="keyword">set</span> type address
        <span class="keyword">set</span> category 192  <span class="comment"># Custom category ID</span>
        <span class="keyword">set</span> resource "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        <span class="keyword">set</span> refresh-rate 60    <span class="comment"># Refresh every 60 minutes</span>
        <span class="keyword">set</span> source-ip 0.0.0.0
        <span class="keyword">set</span> username ""
        <span class="keyword">set</span> password ""
        <span class="keyword">set</span> status enable
    <span class="keyword">next</span>
    <span class="keyword">edit</span> "Internal-IOC-List"
        <span class="keyword">set</span> type address
        <span class="keyword">set</span> resource "http://internal-siem.corp.local/threat-feeds/iocs.txt"
        <span class="keyword">set</span> refresh-rate 5
        <span class="keyword">set</span> status enable
        <span class="keyword">set</span> comments "Internal IOC feed from FortiSIEM"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Use threat feed as address object in policy</span>
<span class="keyword">config</span> firewall policy
    <span class="keyword">edit</span> 1
        <span class="keyword">set</span> name "Block-Known-Bad-IPs"
        <span class="keyword">set</span> srcintf "LAN-Zone"
        <span class="keyword">set</span> dstintf "WAN-Zone"
        <span class="keyword">set</span> action deny
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "Emerging-Threats-IPs"  <span class="comment"># Threat feed object</span>
        <span class="keyword">set</span> service "ALL"
        <span class="keyword">set</span> schedule "always"
        <span class="keyword">set</span> logtraffic all
        <span class="keyword">set</span> comments "Block known malicious IPs from Emerging Threats feed"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Status and diagnostics</span>
<span class="command">diagnose system external-resource status</span>
<span class="command">show system external-resource</span></code></pre>
</div>

<div class="callout best-practice">
    <div class="callout-title">🎯 Best Practice</div>
    <p>Place the threat feed deny policy at the <strong>very top</strong> of your policy list (highest priority) so it's evaluated before any allow rules. This ensures known bad IPs are always blocked regardless of other policies.</p>
</div>
`;

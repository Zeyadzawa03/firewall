// ============================================================
// FortiGate Security Profiles — Complete Coverage
// AV, IPS, App Control, Web Filter, DNS Filter, SSL Inspection,
// Email Filter, AntiSpam, DoS Policy, ZTNA, CASB, Sandbox
// ============================================================

KB.content['fg-antivirus'] = `
<h1><span class="h1-icon">🦠</span> Antivirus (AV) Profile</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>The FortiGate Antivirus profile scans file transfers through the firewall for malware. It supports multiple inspection modes, protocol coverage (HTTP, HTTPS, FTP, SMTP, IMAP, POP3, SMB), real-time FortiGuard cloud lookups, and FortiSandbox integration for zero-day detection.</p>
</div>

<div class="gui-path">Security Profiles <span class="gui-sep">›</span> AntiVirus</div>

<h2 id="av-inspection-modes">Inspection Modes</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Mode</th><th>How It Works</th><th>Performance</th><th>Detection</th></tr>
</thead>
<tbody>
<tr><td><strong>Flow-Based</strong></td><td>Scans as data streams through — no buffering</td><td>Highest</td><td>Good — cannot detect in compressed archives fully</td></tr>
<tr><td><strong>Proxy-Based</strong></td><td>Buffers entire file, then scans</td><td>Lower — adds latency</td><td>Best — full file reconstruction, archive scanning</td></tr>
</tbody>
</table>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — AV Profile Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> antivirus profile
    <span class="keyword">edit</span> "Corporate-AV"
        <span class="keyword">set</span> inspection-mode flow-based
        <span class="keyword">set</span> ftgd-analytics everything  <span class="comment"># Submit all unknown files to cloud</span>

        <span class="comment"># HTTP scanning</span>
        <span class="keyword">config</span> http
            <span class="keyword">set</span> av-scan enable
            <span class="keyword">set</span> outbreak-prevention enable  <span class="comment"># FortiGuard cloud detection</span>
            <span class="keyword">set</span> fortiai enable               <span class="comment"># FortiAI ML detection</span>
            <span class="keyword">set</span> quarantine enable
            <span class="keyword">set</span> archive-scan enable
            <span class="keyword">set</span> archive-block encrypted corrupt
        <span class="keyword">end</span>

        <span class="comment"># HTTPS scanning (requires SSL inspection)</span>
        <span class="keyword">config</span> https
            <span class="keyword">set</span> av-scan enable
            <span class="keyword">set</span> outbreak-prevention enable
        <span class="keyword">end</span>

        <span class="comment"># FTP scanning</span>
        <span class="keyword">config</span> ftp
            <span class="keyword">set</span> av-scan enable
            <span class="keyword">set</span> archive-scan enable
        <span class="keyword">end</span>

        <span class="comment"># Email scanning (SMTP/IMAP/POP3)</span>
        <span class="keyword">config</span> smtp
            <span class="keyword">set</span> av-scan enable
            <span class="keyword">set</span> outbreak-prevention enable
            <span class="keyword">set</span> executables virus  <span class="comment"># Block all executables in email</span>
        <span class="keyword">end</span>

        <span class="comment"># SMB (Windows file shares)</span>
        <span class="keyword">config</span> cifs
            <span class="keyword">set</span> av-scan enable
        <span class="keyword">end</span>

        <span class="comment"># Content disarm and reconstruct (CDR)</span>
        <span class="keyword">set</span> feature-set flow   <span class="comment"># or proxy</span>

        <span class="comment"># FortiSandbox integration</span>
        <span class="keyword">set</span> analytics-db enable
        <span class="keyword">set</span> analytics-max-upload 10  <span class="comment"># MB per file</span>
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<div class="callout warning">
    <div class="callout-title">⚠️ Common Mistakes</div>
    <p>• AV does NOT inspect HTTPS without <strong>SSL deep inspection</strong> — enable SSL inspection in the same policy<br>
    • Flow-based AV may miss malware hidden in <strong>password-protected archives</strong> — use proxy mode for high-risk environments<br>
    • AV adds latency — tune file size limits for scan to avoid excessive delay on large transfers</p>
</div>

<h2 id="av-diagnostics">AV Diagnostics</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — AV Diagnostics</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># AV engine status</span>
<span class="command">diagnose autoupdate status</span>

<span class="comment"># AV database version</span>
<span class="command">diagnose autoupdate versions | grep virus</span>

<span class="comment"># AV statistics</span>
<span class="command">diagnose test application scanunitd 1</span>

<span class="comment"># Test AV with EICAR test file</span>
<span class="comment"># Download http://www.eicar.org/download/eicar.com.txt through the firewall</span>
<span class="comment"># Should be blocked with AV detection</span>

<span class="comment"># AV debug</span>
<span class="command">diagnose debug application scanunitd -1</span>
<span class="command">diagnose debug enable</span></code></pre>
</div>
`;

KB.content['fg-ips'] = `
<h1><span class="h1-icon">🛡️</span> IPS (Intrusion Prevention System)</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>IPS detects and blocks network-based attacks: exploitation of vulnerabilities, buffer overflows, SQL injection in network traffic, protocol anomalies, botnet communication, and more. FortiGate IPS uses FortiGuard signature updates (5,000+ signatures) and anomaly-based detection.</p>
</div>

<div class="gui-path">Security Profiles <span class="gui-sep">›</span> Intrusion Prevention</div>

<h2 id="ips-profile-config">IPS Profile Configuration</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — IPS Sensor Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> ips sensor
    <span class="keyword">edit</span> "Corporate-IPS"
        <span class="keyword">set</span> comment "Main IPS sensor for corporate traffic"
        <span class="keyword">set</span> replacemsg-group ""
        <span class="keyword">set</span> block-malicious-url enable  <span class="comment"># Block malicious URLs in traffic</span>
        <span class="keyword">set</span> extended-log enable

        <span class="keyword">config</span> entries
            <span class="comment"># Block all critical/high severity signatures</span>
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> status enable
                <span class="keyword">set</span> severity critical high
                <span class="keyword">set</span> action block
                <span class="keyword">set</span> log enable
            <span class="keyword">next</span>

            <span class="comment"># Monitor medium severity</span>
            <span class="keyword">edit</span> 2
                <span class="keyword">set</span> status enable
                <span class="keyword">set</span> severity medium
                <span class="keyword">set</span> action monitor  <span class="comment"># Log but don't block</span>
                <span class="keyword">set</span> log enable
            <span class="keyword">next</span>

            <span class="comment"># Specific signature override — always block this CVE</span>
            <span class="keyword">edit</span> 3
                <span class="keyword">set</span> rule 33333      <span class="comment"># Specific signature ID</span>
                <span class="keyword">set</span> action block
                <span class="keyword">set</span> status enable
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>

    <span class="comment"># DMZ profile - stricter, protect servers</span>
    <span class="keyword">edit</span> "DMZ-IPS-Strict"
        <span class="keyword">config</span> entries
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> status enable
                <span class="keyword">set</span> severity critical high medium low
                <span class="keyword">set</span> action block
                <span class="keyword">set</span> log enable
            <span class="keyword">next</span>

            <span class="comment"># Web server-specific filter</span>
            <span class="keyword">edit</span> 2
                <span class="keyword">set</span> status enable
                <span class="keyword">set</span> os-type windows linux
                <span class="keyword">set</span> application "HTTP" "HTTPS"
                <span class="keyword">set</span> action block
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<h2 id="ips-diagnostics">IPS Diagnostics</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — IPS Monitoring</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># IPS engine status</span>
<span class="command">diagnose test application ips 1</span>

<span class="comment"># IPS signature database version</span>
<span class="command">diagnose autoupdate versions | grep ips</span>

<span class="comment"># IPS statistics</span>
<span class="command">diagnose test application ips 3</span>

<span class="comment"># View IPS signature details</span>
<span class="command">diagnose ips filter rule 33333</span>

<span class="comment"># IPS bypass (troubleshooting only!)</span>
<span class="command">diagnose test application ips 5</span>  <span class="comment"># IPS bypass mode</span>

<span class="comment"># Debug IPS</span>
<span class="command">diagnose debug application ips -1</span>
<span class="command">diagnose debug enable</span></code></pre>
</div>

<div class="callout tip">
    <div class="callout-title">💡 IPS Tuning Strategy</div>
    <p><strong>Phase 1</strong>: Start with all signatures in <strong>monitor</strong> mode for 2 weeks. Collect baseline.<br>
    <strong>Phase 2</strong>: Move critical/high to <strong>block</strong>. Keep medium/low in monitor.<br>
    <strong>Phase 3</strong>: Review false positives. Create exceptions for legitimate traffic.<br>
    <strong>Phase 4</strong>: Move medium to block after false positive tuning.<br>
    Never start directly in block-all mode — you will break legitimate traffic.</p>
</div>

<div class="callout warning">
    <div class="callout-title">⚠️ IPS Performance Impact</div>
    <p>IPS is CPU-intensive. Check NP acceleration capabilities for your model. Some FortiGate models have dedicated CP (Content Processor) ASICs for IPS offload. Check <code>diagnose npu npu-feature</code> to see what's hardware-accelerated.</p>
</div>
`;

KB.content['fg-app-control'] = `
<h1><span class="h1-icon">📱</span> Application Control</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Application Control identifies and controls applications at Layer 7, regardless of port or protocol. It can identify 5,000+ applications: social media, video streaming, file sharing, VoIP, gaming, proxies, and more. Unlike port-based filtering, it works even when apps use non-standard ports or encryption.</p>
</div>

<div class="gui-path">Security Profiles <span class="gui-sep">›</span> Application Control</div>

<div class="code-block">
    <div class="code-header"><span>CLI — Application Control Profile</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> application list
    <span class="keyword">edit</span> "Corporate-AppControl"
        <span class="keyword">set</span> comment "Corporate application control policy"
        <span class="keyword">set</span> extended-log enable

        <span class="keyword">config</span> entries
            <span class="comment"># Block P2P (BitTorrent, eMule)</span>
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> category 12  <span class="comment"># P2P category</span>
                <span class="keyword">set</span> action block
                <span class="keyword">set</span> log enable
            <span class="keyword">next</span>

            <span class="comment"># Block proxy/anonymizers</span>
            <span class="keyword">edit</span> 2
                <span class="keyword">set</span> category 7   <span class="comment"># Proxy category</span>
                <span class="keyword">set</span> action block
                <span class="keyword">set</span> log enable
            <span class="keyword">next</span>

            <span class="comment"># Allow and monitor Microsoft Teams</span>
            <span class="keyword">edit</span> 3
                <span class="keyword">set</span> application 34276  <span class="comment"># MS Teams ID</span>
                <span class="keyword">set</span> action allow
                <span class="keyword">set</span> log enable
            <span class="keyword">next</span>

            <span class="comment"># Block social media (except during lunch)</span>
            <span class="keyword">edit</span> 4
                <span class="keyword">set</span> category 6   <span class="comment"># Social.Networking</span>
                <span class="keyword">set</span> action block
                <span class="keyword">set</span> log enable
            <span class="keyword">next</span>

            <span class="comment"># Rate-limit video streaming</span>
            <span class="keyword">edit</span> 5
                <span class="keyword">set</span> category 4   <span class="comment"># Video/Audio</span>
                <span class="keyword">set</span> action pass
                <span class="keyword">set</span> log enable
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Find application IDs</span>
<span class="command">get application name | grep -i teams</span>
<span class="command">get application category</span></code></pre>
</div>
`;

KB.content['fg-web-filter'] = `
<h1><span class="h1-icon">🌐</span> Web Filter</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>Web Filter controls which websites users can access by URL category, URL pattern, domain, or content type. It uses the FortiGuard Web Filter database with 90+ categories covering billions of URLs. It can block, allow, monitor, warn, or authenticate per category.</p>
</div>

<div class="gui-path">Security Profiles <span class="gui-sep">›</span> Web Filter</div>

<h2 id="webfilter-config">Web Filter Profile</h2>

<div class="code-block">
    <div class="code-header"><span>CLI — Web Filter Profile</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> webfilter profile
    <span class="keyword">edit</span> "Corporate-WebFilter"
        <span class="keyword">set</span> comment "Corporate web filtering policy"
        <span class="keyword">set</span> inspection-mode flow-based
        <span class="keyword">set</span> ftgd-wf-rating-options allow-unrated  <span class="comment"># or block-unrated</span>

        <span class="comment"># FortiGuard category-based filtering</span>
        <span class="keyword">config</span> ftgd-wf
            <span class="keyword">config</span> filters
                <span class="comment"># Block malicious categories</span>
                <span class="keyword">edit</span> 1
                    <span class="keyword">set</span> category 26   <span class="comment"># Malicious Websites</span>
                    <span class="keyword">set</span> action block
                <span class="keyword">next</span>
                <span class="keyword">edit</span> 2
                    <span class="keyword">set</span> category 62   <span class="comment"># Phishing</span>
                    <span class="keyword">set</span> action block
                <span class="keyword">next</span>
                <span class="keyword">edit</span> 3
                    <span class="keyword">set</span> category 68   <span class="comment"># Spam URLs</span>
                    <span class="keyword">set</span> action block
                <span class="keyword">next</span>

                <span class="comment"># Block adult content</span>
                <span class="keyword">edit</span> 4
                    <span class="keyword">set</span> category 11   <span class="comment"># Adult/Mature Content</span>
                    <span class="keyword">set</span> action block
                <span class="keyword">next</span>

                <span class="comment"># Warn on social media</span>
                <span class="keyword">edit</span> 5
                    <span class="keyword">set</span> category 8    <span class="comment"># Social Networking</span>
                    <span class="keyword">set</span> action warning <span class="comment"># Show warning page, user can proceed</span>
                <span class="keyword">next</span>

                <span class="comment"># Monitor news/entertainment</span>
                <span class="keyword">edit</span> 6
                    <span class="keyword">set</span> category 5    <span class="comment"># News/Media</span>
                    <span class="keyword">set</span> action monitor
                <span class="keyword">next</span>
            <span class="keyword">end</span>
        <span class="keyword">end</span>

        <span class="comment"># URL exception list</span>
        <span class="keyword">config</span> web
            <span class="keyword">set</span> whitelist except-allow-list
            <span class="keyword">config</span> urlfilter
                <span class="keyword">edit</span> 1
                    <span class="keyword">set</span> id 1
                    <span class="keyword">set</span> url "*.corpexample.com"
                    <span class="keyword">set</span> type wildcard
                    <span class="keyword">set</span> action exempt  <span class="comment"># Bypass all filtering</span>
                <span class="keyword">next</span>
                <span class="keyword">edit</span> 2
                    <span class="keyword">set</span> id 2
                    <span class="keyword">set</span> url "gambling.com"
                    <span class="keyword">set</span> type simple
                    <span class="keyword">set</span> action block
                <span class="keyword">next</span>
            <span class="keyword">end</span>
        <span class="keyword">end</span>

        <span class="comment"># Safe search enforcement</span>
        <span class="keyword">set</span> search-engines-safe-search enable
        <span class="keyword">set</span> youtube-restrict moderate  <span class="comment"># or strict</span>
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<div class="callout warning">
    <div class="callout-title">⚠️ HTTPS Web Filtering Requires SSL Inspection</div>
    <p>Web filtering on HTTPS sites requires <strong>SSL deep inspection</strong>. Without it, FortiGate can only see the SNI hostname (for simple matching) but cannot inspect URLs, content, or apply full category filtering. Always pair web filter with SSL inspection on HTTPS policies.</p>
</div>
`;

KB.content['fg-dns-filter'] = `
<h1><span class="h1-icon">🔍</span> DNS Filter</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>DNS Filter inspects DNS queries and blocks resolution of malicious or restricted domains at the DNS layer — <em>before</em> a TCP connection is even established. It's faster and more efficient than web filtering because it operates on DNS traffic (UDP/53 or DoH), not HTTP/S content.</p>
</div>

<div class="gui-path">Security Profiles <span class="gui-sep">›</span> DNS Filter</div>

<div class="code-block">
    <div class="code-header"><span>CLI — DNS Filter Profile</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> dnsfilter profile
    <span class="keyword">edit</span> "Corporate-DNS-Filter"
        <span class="keyword">set</span> comment "Block malicious and unwanted DNS queries"

        <span class="comment"># FortiGuard DNS category filtering</span>
        <span class="keyword">config</span> ftgd-dns
            <span class="keyword">config</span> filters
                <span class="keyword">edit</span> 1
                    <span class="keyword">set</span> category 26   <span class="comment"># Malicious Sites</span>
                    <span class="keyword">set</span> action block
                <span class="keyword">next</span>
                <span class="keyword">edit</span> 2
                    <span class="keyword">set</span> category 62   <span class="comment"># Phishing</span>
                    <span class="keyword">set</span> action block
                <span class="keyword">next</span>
            <span class="keyword">end</span>
        <span class="keyword">end</span>

        <span class="comment"># Block botnet C2 DNS</span>
        <span class="keyword">set</span> block-botnet-domains enable

        <span class="comment"># DNS Safe Search</span>
        <span class="keyword">set</span> safe-search enable

        <span class="comment"># Custom domain block/allow</span>
        <span class="keyword">config</span> domain-filter
            <span class="keyword">config</span> entries
                <span class="keyword">edit</span> 1
                    <span class="keyword">set</span> domain "malware-c2.example.com"
                    <span class="keyword">set</span> type simple
                    <span class="keyword">set</span> action block
                <span class="keyword">next</span>
                <span class="keyword">edit</span> 2
                    <span class="keyword">set</span> domain "*.maliciousdomain.net"
                    <span class="keyword">set</span> type wildcard
                    <span class="keyword">set</span> action block
                <span class="keyword">next</span>
            <span class="keyword">end</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<div class="callout best-practice">
    <div class="callout-title">🎯 DNS Filter vs Web Filter</div>
    <p>Use DNS Filter as a <strong>first line of defense</strong> — it's lightweight and catches malicious domains before any connection is made. Use Web Filter as a <strong>second layer</strong> for URL-level control and content inspection. They work together, not as alternatives. DNS Filter is also effective against <strong>DNS tunneling</strong> and <strong>C2 beaconing</strong>.</p>
</div>
`;

KB.content['fg-ssl-inspection'] = `
<h1><span class="h1-icon">🔒</span> SSL/TLS Inspection</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>SSL Inspection (also called SSL deep inspection or HTTPS inspection) decrypts TLS traffic so other security profiles (AV, IPS, Web Filter, App Control) can inspect encrypted content. Without SSL inspection, 80%+ of internet traffic is a blind spot.</p>
</div>

<div class="gui-path">Security Profiles <span class="gui-sep">›</span> SSL/SSH Inspection</div>

<h2 id="ssl-modes">SSL Inspection Modes</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Mode</th><th>How It Works</th><th>CA Needed?</th><th>Best For</th></tr>
</thead>
<tbody>
<tr><td><strong>Certificate Inspection</strong></td><td>Inspects certificate only (not payload). Checks cert validity, hostname, CA trust.</td><td>No</td><td>Basic certificate validation, minimal overhead</td></tr>
<tr><td><strong>Full SSL Inspection</strong></td><td>Man-in-the-middle: FortiGate decrypts, inspects, re-encrypts</td><td>Yes — must be trusted by clients</td><td>Maximum security — content inspection on HTTPS</td></tr>
</tbody>
</table>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — SSL Inspection Profile</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> firewall ssl-ssh-profile
    <span class="keyword">edit</span> "corporate-deep-inspection"
        <span class="keyword">set</span> comment "Full SSL inspection - CA deployed via GPO"

        <span class="comment"># HTTPS inspection</span>
        <span class="keyword">config</span> https
            <span class="keyword">set</span> action deep-inspection
            <span class="keyword">set</span> cert-validation-timeout ignore  <span class="comment"># or allow/block</span>
            <span class="keyword">set</span> expired-server-cert ignore
            <span class="keyword">set</span> revoked-server-cert block       <span class="comment"># Block revoked certs</span>
            <span class="keyword">set</span> min-allowed-ssl-version tls-1.2  <span class="comment"># Block TLS 1.0/1.1</span>
            <span class="keyword">set</span> client-certificate inspect
        <span class="keyword">end</span>

        <span class="comment"># SSL VPN inspection</span>
        <span class="keyword">config</span> ssl
            <span class="keyword">set</span> inspect-all enable
        <span class="keyword">end</span>

        <span class="comment"># CA certificate used to re-sign intercepted certs</span>
        <span class="keyword">set</span> caname "corporate-ssl-inspection-ca"
        <span class="keyword">set</span> server-cert-mode resign

        <span class="comment"># Exempt specific domains (banking, health)</span>
        <span class="keyword">config</span> ssl-exempt
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> type wildcard
                <span class="keyword">set</span> wildcard "*.bankofamerica.com"
            <span class="keyword">next</span>
            <span class="keyword">edit</span> 2
                <span class="keyword">set</span> type fortiguard-category
                <span class="keyword">set</span> fortiguard-category 42  <span class="comment"># Finance/Banking category</span>
            <span class="keyword">next</span>
            <span class="keyword">edit</span> 3
                <span class="keyword">set</span> type fortiguard-category
                <span class="keyword">set</span> fortiguard-category 55  <span class="comment"># Health/Medical</span>
            <span class="keyword">next</span>
        <span class="keyword">end</span>

        <span class="comment"># Block if cannot inspect</span>
        <span class="keyword">set</span> block-blacklisted-certificates enable
        <span class="keyword">set</span> ssl-invalid-server-cert-log enable
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>

<div class="callout danger">
    <div class="callout-title">🚨 SSL Inspection Prerequisites</div>
    <p><strong>1. Deploy CA cert to ALL endpoints FIRST</strong> — via GPO (Windows), MDM (mobile), or browser policy<br>
    <strong>2. Exempt certificate-pinned apps</strong> — mobile banking, some Microsoft apps use cert pinning and will break<br>
    <strong>3. Exempt health/legal/banking</strong> — privacy regulations may prohibit inspection of these categories<br>
    <strong>4. Certificate must be trusted</strong> — users will see errors for every HTTPS site if CA not trusted<br>
    <strong>5. Monitor performance impact</strong> — SSL inspection is CPU-intensive, check your model's rated SSL throughput</p>
</div>
`;

KB.content['fg-dos-policy'] = `
<h1><span class="h1-icon">💥</span> DoS Policy</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>DoS (Denial of Service) Policies protect FortiGate and downstream resources from flood attacks by rate-limiting specific traffic patterns. They operate at the earliest point in packet processing — <strong>before firewall policies</strong> — making them extremely efficient. They protect against SYN floods, ICMP floods, UDP floods, port scans, and application-layer floods.</p>
</div>

<div class="gui-path">Policy &amp; Objects <span class="gui-sep">›</span> DoS Policy</div>

<div class="code-block">
    <div class="code-header"><span>CLI — DoS Policy</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> firewall DoS-policy
    <span class="keyword">edit</span> 1
        <span class="keyword">set</span> name "WAN-DoS-Protection"
        <span class="keyword">set</span> status enable
        <span class="keyword">set</span> interface "port1"   <span class="comment"># WAN interface</span>
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> dstaddr "all"
        <span class="keyword">set</span> service "ALL"

        <span class="keyword">config</span> anomaly
            <span class="comment"># TCP SYN flood protection</span>
            <span class="keyword">edit</span> "tcp_syn_flood"
                <span class="keyword">set</span> status enable
                <span class="keyword">set</span> log enable
                <span class="keyword">set</span> action block
                <span class="keyword">set</span> threshold 2000      <span class="comment"># packets/sec before blocking</span>
            <span class="keyword">next</span>

            <span class="comment"># ICMP flood protection</span>
            <span class="keyword">edit</span> "icmp_flood"
                <span class="keyword">set</span> status enable
                <span class="keyword">set</span> log enable
                <span class="keyword">set</span> action block
                <span class="keyword">set</span> threshold 500
            <span class="keyword">next</span>

            <span class="comment"># UDP flood</span>
            <span class="keyword">edit</span> "udp_flood"
                <span class="keyword">set</span> status enable
                <span class="keyword">set</span> log enable
                <span class="keyword">set</span> action block
                <span class="keyword">set</span> threshold 5000
            <span class="keyword">next</span>

            <span class="comment"># Port scan detection</span>
            <span class="keyword">edit</span> "tcp_port_scan"
                <span class="keyword">set</span> status enable
                <span class="keyword">set</span> log enable
                <span class="keyword">set</span> action block
                <span class="keyword">set</span> threshold 1000
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># DoS diagnostics</span>
<span class="command">diagnose dos-attack list</span>
<span class="command">diagnose dos-attack clear</span>
<span class="command">diagnose dos-attack status</span></code></pre>
</div>
`;

KB.content['fg-ztna'] = `
<h1><span class="h1-icon">🔐</span> ZTNA (Zero Trust Network Access)</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>ZTNA implements the Zero Trust principle: <strong>"Never trust, always verify"</strong>. Instead of VPN-based access where authenticated users get broad network access, ZTNA grants access to specific applications based on <strong>device posture + user identity + context</strong>. FortiGate ZTNA works with FortiClient EMS to enforce endpoint compliance.</p>
</div>

<div class="gui-path">Policy &amp; Objects <span class="gui-sep">›</span> ZTNA</div>

<h2 id="ztna-vs-vpn">ZTNA vs. VPN</h2>

<div class="table-wrapper">
<table>
<thead>
<tr><th>Aspect</th><th>Traditional VPN</th><th>ZTNA</th></tr>
</thead>
<tbody>
<tr><td>Access Model</td><td>Network access — connect to LAN</td><td>Application access — specific apps only</td></tr>
<tr><td>Implicit Trust</td><td>High — VPN user has broad access</td><td>None — each app access re-verified</td></tr>
<tr><td>Device Check</td><td>Usually credential-only</td><td>Continuous posture check (AV, OS patch, etc.)</td></tr>
<tr><td>Lateral Movement</td><td>High risk if endpoint compromised</td><td>Minimized — only specific app accessible</td></tr>
<tr><td>Split Tunneling</td><td>Optional, complex</td><td>Built-in — only app traffic tunneled</td></tr>
<tr><td>Visibility</td><td>Limited</td><td>Per-application, per-session telemetry</td></tr>
</tbody>
</table>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — ZTNA Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># ZTNA server (defines the application to protect)</span>
<span class="keyword">config</span> firewall access-proxy
    <span class="keyword">edit</span> "ZTNA-InternalApp"
        <span class="keyword">set</span> vip "VIP-InternalApp-ZTNA"
        <span class="keyword">set</span> client-cert enable  <span class="comment"># Require client certificate</span>
        <span class="keyword">config</span> api-gateway
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> url-map "/app"
                <span class="keyword">set</span> service http
                <span class="keyword">config</span> realservers
                    <span class="keyword">edit</span> 1
                        <span class="keyword">set</span> ip 10.10.50.100
                        <span class="keyword">set</span> port 80
                    <span class="keyword">next</span>
                <span class="keyword">end</span>
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># ZTNA tags (device posture requirements)</span>
<span class="keyword">config</span> firewall ztna-ems-tag
    <span class="keyword">edit</span> "Corporate-Compliant"
        <span class="keyword">set</span> tag-det "AV-Running, OS-Patched, Disk-Encrypted"
        <span class="keyword">set</span> ems-id 1
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># ZTNA rule</span>
<span class="keyword">config</span> firewall ztna-traffic-forward-proxy
    <span class="keyword">edit</span> 1
        <span class="keyword">set</span> name "ZTNA-InternalApp-Policy"
        <span class="keyword">set</span> access-proxy "ZTNA-InternalApp"
        <span class="keyword">set</span> srcaddr "all"
        <span class="keyword">set</span> ztna-tag "Corporate-Compliant"
        <span class="keyword">set</span> users "domain\\Domain-Users"
        <span class="keyword">set</span> action accept
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>
`;

KB.content['fg-casb'] = `
<h1><span class="h1-icon">☁️</span> CASB (Cloud Access Security Broker)</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>CASB (Cloud Access Security Broker) controls access to cloud applications (SaaS, IaaS). FortiGate inline CASB inspects cloud traffic and enforces policies: allow only corporate tenants, block personal accounts, control data upload/download, enforce DLP on cloud storage.</p>
</div>

<div class="gui-path">Security Profiles <span class="gui-sep">›</span> CASB</div>

<div class="code-block">
    <div class="code-header"><span>CLI — CASB Profile</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> casb profile
    <span class="keyword">edit</span> "Corporate-CASB"
        <span class="keyword">set</span> saas-application "Microsoft365" "GoogleWorkspace" "Dropbox"

        <span class="keyword">config</span> saas-application
            <span class="keyword">edit</span> "Microsoft365"
                <span class="keyword">set</span> access-rule allow
                <span class="keyword">set</span> custom-control "allow-only-corporate-tenant"
            <span class="keyword">next</span>
            <span class="keyword">edit</span> "Dropbox"
                <span class="keyword">set</span> access-rule block  <span class="comment"># Block personal Dropbox</span>
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>
`;

KB.content['fg-sandbox'] = `
<h1><span class="h1-icon">📦</span> FortiSandbox Integration</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>FortiSandbox analyzes suspicious files in an isolated virtual environment (sandbox) to detect zero-day malware and advanced persistent threats (APT) that signature-based AV misses. FortiGate can forward suspicious files to FortiSandbox (on-prem or cloud) for analysis.</p>
</div>

<div class="gui-path">Security Fabric <span class="gui-sep">›</span> Fabric Connectors <span class="gui-sep">›</span> FortiSandbox</div>

<div class="code-block">
    <div class="code-header"><span>CLI — FortiSandbox Integration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Connect to FortiSandbox</span>
<span class="keyword">config</span> system fortisandbox
    <span class="keyword">set</span> status enable
    <span class="keyword">set</span> server "10.10.10.200"      <span class="comment"># On-prem FSandbox IP</span>
    <span class="keyword">set</span> email "admin@company.com"
    <span class="keyword">set</span> interface "port3"
    <span class="keyword">set</span> enc-algorithm default
<span class="keyword">end</span>

<span class="comment"># AV profile - enable sandbox submission</span>
<span class="keyword">config</span> antivirus profile
    <span class="keyword">edit</span> "Corporate-AV"
        <span class="keyword">set</span> analytics-db enable
        <span class="keyword">set</span> fortisandbox-mode inline  <span class="comment"># inline blocks until verdict</span>
        <span class="keyword">set</span> analytics-max-upload 10   <span class="comment"># MB</span>
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Sandbox status</span>
<span class="command">diagnose test application forticldd 1</span>
<span class="command">diagnose sys fortisandbox status</span></code></pre>
</div>

<div class="callout warning">
    <div class="callout-title">⚠️ Inline vs. Analytics Mode</div>
    <p><strong>Inline mode</strong>: File is held until sandbox verdict (adds latency up to 60 seconds for first-seen files). Best for high-security environments.<br>
    <strong>Analytics mode</strong>: File is delivered immediately; sandbox runs analysis in background. Risk: malware may execute before block action. Best for performance-sensitive environments.</p>
</div>
`;

// ============================================================
// FortiGate Authentication — LDAP, RADIUS, SSO, SAML, FortiToken
// ============================================================

KB.content['fg-ldap'] = `
<h1><span class="h1-icon">📂</span> LDAP Authentication</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>LDAP (Lightweight Directory Access Protocol) integration allows FortiGate to authenticate users against Active Directory, OpenLDAP, or other directory services. Used for administrator login, SSL VPN authentication, captive portal, firewall user groups, and FSSO.</p>
</div>

<div class="gui-path">User &amp; Authentication <span class="gui-sep">›</span> LDAP Servers</div>

<div class="code-block">
    <div class="code-header"><span>CLI — LDAP Server Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> user ldap
    <span class="keyword">edit</span> "Corp-AD"
        <span class="keyword">set</span> server "dc01.corp.local"
        <span class="keyword">set</span> secondary-server "dc02.corp.local"
        <span class="keyword">set</span> cnid "sAMAccountName"        <span class="comment"># Login username attribute</span>
        <span class="keyword">set</span> dn "DC=corp,DC=local"        <span class="comment"># Search base DN</span>
        <span class="keyword">set</span> type regular                 <span class="comment"># simple | regular | anonymous</span>
        <span class="keyword">set</span> username "CN=FG-SVC-LDAP,OU=ServiceAccounts,DC=corp,DC=local"
        <span class="keyword">set</span> password <span class="string">"ServiceAccount!Pass"</span>
        <span class="keyword">set</span> port 636                     <span class="comment"># 389 plain, 636 LDAPS</span>
        <span class="keyword">set</span> secure ldaps                 <span class="comment"># none | starttls | ldaps</span>
        <span class="keyword">set</span> ca-cert "Corp-Root-CA"       <span class="comment"># Verify server cert</span>
        <span class="keyword">set</span> group-member-check user-attr  <span class="comment"># memberOf attribute</span>
        <span class="keyword">set</span> group-search-base "OU=Groups,DC=corp,DC=local"
        <span class="keyword">set</span> group-object-filter "(&(objectClass=group)(cn=VPN-*))"
        <span class="keyword">set</span> member-attr "memberOf"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Create user group mapped to LDAP group</span>
<span class="keyword">config</span> user group
    <span class="keyword">edit</span> "VPN-Users"
        <span class="keyword">set</span> member "Corp-AD"
        <span class="keyword">config</span> match
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> server-name "Corp-AD"
                <span class="keyword">set</span> group-name "CN=VPN-Users,OU=Groups,DC=corp,DC=local"
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Test LDAP authentication</span>
<span class="command">diagnose test authserver ldap Corp-AD johndoe Password123!</span></code></pre>
</div>

<div class="callout danger">
    <div class="callout-title">🚨 LDAP Security Requirements</div>
    <p>• <strong>Always use LDAPS (port 636)</strong> — plain LDAP (389) sends credentials in cleartext<br>
    • Use a <strong>dedicated read-only service account</strong> — never bind with a privileged AD account<br>
    • Set the service account password to <strong>never expire</strong> — expired password = all LDAP auth failures<br>
    • Configure <strong>two domain controllers</strong> for redundancy</p>
</div>
`;

KB.content['fg-radius'] = `
<h1><span class="h1-icon">📡</span> RADIUS Authentication</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>RADIUS (Remote Authentication Dial-In User Service) is an AAA (Authentication, Authorization, Accounting) protocol. FortiGate uses RADIUS for admin authentication, SSL VPN, captive portal, and 802.1X. RADIUS is commonly used with MFA systems (Cisco ISE, Microsoft NPS, Duo, Okta).</p>
</div>

<div class="gui-path">User &amp; Authentication <span class="gui-sep">›</span> RADIUS Servers</div>

<div class="code-block">
    <div class="code-header"><span>CLI — RADIUS Server Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> user radius
    <span class="keyword">edit</span> "Corp-NPS"
        <span class="keyword">set</span> server "10.0.0.50"
        <span class="keyword">set</span> secondary-server "10.0.0.51"
        <span class="keyword">set</span> secret <span class="string">"R@diusSharedSecret!"</span>
        <span class="keyword">set</span> auth-type auto           <span class="comment"># auto | pap | chap | ms_chap | ms_chap_v2</span>
        <span class="keyword">set</span> timeout 5               <span class="comment"># seconds to wait for response</span>
        <span class="keyword">set</span> nas-ip 203.0.113.2       <span class="comment"># Source IP for RADIUS requests</span>
        <span class="keyword">set</span> acct-interim-interval 300
        <span class="keyword">set</span> radius-coa enable        <span class="comment"># Change of Authorization (for dynamic policy)</span>

        <span class="comment"># RADIUS attributes for group membership</span>
        <span class="keyword">config</span> class-attribute
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> name "Class"
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Test RADIUS</span>
<span class="command">diagnose test authserver radius Corp-NPS pap johndoe Password123</span></code></pre>
</div>
`;

KB.content['fg-sso'] = `
<h1><span class="h1-icon">🔗</span> FSSO (Fortinet Single Sign-On)</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>FSSO (Fortinet Single Sign-On) provides <strong>transparent, agent-based user identification</strong>. When users log into Windows domain computers, FSSO captures their username, IP address, and AD group membership and passes this to FortiGate. This enables identity-based firewall policies without prompting users for credentials.</p>
</div>

<div class="gui-path">Security Fabric <span class="gui-sep">›</span> Fabric Connectors <span class="gui-sep">›</span> SSO/Identity</div>

<h2 id="fsso-components">FSSO Architecture</h2>

<div class="mermaid-wrapper">
<div class="mermaid">
graph LR
    DC["Domain Controller\n(Windows)"] -->|Login Events| CA["Collector Agent\n(Windows Service)"]
    CA -->|User-IP mapping| FG["FortiGate"]
    FG -->|Policy Lookup| POL["Identity-Based Policy\nUser=Finance-Group → Allow"]
    style FG fill:#ee3124,color:#fff
    style CA fill:#1e293b,color:#e2e8f0
</div>
<div class="mermaid-caption">FSSO Architecture — Active Directory to FortiGate user-IP mapping</div>
</div>

<div class="code-block">
    <div class="code-header"><span>CLI — FSSO Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># FSSO Collector Agent connection</span>
<span class="keyword">config</span> user fsso
    <span class="keyword">edit</span> "Corp-FSSO"
        <span class="keyword">set</span> server "10.0.0.30"          <span class="comment"># Collector Agent IP</span>
        <span class="keyword">set</span> port 8000
        <span class="keyword">set</span> password <span class="string">"FSSO-Secret!"</span>
        <span class="keyword">set</span> ldap-server "Corp-AD"
        <span class="keyword">set</span> group-poll-interval 20      <span class="comment"># seconds</span>
        <span class="keyword">set</span> ldap-poll-interval 30
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># FSSO user groups</span>
<span class="keyword">config</span> user group
    <span class="keyword">edit</span> "FSSO-Finance"
        <span class="keyword">set</span> member "Corp-FSSO"
        <span class="keyword">config</span> match
            <span class="keyword">edit</span> 1
                <span class="keyword">set</span> server-name "Corp-FSSO"
                <span class="keyword">set</span> group-name "corp.local/Finance"
            <span class="keyword">next</span>
        <span class="keyword">end</span>
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># FSSO diagnostics</span>
<span class="command">diagnose debug authd fsso list</span>
<span class="command">diagnose debug authd fsso stats</span>
<span class="command">diagnose firewall auth list</span>  <span class="comment"># View authenticated users</span></code></pre>
</div>
`;

KB.content['fg-fortitoken'] = `
<h1><span class="h1-icon">🔑</span> FortiToken & Two-Factor Authentication</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>FortiToken provides two-factor authentication (2FA/MFA) for FortiGate access. It supports hardware tokens (FortiToken 200), mobile app (FortiToken Mobile), and email/SMS OTP. 2FA adds a one-time password (TOTP) requirement on top of regular credentials, dramatically reducing account compromise risk.</p>
</div>

<div class="gui-path">User &amp; Authentication <span class="gui-sep">›</span> FortiTokens</div>

<div class="code-block">
    <div class="code-header"><span>CLI — 2FA Configuration</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="comment"># Assign FortiToken to user</span>
<span class="keyword">config</span> user local
    <span class="keyword">edit</span> "john.doe"
        <span class="keyword">set</span> type password
        <span class="keyword">set</span> passwd <span class="string">"P@ssw0rd!"</span>
        <span class="keyword">set</span> two-factor fortitoken-cloud  <span class="comment"># or fortitoken (hardware)</span>
        <span class="keyword">set</span> email-to "john.doe@corp.com"  <span class="comment"># For FortiToken Cloud</span>
        <span class="keyword">set</span> fortitoken "FTK-XXXXXXXX"     <span class="comment"># Hardware token serial</span>
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># Enable 2FA for admin accounts</span>
<span class="keyword">config</span> system admin
    <span class="keyword">edit</span> "admin-john"
        <span class="keyword">set</span> two-factor fortitoken-cloud
        <span class="keyword">set</span> email-to "john.doe@corp.com"
    <span class="keyword">next</span>
<span class="keyword">end</span>

<span class="comment"># FortiToken Cloud settings</span>
<span class="keyword">config</span> system ftm-push
    <span class="keyword">set</span> status enable
    <span class="keyword">set</span> server-ip "FortiToken-Cloud"  <span class="comment"># Fortinet cloud server</span>
<span class="keyword">end</span></code></pre>
</div>

<div class="callout best-practice">
    <div class="callout-title">🎯 2FA Best Practices</div>
    <p>• Enable 2FA for <strong>ALL</strong> administrator accounts — no exceptions<br>
    • Enable 2FA for <strong>all SSL VPN users</strong> — accounts will be brute-forced<br>
    • Use <strong>FortiToken Cloud</strong> for push notification (better UX than TOTP code entry)<br>
    • Maintain a <strong>break-glass admin</strong> account with hardware token stored in a safe<br>
    • Test token authentication monthly — FortiToken Cloud depends on internet connectivity</p>
</div>
`;

KB.content['fg-saml'] = `
<h1><span class="h1-icon">🎫</span> SAML Authentication</h1>

<div class="callout info">
    <div class="callout-title">ℹ️ What It Is</div>
    <p>SAML (Security Assertion Markup Language) allows FortiGate to integrate with enterprise Identity Providers (IdP) like Azure AD, Okta, Ping Identity, and ADFS. Users authenticate to the IdP (SSO), which then provides SAML assertions to FortiGate. This enables centralized authentication with existing enterprise IdP investment.</p>
</div>

<div class="gui-path">User &amp; Authentication <span class="gui-sep">›</span> Single Sign-On <span class="gui-sep">›</span> SAML SP</div>

<div class="code-block">
    <div class="code-header"><span>CLI — SAML SP (Service Provider) Config</span><button class="code-copy-btn">Copy</button></div>
    <pre><code><span class="keyword">config</span> user saml
    <span class="keyword">edit</span> "Azure-AD-SSO"
        <span class="keyword">set</span> cert "ssl-vpn-cert"          <span class="comment"># SP signing cert</span>
        <span class="keyword">set</span> entity-id "https://vpn.corp.com/metadata"
        <span class="keyword">set</span> single-sign-on-url "https://vpn.corp.com/remote/saml/login"
        <span class="keyword">set</span> single-logout-url "https://vpn.corp.com/remote/saml/logout"
        <span class="keyword">set</span> idp-entity-id "https://login.microsoftonline.com/&lt;tenant&gt;/saml2"
        <span class="keyword">set</span> idp-single-sign-on-url "https://login.microsoftonline.com/&lt;tenant&gt;/saml2"
        <span class="keyword">set</span> idp-cert "AzureAD-SAML-Cert"
        <span class="keyword">set</span> user-name "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
        <span class="keyword">set</span> group-name "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
    <span class="keyword">next</span>
<span class="keyword">end</span></code></pre>
</div>
`;

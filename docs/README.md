# SentryFW documentation

- [REST API reference](API.md): authentication, conventions, the rule object, every route and its permission.
- `README.md` in the repository root covers installation, the CLI and configuration.
- The Fortinet knowledge base (FortiGate and FortiSIEM reference) is served at [/kb/](/kb/).

## Operator checklist before enforcing

1. Create a rule that allows your management access (for example, SSH or RDP from your admin network), at a low priority number.
2. Use **Rules → Test a packet** to confirm that management traffic is allowed and unwanted traffic is denied.
3. Run **Rules → Rule analysis** and resolve any *shadowed* or *exposed-service* findings.
4. Take a backup (**Backups → Create backup**).
5. Switch the provider, restart elevated, enable **Apply rules to the operating system**, then **Apply all to OS**.
6. Run **Check OS sync**. Repeat it after any change made outside SentryFW (for example in `wf.msc` or with `iptables`).

## Recovering access

- Lost admin password: stop the server, run `node bin/fwctl.js user reset admin`, and sign in with the one-time password it prints.
- Locked out by a rule: stop the server; `node bin/fwctl.js rules disable "<rule>"` or `node bin/fwctl.js backup restore <file> --yes`, then `node bin/fwctl.js rules apply --yes`.

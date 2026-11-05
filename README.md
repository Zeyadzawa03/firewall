# SentryFW

A host firewall management console for Windows and Linux: a web GUI, a REST API and a CLI (`fwctl`), all driving one rule engine. It includes traffic monitoring, threat detection, an IP blocklist, a tamper-evident audit trail, backups, and an embedded Fortinet (FortiGate / FortiSIEM) knowledge base.

No dependencies: Node.js 22+ and nothing from npm.

## Quick start

```bash
npm start                  # same as: node bin/fwctl.js serve
```

On first run the server prints a one-time `admin` password. Open <http://127.0.0.1:8787/>, sign in, and choose a new password. The knowledge base is at <http://127.0.0.1:8787/kb/>.

Out of the box SentryFW is **safe to explore**: the `simulated` provider stores and evaluates rules but never touches the operating system firewall. When you are ready to enforce:

1. **Settings → Firewall provider**: `windows` or `linux` (or `auto`), then restart.
2. Run the server elevated (Administrator on Windows, root / `CAP_NET_ADMIN` on Linux).
3. **Settings → Apply rules to the operating system**: on.
4. **Rules → Apply all to OS**, then **Check OS sync** to confirm.

Make sure a rule allows your own management access before you set a default-deny policy.

## What's in the console

| Page | |
|---|---|
| Dashboard | Rule and traffic counters, allowed/denied chart, rule analysis, detection findings, exposed listeners. |
| Traffic | Connections tracked by the monitor, with the policy decision for each; the live socket table; listeners; interfaces. One-click block. |
| Detection | Port scans, connection floods, denied bursts, beaconing, new listeners and public access to sensitive ports. Acknowledge or block. |
| Rules | Create, edit, enable/disable and delete rules; preview the native OS command; test a packet against the policy; apply to the OS and detect drift. Shadowed, duplicate and risky rules are flagged. |
| Blocklist | Block IPs or CIDRs (optionally for a time), each backed by real deny rules; bulk import. |
| Quick hardening | Recipes such as "allow RDP only from a trusted network" or "restrict outbound to essential services". |
| Event log | Filter, page and export events; live streaming. |
| Audit trail | Who changed what, with before/after snapshots, in a SHA-256 hash chain that exposes edits. |
| Backups | Snapshots of rules, blocklist and settings; restore with an automatic rollback point. |
| Settings / Users | Editable settings; admin / operator / auditor accounts and active sessions. |

## CLI

`fwctl` exposes the same operations. It works on the data directory in-process, so **mutating commands refuse to run while `fwctl serve` is running** (the server holds state in memory); use the console then, or stop the server.

```bash
node bin/fwctl.js help                                   # all commands
node bin/fwctl.js status
node bin/fwctl.js rules add --name "Allow HTTPS" -d inbound -a allow -p tcp --dport 443
node bin/fwctl.js rules                                  # list
node bin/fwctl.js rules analyse                          # exit code 1 on high/critical findings
node bin/fwctl.js test -d inbound -p tcp --src 203.0.113.9 --dport 3389
node bin/fwctl.js block 203.0.113.9 --reason "SSH brute force" --ttl 24
node bin/fwctl.js logs --level warn,error --follow
node bin/fwctl.js audit verify
node bin/fwctl.js backup create --note "before change #42"
node bin/fwctl.js user reset admin                       # recover a lost admin password
```

Every command accepts `--json` for scripting and `--help` for its options. Exit codes: `0` success, `1` failure, `2` usage error.

## API

See [docs/API.md](docs/API.md) (also served at `/docs/API.md`). `GET /api` lists every route with its required permission.

## Configuration

`config/default.json` is the shipped baseline; don't edit it. Changes made in Settings or with `fwctl settings set` are stored in `data/config.json`. Environment variables override both:

| Variable | Setting |
|---|---|
| `FWCTL_HOST`, `FWCTL_PORT` | Bind address (default `127.0.0.1:8787`). Binding elsewhere is logged as a warning: put it behind TLS. |
| `FWCTL_PROVIDER` | `simulated`, `windows`, `linux`, `auto` |
| `FWCTL_APPLY_TO_OS` | `true` to write rules into the OS firewall |
| `FWCTL_REQUIRE_AUTH` | `false` disables sign-in (isolated labs only; every visitor becomes admin) |
| `FWCTL_MONITOR`, `FWCTL_MONITOR_INTERVAL` | Traffic monitor on/off and sampling interval (seconds) |
| `FWCTL_DETECTION` | Threat detection on/off |
| `FWCTL_LOG_LEVEL`, `FWCTL_LOG_CONSOLE` | Log verbosity; echo events to the console |
| `FWCTL_DATA_DIR`, `FWCTL_LOG_DIR` | Relocate `data/` and `logs/` (e.g. `/var/lib/sentryfw`) |

State lives in `data/` (rules, users, blocklist, settings, backups) and `logs/` (`events.log`, `audit.log`); both are created on demand.

## How it works

```
 GUI (public/)  ─┐
 REST API       ─┼─► firewall manager ─► rule store (data/rules.json)
 fwctl CLI      ─┘        │                     ▲
                          ├─► provider ── simulated │ windows (NetSecurity) │ linux (iptables/nft/ufw/firewalld)
                          ├─► audit trail (hash chain)   │
                          └─► event log                  │
 traffic monitor ─► socket table ─► policy evaluation ───┘ hit counters
                                  └─► detection engine ─► findings / auto-block
```

- Rules are saved before they are applied to the OS. A failed OS call leaves the rule marked *pending* with the error, never an orphan OS rule.
- Evaluation is first-match by priority. Windows applies any matching Block rule before Allow rules regardless of order; the packet tester warns when that changes the outcome.
- The monitor reports what the **policy** says about each observed connection. With `applyToOS` off, a connection the policy denies can still be established, and the event log says so.
- Loopback traffic is tracked but not scored, as OS firewalls exempt it.

## Security notes

- Passwords: PBKDF2-SHA512 (210k iterations). No default credentials; the first admin password is random and must be changed.
- Sessions: HttpOnly, SameSite=Strict cookies, CSRF token on every write, Origin check against DNS rebinding, login rate limiting and lockout.
- Strict CSP. The console has no inline scripts and renders untrusted data (log lines, process names, addresses) as text only.
- OS commands run without a shell, from an allow-list of executables, with validated arguments.
- The audit chain is tamper-*evident*, not tamper-*proof*: ship `logs/audit.log` to a SIEM or WORM storage if you need stronger guarantees.

## Development

```bash
npm test                    # unit tests
npm run test:integration    # starts a real server on an ephemeral port with a temp data dir
npm run test:all
```

The tests never touch `data/`, `logs/` or the host firewall.

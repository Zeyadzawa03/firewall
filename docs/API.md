# SentryFW REST API

The console GUI and any script use the same API. Every route declares the permission it needs; the server enforces authentication, CSRF and role checks from that declaration. `GET /api` returns the live route list.

## Authentication

Sessions are cookie-based. Sign in, keep the cookie, and send the returned CSRF token on every state-changing request.

```bash
# Sign in (stores the HttpOnly session cookie in cookies.txt)
curl -s -c cookies.txt -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"…"}' http://127.0.0.1:8787/api/auth/login
# → {"user":{…},"csrf":"<token>","expiresAt":"…","mustChangePassword":false}

# Read (no CSRF needed)
curl -s -b cookies.txt http://127.0.0.1:8787/api/rules

# Write (CSRF header required)
curl -s -b cookies.txt -H "X-SentryFW-CSRF: <token>" -H 'Content-Type: application/json' \
     -d '{"name":"Allow HTTPS","direction":"inbound","action":"allow","protocol":"tcp","dstPort":"443"}' \
     http://127.0.0.1:8787/api/rules
```

| Endpoint | Purpose |
|---|---|
| `POST /api/auth/login` | `{username, password}` → session cookie + `csrf` token. Rate-limited; repeated failures lock the account for `security.loginLockoutSeconds`. |
| `POST /api/auth/logout` | Ends the session. |
| `GET /api/auth/session` | Current session, or `{authenticated:false, requireAuth}`. Returns the CSRF token again after a page reload. |
| `GET /api/events/stream` | Server-sent events (`event: log`) with every new event-log entry. Needs `logs:read`. |

A session created with a one-time password (first run, `fwctl user reset`, or an admin reset) can only call `GET /api/account` and `POST /api/account/password` until the password is changed; everything else returns `403 PASSWORD_CHANGE_REQUIRED`.

## Roles

| Role | Can |
|---|---|
| `admin` | Everything, including users, settings and restores. |
| `operator` | Rules, OS apply/sync, blocklist, monitoring, backups (read), logs. |
| `auditor` | Read-only access to everything including the audit trail. No writes. |

## Conventions

- **Errors** always use one envelope: `{"error":{"code":"VALIDATION_ERROR","message":"…","details":[{"field":"dstPort","message":"…"}],"requestId":"req_…"}}`. Codes include `VALIDATION_ERROR` (400), `UNAUTHENTICATED` (401), `FORBIDDEN` / `PASSWORD_CHANGE_REQUIRED` / `PRIVILEGE_REQUIRED` (403), `NOT_FOUND` (404), `CONFLICT` (409), `RATE_LIMITED` (429, with `Retry-After`), `PROVIDER_ERROR` (502).
- **Destructive calls** (delete a rule, apply all, repair drift, import, restore, delete a user or backup) answer `409 CONFLICT` with `details.requiresConfirmation: true` unless the body contains `"confirm": true` (or `?confirm=true`). Disable with `security.requireConfirmForDestructive`.
- **Reasons**: any mutating body may include `"reason": "…"`; it is stored in the audit trail.
- **Path parameters** are URL-encoded. A CIDR blocklist entry is removed with `DELETE /api/blocklist/10.0.0.0%2F8`.
- **Lists** accept `limit` and `offset` and return `{ total, offset, limit, <items> }`.
- **Cross-origin** state-changing requests are refused (`Origin` must match `Host`).

## Rule object

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | string | — | Required, unique (case-insensitive), ≤ 96 chars. |
| `description` | string | `""` | ≤ 400 chars. |
| `direction` | `inbound` \| `outbound` | `inbound` | |
| `action` | `allow` \| `deny` | `deny` | |
| `protocol` | `tcp` \| `udp` \| `icmp` \| `icmpv6` \| `any` | `any` | Ports are only valid with `tcp`/`udp`. |
| `srcAddress`, `dstAddress` | address spec | `any` | `any`, an IP, a CIDR, `a.b.c.d-e.f.g.h`, or a comma list (≤ 32). |
| `srcPort`, `dstPort` | port spec | `any` | `any`, `443`, `8000-8100`, `80,443,8080-8090`. Ports are 1–65535. |
| `iface` | string | `any` | Interface alias. |
| `profiles` | list | `["Any"]` | Windows profiles: `Domain`, `Private`, `Public`, `Any`. |
| `program` | path | `""` | Absolute executable path (Windows application rules). |
| `priority` | 1–65535 | `100` | Lower is evaluated first; first match wins. |
| `enabled` | boolean | `true` | |
| `tags` | list | `[]` | ≤ 16 tags of `[A-Za-z0-9_.-]`. |

Read-only fields added by the server: `id`, `createdAt/By`, `updatedAt/By`, `revision`, `osRuleName`, `osApplied`, `osLastError`, `hitCount`, `lastHitAt`.

Create and update responses are `{ rule, os }`, where `os` reports what happened in the operating system firewall (`{ ok, skipped, reason }` when `firewall.applyToOS` is off, `{ ok:false, error, hint }` on failure). A rule is always saved first; an OS failure leaves it marked pending rather than losing it.

## Routes

### General

| Method | Path | Permission |
|---|---|---|
| GET | `/api` | public |
| GET | `/api/health` | public |
| GET | `/api/system` | settings:read |
| GET | `/api/dashboard` | traffic:read |

### Rules

| Method | Path | Permission |
|---|---|---|
| GET | `/api/rules` | rules:read |
| GET | `/api/rules/stats` | rules:read |
| GET | `/api/rules/analysis` | rules:read |
| POST | `/api/rules/preview` | rules:read |
| POST | `/api/rules/test` | rules:read |
| GET | `/api/rules/schema` | rules:read |
| GET | `/api/rules/:id` | rules:read |
| POST | `/api/rules` | rules:write |
| PATCH | `/api/rules/:id` | rules:write |
| DELETE | `/api/rules/:id` | rules:write |
| POST | `/api/rules/:id/enable` | rules:write |
| POST | `/api/rules/:id/disable` | rules:write |
| POST | `/api/rules/reorder` | rules:write |
| POST | `/api/rules/apply` | rules:apply |
| POST | `/api/rules/sync` | rules:apply |
| GET | `/api/rules/os/list` | rules:read |
| GET | `/api/rules/export/json` | backup:read |
| POST | `/api/rules/import` | backup:write |

### Traffic

| Method | Path | Permission |
|---|---|---|
| GET | `/api/traffic/connections` | traffic:read |
| GET | `/api/traffic/stats` | traffic:read |
| GET | `/api/traffic/series` | traffic:read |
| GET | `/api/traffic/listeners` | traffic:read |
| GET | `/api/traffic/interfaces` | traffic:read |
| GET | `/api/traffic/monitor` | traffic:read |
| POST | `/api/traffic/sample` | traffic:read |
| POST | `/api/traffic/monitor/start` | settings:write |
| POST | `/api/traffic/monitor/stop` | settings:write |

### Detection

| Method | Path | Permission |
|---|---|---|
| GET | `/api/detection/findings` | logs:read |
| GET | `/api/detection/summary` | logs:read |
| POST | `/api/detection/findings/:id/acknowledge` | logs:read |

### Blocklist

| Method | Path | Permission |
|---|---|---|
| GET | `/api/blocklist` | blocklist:read |
| GET | `/api/blocklist/stats` | blocklist:read |
| POST | `/api/blocklist` | blocklist:write |
| DELETE | `/api/blocklist/:target` | blocklist:write |
| POST | `/api/blocklist/import` | blocklist:write |
| GET | `/api/blocklist/check/:ip` | blocklist:read |

### Event log

| Method | Path | Permission |
|---|---|---|
| GET | `/api/logs` | logs:read |
| GET | `/api/logs/stats` | logs:read |
| GET | `/api/logs/export` | logs:export |

### Audit trail

| Method | Path | Permission |
|---|---|---|
| GET | `/api/audit` | audit:read |
| GET | `/api/audit/stats` | audit:read |
| GET | `/api/audit/verify` | audit:read |
| GET | `/api/audit/export` | audit:read |

### Settings & providers

| Method | Path | Permission |
|---|---|---|
| GET | `/api/settings` | settings:read |
| PATCH | `/api/settings` | settings:write |
| GET | `/api/providers` | settings:read |
| GET | `/api/providers/status` | settings:read |

### Backups

| Method | Path | Permission |
|---|---|---|
| GET | `/api/backups` | backup:read |
| POST | `/api/backups` | backup:write |
| GET | `/api/backups/export` | backup:read |
| GET | `/api/backups/:filename` | backup:read |
| DELETE | `/api/backups/:filename` | backup:write |
| POST | `/api/backups/validate` | backup:read |
| POST | `/api/backups/restore` | backup:write |

### Users & sessions

| Method | Path | Permission |
|---|---|---|
| GET | `/api/users` | users:read |
| POST | `/api/users` | users:write |
| PATCH | `/api/users/:username` | users:write |
| DELETE | `/api/users/:username` | users:write |
| GET | `/api/sessions` | users:read |
| POST | `/api/account/password` | rules:read |
| GET | `/api/account` | rules:read |

### Quick hardening

| Method | Path | Permission |
|---|---|---|
| GET | `/api/scenarios` | rules:read |
| POST | `/api/scenarios/:id` | rules:write |

## Examples

```bash
H='Content-Type: application/json'; X="X-SentryFW-CSRF: $CSRF"; B=http://127.0.0.1:8787

# What would happen to RDP from the internet?
curl -s -b cookies.txt -H "$X" -H "$H" -d '{"direction":"inbound","protocol":"tcp","srcAddress":"203.0.113.7","dstPort":"3389"}' $B/api/rules/test

# Block a network for 24 hours
curl -s -b cookies.txt -H "$X" -H "$H" -d '{"target":"198.51.100.0/24","reason":"scanner","ttlHours":24}' $B/api/blocklist

# Disable a rule, then delete it
curl -s -b cookies.txt -H "$X" -X POST $B/api/rules/rule_abc123/disable
curl -s -b cookies.txt -H "$X" -H "$H" -X DELETE -d '{"confirm":true,"reason":"change #42"}' $B/api/rules/rule_abc123

# Export the event log as CSV
curl -s -b cookies.txt "$B/api/logs/export?format=csv&level=warn,error" -o events.csv
```

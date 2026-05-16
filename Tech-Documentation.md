# SendQ-Relay — Technical Reference (for AI & human maintainers)

This document is the authoritative internal reference for the SendQ-Relay
codebase. It is intended for engineers and AI assistants who need to
understand, modify, or extend the platform. Treat the source as ground
truth; this file is a curated map and explainer.

## Update protocol (read first)

**This document MUST be updated as part of any change that:**

- Adds, removes, or renames a module, CLI command, dashboard endpoint,
  or config key.
- Changes the mail flow (inbound, queueing, signing, delivery).
- Changes on-disk state (config layout, queue spool, key files,
  pidfiles, log files).
- Changes signals, IPC, or how a running daemon is reloaded.
- Changes a default behaviour an operator could depend on (signing,
  retry, validation, permissions).
- Introduces a non-obvious gotcha worth recording.

Update rule: every PR that touches `src/`, `pyproject.toml`,
`config/`, or `systemd/` must touch this file in the same commit, or
explicitly justify in the commit message why no update is needed
("docs: N/A — internal refactor, no observable change"). The
**Recent fixes & gotchas** section is the running changelog of
non-obvious behaviour; append to it; do not silently rewrite history.

When in doubt: longer is fine. The cost of stale docs is much higher
than the cost of an extra paragraph.

---

## 1. What this is

SendQ-Relay (package name `sendq-mta`, CLI `sendq-mta`) is an
async-IO SMTP MTA. It accepts mail on standard SMTP ports, queues it
to disk, and either relays through an upstream smarthost or delivers
directly to recipient MX hosts. Out of the box it supports SMTP AUTH,
TLS (STARTTLS + implicit), DKIM signing, SPF/DMARC checks, per-IP
rate limiting, a Prometheus metrics endpoint, and a Flask-based web
dashboard. The package targets Python 3.11+ on Linux with systemd.

Top-level public surface:

| Layer            | Entry point                                           |
| ---              | ---                                                   |
| CLI              | `sendq-mta` → `sendq_mta.cli.main:main`               |
| SMTP server      | `sendq_mta.core.server.MTAServer`                     |
| Dashboard        | `sendq_mta.dashboard.app:app` (Flask)                 |
| Mgmt HTTP API    | `sendq_mta.core.management.ManagementAPI` (UNIX sock) |
| Prometheus       | `sendq_mta.core.metrics`                              |

---

## 2. Repository layout

```
SendQ-relay/
├── pyproject.toml              package metadata, deps (dkimpy is CORE)
├── README.md                   end-user oriented; do NOT duplicate here
├── SendQ-MTA_Documentation.pdf user manual; lags the code
├── generate_docs.py            regenerates the PDF
├── config/
│   ├── sendq-mta.yml           shipped sample config
│   ├── users.yml               sample user DB
│   └── aliases.yml             sample aliases
├── systemd/
│   └── sendq-mta.service       hardened unit (User=sendq, ProtectSystem=strict)
├── scripts/                    installer / uninstaller / packagers
├── tests/                      pytest suite (asyncio_mode=auto)
└── src/sendq_mta/
    ├── __main__.py             python -m sendq_mta → cli.main:main
    ├── auth/
    │   ├── authenticator.py    Argon2 user store, YAML-backed
    │   ├── dkim.py             DKIMSigner (per-domain) + DKIMVerifier
    │   ├── spf.py              SPF check wrapper (optional dep: pyspf)
    │   └── dmarc.py            DMARC policy lookup
    ├── cli/main.py             click app: every operator command
    ├── core/
    │   ├── config.py           defaults + load/save + atomic IO + validate
    │   ├── server.py           aiosmtpd-based SMTP listener wrapper
    │   ├── management.py       UNIX-socket admin endpoint
    │   ├── metrics.py          Prometheus exporter
    │   └── rate_limiter.py     per-IP / per-user / per-domain limits
    ├── dashboard/
    │   ├── app.py              Flask app + REST API
    │   └── templates/          Jinja templates
    ├── queue/
    │   └── manager.py          QueueManager + QueueMessage + worker loop
    ├── transport/
    │   ├── delivery.py         DeliveryEngine: relay or direct MX
    │   └── connection_pool.py  outbound SMTP connection reuse
    └── utils/logging_setup.py  JSON + line logging
```

---

## 3. Process & runtime model

One `sendq-mta start` process owns:

1. **The aiosmtpd listeners** (one Controller per `listeners[]` entry).
   Each listener binds a port and routes connections through
   `SendQHandler`.
2. **A pool of N async delivery workers** (`queue.workers`, default 16),
   each pulling from an in-memory `asyncio.Queue` populated by the
   handler and by `_load_existing_queue()` at startup.
3. **Background tasks**: metrics exporter, dashboard (only if
   `dashboard` subcommand is used), management socket.

Signals:

| Signal     | Behaviour                                                                                                          |
| ---        | ---                                                                                                                |
| `SIGINT/SIGTERM` | Graceful shutdown. Cancel workers, drain queue.                                                              |
| `SIGHUP`   | `Config.reload()`, `authenticator._load_users()`, **`queue_manager.reload_dkim_signer()`**. Wired in `core/server.py:_reload_handler`. |
| `SIGUSR1`  | `queue_manager.reload_active_queue()` — pick up messages dropped into the spool by external tools or `flush-queue`. |

There is no internal scheduler beyond asyncio; nothing depends on a
periodic cron-like loop.

---

## 4. Mail flow end-to-end

```
client SMTP
    │
    ▼
core.server.SendQHandler  (handle_MAIL → handle_RCPT → handle_DATA)
    │  validates AUTH, blocked/local/relay domains, message size, rate limits
    ▼
queue.QueueManager.enqueue()
    │  writes <msg_id>.meta.json + <msg_id>.eml under queue.directory
    │  pushes QueueMessage onto in-memory asyncio.Queue
    ▼
queue.QueueManager._delivery_worker (one of N)
    │  reads self._dkim_signer per message (so SIGHUP reloads take effect)
    │  if signer.enabled and msg.sender has @domain:
    │      msg.data = dkim_signer.sign(msg.data, sender_domain.lower())
    │  → engine.deliver(msg)
    ▼
transport.DeliveryEngine.deliver()
    │  if relay.enabled:  _deliver_via_relay() with failover[]
    │  else:              _deliver_direct() via DNS MX lookup
    │
    ▼   either path uses _send_smtp() → aiosmtplib.SMTP.sendmail(...)
    │   SSRF guard: _validate_relay_host() refuses 127/8, 10/8, 172.16/12,
    │   192.168/16, 169.254/16, ::1, fc00::/7, fe80::/10, and ipv4-mapped
    │   forms thereof.
    │
    ▼
on success:  remove <msg_id>.* from queue.directory, _stats["delivered"]++
on failure:  move to queue.failed_directory, _stats["failed"]++
             (NO retry — failures are terminal; see queue/manager.py:170)
```

`msg.data` is bytes throughout. The on-disk `.eml` is the **unsigned**
original; signing happens in-memory right before delivery. There is no
way to inspect the signed bytes from disk — capture at the receiving
end if you need to see what went on the wire.

---

## 5. Module reference

### `auth/dkim.py` — `DKIMSigner`, `DKIMVerifier`

- One `DKIMSigner` instance lives on `QueueManager._dkim_signer`. It
  is rebuilt by `reload_dkim_signer()` (called at `start_workers()`
  and on every SIGHUP).
- `dkimpy` import is wrapped in `try/except`; missing package sets
  `DKIM_AVAILABLE=False` and the signer disables itself with a loud
  log line. `dkimpy` is now a **core dependency** in
  `pyproject.toml`.
- Per-domain keys: loaded from a dict `_keys: {domain: privkey_bytes}`.
  Key resolution per domain in `_resolve_key_path()` order:
  1. Explicit `dkim.keys[domain]` mapping
  2. Naming convention `<dkim.key_dir>/<domain>.<selector>.private.pem`
  3. Legacy `dkim.key_file` (only when **exactly one** signing domain
     is configured)
- Missing key for one domain does NOT disable the signer for others;
  it logs an error for that domain and continues.
- Sender-domain matching is **case-insensitive** but **not
  subdomain-aware**. `From: x@mail.example.com` will NOT be signed by
  a `example.com` key — operators must list each domain explicitly.
- The signature is produced by `dkim.sign(...)` from dkimpy with
  default canonicalization (`relaxed/simple`) and the configured
  `headers_to_sign` list. The returned `b"DKIM-Signature: ...\r\n"`
  header is prepended to the message.
- `algorithm` config field is currently advisory only — it's read into
  `self._algorithm` but never passed to `dkim.sign()`, which defaults
  to `rsa-sha256`. Switching to Ed25519 requires plumbing
  `signature_algorithm` through.

### `auth/authenticator.py` — internal Argon2 user DB

- YAML-backed at `auth.users_file`. `_save_users()` uses
  `core.config.atomic_write_yaml` (atomic; preserves `<file>.bak`).
- `_load_users()` is called on init, on SIGHUP, and on first auth
  attempt if file mtime changed (so dashboard/CLI user changes are
  picked up without a restart).

### `auth/spf.py`, `auth/dmarc.py`

Optional dependencies (`pyspf`, etc.). Inbound checks only — they
gate `handle_RCPT`/`handle_DATA` based on policy
(`spf.hard_fail_action`, `dmarc.reject_action`).

### `core/config.py`

- `DEFAULTS` is the source of truth for the default schema.
  User-supplied YAML is `_deep_merge`d into it on load.
- `Config.get("dotted.path", default)` and `Config.set(...)` for
  dotted access.
- `validate()` returns a list of error strings; `validate_or_exit()`
  prints and `sys.exit(1)`s. It checks: listener present,
  hostname set, queue workers ≥ 1, auth backend valid, DKIM
  prerequisites (signing_domains + one of key_dir/key_file/keys +
  dkimpy importable when enabled).
- **Atomic writes**: `atomic_write_yaml(path, data, mode)` writes to
  a same-directory temp file, `fsync`s, `os.replace`s into place, and
  snapshots the previous contents to `<path>.bak`. Used by both
  `Config.save()` and `Authenticator._save_users()`.
- **Friendly parse errors**: `_safe_load_yaml(path)` catches
  `yaml.YAMLError`, extracts `problem_mark`, renders three lines of
  context around the failure, and `raise SystemExit(...)` with the
  exact `file:line:col` and rollback hint if `.bak` is good. No more
  buried stack traces on a malformed config.

### `core/server.py` — `MTAServer`

- Builds one aiosmtpd `Controller` per `listeners[]` entry.
- `_build_ssl_context()` resolves cert/key, auto-generating a
  "snakeoil" self-signed cert on first run via `_generate_snakeoil()`.
- `SendQHandler` enforces: rate limits, trusted networks for
  no-auth relay, blocked domains, local/relay domain routing,
  max message size, AUTH for external rcpts.
- Hot-reload of `Listeners` is NOT supported. Changing `listeners[]`
  requires a full restart.

### `core/management.py` — `ManagementAPI`

UNIX-domain socket at `/var/run/sendq-mta/mgmt.sock`. Trivially
parseable JSON line protocol for tools that don't want HTTP. CLI
commands like `stop`, `reload`, `status` use it.

### `core/rate_limiter.py`

Token-bucket per IP/user/domain with a separate "bans" table that
records consecutive errors and locks an IP out for
`rate_limiting.ban_duration` seconds.

### `core/metrics.py`

Prometheus `aiohttp` exporter at `metrics.prometheus.address:port`.
Exposes counters from `QueueManager.get_stats()` and
`RateLimiter.get_stats()`.

### `queue/manager.py` — `QueueManager`, `QueueMessage`

- On-disk layout:
  ```
  queue.directory/   <msg_id>.meta.json   <msg_id>.eml
  queue.failed_directory/  same
  queue.deferred_directory/  legacy; no longer written to (no-retry mode)
  ```
- `_safe_msg_id()` guards against path traversal via crafted IDs.
- Message IDs: `sendq-<hex16>-<unix_ts>`. Reused as the `Message-ID`
  for outgoing test-send mails.
- **No retries.** Failed deliveries are moved to `failed_directory`
  once; ops decide whether to manually re-flush. This is intentional
  (commit `866a5ac`) — backoff was deleted because it caused
  amplification under upstream outages.
- `_delivery_worker` reads `self._dkim_signer` **per message** so
  SIGHUP-driven signer rebuilds reach already-running workers.
- `reload_dkim_signer()` is also called from `core/server.py`
  SIGHUP handler; never raises (on failure, sets signer to None and
  logs).

### `transport/delivery.py` — `DeliveryEngine`

- Relay mode: tries `relay.host:port` with creds; on exception walks
  `relay.failover[]` in order. SSRF guard rejects relay hosts that
  resolve to private/loopback.
- Direct mode: groups recipients by domain, resolves MX (falls back to
  A on `NoAnswer`), tries hosts in priority order.
- DNS uses `dns.resolver.Resolver` with system config; if none, falls
  back to `["8.8.8.8", "1.1.1.1", "9.9.9.9"]`.
- Outbound TLS: `opportunistic` STARTTLS for direct MX,
  `relay.tls_mode` for relay (`starttls` | `implicit` | `none`).
  `relay.tls_verify=true` makes STARTTLS failures fatal.
- 5xx SMTP responses propagate as exceptions so the caller can mark
  failure-permanent; 4xx returns False to try the next host.

### `transport/connection_pool.py` — `ConnectionPool`

Currently **instantiated but unused** (`delivery.py:81`). Each
`_send_smtp()` opens a fresh `aiosmtplib.SMTP`. Wiring it in is
TBD; do not assume connections are reused.

### `cli/main.py`

Click app. See **CLI reference** below.

### `dashboard/app.py`

Flask app with two surfaces:
- HTML at `/`, `/dashboard/*` — Jinja templates in `dashboard/templates/`
- JSON API under `/api/*` — feature toggles, relay edit, log view,
  user CRUD, etc.

Writes go through `_save_and_reload()`, which calls
`Config.save()` (atomic) and `os.kill(pid, SIGHUP)` to the running
server. PID file path is `server.pid_file` (default
`/var/run/sendq-mta/sendq-mta.pid`).

Sensitive fields (`relay.password`, etc.) are masked to `********`
on read and substituted with the persisted value on write
(`app.py:655`).

---

## 6. Configuration schema (key paths)

Highlights only — read `core/config.py:DEFAULTS` for the full tree.

```
server:
  hostname: <required>
  bind_address: 0.0.0.0
  banner: "SendQ-MTA Enterprise ESMTP"
  max_message_size: 52428800
  trusted_networks: []          # IPs/CIDRs allowed to relay without AUTH
  pid_file: /var/run/sendq-mta/sendq-mta.pid
  user: sendq                   # used by generate-dkim for chown

listeners:
  - port: 25         tls: starttls   require_auth: false
  - port: 587        tls: starttls   require_auth: true
  - port: 465        tls: implicit   require_auth: true

tls:
  cert_file: ...
  key_file:  ...

auth:
  backend: internal             # only "internal" wired today
  users_file: /etc/sendq-mta/users.yml
  password_hash: argon2         # bcrypt also supported if [bcrypt] extra
  require_auth_for_relay: true

domains:
  local_domains: []
  relay_domains: []
  blocked_domains: []
  alias_file: /etc/sendq-mta/aliases.yml

queue:
  workers: 16
  directory:          /var/spool/sendq-mta/queue
  failed_directory:   /var/spool/sendq-mta/failed
  deferred_directory: /var/spool/sendq-mta/deferred   # legacy

relay:
  enabled: false
  host: ""
  port: 587
  tls_mode: starttls            # starttls | implicit | none
  tls_verify: true
  failover: []                  # [{host, port, username, password, tls_mode}]
  connection_pool:
    enabled: true               # pool currently NOT used by delivery.py

dkim:
  enabled: false
  selector: sendq
  key_dir: /etc/sendq-mta/dkim                # auto-discovery root
  key_file: ""                                # legacy single-domain only
  keys: {}                                    # explicit {domain: path} map
  signing_domains: []
  headers_to_sign: [From, To, Subject, Date, Message-ID, MIME-Version, Content-Type]
  algorithm: rsa-sha256                       # advisory; not yet wired through
  key_bits: 2048

spf:    {enabled: true,  hard_fail_action: reject, ...}
dmarc:  {enabled: true,  reject_action: reject, ...}

logging:
  level: info
  file: /var/log/sendq-mta/sendq-mta.log
  format: json                  # also writes line-format alongside

metrics:
  enabled: true
  prometheus: {enabled: true, address: 127.0.0.1, port: 9225}
```

---

## 7. DKIM in detail (because this is where the lifecycle bugs live)

This subsystem has been the source of several recurring bugs. Keep
this section honest.

### Multi-domain signing

- Each entry in `dkim.signing_domains` must have its own private key.
  The signer maintains a `dict[domain] → privkey_bytes`. Mail with
  `From: x@d` is signed with the key for `d` only.
- DNS verification requires the matching public key at
  `<selector>._domainkey.<domain>` for **each** signing domain. The
  `generate-dkim` CLI writes the exact TXT record to
  `<key_dir>/<domain>.<selector>.dns.txt`.

### Naming convention

`generate-dkim -d <domain> -s <selector>` writes:
- `<output_dir>/<domain>.<selector>.private.pem` (PKCS#8 RSA, mode
  0o640, chowned to `server.user` when run as root)
- `<output_dir>/<domain>.<selector>.dns.txt`

It then sets `dkim.enabled=true`, `dkim.key_dir=<output_dir>`,
appends the lowercased domain to `dkim.signing_domains`, and SIGHUPs
the running daemon via `server.pid_file`.

**It does NOT write `dkim.key_file`.** That field is preserved for
back-compat with single-domain configs; the new code never touches it.

### Lifecycle / reload semantics

- `DKIMSigner` lives on `QueueManager._dkim_signer`, rebuilt by
  `QueueManager.reload_dkim_signer()`.
- That method is called from `start_workers()` and from the SIGHUP
  handler in `core/server.py`. So `dashboard` toggle and
  `generate-dkim` both take effect without a process restart.
- Workers read `self._dkim_signer` per message (NOT at coroutine
  start), so an in-flight worker picks up the new signer for its next
  message.

### Failure modes and what's logged

Every state has a deterministic log line you should grep for in
`/var/log/sendq-mta/sendq-mta.log`:

| Condition                                            | Log level | Message                                                                                  |
| ---                                                  | ---       | ---                                                                                      |
| dkimpy missing                                       | ERROR     | `DKIM enabled but 'dkimpy' package not installed ... `                                   |
| No signing_domains                                   | ERROR     | `DKIM enabled but dkim.signing_domains is empty ...`                                     |
| Per-domain key file missing                          | ERROR     | `No DKIM key for <domain> — expected <path> (or set dkim.keys.<domain>). ... UNSIGNED.`  |
| Per-domain key unreadable                            | ERROR     | `Cannot read DKIM key <path> for <domain>: ... UNSIGNED`                                 |
| All keys loaded                                      | INFO      | `DKIM signing enabled (selector=..., signed_domains=[...])`                              |
| Signer ended up inactive but config asked for it     | WARNING   | `dkim.enabled=true but DKIM signing is INACTIVE ... Outbound mail will be sent UNSIGNED` |
| SIGHUP                                               | INFO      | `Reloaded users and DKIM signer after SIGHUP`                                            |

### Things `DKIMSigner` deliberately does NOT do

- Subdomain matching. `mail.example.com` needs its own key.
- Re-sign already-signed mail (relays may add their own; we add ours
  on top — both can coexist).
- Verify outbound signatures.
- Handle Ed25519 keys — the algorithm field is read but not wired.
- Sign bounces (empty `From:` / `<>` sender).

---

## 8. State on disk (where things live)

| Path                                        | Owner    | Notes                                                |
| ---                                         | ---      | ---                                                  |
| `/etc/sendq-mta/sendq-mta.yml`              | root     | main config; `<path>.bak` is the previous version    |
| `/etc/sendq-mta/users.yml`                  | sendq    | argon2 hashes; mode 0o600                            |
| `/etc/sendq-mta/aliases.yml`                | sendq    | optional rewrite rules                               |
| `/etc/sendq-mta/dkim/*.private.pem`         | sendq    | mode 0o640; **must be readable by service user**     |
| `/etc/sendq-mta/dkim/*.dns.txt`             | sendq    | helper file for ops; not used by the server         |
| `/etc/sendq-mta/certs/snakeoil.{pem,key}`   | sendq    | auto-generated self-signed fallback                  |
| `/var/spool/sendq-mta/queue/`               | sendq    | active messages (`.meta.json` + `.eml`)              |
| `/var/spool/sendq-mta/failed/`              | sendq    | permanently failed messages                          |
| `/var/spool/sendq-mta/deferred/`            | sendq    | legacy, empty in no-retry mode                       |
| `/var/log/sendq-mta/sendq-mta.log`          | sendq    | both JSON and line-format records                    |
| `/var/run/sendq-mta/sendq-mta.pid`          | sendq    | written by `start --foreground` and daemon mode      |
| `/var/run/sendq-mta/mgmt.sock`              | sendq    | UNIX-socket admin API                                |
| `/var/lib/sendq-mta/`                       | sendq    | reserved (currently unused)                          |

Atomic-write convention: `Config.save()` and `Authenticator._save_users()`
write a `<file>.tmp.<random>` in the same dir, fsync, then `os.replace`.
A copy of the previous good file is preserved at `<file>.bak`. This is
implemented once in `core.config.atomic_write_yaml`.

---

## 9. Operational concerns (systemd)

`systemd/sendq-mta.service` runs as `User=sendq` with:

```
ProtectSystem=strict   ProtectHome=yes   PrivateTmp=yes
NoNewPrivileges=yes    AmbientCapabilities=CAP_NET_BIND_SERVICE
ReadWritePaths=/var/spool/sendq-mta /var/log/sendq-mta /var/run/sendq-mta
              /var/lib/sendq-mta /etc/sendq-mta/certs
```

Consequences:

- `/etc/sendq-mta/` is **read-only** to the service. Configuration
  changes from the **service itself** (e.g. `_save_and_reload()` from
  the dashboard) are NOT possible — but the dashboard is typically run
  as a separate process (often as the operator user via
  `sendq-mta dashboard`).
- `/etc/sendq-mta/dkim/` is read-only to the service but writable to
  root. Keys created by `generate-dkim` (run as root) must be readable
  by `sendq`. `generate-dkim` now does this `chown sendq:sendq` +
  `chmod 0640` automatically when invoked as root.
- The hardening blocks WRITES, not reads. Reads from any path under
  `/etc/sendq-mta/` work as long as standard POSIX perms permit.

---

## 10. CLI reference

Implemented in `cli/main.py`. Every command takes `-c/--config <path>`
to point at a non-default config.

| Command          | Purpose                                                           |
| ---              | ---                                                               |
| `start [-f]`     | Daemonize unless `-f` (foreground). Writes pidfile.               |
| `stop`           | SIGTERM via pidfile.                                              |
| `restart`        | stop + start.                                                     |
| `status`         | Reports process running + queue/listener stats.                   |
| `reload`         | SIGHUP via pidfile.                                               |
| `list/add/edit/delete/show-user`, `change-pass` | User management.                                                  |
| `list/add/remove-domain`         | Edits `domains.local_domains` / `relay_domains` / `blocked_domains`. |
| `queue-status`                   | Lists queued/failed messages.                                     |
| `flush-queue`                    | Picks up messages dropped into the spool dir externally. SIGUSR1. |
| `delete-msg <id>`, `purge-failed`| Removes from the spool.                                           |
| `validate-config`                | Runs `Config.validate()`; non-zero exit on error.                 |
| `show-config [section]`          | Dumps merged config as YAML.                                      |
| `test-relay`                     | Connects to `relay.host:port` and exercises EHLO/STARTTLS/AUTH.   |
| `test-send --to <addr>`          | Sends a small MIME message via local `localhost:25`. Goes through the full queue and signing path. |
| `generate-dkim -d <domain>`      | Creates key pair + DNS TXT, updates config, SIGHUPs daemon.       |
| `dashboard`                      | Launches the Flask dashboard (separate process).                  |

---

## 11. Dashboard

- `sendq-mta dashboard` runs `flask` against `dashboard/app.py`.
- API key auto-generated on first launch (commit `628917e`) and stored
  in `management_api.http.api_key`. Browser auth uses the same key as
  a cookie/header (`b5301c4`).
- All writes go through `_save_and_reload()` → `Config.save()` (atomic)
  → `SIGHUP` to the daemon.
- Feature toggles map (`api/features/toggle`):
  `dkim`→`dkim.enabled`, `spf`→`spf.enabled`, `dmarc`→`dmarc.enabled`,
  `rate_limiting`→`rate_limiting.enabled`.

---

## 12. Tests

```
tests/
├── test_auth.py          internal authenticator + Argon2 verification
├── test_config.py        defaults + merge + dotted set/get + validate
└── test_rate_limiter.py  token bucket + ban table
```

Run with `pytest tests/` (asyncio_mode=auto is set in pyproject). There
are NO end-to-end SMTP tests and NO DKIM tests today — exercise the
mail path manually with `test-send` and mail-tester.com when changing
DKIM or delivery code.

---

## 13. Recent fixes & gotchas (running changelog of non-obvious behaviour)

Append a dated entry whenever you fix a non-obvious bug or change a
default. Newest first.

- **2026-05-16 (commit `966888c`)** — `Config.save()` and
  `Authenticator._save_users()` are now atomic via
  `core.config.atomic_write_yaml`. Previously a non-atomic write could
  truncate the file on Ctrl-C / concurrent dashboard+CLI saves; the
  resulting buried `yaml.ParserError` stack trace was the cause of an
  earlier outage. `_safe_load_yaml` renders human-readable parse
  errors and surfaces the `<path>.bak` rollback command when
  available.
- **2026-05-16 (commit `39d7199`)** — DKIM moved from a single
  `dkim.key_file` (which could only sign one domain at a time) to a
  per-domain `dict[domain] → privkey`. Keys are auto-discovered via
  the `<domain>.<selector>.private.pem` naming convention under
  `dkim.key_dir`. `dkim.keys` is an optional explicit override map;
  `dkim.key_file` is preserved as legacy fallback only when exactly
  one signing domain is configured. `generate-dkim` no longer
  clobbers `dkim.key_file` on each invocation.
- **2026-05-16 (commit `86ac587`)** — `dkimpy` moved from optional
  `[dkim]` extra into base dependencies. The earlier "graceful
  degrade" path hid the fact that a default `pip install sendq-mta`
  produced an MTA where DKIM was a no-op. `validate-config` now
  errors out when `dkim.enabled=true` and `dkimpy` is not
  importable. `QueueManager.reload_dkim_signer()` logs a loud
  `WARNING` when the config asked for DKIM but the signer ended up
  inactive — surfaces missing-key, missing-package, perm-error
  uniformly.
- **2026-05-16 (commit `dee14ea`)** — SIGHUP now rebuilds the
  in-memory `DKIMSigner` (`reload_dkim_signer()` on the queue
  manager). Workers read `self._dkim_signer` per message instead of
  capturing it at coroutine start, so flipping `dkim.enabled` via
  the dashboard or running `generate-dkim` on a live server now
  takes effect without restarting the daemon. `generate-dkim` sends
  the SIGHUP automatically after `config.save()`.
- **2026-05-16 (commit `ca071c7`)** — `DKIMSigner.__init__` wraps the
  key-file read in `try/except` and disables itself instead of
  killing the worker on `PermissionError`. `signing_domains` are
  normalized to lowercase. `generate-dkim` chowns the key to
  `server.user` (default `sendq`) when run as root and uses mode
  `0o640` so the daemon can actually read it. (The original symptom
  was: every worker died silently on startup, the queue filled, no
  mail was sent.)

Older milestones (from `git log`):

- `866a5ac` — Retry/deferred logic removed. Failures are terminal.
- `d44fecf` — IPv6-mapped IPv4 SSRF bypass closed in delivery.py
  (`_check_addr_blocked` unwraps `::ffff:`).
- `f42705f` — SSRF protection added to dashboard's relay-test and
  MX delivery (private/loopback hosts refused).
- `06be5ee` — Production hardening pass (11 fixes across 6 files).

---

## 14. Conventions

- **No retries.** Anywhere. Delivery failures are terminal. Don't
  re-introduce backoff loops without explicit design discussion —
  upstream-outage amplification is the reason it was removed.
- **Direct edits are atomic.** Any new write to
  `/etc/sendq-mta/` or `/var/lib/sendq-mta/` should route through
  `atomic_write_yaml` or an equivalent rename-based helper.
- **Reloads use SIGHUP.** Anything that should survive a config flip
  belongs in `core/server.py:_reload_handler`. Workers must not
  cache state across messages that the user can change at runtime.
- **Logging.** `logging.getLogger("sendq-mta.<area>")`. JSON
  formatter is the prod default; line formatter is mirrored.
- **No emojis in code, logs, or commit messages.**
- **No `*.md` docs added except this file
  (`Tech-Documentation.md`) and `README.md`.** The PDF is generated;
  do not hand-edit it. Future AI sessions: read this file at the
  start of every session that touches the codebase. Symlink it as
  `CLAUDE.md` if you want Claude Code to auto-load it
  (`ln -s Tech-Documentation.md CLAUDE.md`).
- **Commit messages**: explain the *why*. Keep the first line under
  72 chars and avoid the word "complex."

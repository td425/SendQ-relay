# SendQ-Relay

Enterprise-grade Mail Transfer Agent for Linux. High-performance async SMTP server with relay support, DKIM/SPF/DMARC authentication, persistent queue, connection pooling, rate limiting, and a built-in web management dashboard.

## Features

- **High-Traffic Engine** — Async I/O (asyncio + aiosmtpd), worker pool delivery, connection pooling
- **SMTP Relay** — Route outbound mail through upstream SMTP relay (smarthost) with failover
- **Direct MX Delivery** — DNS MX lookup for direct delivery when relay is disabled
- **Persistent Queue** — Disk-backed queue with configurable retry intervals and exponential backoff
- **DKIM Signing** — RSA-SHA256 / Ed25519-SHA256 message signing
- **SPF Checking** — Sender Policy Framework verification on inbound mail
- **DMARC Enforcement** — Policy-based reject/quarantine/tag on alignment failures
- **TLS** — STARTTLS (ports 25, 587) and implicit TLS (port 465), TLS 1.2+ enforced
- **Rate Limiting** — Per-IP, per-domain, per-user, and global rate controls
- **User Management** — CLI and web-based user CRUD with Argon2/bcrypt password hashing
- **Web Dashboard** — Full management UI with realtime meters, log viewer, health checks, relay/failover management, feature toggles, and configuration editor
- **YAML Configuration** — Single config file for all settings, hot-reloadable (SIGHUP)
- **Self Health Check** — Automated checks for ports, TLS certificates, DNS, relay connectivity, outbound delivery, and queue directories
- **Prometheus Metrics** — Built-in metrics exporter for monitoring
- **Systemd Integration** — Hardened service unit with security policies

## Quick Start

```bash
# Install
sudo bash scripts/install.sh

# Configure
sudo nano /etc/sendq-mta/sendq-mta.yml

# Add domain and user
sendq-mta add-domain example.com
sendq-mta add-user admin

# Generate DKIM keys
sendq-mta generate-dkim -d example.com

# Validate and start
sendq-mta validate-config
sudo systemctl enable --now sendq-mta

# Launch the web dashboard
sendq-mta dashboard
```

## Web Dashboard

SendQ-MTA ships with a separately-versioned web management portal (`sendq_dashboard` package) for full control over the mail server.

### Install

```bash
pip install 'sendq-mta[dashboard]'
```

This pulls in Flask, pyotp (TOTP), and qrcode. The MTA itself runs fine without the dashboard installed.

### First-time setup

```bash
# 1. Create the first admin (interactive password prompt). No default admin is
#    auto-created — the dashboard refuses logins until at least one exists.
sudo sendq-mta portal-user add admin --role admin

# 2. Enable the dashboard service so it boots automatically (recommended).
sudo systemctl enable --now sendq-dashboard
# → http://0.0.0.0:8443  (plain HTTP — terminate TLS on your reverse proxy)

# 3. From your browser, log in. Admin accounts must enroll TOTP on first login;
#    scan the QR code with any authenticator app (Aegis, 1Password, Authy, etc.).
```

### Managing the dashboard daemon

The dashboard is a long-running service, controllable either through systemd or directly via the CLI:

```bash
# systemd (preferred for production)
sudo systemctl start   sendq-dashboard
sudo systemctl stop    sendq-dashboard
sudo systemctl restart sendq-dashboard
sudo systemctl status  sendq-dashboard

# Equivalent CLI commands (work even on hosts without systemd)
sudo sendq-mta dashboard start          # daemonize into background
sudo sendq-mta dashboard stop           # SIGTERM the running daemon
sudo sendq-mta dashboard restart
sudo sendq-mta dashboard status
sudo sendq-mta dashboard start -f       # foreground (no daemonize)
sudo sendq-mta dashboard run            # foreground (the systemd entry point)
```

The PID file lives at `/var/run/sendq-mta/dashboard.pid` (configurable via `dashboard.pid_file`). Logs go to `/var/log/sendq-mta/dashboard.log`.

### Deployment model — terminate TLS upstream

The dashboard listens on **plain HTTP** by design. Put a reverse proxy in front of it (commonly an nginx box separate from the MTA host) to terminate TLS:

```nginx
server {
    listen 443 ssl http2;
    server_name mta-admin.example.com;
    ssl_certificate     /etc/letsencrypt/live/mta-admin/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mta-admin/privkey.pem;

    location / {
        proxy_pass http://<mta-host>:8443;
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host  $host;
    }
}
```

Then in the MTA host's `sendq-mta.yml`:

```yaml
dashboard:
  bind_address: 0.0.0.0
  port: 8443
  cookie_secure: true       # session cookies require HTTPS — flip to false ONLY
                            # if you intentionally serve the dashboard over HTTP
                            # (local testing without a TLS proxy in front).
  trusted_proxies:
    - 10.0.0.5/32          # the nginx box's IP — only this peer is allowed to
                            # supply X-Forwarded-* headers (anti-spoofing).
  admin_ip_allowlist:
    - 10.0.0.0/24          # admin API routes refuse traffic from any other
                            # client IP (after X-Forwarded-For resolution).
  session_timeout_minutes: 30
  history_retention_days: 30
  audit_retention_days: 365
  sqlite_path: /var/lib/sendq-mta/dashboard.db
```

**Critical**: configure your firewall so port 8443 on the MTA host accepts traffic **only** from the nginx box's IP. With `trusted_proxies` empty, `X-Forwarded-For` is ignored and the dashboard uses the direct peer IP everywhere.

#### Testing over plain HTTP (no nginx in front yet)

If you point your browser directly at `http://<mta-host>:8443` for testing, the login form will appear to do nothing — submitting credentials redirects you back to `/login`. That's because the session cookie is set with the `Secure` attribute, so the browser refuses to send it back over plain HTTP. Two ways to resolve:

```yaml
# Option A (recommended): put a TLS proxy in front and list its IP in
# trusted_proxies — production behavior.

# Option B: for local-only HTTP testing, disable the Secure flag.
dashboard:
  cookie_secure: false
```

The dashboard prints a startup warning if it detects this misconfiguration (Secure cookies enabled, no trusted proxies, non-loopback bind).

### Roles

- **Admin** — full CRUD over MTA users, portal users, domains, configuration, DKIM, relay, queue. TOTP is mandatory; the first login forces enrollment.
- **User** — read-only. Sees only messages and log lines for the domains assigned to them by an admin. Cannot reach admin API routes (HTTP 403).

### Portal user CLI

```bash
sendq-mta portal-user add <name> --role admin
sendq-mta portal-user add <name> --role user --domain example.com --domain other.com
sendq-mta portal-user list
sendq-mta portal-user set-password <name>
sendq-mta portal-user disable-totp <name>   # lost-phone recovery
sendq-mta portal-user delete <name>
```

Portal users live in `/etc/sendq-mta/portal-users.yml` (mode `0600`). They are completely separate from SMTP-AUTH users (`/etc/sendq-mta/users.yml`) — a portal user has no SMTP send rights, and an SMTP user cannot log into the dashboard.

### Dashboard panels

- **Dashboard** — Realtime meters (active / deferred / failed queue), server state, feature chips, listener overview.
- **Messages** — Indexed, filterable message history with per-message timeline: receive → each delivery attempt (host, SMTP code, response) → final state. Status badges colour-coded green / amber / red / blue / grey.
- **Raw logs** — Tail of the structured log file with level + substring filtering and 5-second auto-refresh.
- **Queue** — Browse / delete in-flight queue files.
- **Domains** — Add/remove local, relay, blocked domains.
- **DKIM** — Per-domain key listing with DNS TXT record display, key generation, key removal, signing toggle.
- **MTA users** — SMTP-AUTH user CRUD (unchanged from before).
- **Portal users** — Dashboard login accounts; assign domains; reset password; disable TOTP; enable/disable.
- **Relay** — Edit relay host/port/auth/TLS and test connectivity.
- **Configuration** — Every config key rendered as a labelled form field (text / number / dropdown / checkbox / multitext). Saves trigger an immediate hot-reload via SIGHUP.
- **Health** — Process, listener, port checks at a glance.

### Storage

| Data | Backend |
|---|---|
| Portal users, roles, TOTP, lockout, domain assignments | YAML (`portal-users.yml`, mode 0600) |
| Message history, delivery attempts, audit log | SQLite (WAL mode) at `/var/lib/sendq-mta/dashboard.db` |
| MTA config, SMTP users, queue spool, DKIM PEM files | Unchanged — YAML/files |

SQLite handles ~30k msgs/day comfortably with indexes; no separate database service required. The MTA daemon never blocks on the dashboard DB — history events are written from a background thread.

### Security defaults

- Argon2id password hashing (reused from the existing `Authenticator`).
- Per-account exponential lockout (5 → 1 min, 10 → 5 min, 20 → 1 h, 30 → 24 h); per-IP rolling 5-minute lockout at 30 failed attempts.
- TOTP/2FA mandatory for admins.
- Session cookies: `HttpOnly`, `Secure`, `SameSite=Strict`, configurable idle timeout.
- CSRF token required on every state-changing request.
- Strict `Content-Security-Policy` with `script-src 'self'`.
- `Cache-Control: no-store` on every `/api/*` response so edits show up without a hard refresh.
- IP allowlist on admin-only routes.
- Audit log of every admin action in `audit_log` table.

## CLI Reference

### Server Control

```bash
sendq-mta start              # Start the server (daemonize)
sendq-mta start -f           # Start in foreground
sendq-mta stop               # Stop the server
sendq-mta restart             # Restart the server
sendq-mta status              # Show server status
sendq-mta reload              # Reload config (SIGHUP)
sendq-mta dashboard           # Launch web management dashboard
```

### User Management

```bash
sendq-mta list-users                         # List all users
sendq-mta add-user <username>                # Add user (prompts for password)
sendq-mta add-user <username> -p <password>  # Add user with password
sendq-mta edit-user <username> --email new@example.com
sendq-mta edit-user <username> --enable      # Enable user
sendq-mta edit-user <username> --disable     # Disable user
sendq-mta delete-user <username>             # Delete user
sendq-mta change-pass <username>             # Change password
sendq-mta show-user <username>               # Show user details
```

### Domain Management

```bash
sendq-mta list-domains                       # List all domains
sendq-mta add-domain example.com             # Add local domain
sendq-mta add-domain relay.com --type relay  # Add relay domain
sendq-mta remove-domain example.com          # Remove domain
```

### Queue Management

```bash
sendq-mta queue-status              # Show queue counts
sendq-mta queue-status -v           # Show all queued messages
sendq-mta flush-queue               # Delete all messages from active & deferred queues
sendq-mta flush-queue -y            # Delete without confirmation prompt
sendq-mta delete-msg <msg-id>       # Delete specific message
sendq-mta purge-failed              # Delete all permanently failed messages
```

### Configuration

```bash
sendq-mta validate-config           # Validate config file
sendq-mta show-config               # Show full config (secrets redacted)
sendq-mta show-config -s relay      # Show specific section
sendq-mta test-relay                # Test SMTP relay connectivity
```

### DKIM

```bash
sendq-mta generate-dkim -d example.com              # Generate DKIM keypair
sendq-mta generate-dkim -d example.com -s mail2025   # Custom selector
sendq-mta generate-dkim -d example.com -b 4096       # 4096-bit key
```

### Testing

```bash
sendq-mta test-send --to user@example.com            # Send a test email
sendq-mta test-send --to user@example.com -p 587     # Via submission port
```

## Configuration

The main configuration file is at `/etc/sendq-mta/sendq-mta.yml`. Key sections:

### SMTP Relay

```yaml
relay:
  enabled: true
  host: "smtp.mailprovider.com"
  port: 587
  username: "your-username"
  password: "your-password"
  auth_method: "auto"
  tls_mode: "starttls"        # starttls | implicit | none
  tls_verify: true
  connection_pool_size: 20
  failover:
    - host: "backup-smtp.provider.com"
      port: 587
      username: "backup-user"
      password: "backup-pass"
      tls_mode: "starttls"
```

### Listeners

```yaml
listeners:
  - name: "smtp"
    address: "0.0.0.0"
    port: 25
    tls_mode: "starttls"
    require_auth: false

  - name: "submission"
    address: "0.0.0.0"
    port: 587
    tls_mode: "starttls"
    require_auth: true

  - name: "smtps"
    address: "0.0.0.0"
    port: 465
    tls_mode: "implicit"
    require_auth: true
```

### Rate Limiting

```yaml
rate_limiting:
  enabled: true
  inbound:
    max_connections_per_ip: 50
    max_messages_per_ip_per_minute: 100
  outbound:
    max_messages_per_domain_per_minute: 200
    max_messages_per_second: 500
  per_user:
    max_messages_per_hour: 500
```

See the full [config/sendq-mta.yml](config/sendq-mta.yml) for all options.

## Architecture

```
Client  -->  [SMTP Listener]  -->  [Auth + SPF + Rate Limit]
                                          |
                                          v
                                    [DKIM Signing]
                                          |
                                          v
                                  [Persistent Queue]
                                          |
                                   +------+------+
                                   v              v
                            [Relay Mode]    [Direct MX]
                            (Smarthost)     (DNS Lookup)
                                   |              |
                                   v              v
                              [Connection Pool -> Delivery Workers]
                                          |
                                   Success / Retry / Bounce

Web Dashboard (port 8225)
   |
   +-- REST API --> Config, Queue, Users, Domains, Relay, Logs, Health
```

## Installation

### From source

```bash
git clone https://github.com/sendq-mta/sendq-mta.git
cd sendq-mta
pip install -e '.[full]'
```

### Optional extras

```bash
pip install 'sendq-mta[dkim]'       # DKIM signing support
pip install 'sendq-mta[spf]'        # SPF checking support
pip install 'sendq-mta[dashboard]'  # Web management dashboard (Flask)
pip install 'sendq-mta[full]'       # All optional dependencies
```

## Requirements

- Linux (systemd)
- Python 3.11+
- TLS certificate (for STARTTLS/SMTPS)

## Documentation

A comprehensive PDF documentation covering installation, configuration, all CLI commands, troubleshooting, and FAQ is available. Generate it with:

```bash
python generate_docs.py
```

## Author

**Zabith Siraj** — hello@zabith.in

## License

MIT License — Copyright (c) 2026 Zabith Siraj. See [LICENSE](LICENSE) for details.

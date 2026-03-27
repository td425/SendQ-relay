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

SendQ-MTA ships with a built-in web management dashboard for full control over the mail server.

```bash
# Start the dashboard (default: http://0.0.0.0:8225)
sendq-mta dashboard

# Custom host and port
sendq-mta dashboard -H 127.0.0.1 -p 9000
```

Install the dashboard dependency:

```bash
pip install 'sendq-mta[dashboard]'
```

### Dashboard Panels

- **Dashboard** — Realtime meters showing active, deferred, and failed queue counts; server status; listener overview; feature status chips
- **Queue** — Browse, filter, and delete queued messages across active/deferred/failed queues; flush entire queue; purge failed messages
- **Users** — Full user CRUD: add, edit, delete users; change passwords; set quotas and send limits; enable/disable accounts
- **Domains** — Manage local, relay, and blocked domains
- **Relay & Failover** — Configure primary SMTP relay settings (host, port, TLS, auth); add/edit/remove failover relays; test relay connectivity; toggle relay on/off
- **Configuration** — Section-by-section config editor with auto-generated forms; edit any config key; changes auto-saved and hot-reloaded
- **Logs** — Realtime log viewer with filtering by level, search text, IP from, IP to, mail from, mail to; sortable ascending/descending; auto-refresh
- **Health Check** — 9 automated infrastructure checks: server process, listener ports, queue directories, TLS certificate expiry, relay connectivity, DNS resolution, log file writability, config validation, outbound port 25 reachability

### Feature Toggles

Toggle DKIM, SPF, DMARC, and rate limiting on/off directly from the dashboard. Changes take effect immediately via hot-reload.

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

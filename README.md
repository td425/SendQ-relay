# SendQ-MTA

Enterprise-grade Mail Transfer Agent for Linux. High-performance async SMTP server with relay support, DKIM/SPF/DMARC authentication, persistent queue, connection pooling, and rate limiting.

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
- **User Management** — CLI-based user CRUD with Argon2/bcrypt password hashing
- **YAML Configuration** — Single config file for all settings, hot-reloadable (SIGHUP)
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
```

## CLI Reference

### Server Control

```bash
sendq-mta start              # Start the server (daemonize)
sendq-mta start -f           # Start in foreground
sendq-mta stop               # Stop the server
sendq-mta restart             # Restart the server
sendq-mta status              # Show server status
sendq-mta reload              # Reload config (SIGHUP)
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
sendq-mta flush-queue               # Retry all deferred messages now
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
Client  ──>  [SMTP Listener]  ──>  [Auth + SPF + Rate Limit]
                                          │
                                          v
                                    [DKIM Signing]
                                          │
                                          v
                                  [Persistent Queue]
                                          │
                                   ┌──────┴──────┐
                                   v              v
                            [Relay Mode]    [Direct MX]
                            (Smarthost)     (DNS Lookup)
                                   │              │
                                   v              v
                              [Connection Pool → Delivery Workers]
                                          │
                                   Success / Retry / Bounce
```

## Requirements

- Linux (systemd)
- Python 3.11+
- TLS certificate (for STARTTLS/SMTPS)

## License

MIT

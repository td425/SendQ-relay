#!/usr/bin/env bash
# ============================================================================
# SendQ-MTA Installation Script
# ============================================================================
# Usage: sudo bash scripts/install.sh
# ============================================================================
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; }

INSTALL_PREFIX="/usr/local"
CONFIG_DIR="/etc/sendq-mta"
DATA_DIR="/var/lib/sendq-mta"
SPOOL_DIR="/var/spool/sendq-mta"
LOG_DIR="/var/log/sendq-mta"
RUN_DIR="/var/run/sendq-mta"
SERVICE_USER="sendq"
SERVICE_GROUP="sendq"

# ============================================================================
# Preflight checks
# ============================================================================
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (sudo)."
    exit 1
fi

log "SendQ-MTA Installation"
echo "=============================================="

# Check Python version
PYTHON_BIN=""
for py in python3.13 python3.12 python3.11 python3; do
    if command -v "$py" &>/dev/null; then
        ver=$("$py" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$major" -ge 3 && "$minor" -ge 11 ]]; then
            PYTHON_BIN="$py"
            break
        fi
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    err "Python 3.11+ is required but not found."
    err "Install it with: apt install python3.11 python3.11-venv  (Debian/Ubuntu)"
    err "                 dnf install python3.11                   (RHEL/Fedora)"
    exit 1
fi

log "Using Python: $PYTHON_BIN ($($PYTHON_BIN --version 2>&1))"

# ============================================================================
# Create system user/group
# ============================================================================
if ! getent group "$SERVICE_GROUP" &>/dev/null; then
    log "Creating system group: $SERVICE_GROUP"
    groupadd --system "$SERVICE_GROUP"
fi

if ! id "$SERVICE_USER" &>/dev/null; then
    log "Creating system user: $SERVICE_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --gid "$SERVICE_GROUP" "$SERVICE_USER"
fi

# ============================================================================
# Create directories
# ============================================================================
log "Creating directories..."

mkdir -p "$CONFIG_DIR/certs"
mkdir -p "$CONFIG_DIR/dkim"
mkdir -p "$DATA_DIR"
mkdir -p "$SPOOL_DIR/queue"
mkdir -p "$SPOOL_DIR/deferred"
mkdir -p "$SPOOL_DIR/failed"
mkdir -p "$LOG_DIR"
mkdir -p "$RUN_DIR"

chown "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR"
chown "$SERVICE_USER:$SERVICE_GROUP" "$SPOOL_DIR" "$SPOOL_DIR/queue" "$SPOOL_DIR/deferred" "$SPOOL_DIR/failed"
chown "$SERVICE_USER:$SERVICE_GROUP" "$LOG_DIR"
chown "$SERVICE_USER:$SERVICE_GROUP" "$RUN_DIR"
chmod 750 "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR/dkim"

# ============================================================================
# Generate snakeoil TLS certificate (self-signed, for immediate use)
# ============================================================================
SNAKEOIL_CERT="$CONFIG_DIR/certs/snakeoil.pem"
SNAKEOIL_KEY="$CONFIG_DIR/certs/snakeoil.key"

if [[ ! -f "$SNAKEOIL_CERT" || ! -f "$SNAKEOIL_KEY" ]]; then
    log "Generating snakeoil self-signed TLS certificate..."

    # Detect hostname for the certificate CN/SAN
    SYSTEM_HOSTNAME="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo 'localhost')"

    openssl req -x509 -newkey rsa:2048 \
        -keyout "$SNAKEOIL_KEY" \
        -out "$SNAKEOIL_CERT" \
        -days 3650 \
        -nodes \
        -subj "/CN=$SYSTEM_HOSTNAME/O=SendQ-MTA/OU=Mail Server" \
        -addext "subjectAltName=DNS:$SYSTEM_HOSTNAME,DNS:localhost,IP:127.0.0.1" \
        2>/dev/null

    chmod 600 "$SNAKEOIL_KEY"
    chmod 644 "$SNAKEOIL_CERT"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$SNAKEOIL_KEY" "$SNAKEOIL_CERT"

    log "Snakeoil cert generated: $SNAKEOIL_CERT (CN=$SYSTEM_HOSTNAME, valid 10 years)"
    warn "This is a self-signed certificate — replace with real certs for production."
else
    log "Snakeoil certificate already exists at $SNAKEOIL_CERT (not overwritten)"
fi

# ============================================================================
# Install Python package
# ============================================================================
log "Installing SendQ-MTA Python package..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Create virtual environment
VENV_DIR="$INSTALL_PREFIX/lib/sendq-mta"
if [[ ! -d "$VENV_DIR" ]]; then
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel 2>/dev/null
"$VENV_DIR/bin/pip" install "$SCRIPT_DIR[full]"

# Create symlinks for the CLI — both /usr/local/bin and /usr/bin
# Many systems (especially root shells) don't include /usr/local/bin in PATH
ln -sf "$VENV_DIR/bin/sendq-mta" "$INSTALL_PREFIX/bin/sendq-mta"
ln -sf "$VENV_DIR/bin/sendq-mta" "/usr/bin/sendq-mta"
log "CLI installed at: /usr/bin/sendq-mta"

# Also ensure /usr/local/bin is in PATH for future sessions
PROFILE_LINE='export PATH="/usr/local/bin:$PATH"'
for profile_file in /etc/profile.d/sendq-mta.sh; do
    if [[ ! -f "$profile_file" ]]; then
        echo "#!/bin/sh" > "$profile_file"
        echo '# Added by SendQ-MTA installer — ensures /usr/local/bin is in PATH' >> "$profile_file"
        echo "$PROFILE_LINE" >> "$profile_file"
        chmod 644 "$profile_file"
        log "Added /usr/local/bin to PATH via $profile_file"
    fi
done

# ============================================================================
# Install configuration
# ============================================================================
if [[ ! -f "$CONFIG_DIR/sendq-mta.yml" ]]; then
    log "Installing default configuration..."
    cp "$SCRIPT_DIR/config/sendq-mta.yml" "$CONFIG_DIR/sendq-mta.yml"
    chmod 640 "$CONFIG_DIR/sendq-mta.yml"
    chown root:"$SERVICE_GROUP" "$CONFIG_DIR/sendq-mta.yml"
else
    warn "Configuration already exists at $CONFIG_DIR/sendq-mta.yml (not overwritten)"
fi

# Create empty users file
if [[ ! -f "$CONFIG_DIR/users.yml" ]]; then
    echo "users: {}" > "$CONFIG_DIR/users.yml"
    chmod 600 "$CONFIG_DIR/users.yml"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/users.yml"
fi

# Create empty aliases file
if [[ ! -f "$CONFIG_DIR/aliases.yml" ]]; then
    echo "aliases: {}" > "$CONFIG_DIR/aliases.yml"
    chmod 640 "$CONFIG_DIR/aliases.yml"
    chown root:"$SERVICE_GROUP" "$CONFIG_DIR/aliases.yml"
fi

# ============================================================================
# Install systemd service
# ============================================================================
log "Installing systemd service..."
cp "$SCRIPT_DIR/systemd/sendq-mta.service" /etc/systemd/system/sendq-mta.service
systemctl daemon-reload

# ============================================================================
# tmpfiles.d for /var/run persistence across reboots
# ============================================================================
cat > /etc/tmpfiles.d/sendq-mta.conf <<'TMPFILES'
d /var/run/sendq-mta 0755 sendq sendq -
TMPFILES

# ============================================================================
# Done
# ============================================================================
echo ""
echo "=============================================="
log "SendQ-MTA installed successfully!"
echo ""
echo -e "${CYAN}Next steps:${NC}"
echo ""
echo "  1. Edit configuration:"
echo "     sudo nano $CONFIG_DIR/sendq-mta.yml"
echo ""
echo "  2. Configure your SMTP relay (if using one):"
echo "     Set relay.enabled: true and fill in host/port/username/password"
echo ""
echo "  3. TLS is ready out of the box (snakeoil self-signed cert)."
echo "     For production, replace with real certs:"
echo "     sudo nano $CONFIG_DIR/sendq-mta.yml  # update tls.cert_file / tls.key_file"
echo ""
echo "  4. Add your first domain and user:"
echo "     sendq-mta add-domain example.com"
echo "     sendq-mta add-user admin"
echo ""
echo "  5. Generate DKIM keys (optional):"
echo "     sendq-mta generate-dkim -d example.com"
echo ""
echo "  6. Validate and start:"
echo "     sendq-mta validate-config"
echo "     sudo systemctl enable --now sendq-mta"
echo ""
echo "  7. Check status:"
echo "     sendq-mta status"
echo "     sudo systemctl status sendq-mta"
echo ""
echo "=============================================="

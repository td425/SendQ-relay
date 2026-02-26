#!/usr/bin/env bash
# ============================================================================
# SendQ-MTA Uninstall Script
# ============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[x]${NC} This script must be run as root (sudo)." >&2
    exit 1
fi

echo "=============================================="
echo "SendQ-MTA Uninstaller"
echo "=============================================="
echo ""

read -p "This will stop and remove SendQ-MTA. Continue? [y/N] " -r
if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Stop service
if systemctl is-active --quiet sendq-mta 2>/dev/null; then
    log "Stopping sendq-mta service..."
    systemctl stop sendq-mta
fi

if systemctl is-enabled --quiet sendq-mta 2>/dev/null; then
    log "Disabling sendq-mta service..."
    systemctl disable sendq-mta
fi

# Remove systemd unit
if [[ -f /etc/systemd/system/sendq-mta.service ]]; then
    log "Removing systemd service..."
    rm -f /etc/systemd/system/sendq-mta.service
    systemctl daemon-reload
fi

# Remove tmpfiles
rm -f /etc/tmpfiles.d/sendq-mta.conf

# Remove virtualenv
if [[ -d /usr/local/lib/sendq-mta ]]; then
    log "Removing Python environment..."
    rm -rf /usr/local/lib/sendq-mta
fi

# Remove CLI symlink
rm -f /usr/local/bin/sendq-mta

# Remove runtime dir
rm -rf /var/run/sendq-mta

log "Uninstall complete."
echo ""
warn "The following directories were NOT removed (may contain your data):"
echo "  - /etc/sendq-mta        (configuration)"
echo "  - /var/spool/sendq-mta  (mail queue)"
echo "  - /var/log/sendq-mta    (logs)"
echo "  - /var/lib/sendq-mta    (data)"
echo ""
echo "Remove them manually if no longer needed:"
echo "  sudo rm -rf /etc/sendq-mta /var/spool/sendq-mta /var/log/sendq-mta /var/lib/sendq-mta"
echo ""
warn "System user 'sendq' was NOT removed. Remove with: sudo userdel sendq"

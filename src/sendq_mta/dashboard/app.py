"""SendQ-MTA Web Dashboard — Flask application with full management API."""

import copy
import hmac
import html as html_mod
import json
import logging
import os
import signal
import socket
import subprocess
import ssl
import time
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from sendq_mta.core.config import Config
from sendq_mta.auth.authenticator import Authenticator
from sendq_mta.queue.manager import _safe_msg_id

logger = logging.getLogger("sendq-mta.dashboard")

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
)

# ── Globals initialised by ``init_app()`` ─────────────────────────────────
_config: Config | None = None
_auth: Authenticator | None = None
_api_key: str = ""


def init_app(config: Config) -> Flask:
    global _config, _auth, _api_key
    _config = config
    _auth = Authenticator(config)
    _api_key = config.get("management_api.http.api_key", "")
    return app


# ── API Key Authentication ────────────────────────────────────────────────

@app.before_request
def _require_api_key():
    """Enforce API key authentication on all endpoints except static page
    and a stripped-down health check."""
    # Allow the static dashboard HTML page without auth
    if request.path == "/" and request.method == "GET":
        return None
    # Allow a minimal health probe without auth (no sensitive data)
    if request.path == "/api/health" and request.method == "GET":
        return None

    if not _api_key:
        return jsonify({
            "status": "error",
            "message": "Dashboard API key not configured. "
                       "Set management_api.http.api_key in config.",
        }), 503

    # Accept key via Authorization: Bearer <key> or X-API-Key: <key>
    provided_key = ""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        provided_key = auth_header[7:]
    if not provided_key:
        provided_key = request.headers.get("X-API-Key", "")

    if not provided_key or not hmac.compare_digest(provided_key, _api_key):
        return jsonify({
            "status": "error",
            "message": "Invalid or missing API key",
        }), 401

    return None


@app.after_request
def _security_headers(response):
    """Add security headers and restrict CORS."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    # Deny all cross-origin requests
    response.headers["Access-Control-Allow-Origin"] = request.host_url.rstrip("/")
    response.headers["Access-Control-Allow-Headers"] = "Authorization, X-API-Key, Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE"
    return response


# ── Helpers ────────────────────────────────────────────────────────────────

def _get_pid() -> int | None:
    pid_file = _config.get("server.pid_file", "/var/run/sendq-mta/sendq-mta.pid")
    if not os.path.isfile(pid_file):
        return None
    try:
        with open(pid_file) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return pid
    except (ValueError, ProcessLookupError, PermissionError):
        return None


def _count_messages(d: str) -> int:
    if os.path.isdir(d):
        return sum(1 for f in os.listdir(d) if f.endswith(".meta.json"))
    return 0


def _list_messages(d: str) -> list[dict]:
    msgs: list[dict] = []
    if not os.path.isdir(d):
        return msgs
    for f in os.listdir(d):
        if not f.endswith(".meta.json"):
            continue
        try:
            with open(os.path.join(d, f)) as fh:
                meta = json.load(fh)
                meta["msg_id"] = f.replace(".meta.json", "")
                msgs.append(meta)
        except Exception:
            pass
    return msgs


def _delete_message_from_dirs(msg_id: str, dirs: list[str]) -> bool:
    # Defense-in-depth: validate msg_id to prevent path traversal
    _safe_msg_id(msg_id)
    for d in dirs:
        meta = os.path.join(d, f"{msg_id}.meta.json")
        eml = os.path.join(d, f"{msg_id}.eml")
        if os.path.exists(meta):
            os.unlink(meta)
            if os.path.exists(eml):
                os.unlink(eml)
            return True
    return False


def _all_queue_dirs() -> tuple[str, str, str]:
    q = _config.get("queue.directory", "/var/spool/sendq-mta/queue")
    d = _config.get("queue.deferred_directory", "/var/spool/sendq-mta/deferred")
    f = _config.get("queue.failed_directory", "/var/spool/sendq-mta/failed")
    return q, d, f


def _read_log_lines(n: int = 200) -> list[str]:
    log_file = _config.get("logging.file", "/var/log/sendq-mta/sendq-mta.log")
    if not os.path.isfile(log_file):
        return []
    try:
        result = subprocess.run(
            ["tail", "-n", str(n), log_file],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip().split("\n") if result.stdout.strip() else []
    except Exception:
        return []


def _check_port(host: str, port: int, timeout: float = 3.0) -> dict:
    """Check TCP connectivity to host:port."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return {"reachable": True, "error": None}
    except socket.timeout:
        return {"reachable": False, "error": "Connection timed out"}
    except ConnectionRefusedError:
        return {"reachable": False, "error": "Connection refused"}
    except socket.gaierror:
        return {"reachable": False, "error": "DNS resolution failed"}
    except Exception as e:
        return {"reachable": False, "error": str(e)}


def _check_tls(host: str, port: int, timeout: float = 5.0) -> dict:
    """Check TLS handshake and certificate validity."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                return {
                    "valid": True,
                    "subject": dict(x[0] for x in cert.get("subject", ())),
                    "issuer": dict(x[0] for x in cert.get("issuer", ())),
                    "expires": cert.get("notAfter", ""),
                    "error": None,
                }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"Certificate error: {e.verify_message}"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def _save_and_reload():
    """Save config and signal server to reload if running."""
    _config.save()
    pid = _get_pid()
    if pid:
        try:
            os.kill(pid, signal.SIGHUP)
        except ProcessLookupError:
            pass


# ── Pages ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── API: Status & Realtime Meters ──────────────────────────────────────────

@app.route("/api/status")
def api_status():
    q, d, f = _all_queue_dirs()
    pid = _get_pid()
    hostname = _config.get("server.hostname", "localhost")
    listeners = _config.get("listeners", [])
    relay = _config.get("relay", {})
    failover = relay.get("failover", [])

    return jsonify({
        "server": {
            "running": pid is not None,
            "pid": pid,
            "hostname": hostname,
            "version": "1.0.0",
        },
        "queue": {
            "active": _count_messages(q),
            "deferred": _count_messages(d),
            "failed": _count_messages(f),
        },
        "listeners": [
            {
                "name": l.get("name", "?"),
                "address": l.get("address", "0.0.0.0"),
                "port": l.get("port", 0),
                "tls_mode": l.get("tls_mode", "none"),
                "require_auth": l.get("require_auth", False),
            }
            for l in listeners
        ],
        "relay": {
            "enabled": relay.get("enabled", False),
            "host": relay.get("host", ""),
            "port": relay.get("port", 587),
            "tls_mode": relay.get("tls_mode", "starttls"),
            "has_credentials": bool(relay.get("username")),
            "failover_count": len(failover),
        },
        "features": {
            "dkim": _config.get("dkim.enabled", False),
            "spf": _config.get("spf.enabled", True),
            "dmarc": _config.get("dmarc.enabled", True),
            "rate_limiting": _config.get("rate_limiting.enabled", True),
        },
        "users_count": _auth.user_count if _auth else 0,
    })


# ── API: Server Control ───────────────────────────────────────────────────

@app.route("/api/server/<action>", methods=["POST"])
def api_server_action(action: str):
    pid = _get_pid()

    if action == "stop":
        if not pid:
            return jsonify({"status": "error", "message": "Server is not running"}), 400
        os.kill(pid, signal.SIGTERM)
        return jsonify({"status": "ok", "message": "Stop signal sent"})

    elif action == "reload":
        if not pid:
            return jsonify({"status": "error", "message": "Server is not running"}), 400
        os.kill(pid, signal.SIGHUP)
        return jsonify({"status": "ok", "message": "Reload signal sent"})

    elif action == "start":
        if pid:
            return jsonify({"status": "error", "message": "Server is already running"}), 400
        try:
            subprocess.Popen(["sendq-mta", "start"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return jsonify({"status": "ok", "message": "Start command issued"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    elif action == "restart":
        try:
            if pid:
                os.kill(pid, signal.SIGTERM)
                time.sleep(2)
            subprocess.Popen(["sendq-mta", "start"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return jsonify({"status": "ok", "message": "Restart command issued"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"status": "error", "message": f"Unknown action: {action}"}), 400


# ── API: Queue ─────────────────────────────────────────────────────────────

@app.route("/api/queue/list")
def api_queue_list():
    q, d, f = _all_queue_dirs()
    queue_type = request.args.get("type", "all")

    messages = []
    if queue_type in ("active", "all"):
        for m in _list_messages(q):
            m["queue"] = "active"
            messages.append(m)
    if queue_type in ("deferred", "all"):
        for m in _list_messages(d):
            m["queue"] = "deferred"
            messages.append(m)
    if queue_type in ("failed", "all"):
        for m in _list_messages(f):
            m["queue"] = "failed"
            messages.append(m)

    return jsonify({"status": "ok", "data": messages})


@app.route("/api/queue/flush", methods=["POST"])
def api_queue_flush():
    q, d, _f = _all_queue_dirs()
    count = 0
    for directory in (q, d):
        if os.path.isdir(directory):
            for f in os.listdir(directory):
                try:
                    os.unlink(os.path.join(directory, f))
                    if f.endswith(".meta.json"):
                        count += 1
                except OSError:
                    pass
    return jsonify({"status": "ok", "flushed": count})


@app.route("/api/queue/delete", methods=["POST"])
def api_queue_delete():
    msg_id = request.json.get("msg_id", "") if request.json else ""
    if not msg_id:
        return jsonify({"status": "error", "message": "msg_id required"}), 400
    try:
        _safe_msg_id(msg_id)
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid message ID"}), 400
    q, d, f = _all_queue_dirs()
    deleted = _delete_message_from_dirs(msg_id, [q, d, f])
    if deleted:
        return jsonify({"status": "ok", "deleted": True})
    return jsonify({"status": "error", "message": "Message not found"}), 404


@app.route("/api/queue/purge-failed", methods=["POST"])
def api_queue_purge_failed():
    f_dir = _config.get("queue.failed_directory", "/var/spool/sendq-mta/failed")
    count = 0
    if os.path.isdir(f_dir):
        for fname in os.listdir(f_dir):
            try:
                os.unlink(os.path.join(f_dir, fname))
                if fname.endswith(".meta.json"):
                    count += 1
            except OSError:
                pass
    return jsonify({"status": "ok", "purged": count})


# ── API: Users ─────────────────────────────────────────────────────────────

@app.route("/api/users")
def api_list_users():
    return jsonify({"status": "ok", "data": _auth.list_users()})


@app.route("/api/users", methods=["POST"])
def api_add_user():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"status": "error", "message": "username and password required"}), 400
    try:
        ok = _auth.add_user(
            username, password,
            email=data.get("email", ""),
            display_name=data.get("display_name", ""),
            quota_mb=int(data.get("quota_mb", 0)),
            send_limit_per_hour=int(data.get("send_limit_per_hour", 0)),
        )
        if not ok:
            return jsonify({"status": "error", "message": "User already exists"}), 409
        return jsonify({"status": "ok", "message": f"User '{username}' created"})
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route("/api/users/<username>", methods=["PUT"])
def api_edit_user(username: str):
    data = request.json or {}
    kwargs = {}
    for key in ("email", "display_name", "enabled", "quota_mb", "send_limit_per_hour"):
        if key in data:
            kwargs[key] = data[key]
    if not _auth.edit_user(username, **kwargs):
        return jsonify({"status": "error", "message": "User not found"}), 404
    return jsonify({"status": "ok", "message": f"User '{username}' updated"})


@app.route("/api/users/<username>", methods=["DELETE"])
def api_delete_user(username: str):
    if not _auth.delete_user(username):
        return jsonify({"status": "error", "message": "User not found"}), 404
    return jsonify({"status": "ok", "message": f"User '{username}' deleted"})


@app.route("/api/users/<username>/password", methods=["POST"])
def api_change_password(username: str):
    data = request.json or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"status": "error", "message": "password required"}), 400
    try:
        if not _auth.change_password(username, password):
            return jsonify({"status": "error", "message": "User not found"}), 404
        return jsonify({"status": "ok", "message": "Password changed"})
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400


# ── API: Domains ───────────────────────────────────────────────────────────

@app.route("/api/domains")
def api_list_domains():
    return jsonify({
        "status": "ok",
        "data": {
            "local": _config.get("domains.local_domains", []),
            "relay": _config.get("domains.relay_domains", []),
            "blocked": _config.get("domains.blocked_domains", []),
        },
    })


@app.route("/api/domains", methods=["POST"])
def api_add_domain():
    data = request.json or {}
    domain = data.get("domain", "").strip().lower()
    dtype = data.get("type", "local")
    if not domain:
        return jsonify({"status": "error", "message": "domain required"}), 400
    key = f"domains.{dtype}_domains"
    domains = list(_config.get(key, []))
    if domain in domains:
        return jsonify({"status": "error", "message": "Domain already exists"}), 409
    domains.append(domain)
    _config.set(key, domains)
    _save_and_reload()
    return jsonify({"status": "ok", "message": f"Domain '{domain}' added"})


@app.route("/api/domains/<domain>", methods=["DELETE"])
def api_remove_domain(domain: str):
    dtype = request.args.get("type", "local")
    key = f"domains.{dtype}_domains"
    domains = list(_config.get(key, []))
    if domain not in domains:
        return jsonify({"status": "error", "message": "Domain not found"}), 404
    domains.remove(domain)
    _config.set(key, domains)
    _save_and_reload()
    return jsonify({"status": "ok", "message": f"Domain '{domain}' removed"})


# ── API: Relay Management ─────────────────────────────────────────────────

@app.route("/api/relay")
def api_get_relay():
    relay = _config.get("relay", {})
    r = copy.deepcopy(relay)
    if r.get("password"):
        r["password"] = "********"
    for fo in r.get("failover", []):
        if fo.get("password"):
            fo["password"] = "********"
    return jsonify({"status": "ok", "data": r})


@app.route("/api/relay", methods=["PUT"])
def api_update_relay():
    data = request.json or {}
    for key in ("enabled", "host", "port", "username", "auth_method",
                "tls_mode", "tls_verify", "connection_pool_size", "max_connections"):
        if key in data:
            _config.set(f"relay.{key}", data[key])
    if "password" in data and data["password"] != "********":
        _config.set("relay.password", data["password"])
    _save_and_reload()
    return jsonify({"status": "ok", "message": "Relay configuration updated"})


@app.route("/api/relay/toggle", methods=["POST"])
def api_relay_toggle():
    current = _config.get("relay.enabled", False)
    _config.set("relay.enabled", not current)
    _save_and_reload()
    state = "enabled" if not current else "disabled"
    return jsonify({"status": "ok", "message": f"Relay {state}", "enabled": not current})


@app.route("/api/relay/failover")
def api_get_failover():
    failover = copy.deepcopy(_config.get("relay.failover", []))
    for fo in failover:
        if fo.get("password"):
            fo["password"] = "********"
    return jsonify({"status": "ok", "data": failover})


@app.route("/api/relay/failover", methods=["POST"])
def api_add_failover():
    data = request.json or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"status": "error", "message": "host is required"}), 400
    entry = {
        "host": host,
        "port": int(data.get("port", 587)),
        "username": data.get("username", ""),
        "password": data.get("password", ""),
        "tls_mode": data.get("tls_mode", "starttls"),
    }
    failover = list(_config.get("relay.failover", []))
    failover.append(entry)
    _config.set("relay.failover", failover)
    _save_and_reload()
    return jsonify({"status": "ok", "message": f"Failover relay '{host}' added"})


@app.route("/api/relay/failover/<int:idx>", methods=["PUT"])
def api_edit_failover(idx: int):
    failover = list(_config.get("relay.failover", []))
    if idx < 0 or idx >= len(failover):
        return jsonify({"status": "error", "message": "Invalid index"}), 404
    data = request.json or {}
    for key in ("host", "port", "username", "tls_mode"):
        if key in data:
            failover[idx][key] = data[key]
    if "password" in data and data["password"] != "********":
        failover[idx]["password"] = data["password"]
    _config.set("relay.failover", failover)
    _save_and_reload()
    return jsonify({"status": "ok", "message": "Failover relay updated"})


@app.route("/api/relay/failover/<int:idx>", methods=["DELETE"])
def api_delete_failover(idx: int):
    failover = list(_config.get("relay.failover", []))
    if idx < 0 or idx >= len(failover):
        return jsonify({"status": "error", "message": "Invalid index"}), 404
    removed = failover.pop(idx)
    _config.set("relay.failover", failover)
    _save_and_reload()
    return jsonify({"status": "ok", "message": f"Failover '{removed.get('host', '')}' removed"})


@app.route("/api/relay/test", methods=["POST"])
def api_test_relay():
    """Test connectivity to relay or a specific host."""
    data = request.json or {}
    host = data.get("host", _config.get("relay.host", ""))
    port = int(data.get("port", _config.get("relay.port", 587)))
    if not host:
        return jsonify({"status": "error", "message": "No relay host configured"}), 400
    result = _check_port(host, port, timeout=5.0)
    return jsonify({"status": "ok", "data": {"host": host, "port": port, **result}})


# ── API: Feature Toggles ──────────────────────────────────────────────────

@app.route("/api/features/toggle", methods=["POST"])
def api_toggle_feature():
    data = request.json or {}
    feature = data.get("feature", "")
    mapping = {
        "dkim": "dkim.enabled",
        "spf": "spf.enabled",
        "dmarc": "dmarc.enabled",
        "rate_limiting": "rate_limiting.enabled",
    }
    key = mapping.get(feature)
    if not key:
        return jsonify({"status": "error", "message": f"Unknown feature: {feature}"}), 400
    current = _config.get(key, False)
    _config.set(key, not current)
    _save_and_reload()
    state = "enabled" if not current else "disabled"
    return jsonify({"status": "ok", "message": f"{feature.upper()} {state}", "enabled": not current})


# ── API: Configuration Editing ─────────────────────────────────────────────

@app.route("/api/config")
def api_config():
    cfg = copy.deepcopy(_config.data)
    if "relay" in cfg and cfg["relay"].get("password"):
        cfg["relay"]["password"] = "********"
    for fo in cfg.get("relay", {}).get("failover", []):
        if fo.get("password"):
            fo["password"] = "********"
    if "auth" in cfg:
        cfg["auth"].pop("password_hash", None)
    return jsonify({"status": "ok", "data": cfg, "path": _config.path})


@app.route("/api/config/section/<section>")
def api_config_section(section: str):
    """Get a specific config section."""
    data = _config.get(section, {})
    result = copy.deepcopy(data) if isinstance(data, (dict, list)) else data
    if section == "relay" and isinstance(result, dict):
        if result.get("password"):
            result["password"] = "********"
        for fo in result.get("failover", []):
            if fo.get("password"):
                fo["password"] = "********"
    return jsonify({"status": "ok", "data": result})


@app.route("/api/config/section/<section>", methods=["PUT"])
def api_update_config_section(section: str):
    """Update a full config section."""
    data = request.json or {}
    # Prevent overwriting passwords with the mask
    if section == "relay":
        current = _config.get("relay", {})
        if data.get("password") == "********":
            data["password"] = current.get("password", "")
        for i, fo in enumerate(data.get("failover", [])):
            if fo.get("password") == "********":
                old_fo = current.get("failover", [])
                if i < len(old_fo):
                    fo["password"] = old_fo[i].get("password", "")
    _config.set(section, data)
    _save_and_reload()
    return jsonify({"status": "ok", "message": f"Section '{section}' updated"})


@app.route("/api/config/key", methods=["PUT"])
def api_update_config_key():
    """Update a single dotted config key."""
    data = request.json or {}
    key = data.get("key", "")
    value = data.get("value")
    if not key:
        return jsonify({"status": "error", "message": "key is required"}), 400
    _config.set(key, value)
    _save_and_reload()
    return jsonify({"status": "ok", "message": f"'{key}' updated"})


# ── API: Logs with Filtering ──────────────────────────────────────────────

@app.route("/api/logs")
def api_logs():
    n = min(int(request.args.get("lines", 200)), 2000)
    lines = _read_log_lines(n)

    # Apply filters
    level = request.args.get("level", "").lower()
    search = request.args.get("search", "").lower()
    ip_from = request.args.get("ip_from", "")
    ip_to = request.args.get("ip_to", "")
    mail_from = request.args.get("mail_from", "").lower()
    mail_to = request.args.get("mail_to", "").lower()

    if level or search or ip_from or ip_to or mail_from or mail_to:
        filtered = []
        for line in lines:
            ll = line.lower()
            if level and level not in ll:
                continue
            if search and search not in ll:
                continue
            if ip_from and ip_from not in line:
                continue
            if ip_to and ip_to not in line:
                continue
            if mail_from and mail_from not in ll:
                continue
            if mail_to and mail_to not in ll:
                continue
            filtered.append(line)
        lines = filtered

    sort_order = request.args.get("sort", "desc")
    if sort_order == "asc":
        pass  # already oldest-first from tail
    else:
        lines = list(reversed(lines))

    # Sanitize log lines to prevent XSS via crafted email headers
    sanitized = [html_mod.escape(line) for line in lines]
    return jsonify({"status": "ok", "data": sanitized, "total": len(sanitized)})


# ── API: Health Check ──────────────────────────────────────────────────────

@app.route("/api/health")
def api_health():
    """Comprehensive self-health check.

    When accessed without a valid API key (unauthenticated), returns only
    a minimal ``{"healthy": true/false}`` response to avoid leaking
    internal details to unauthenticated callers.
    """
    # Check if the caller is authenticated (health endpoint is exempt
    # from the before_request gate, but we still inspect the key here
    # to decide how much detail to return).
    authenticated = False
    if _api_key:
        provided = ""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            provided = auth_header[7:]
        if not provided:
            provided = request.headers.get("X-API-Key", "")
        if provided and hmac.compare_digest(provided, _api_key):
            authenticated = True

    checks = {}

    # 1. Server process
    pid = _get_pid()
    checks["server_process"] = {
        "ok": pid is not None,
        "detail": f"Running (PID {pid})" if pid else "Not running",
    }

    # 2. Listener ports
    listeners = _config.get("listeners", [])
    port_checks = []
    for l in listeners:
        name = l.get("name", "?")
        port = l.get("port", 0)
        addr = l.get("address", "0.0.0.0")
        bind_addr = "127.0.0.1" if addr == "0.0.0.0" else addr
        result = _check_port(bind_addr, port, timeout=2.0)
        port_checks.append({
            "name": name, "port": port, "address": addr,
            "ok": result["reachable"], "error": result["error"],
        })
    checks["listener_ports"] = port_checks

    # 3. Queue directories
    q, d, f = _all_queue_dirs()
    dir_checks = []
    for label, path in [("active", q), ("deferred", d), ("failed", f)]:
        exists = os.path.isdir(path)
        writable = os.access(path, os.W_OK) if exists else False
        dir_checks.append({
            "name": label, "path": path,
            "ok": exists and writable,
            "exists": exists, "writable": writable,
        })
    checks["queue_directories"] = dir_checks

    # 4. TLS certificate
    cert_file = _config.get("tls.cert_file", "")
    key_file = _config.get("tls.key_file", "")
    tls_ok = True
    tls_detail = ""
    if cert_file:
        if not os.path.isfile(cert_file):
            tls_ok = False
            tls_detail = f"Certificate file not found: {cert_file}"
        elif not os.path.isfile(key_file):
            tls_ok = False
            tls_detail = f"Key file not found: {key_file}"
        else:
            try:
                result = subprocess.run(
                    ["openssl", "x509", "-in", cert_file, "-checkend", "2592000", "-noout"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode != 0:
                    tls_detail = "Certificate expires within 30 days"
                    tls_ok = False
                else:
                    tls_detail = "Valid"
            except Exception:
                tls_detail = "Cannot verify"
    else:
        tls_detail = "No TLS configured"
        tls_ok = False
    checks["tls_certificate"] = {"ok": tls_ok, "detail": tls_detail}

    # 5. Relay connectivity
    relay = _config.get("relay", {})
    if relay.get("enabled") and relay.get("host"):
        rc = _check_port(relay["host"], relay.get("port", 587), timeout=5.0)
        checks["relay_connectivity"] = {
            "ok": rc["reachable"],
            "host": relay["host"],
            "port": relay.get("port", 587),
            "error": rc["error"],
        }
    else:
        checks["relay_connectivity"] = {
            "ok": True,
            "detail": "Relay disabled (direct MX delivery)",
        }

    # 6. DNS resolution
    dns_ok = True
    dns_detail = ""
    try:
        socket.getaddrinfo("gmail.com", 25, socket.AF_INET)
        dns_detail = "Working"
    except Exception as e:
        dns_ok = False
        dns_detail = f"DNS resolution failed: {e}"
    checks["dns_resolution"] = {"ok": dns_ok, "detail": dns_detail}

    # 7. Log file
    log_file = _config.get("logging.file", "/var/log/sendq-mta/sendq-mta.log")
    log_dir = os.path.dirname(log_file)
    log_ok = os.path.isdir(log_dir) and os.access(log_dir, os.W_OK)
    checks["log_file"] = {
        "ok": log_ok,
        "path": log_file,
        "detail": "Writable" if log_ok else "Directory not writable",
    }

    # 8. Config file
    config_ok = _config.path is not None and os.path.isfile(_config.path)
    errors = _config.validate() if config_ok else ["Config file not found"]
    checks["configuration"] = {
        "ok": config_ok and len(errors) == 0,
        "path": _config.path,
        "errors": errors,
    }

    # 9. Outbound port 25 (can we send mail?)
    outbound25 = _check_port("gmail-smtp-in.l.google.com", 25, timeout=5.0)
    checks["outbound_port_25"] = {
        "ok": outbound25["reachable"],
        "detail": "Can reach external MX" if outbound25["reachable"] else outbound25["error"],
    }

    # Overall
    all_ok = all(
        c.get("ok", True) if isinstance(c, dict) else all(x.get("ok", True) for x in c)
        for c in checks.values()
    )

    if not authenticated:
        # Minimal response for unauthenticated callers (load-balancer probes)
        return jsonify({"status": "ok", "healthy": all_ok})

    return jsonify({"status": "ok", "healthy": all_ok, "checks": checks})


# ── Run ────────────────────────────────────────────────────────────────────

def run_dashboard(config: Config, host: str = "127.0.0.1", port: int = 8225):
    """Start the dashboard web server."""
    init_app(config)

    api_key = config.get("management_api.http.api_key", "")
    if not api_key:
        logger.error(
            "Dashboard requires management_api.http.api_key to be set in config. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )
        raise SystemExit(
            "FATAL: management_api.http.api_key is not configured. "
            "The dashboard refuses to start without authentication."
        )
    if len(api_key) < 32:
        raise SystemExit(
            "FATAL: management_api.http.api_key must be at least 32 characters."
        )

    app.run(host=host, port=port, debug=False)

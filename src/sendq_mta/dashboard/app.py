"""SendQ-MTA Web Dashboard — Flask application."""

import json
import os
import signal
import subprocess
import time
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from sendq_mta.core.config import Config
from sendq_mta.auth.authenticator import Authenticator

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
)

# ── Globals initialised by ``init_app()`` ─────────────────────────────────
_config: Config | None = None
_auth: Authenticator | None = None


def init_app(config: Config) -> Flask:
    """Bind a loaded Config to the Flask app so routes can use it."""
    global _config, _auth
    _config = config
    _auth = Authenticator(config)
    return app


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


def _read_log_tail(n: int = 100) -> list[str]:
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


# ── Pages ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── API: Server ────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    q, d, f = _all_queue_dirs()
    pid = _get_pid()
    hostname = _config.get("server.hostname", "localhost")

    listeners = _config.get("listeners", [])
    relay = _config.get("relay", {})

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
        },
        "features": {
            "dkim": _config.get("dkim.enabled", False),
            "spf": _config.get("spf.enabled", True),
            "dmarc": _config.get("dmarc.enabled", True),
            "rate_limiting": _config.get("rate_limiting.enabled", True),
        },
        "users_count": _auth.user_count if _auth else 0,
    })


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
            subprocess.Popen(
                ["sendq-mta", "start"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return jsonify({"status": "ok", "message": "Start command issued"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    elif action == "restart":
        try:
            if pid:
                os.kill(pid, signal.SIGTERM)
                time.sleep(2)
            subprocess.Popen(
                ["sendq-mta", "start"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
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
    _config.save()
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
    _config.save()
    return jsonify({"status": "ok", "message": f"Domain '{domain}' removed"})


# ── API: Config ────────────────────────────────────────────────────────────

@app.route("/api/config")
def api_config():
    import copy
    cfg = copy.deepcopy(_config.data)
    # Redact secrets
    for section in ("relay",):
        if section in cfg and "password" in cfg[section]:
            cfg[section]["password"] = "********"
    if "auth" in cfg:
        cfg["auth"].pop("password_hash", None)
    return jsonify({"status": "ok", "data": cfg, "path": _config.path})


# ── API: Logs ──────────────────────────────────────────────────────────────

@app.route("/api/logs")
def api_logs():
    n = int(request.args.get("lines", 80))
    lines = _read_log_tail(min(n, 500))
    return jsonify({"status": "ok", "data": lines})


# ── Run ────────────────────────────────────────────────────────────────────

def run_dashboard(config: Config, host: str = "0.0.0.0", port: int = 8225):
    """Start the dashboard web server."""
    init_app(config)
    app.run(host=host, port=port, debug=False)

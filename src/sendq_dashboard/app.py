"""SendQ-Dashboard — Flask app with session login, RBAC, CSRF, and SQLite logs.

Replaces the old API-key-only dashboard. Listens on plain HTTP behind a
reverse-proxy that terminates TLS (e.g. nginx on a separate host).
"""

from __future__ import annotations

import copy
import hmac
import html as html_mod
import ipaddress
import json
import logging
import os
import secrets
import signal
import socket
import ssl
import subprocess
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import (
    Flask, abort, g, jsonify, redirect, render_template,
    request, session, url_for,
)

from sendq_mta.auth.authenticator import Authenticator
from sendq_mta.core.config import Config
from sendq_mta.queue.manager import _safe_msg_id

from sendq_dashboard import __version__, db, history_writer
from sendq_dashboard.config_schema import SCHEMA as CONFIG_SCHEMA
from sendq_dashboard.portal_auth import AuthError, PortalAuth

logger = logging.getLogger("sendq-dashboard.app")

BASE_DIR = Path(__file__).parent
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)
# Disable Flask's default 12-hour browser cache on static assets — without
# this, every dashboard upgrade is invisible until the user manually does
# a hard refresh because their browser keeps using the cached app.js/css.
# The ``?v=<version>`` query string on each <link>/<script> tag does the
# real cache-busting on releases; this just makes sure browsers never
# hold on longer than necessary.
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.context_processor
def _inject_version() -> dict[str, str]:
    """Make ``{{ version }}`` available in every template — used to
    append ?v=<version> to static asset URLs so browser caches
    invalidate on each release."""
    return {"version": __version__}

# ── Globals initialised by ``init_app()`` ─────────────────────────────
_config: Config | None = None
_portal: PortalAuth | None = None
_mta_auth: Authenticator | None = None
_trusted_proxies: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_admin_ip_allow: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_legacy_api_key: str = ""

# Paths that GUI users with role=user are allowed to GET. Everything
# else under /api/* requires admin role.
_USER_READ_PATHS = {
    "/api/me",
    "/api/csrf-token",
    "/api/messages",
    "/api/logs",
    "/api/status",
    "/api/health",
    "/api/domains",  # they only see their assigned set
}

# Admin-only routes that also get the IP allowlist check.
_ADMIN_GUARDED_PREFIXES = (
    "/api/portal-users",
    "/api/users",
    "/api/config",
    "/api/dkim",
    "/api/domains",
    "/api/relay",
    "/api/server",
    "/api/queue",
    "/api/features",
)


def _parse_cidrs(values: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for v in values or []:
        try:
            out.append(ipaddress.ip_network(v, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid CIDR in trusted_proxies/allowlist: %r", v)
    return out


def _matches_cidrs(
    ip: str, nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def init_app(config: Config) -> Flask:
    global _config, _portal, _mta_auth, _trusted_proxies, _admin_ip_allow, _legacy_api_key

    _config = config

    # Open the shared SQLite DB. The MTA process writes message_history,
    # message_recipients, and delivery_attempts directly into the same
    # file (via sendq_mta.core.history). Both packages declare the
    # schema with IF NOT EXISTS, so it doesn't matter which side gets
    # there first. The dashboard also owns the audit_log table.
    sqlite_path = config.get("dashboard.sqlite_path", "/var/lib/sendq-mta/dashboard.db")
    db.init(sqlite_path)
    history_writer.install(
        history_retention_days=int(config.get("dashboard.history_retention_days", 30)),
        audit_retention_days=int(config.get("dashboard.audit_retention_days", 365)),
    )

    _portal = PortalAuth(config)
    _mta_auth = Authenticator(config)

    # Sanity-check: can we actually write to the portal users file? If not,
    # logins will succeed cryptographically but every request that records
    # last_login or a lockout counter will log a warning. Surface this at
    # startup so the operator can fix permissions before users hit it.
    portal_path = config.get("portal.users_file", "/etc/sendq-mta/portal-users.yml")
    if os.path.isfile(portal_path) and not os.access(portal_path, os.W_OK):
        logger.warning(
            "portal-users.yml at %s is not writable by this process. "
            "Authentications will still work, but last_login / lockout state "
            "won't persist. Fix with: chown <dashboard-user> %s && chmod 0600 %s",
            portal_path, portal_path, portal_path,
        )

    _trusted_proxies = _parse_cidrs(config.get("dashboard.trusted_proxies", []) or [])
    _admin_ip_allow = _parse_cidrs(config.get("dashboard.admin_ip_allowlist", []) or [])
    _legacy_api_key = config.get("management_api.http.api_key", "")

    if not _admin_ip_allow:
        logger.warning(
            "dashboard.admin_ip_allowlist is empty — admin API is reachable from any "
            "IP that can hit the dashboard. Restrict at the proxy or firewall."
        )

    # Session secret — autogenerate on first run.
    secret = config.get("dashboard.session_secret", "")
    if not secret or len(secret) < 32:
        secret = secrets.token_urlsafe(48)
        config.set("dashboard.session_secret", secret)
        try:
            config.save()
            logger.info("Auto-generated dashboard.session_secret")
        except Exception:
            logger.warning("Could not persist dashboard.session_secret", exc_info=True)
    app.secret_key = secret

    idle = int(config.get("dashboard.session_timeout_minutes", 30))
    app.permanent_session_lifetime = timedelta(minutes=idle)
    cookie_secure = bool(config.get("dashboard.cookie_secure", True))
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=cookie_secure,
    )
    if cookie_secure:
        bind = config.get("dashboard.bind_address", "0.0.0.0")
        loopback = bind in ("127.0.0.1", "::1", "localhost")
        if not _trusted_proxies and not loopback:
            logger.warning(
                "dashboard.cookie_secure=true but no trusted_proxies are configured "
                "and bind_address (%s) is not loopback. If you reach the dashboard "
                "over plain HTTP (e.g. for testing), the browser will refuse to send "
                "the Secure session cookie back, causing a login loop. Either put it "
                "behind an HTTPS reverse proxy (and list it in dashboard.trusted_proxies) "
                "or set dashboard.cookie_secure: false.",
                bind,
            )
    return app


# ── Request lifecycle ────────────────────────────────────────────────


@app.before_request
def _resolve_client_ip() -> None:
    """Resolve real client IP, honoring X-Forwarded-For only from trusted proxies."""
    raw = request.remote_addr or ""
    g.client_ip = raw
    if raw and _matches_cidrs(raw, _trusted_proxies):
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            # Leftmost address is the original client.
            g.client_ip = xff.split(",")[0].strip()
    g.is_https = (
        request.headers.get("X-Forwarded-Proto", "").lower() == "https"
        if raw and _matches_cidrs(raw, _trusted_proxies)
        else request.is_secure
    )


@app.before_request
def _gate_request() -> Any:
    path = request.path
    method = request.method

    # Static files and login routes are public.
    if path.startswith("/static/"):
        return None
    if path in ("/login", "/logout") or path.startswith("/login/"):
        return None
    if path == "/api/health" and method == "GET":
        return None

    # Legacy API-key bearer (kept for existing CLI integrations, read-only).
    if path.startswith("/api/v1/"):
        return _check_legacy_key()

    # Everything else under /api/* and the root SPA needs a session.
    user = _current_user()
    if user is None:
        if path == "/":
            return redirect(url_for("login"))
        return jsonify({"status": "error", "message": "Not authenticated"}), 401

    # Role gate: User role only gets GETs on the allowed paths.
    if user["role"] != "admin" and path.startswith("/api/"):
        admin_only = any(path == p or path.startswith(p + "/")
                         for p in _ADMIN_GUARDED_PREFIXES)
        if method != "GET" or (
            admin_only and path not in _USER_READ_PATHS
        ):
            return jsonify({"status": "error", "message": "Forbidden"}), 403

    # Admin route IP allowlist.
    if (
        user["role"] == "admin"
        and _admin_ip_allow
        and any(path == p or path.startswith(p + "/") for p in _ADMIN_GUARDED_PREFIXES)
        and not _matches_cidrs(g.client_ip, _admin_ip_allow)
    ):
        return jsonify({
            "status": "error",
            "message": "Source IP not in admin allowlist",
        }), 403

    # CSRF check on every state-changing method.
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        token = request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf")
        if not expected or not token or not hmac.compare_digest(token, expected):
            return jsonify({"status": "error", "message": "Invalid CSRF token"}), 403

    return None


@app.errorhandler(Exception)
def _handle_unexpected(exc):  # type: ignore[no-untyped-def]
    """Catch-all so unhandled exceptions log a stack trace and surface a useful page.

    Flask's default error page is opaque ("Internal Server Error" with no
    request ID, no log pointer). This handler ensures the dashboard log
    always contains the traceback and the user sees a hint about where to
    look.
    """
    # Let HTTP exceptions (404, 403, etc.) fall through to Flask's normal handling.
    from werkzeug.exceptions import HTTPException
    if isinstance(exc, HTTPException):
        return exc

    rid = secrets.token_hex(6)
    logger.exception("Unhandled exception (request_id=%s) on %s %s",
                     rid, request.method, request.path)
    log_file = (_config.get("dashboard.log_file", "/var/log/sendq-mta/dashboard.log")
                if _config else "the dashboard log")
    body = (
        "<!doctype html><meta charset=utf-8>"
        "<title>SendQ Dashboard — error</title>"
        "<body style='font-family:system-ui;max-width:640px;margin:60px auto;"
        "padding:24px;background:#0f1116;color:#e6e9ef;border-radius:8px;"
        "border:1px solid #232838'>"
        "<h1 style='font-size:20px'>Something went wrong</h1>"
        "<p>The dashboard hit an unexpected error processing your request.</p>"
        f"<p>Request ID: <code style='background:#11141c;padding:2px 6px;"
        f"border-radius:4px'>{rid}</code></p>"
        f"<p>Look for this request ID in <code>{log_file}</code> for the full "
        "stack trace. Common causes: the dashboard process can't write to "
        "<code>portal-users.yml</code> (file permissions), or the SQLite "
        "database directory isn't writable.</p>"
        f"<p><a href='/login' style='color:#4f8cff'>Back to login</a></p>"
        "</body>"
    )
    return body, 500


@app.after_request
def _security_headers(response):  # type: ignore[no-untyped-def]
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/api/") or request.path in ("/", "/login"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    return response


# ── Helpers ───────────────────────────────────────────────────────────


def _check_legacy_key() -> Any:
    if not _legacy_api_key:
        return jsonify({"status": "error", "message": "Legacy API key not configured"}), 503
    provided = ""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        provided = auth_header[7:]
    if not provided:
        provided = request.headers.get("X-API-Key", "")
    if not provided or not hmac.compare_digest(provided, _legacy_api_key):
        return jsonify({"status": "error", "message": "Invalid or missing API key"}), 401
    return None


def _current_user() -> dict[str, Any] | None:
    """Return the logged-in portal user dict, or None."""
    uname = session.get("user")
    if not uname:
        return None
    u = _portal.get(uname) if _portal else None
    if not u or not u.enabled:
        session.clear()
        return None
    # Re-issue idle expiry.
    session.permanent = True
    return {
        "username": u.username,
        "role": u.role,
        "assigned_domains": u.assigned_domains,
        "totp_enrolled": u.totp_enrolled,
    }


def require_admin(fn: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        u = _current_user()
        if not u or u["role"] != "admin":
            return jsonify({"status": "error", "message": "Admin only"}), 403
        return fn(*args, **kwargs)
    return wrapper


def _audit(action: str, target: str = "", **detail: Any) -> None:
    """Best-effort audit write. Never raises — auditing failures must not
    block the request that triggered them."""
    try:
        user = _current_user()
        actor = (user or {}).get("username", "anonymous")
        history_writer.record_audit(
            actor, getattr(g, "client_ip", "-"), action, target,
            json.dumps(detail) if detail else None,
        )
    except Exception:
        logger.warning("audit write failed (action=%s)", action, exc_info=True)


def _save_and_reload() -> None:
    _config.save()
    pid = _get_pid()
    if pid:
        try:
            os.kill(pid, signal.SIGHUP)
        except ProcessLookupError:
            pass


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


def _check_port(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
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


# ── Pages ─────────────────────────────────────────────────────────────


@app.route("/")
def index():
    if not _current_user():
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        csrf=session.get("csrf", ""),
        version=__version__,
    )


@app.route("/login", methods=["GET"])
def login():
    if _current_user():
        return redirect(url_for("index"))
    return render_template("login.html", error=request.args.get("error", ""))


@app.route("/login", methods=["POST"])
def login_post():
    if not _portal:
        return _login_error("Dashboard not initialised")
    form = request.form
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""
    totp_code = (form.get("totp") or "").strip()

    if not _portal.has_admin():
        return _login_error(
            "No portal users exist. Create one with: "
            "sendq-mta portal-user add <name> --role admin"
        )
    if not username or not password:
        return _login_error("Username and password required")

    try:
        user = _portal.authenticate(username, password, totp_code, g.client_ip)
    except AuthError as exc:
        _audit("login_failed", username, ip=g.client_ip, reason=str(exc))
        return _login_error(str(exc))

    # If TOTP is required for admins and this one hasn't enrolled, push them
    # into the enrollment flow. When require_totp_for_admin is false (the
    # default), authenticate() returns a fully-authenticated user above and
    # we skip this branch entirely.
    if (
        user.role == "admin"
        and not user.totp_enrolled
        and _config
        and _config.get("dashboard.require_totp_for_admin", False)
    ):
        session.clear()
        session["totp_enroll_user"] = user.username
        return redirect(url_for("totp_enroll"))

    _start_session(user.username, user.role)
    _audit("login", user.username)
    return redirect(url_for("index"))


def _login_error(msg: str):
    return render_template("login.html", error=msg), 401


def _start_session(username: str, role: str) -> None:
    session.clear()
    session["user"] = username
    session["role"] = role
    session["csrf"] = secrets.token_urlsafe(32)
    session.permanent = True


@app.route("/logout", methods=["POST", "GET"])
def logout():
    user = _current_user()
    if user:
        _audit("logout", user["username"])
    session.clear()
    return redirect(url_for("login"))


# ── TOTP enrollment flow ─────────────────────────────────────────────


@app.route("/login/totp-enroll", methods=["GET"])
def totp_enroll():
    username = session.get("totp_enroll_user")
    if not username or not _portal:
        return redirect(url_for("login"))
    secret = _portal.begin_totp_enrollment(username)
    qr_data_uri = _build_totp_qr(username, secret)
    return render_template(
        "login.html",
        totp_enroll=True,
        totp_secret=secret,
        totp_qr=qr_data_uri,
        totp_username=username,
    )


@app.route("/login/totp-enroll", methods=["POST"])
def totp_enroll_post():
    username = session.get("totp_enroll_user")
    if not username or not _portal:
        return redirect(url_for("login"))
    code = (request.form.get("totp") or "").strip()
    if not _portal.confirm_totp_enrollment(username, code):
        return _login_error("Invalid TOTP code. Try again.")
    user = _portal.get(username)
    if not user:
        return _login_error("User vanished during enrollment")
    _start_session(user.username, user.role)
    _audit("totp_enrolled", user.username)
    return redirect(url_for("index"))


def _build_totp_qr(username: str, secret: str) -> str | None:
    """Render a TOTP enrollment QR as a data: URI, or None if we can't.

    Tries Pillow-backed PNG first for best UX, falls back to qrcode's
    pure-Python SVG backend (which has no third-party deps), then gives
    up. Callers must handle ``None`` by rendering the manual secret only.
    The user can always type the secret into their authenticator app
    instead of scanning, so a missing QR is degraded UX, not a blocker.
    """
    import base64
    import io

    try:
        import pyotp
    except ImportError:
        logger.error("pyotp not installed — TOTP enrollment unavailable")
        return None

    issuer = _config.get("server.hostname", "SendQ-MTA") if _config else "SendQ-MTA"
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

    try:
        import qrcode
    except ImportError:
        logger.error("qrcode not installed — TOTP page will show manual secret only")
        return None

    # PIL/Pillow-backed PNG.
    try:
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        logger.warning(
            "PNG QR render failed (Pillow probably missing). "
            "Falling back to SVG. Install Pillow for crisper rendering: "
            "pip install Pillow",
            exc_info=True,
        )

    # Pure-Python SVG fallback — no external deps required.
    try:
        from qrcode.image.svg import SvgImage
        img = qrcode.make(uri, image_factory=SvgImage)
        buf = io.BytesIO()
        img.save(buf)
        return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        logger.warning("SVG QR render also failed", exc_info=True)
    return None


# ── /api/me + csrf ───────────────────────────────────────────────────


@app.route("/api/me")
def api_me():
    user = _current_user()
    return jsonify({"status": "ok", "data": user})


@app.route("/api/csrf-token")
def api_csrf_token():
    return jsonify({"status": "ok", "token": session.get("csrf", "")})


# ── /api/status ──────────────────────────────────────────────────────


@app.route("/api/status")
def api_status():
    pid = _get_pid()
    hostname = _config.get("server.hostname", "localhost")
    listeners = _config.get("listeners", [])
    relay = _config.get("relay", {})

    # Queue counts from disk (cheap).
    q = _config.get("queue.directory", "/var/spool/sendq-mta/queue")
    d = _config.get("queue.deferred_directory", "/var/spool/sendq-mta/deferred")
    f = _config.get("queue.failed_directory", "/var/spool/sendq-mta/failed")

    def _count(p: str) -> int:
        if not os.path.isdir(p):
            return 0
        return sum(1 for x in os.listdir(p) if x.endswith(".meta.json"))

    return jsonify({
        "status": "ok",
        "server": {
            "running": pid is not None,
            "pid": pid,
            "hostname": hostname,
            "version": __version__,
        },
        "queue": {"active": _count(q), "deferred": _count(d), "failed": _count(f)},
        "listeners": [{
            "name": l.get("name", "?"),
            "address": l.get("address", "0.0.0.0"),
            "port": l.get("port", 0),
            "tls_mode": l.get("tls_mode", "none"),
            "require_auth": l.get("require_auth", False),
        } for l in listeners],
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
    })


# ── /api/server control ──────────────────────────────────────────────


@app.route("/api/server/<action>", methods=["POST"])
@require_admin
def api_server_action(action: str):
    pid = _get_pid()
    if action == "stop":
        if not pid:
            return jsonify({"status": "error", "message": "Not running"}), 400
        os.kill(pid, signal.SIGTERM)
        _audit("server_stop")
        return jsonify({"status": "ok"})
    if action == "reload":
        if not pid:
            return jsonify({"status": "error", "message": "Not running"}), 400
        os.kill(pid, signal.SIGHUP)
        _audit("server_reload")
        return jsonify({"status": "ok"})
    if action == "start":
        if pid:
            return jsonify({"status": "error", "message": "Already running"}), 400
        subprocess.Popen(["sendq-mta", "start"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _audit("server_start")
        return jsonify({"status": "ok"})
    if action == "restart":
        if pid:
            os.kill(pid, signal.SIGTERM)
            time.sleep(2)
        subprocess.Popen(["sendq-mta", "start"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _audit("server_restart")
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": "Unknown action"}), 400


# ── /api/portal-users ────────────────────────────────────────────────


@app.route("/api/portal-users")
@require_admin
def api_portal_users():
    return jsonify({"status": "ok", "data": _portal.list_users()})


@app.route("/api/portal-users", methods=["POST"])
@require_admin
def api_portal_user_add():
    data = request.json or {}
    try:
        _portal.add_user(
            username=(data.get("username") or "").strip(),
            password=data.get("password") or "",
            role=data.get("role") or "user",
            assigned_domains=data.get("assigned_domains") or [],
        )
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    _audit("portal_user_add", data.get("username", ""), role=data.get("role"))
    return jsonify({"status": "ok"})


@app.route("/api/portal-users/<username>", methods=["PUT"])
@require_admin
def api_portal_user_edit(username: str):
    data = request.json or {}
    try:
        _portal.update_user(
            username,
            role=data.get("role"),
            enabled=data.get("enabled"),
            assigned_domains=data.get("assigned_domains"),
        )
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    _audit("portal_user_edit", username)
    return jsonify({"status": "ok"})


@app.route("/api/portal-users/<username>", methods=["DELETE"])
@require_admin
def api_portal_user_delete(username: str):
    try:
        _portal.delete_user(username)
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    _audit("portal_user_delete", username)
    return jsonify({"status": "ok"})


@app.route("/api/portal-users/<username>/password", methods=["POST"])
@require_admin
def api_portal_user_password(username: str):
    data = request.json or {}
    pw = data.get("password") or ""
    if len(pw) < 12:
        return jsonify({"status": "error", "message": "Password too short (min 12)"}), 400
    try:
        _portal.set_password(username, pw)
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    _audit("portal_user_password_reset", username)
    return jsonify({"status": "ok"})


@app.route("/api/portal-users/<username>/totp", methods=["DELETE"])
@require_admin
def api_portal_user_totp_disable(username: str):
    _portal.disable_totp(username)
    _audit("portal_user_totp_disable", username)
    return jsonify({"status": "ok"})


# ── /api/users (SMTP-AUTH users) ─────────────────────────────────────


@app.route("/api/users")
@require_admin
def api_users():
    return jsonify({"status": "ok", "data": _mta_auth.list_users()})


@app.route("/api/users", methods=["POST"])
@require_admin
def api_users_add():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"status": "error", "message": "username and password required"}), 400
    try:
        ok = _mta_auth.add_user(
            username, password,
            email=data.get("email", ""),
            display_name=data.get("display_name", ""),
            quota_mb=int(data.get("quota_mb", 0) or 0),
            send_limit_per_hour=int(data.get("send_limit_per_hour", 0) or 0),
        )
        if not ok:
            return jsonify({"status": "error", "message": "User already exists"}), 409
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    _audit("mta_user_add", username)
    return jsonify({"status": "ok"})


@app.route("/api/users/<username>", methods=["PUT"])
@require_admin
def api_users_edit(username: str):
    data = request.json or {}
    kwargs = {k: data[k] for k in
              ("email", "display_name", "enabled", "quota_mb", "send_limit_per_hour")
              if k in data}
    if not _mta_auth.edit_user(username, **kwargs):
        return jsonify({"status": "error", "message": "Not found"}), 404
    _audit("mta_user_edit", username)
    return jsonify({"status": "ok"})


@app.route("/api/users/<username>", methods=["DELETE"])
@require_admin
def api_users_delete(username: str):
    if not _mta_auth.delete_user(username):
        return jsonify({"status": "error", "message": "Not found"}), 404
    _audit("mta_user_delete", username)
    return jsonify({"status": "ok"})


@app.route("/api/users/<username>/password", methods=["POST"])
@require_admin
def api_users_password(username: str):
    data = request.json or {}
    pw = data.get("password") or ""
    try:
        if not _mta_auth.change_password(username, pw):
            return jsonify({"status": "error", "message": "Not found"}), 404
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    _audit("mta_user_password", username)
    return jsonify({"status": "ok"})


# ── /api/domains ─────────────────────────────────────────────────────


@app.route("/api/domains")
def api_domains():
    user = _current_user()
    data = {
        "local": list(_config.get("domains.local_domains", []) or []),
        "relay": list(_config.get("domains.relay_domains", []) or []),
        "blocked": list(_config.get("domains.blocked_domains", []) or []),
    }
    if user and user["role"] != "admin":
        assigned = set(user["assigned_domains"])
        data = {k: [d for d in v if d in assigned] for k, v in data.items()}
    return jsonify({"status": "ok", "data": data})


@app.route("/api/domains", methods=["POST"])
@require_admin
def api_domain_add():
    data = request.json or {}
    domain = (data.get("domain") or "").strip().lower()
    dtype = data.get("type", "local")
    if dtype not in ("local", "relay", "blocked"):
        return jsonify({"status": "error", "message": "Invalid type"}), 400
    if not domain:
        return jsonify({"status": "error", "message": "domain required"}), 400
    key = f"domains.{dtype}_domains"
    domains = list(_config.get(key, []) or [])
    if domain in domains:
        return jsonify({"status": "error", "message": "Already exists"}), 409
    domains.append(domain)
    _config.set(key, domains)
    _save_and_reload()
    _audit("domain_add", domain, type=dtype)
    return jsonify({"status": "ok"})


@app.route("/api/domains/<domain>", methods=["DELETE"])
@require_admin
def api_domain_delete(domain: str):
    dtype = request.args.get("type", "local")
    key = f"domains.{dtype}_domains"
    domains = list(_config.get(key, []) or [])
    if domain not in domains:
        return jsonify({"status": "error", "message": "Not found"}), 404
    domains.remove(domain)
    _config.set(key, domains)
    _save_and_reload()
    _audit("domain_delete", domain, type=dtype)
    return jsonify({"status": "ok"})


# ── /api/dkim ────────────────────────────────────────────────────────


@app.route("/api/dkim")
@require_admin
def api_dkim():
    enabled = _config.get("dkim.enabled", False)
    selector = _config.get("dkim.selector", "sendq")
    key_dir = _config.get("dkim.key_dir", "/etc/sendq-mta/dkim")
    domains = []
    for d in _config.get("dkim.signing_domains", []) or []:
        d = d.lower()
        key_path = os.path.join(key_dir, f"{d}.{selector}.private.pem")
        dns_path = os.path.join(key_dir, f"{d}.{selector}.dns.txt")
        dns_record = ""
        if os.path.isfile(dns_path):
            try:
                with open(dns_path) as fh:
                    dns_record = fh.read().strip()
            except OSError:
                pass
        domains.append({
            "domain": d,
            "selector": selector,
            "key_present": os.path.isfile(key_path),
            "key_path": key_path,
            "dns_record": dns_record,
        })
    return jsonify({
        "status": "ok",
        "data": {"enabled": enabled, "selector": selector,
                 "key_dir": key_dir, "domains": domains},
    })


@app.route("/api/dkim/keys", methods=["POST"])
@require_admin
def api_dkim_generate():
    from sendq_mta.auth.dkim import generate_domain_key

    data = request.json or {}
    domain = (data.get("domain") or "").strip().lower()
    selector = (data.get("selector") or _config.get("dkim.selector", "sendq")).strip()
    bits = int(data.get("bits", 2048))
    key_dir = _config.get("dkim.key_dir", "/etc/sendq-mta/dkim")
    if not domain:
        return jsonify({"status": "error", "message": "domain required"}), 400
    try:
        result = generate_domain_key(domain, selector, bits, key_dir)
    except (ValueError, RuntimeError) as e:
        return jsonify({"status": "error", "message": str(e)}), 400

    # Auto-update config (same pattern as the CLI command).
    _config.set("dkim.enabled", True)
    _config.set("dkim.key_dir", key_dir)
    _config.set("dkim.selector", selector)
    signing = [d.lower() for d in _config.get("dkim.signing_domains", []) or []]
    if domain not in signing:
        signing.append(domain)
    _config.set("dkim.signing_domains", signing)
    _save_and_reload()
    _audit("dkim_key_generated", domain, selector=selector)
    return jsonify({"status": "ok", "data": result})


@app.route("/api/dkim/keys/<domain>", methods=["DELETE"])
@require_admin
def api_dkim_delete(domain: str):
    domain = domain.lower()
    selector = _config.get("dkim.selector", "sendq")
    key_dir = _config.get("dkim.key_dir", "/etc/sendq-mta/dkim")
    for ext in ("private.pem", "dns.txt"):
        p = os.path.join(key_dir, f"{domain}.{selector}.{ext}")
        if os.path.isfile(p):
            try:
                os.unlink(p)
            except OSError:
                pass
    signing = [d for d in (_config.get("dkim.signing_domains", []) or [])
               if d.lower() != domain]
    _config.set("dkim.signing_domains", signing)
    _save_and_reload()
    _audit("dkim_key_delete", domain)
    return jsonify({"status": "ok"})


@app.route("/api/dkim/toggle", methods=["POST"])
@require_admin
def api_dkim_toggle():
    current = _config.get("dkim.enabled", False)
    _config.set("dkim.enabled", not current)
    _save_and_reload()
    _audit("dkim_toggle", enabled=not current)
    return jsonify({"status": "ok", "enabled": not current})


# ── /api/config (form-based editor) ──────────────────────────────────


@app.route("/api/config/schema")
@require_admin
def api_config_schema():
    return jsonify({"status": "ok", "data": CONFIG_SCHEMA})


@app.route("/api/config")
@require_admin
def api_config():
    cfg = copy.deepcopy(_config.data)
    # Redact secrets.
    if cfg.get("relay", {}).get("password"):
        cfg["relay"]["password"] = "********"
    for fo in cfg.get("relay", {}).get("failover", []):
        if fo.get("password"):
            fo["password"] = "********"
    if "auth" in cfg:
        cfg["auth"].pop("password_hash", None)
    cfg.get("dashboard", {}).pop("session_secret", None)
    return jsonify({"status": "ok", "data": cfg, "path": _config.path})


@app.route("/api/config/key", methods=["PUT"])
@require_admin
def api_config_set_key():
    data = request.json or {}
    key = data.get("key", "")
    value = data.get("value")
    if not key:
        return jsonify({"status": "error", "message": "key required"}), 400
    # Don't overwrite a secret with the placeholder.
    if isinstance(value, str) and value == "********":
        return jsonify({"status": "ok", "message": "unchanged"})
    _config.set(key, value)
    _save_and_reload()
    _audit("config_set", key)
    return jsonify({"status": "ok"})


# ── /api/relay ───────────────────────────────────────────────────────


@app.route("/api/relay")
@require_admin
def api_relay():
    r = copy.deepcopy(_config.get("relay", {}) or {})
    if r.get("password"):
        r["password"] = "********"
    for fo in r.get("failover", []) or []:
        if fo.get("password"):
            fo["password"] = "********"
    return jsonify({"status": "ok", "data": r})


@app.route("/api/relay", methods=["PUT"])
@require_admin
def api_relay_update():
    data = request.json or {}
    for key in ("enabled", "host", "port", "username", "auth_method",
                "tls_mode", "tls_verify"):
        if key in data:
            _config.set(f"relay.{key}", data[key])
    if "password" in data and data["password"] != "********":
        _config.set("relay.password", data["password"])
    _save_and_reload()
    _audit("relay_update")
    return jsonify({"status": "ok"})


@app.route("/api/relay/test", methods=["POST"])
@require_admin
def api_relay_test():
    # Lazy-import: transport.delivery pulls aiosmtplib which we don't need
    # for any other dashboard route.
    from sendq_mta.transport.delivery import _validate_relay_host

    data = request.json or {}
    host = data.get("host", _config.get("relay.host", ""))
    port = int(data.get("port", _config.get("relay.port", 587)))
    if not host:
        return jsonify({"status": "error", "message": "No relay host"}), 400
    try:
        _validate_relay_host(host)
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    return jsonify({"status": "ok", "data": {"host": host, "port": port,
                                              **_check_port(host, port, timeout=5.0)}})


# ── /api/queue ───────────────────────────────────────────────────────


@app.route("/api/queue/list")
@require_admin
def api_queue_list():
    queue_type = request.args.get("type", "all")
    q = _config.get("queue.directory", "/var/spool/sendq-mta/queue")
    d = _config.get("queue.deferred_directory", "/var/spool/sendq-mta/deferred")
    f = _config.get("queue.failed_directory", "/var/spool/sendq-mta/failed")

    def _list(dir_path: str, label: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not os.path.isdir(dir_path):
            return out
        for fn in os.listdir(dir_path):
            if not fn.endswith(".meta.json"):
                continue
            try:
                with open(os.path.join(dir_path, fn)) as fh:
                    meta = json.load(fh)
                meta["queue"] = label
                out.append(meta)
            except (OSError, json.JSONDecodeError):
                continue
        return out

    msgs = []
    if queue_type in ("active", "all"):
        msgs += _list(q, "active")
    if queue_type in ("deferred", "all"):
        msgs += _list(d, "deferred")
    if queue_type in ("failed", "all"):
        msgs += _list(f, "failed")
    return jsonify({"status": "ok", "data": msgs})


@app.route("/api/queue/flush", methods=["POST"])
@require_admin
def api_queue_flush():
    q = _config.get("queue.directory", "/var/spool/sendq-mta/queue")
    count = 0
    if os.path.isdir(q):
        for fn in os.listdir(q):
            try:
                os.unlink(os.path.join(q, fn))
                if fn.endswith(".meta.json"):
                    count += 1
            except OSError:
                pass
    _audit("queue_flush", count=count)
    return jsonify({"status": "ok", "flushed": count})


@app.route("/api/queue/delete", methods=["POST"])
@require_admin
def api_queue_delete():
    data = request.json or {}
    msg_id = data.get("msg_id", "")
    try:
        _safe_msg_id(msg_id)
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid msg_id"}), 400
    deleted = False
    for dir_key in ("queue.directory", "queue.deferred_directory", "queue.failed_directory"):
        dir_path = _config.get(dir_key, "")
        meta = os.path.join(dir_path, f"{msg_id}.meta.json")
        eml = os.path.join(dir_path, f"{msg_id}.eml")
        if os.path.exists(meta):
            os.unlink(meta)
            if os.path.exists(eml):
                os.unlink(eml)
            deleted = True
            break
    if not deleted:
        return jsonify({"status": "error", "message": "Not found"}), 404
    _audit("queue_delete", msg_id)
    return jsonify({"status": "ok"})


# ── /api/features toggles ────────────────────────────────────────────


@app.route("/api/features/toggle", methods=["POST"])
@require_admin
def api_features_toggle():
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
        return jsonify({"status": "error", "message": "Unknown feature"}), 400
    cur = _config.get(key, False)
    _config.set(key, not cur)
    _save_and_reload()
    _audit("feature_toggle", feature, enabled=not cur)
    return jsonify({"status": "ok", "enabled": not cur})


# ── /api/messages (the detailed log view) ────────────────────────────


def _user_domain_filter() -> list[str] | None:
    user = _current_user()
    if not user or user["role"] == "admin":
        return None
    return [d.lower() for d in user["assigned_domains"]]


@app.route("/api/messages")
def api_messages():
    status = request.args.get("status", "")
    domain = request.args.get("domain", "").lower()
    sender = request.args.get("sender", "")
    recipient = request.args.get("recipient", "")
    q_text = request.args.get("q", "")
    from_ts = request.args.get("from_ts", "")
    to_ts = request.args.get("to_ts", "")
    page = max(1, int(request.args.get("page", 1)))
    page_size = min(500, max(1, int(request.args.get("page_size", 100))))

    where: list[str] = []
    params: list[Any] = []
    if status:
        where.append("m.status = ?")
        params.append(status)
    if domain:
        where.append(
            "(m.sender_domain = ? OR EXISTS "
            "(SELECT 1 FROM message_recipients r WHERE r.msg_id = m.msg_id "
            "AND r.recipient_domain = ?))"
        )
        params.extend([domain, domain])
    if sender:
        where.append("m.sender LIKE ?")
        params.append(f"%{sender}%")
    if recipient:
        where.append(
            "EXISTS (SELECT 1 FROM message_recipients r2 "
            "WHERE r2.msg_id = m.msg_id AND r2.recipient LIKE ?)"
        )
        params.append(f"%{recipient}%")
    if q_text:
        where.append("(m.msg_id LIKE ? OR m.last_error LIKE ?)")
        params.extend([f"%{q_text}%", f"%{q_text}%"])
    if from_ts:
        where.append("m.received_at >= ?")
        params.append(from_ts)
    if to_ts:
        where.append("m.received_at <= ?")
        params.append(to_ts)

    user_domains = _user_domain_filter()
    if user_domains is not None:
        if not user_domains:
            return jsonify({"status": "ok", "data": [], "page": page,
                            "page_size": page_size, "total": 0})
        placeholders = ",".join("?" * len(user_domains))
        where.append(
            f"(m.sender_domain IN ({placeholders}) OR EXISTS "
            f"(SELECT 1 FROM message_recipients r3 WHERE r3.msg_id = m.msg_id "
            f"AND r3.recipient_domain IN ({placeholders})))"
        )
        params.extend(user_domains)
        params.extend(user_domains)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    offset = (page - 1) * page_size

    total_row = db.fetch_one(
        f"SELECT COUNT(*) AS c FROM message_history m {where_sql}", tuple(params)
    )
    total = total_row["c"] if total_row else 0

    rows = db.fetch(
        f"SELECT m.* FROM message_history m {where_sql} "
        f"ORDER BY m.received_at DESC LIMIT ? OFFSET ?",
        tuple(params + [page_size, offset]),
    )
    data = [dict(r) for r in rows]
    # Attach recipients in one query.
    if data:
        ids = [d["msg_id"] for d in data]
        ph = ",".join("?" * len(ids))
        rec_rows = db.fetch(
            f"SELECT msg_id, recipient FROM message_recipients WHERE msg_id IN ({ph})",
            tuple(ids),
        )
        by_msg: dict[str, list[str]] = {}
        for r in rec_rows:
            by_msg.setdefault(r["msg_id"], []).append(r["recipient"])
        for d in data:
            d["recipients"] = by_msg.get(d["msg_id"], [])
    return jsonify({"status": "ok", "data": data, "page": page,
                    "page_size": page_size, "total": total})


@app.route("/api/messages/<msg_id>")
def api_message_detail(msg_id: str):
    try:
        _safe_msg_id(msg_id)
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid msg_id"}), 400

    row = db.fetch_one("SELECT * FROM message_history WHERE msg_id = ?", (msg_id,))
    if not row:
        return jsonify({"status": "error", "message": "Not found"}), 404
    msg = dict(row)

    # Role-scope: a user can only see messages touching their domains.
    user_domains = _user_domain_filter()
    if user_domains is not None:
        rec_rows = db.fetch(
            "SELECT recipient_domain FROM message_recipients WHERE msg_id = ?",
            (msg_id,),
        )
        rec_domains = {r["recipient_domain"] for r in rec_rows}
        allowed = set(user_domains)
        if msg["sender_domain"] not in allowed and not (rec_domains & allowed):
            return jsonify({"status": "error", "message": "Forbidden"}), 403

    msg["recipients"] = [
        r["recipient"] for r in db.fetch(
            "SELECT recipient FROM message_recipients WHERE msg_id = ?", (msg_id,)
        )
    ]
    msg["attempts"] = [
        dict(r) for r in db.fetch(
            "SELECT attempt_at, remote_host, smtp_code, smtp_resp, outcome "
            "FROM delivery_attempts WHERE msg_id = ? ORDER BY attempt_at ASC",
            (msg_id,),
        )
    ]
    return jsonify({"status": "ok", "data": msg})


# ── /api/logs (raw tail) ─────────────────────────────────────────────


@app.route("/api/logs")
def api_logs():
    n = min(int(request.args.get("lines", 200)), 2000)
    lines = _read_log_lines(n)

    user_domains = _user_domain_filter()
    if user_domains is not None:
        if not user_domains:
            lines = []
        else:
            needles = [d.lower() for d in user_domains]
            lines = [
                l for l in lines
                if any(n in l.lower() for n in needles)
            ]

    level = request.args.get("level", "").lower()
    search = request.args.get("search", "").lower()
    if level:
        lines = [l for l in lines if level in l.lower()]
    if search:
        lines = [l for l in lines if search in l.lower()]

    sort_order = request.args.get("sort", "desc")
    if sort_order != "asc":
        lines = list(reversed(lines))

    sanitized = [html_mod.escape(l) for l in lines]
    return jsonify({"status": "ok", "data": sanitized, "total": len(sanitized)})


# ── /api/health (public minimal, detailed when logged in) ────────────


@app.route("/api/health")
def api_health():
    pid = _get_pid()
    listeners = _config.get("listeners", [])
    user = _current_user()
    if user is None:
        return jsonify({"status": "ok", "healthy": pid is not None})

    checks: dict[str, Any] = {
        "server_process": {
            "ok": pid is not None,
            "detail": f"PID {pid}" if pid else "Not running",
        },
    }
    port_checks = []
    for l in listeners:
        addr = l.get("address", "0.0.0.0")
        port = l.get("port", 0)
        bind = "127.0.0.1" if addr == "0.0.0.0" else addr
        r = _check_port(bind, port, timeout=2.0)
        port_checks.append({"name": l.get("name", "?"), "port": port,
                            "ok": r["reachable"], "error": r["error"]})
    checks["listener_ports"] = port_checks

    return jsonify({"status": "ok", "healthy": pid is not None, "checks": checks})


# ── Run entrypoint ───────────────────────────────────────────────────


def run_dashboard(
    config: Config,
    host: str | None = None,
    port: int | None = None,
) -> None:
    """Start the dashboard web server (blocking)."""
    init_app(config)
    host = host or config.get("dashboard.bind_address", "0.0.0.0")
    port = int(port or config.get("dashboard.port", 8443))
    logger.info("Dashboard listening on http://%s:%d (plain HTTP — TLS terminates upstream)",
                host, port)
    app.run(host=host, port=port, debug=False, threaded=True)

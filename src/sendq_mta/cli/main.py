"""SendQ-MTA Command Line Interface — the `sendq-mta` command."""

import asyncio
import json
import os
import signal
import sys
import time

import click
import yaml

from sendq_mta import __version__, __app_name__
from sendq_mta.core.config import Config


def _load_config(ctx: click.Context) -> Config:
    """Load config from the CLI-provided path or default search."""
    config_path = ctx.obj.get("config") if ctx.obj else None
    return Config(config_path)


def _print_table(headers: list[str], rows: list[list[str]]) -> None:
    """Print a simple ASCII table."""
    if not rows:
        click.echo("  (no entries)")
        return

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))

    header_line = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    separator = "  ".join("-" * col_widths[i] for i in range(len(headers)))

    click.echo(f"  {header_line}")
    click.echo(f"  {separator}")
    for row in rows:
        line = "  ".join(
            str(cell).ljust(col_widths[i]) if i < len(col_widths) else str(cell)
            for i, cell in enumerate(row)
        )
        click.echo(f"  {line}")


def _get_pid(config: Config) -> int | None:
    """Read PID from the pid file. Returns None if not running."""
    pid_file = config.get("server.pid_file", "/var/run/sendq-mta/sendq-mta.pid")
    if not os.path.isfile(pid_file):
        return None
    try:
        with open(pid_file) as f:
            pid = int(f.read().strip())
        # Check if process is alive
        os.kill(pid, 0)
        return pid
    except (ValueError, ProcessLookupError, PermissionError):
        return None


# ============================================================================
# Main CLI Group
# ============================================================================


@click.group(invoke_without_command=True)
@click.option(
    "-c", "--config",
    type=click.Path(exists=True),
    default=None,
    help="Path to configuration file.",
)
@click.option("--version", is_flag=True, help="Show version and exit.")
@click.pass_context
def cli(ctx: click.Context, config: str | None, version: bool) -> None:
    """SendQ-MTA — Enterprise Mail Transfer Agent.

    High-performance SMTP server with relay support, DKIM/SPF/DMARC,
    persistent queue, and enterprise-grade rate limiting.
    """
    ctx.ensure_object(dict)
    ctx.obj["config"] = config

    if version:
        click.echo(f"{__app_name__} v{__version__}")
        ctx.exit()

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ============================================================================
# Server Control Commands
# ============================================================================


@cli.command("start")
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (no daemonize).")
@click.pass_context
def server_start(ctx: click.Context, foreground: bool) -> None:
    """Start the SendQ-MTA server."""
    config = _load_config(ctx)

    pid = _get_pid(config)
    if pid:
        click.echo(f"SendQ-MTA is already running (PID {pid})", err=True)
        ctx.exit(1)

    click.echo("Starting SendQ-MTA...")

    if foreground:
        _run_server(config)
    else:
        _daemonize(config)


@cli.command("stop")
@click.pass_context
def server_stop(ctx: click.Context) -> None:
    """Stop the SendQ-MTA server."""
    config = _load_config(ctx)
    pid = _get_pid(config)
    if not pid:
        click.echo("SendQ-MTA is not running.", err=True)
        ctx.exit(1)

    click.echo(f"Stopping SendQ-MTA (PID {pid})...")
    os.kill(pid, signal.SIGTERM)

    # Wait for process to exit
    for _ in range(30):
        try:
            os.kill(pid, 0)
            time.sleep(1)
        except ProcessLookupError:
            click.echo("SendQ-MTA stopped.")
            return

    click.echo("Warning: Process did not stop within 30 seconds.", err=True)


@cli.command("restart")
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground.")
@click.pass_context
def server_restart(ctx: click.Context, foreground: bool) -> None:
    """Restart the SendQ-MTA server."""
    config = _load_config(ctx)
    pid = _get_pid(config)
    if pid:
        click.echo(f"Stopping SendQ-MTA (PID {pid})...")
        os.kill(pid, signal.SIGTERM)
        for _ in range(30):
            try:
                os.kill(pid, 0)
                time.sleep(1)
            except ProcessLookupError:
                break

    click.echo("Starting SendQ-MTA...")
    if foreground:
        _run_server(config)
    else:
        _daemonize(config)


@cli.command("status")
@click.pass_context
def server_status(ctx: click.Context) -> None:
    """Show server status."""
    config = _load_config(ctx)
    pid = _get_pid(config)

    click.echo(f"SendQ-MTA v{__version__}")
    click.echo(f"Config: {config.path or '(defaults)'}")

    if pid:
        click.echo(f"Status: RUNNING (PID {pid})")
    else:
        click.echo("Status: STOPPED")

    # Show queue stats
    queue_dir = config.get("queue.directory", "/var/spool/sendq-mta/queue")
    deferred_dir = config.get("queue.deferred_directory", "/var/spool/sendq-mta/deferred")
    failed_dir = config.get("queue.failed_directory", "/var/spool/sendq-mta/failed")

    def _count_messages(d: str) -> int:
        if os.path.isdir(d):
            return sum(1 for f in os.listdir(d) if f.endswith(".meta.json"))
        return 0

    click.echo(f"\nQueue:")
    click.echo(f"  Active:   {_count_messages(queue_dir)}")
    click.echo(f"  Deferred: {_count_messages(deferred_dir)}")
    click.echo(f"  Failed:   {_count_messages(failed_dir)}")

    # Show listeners
    listeners = config.get("listeners", [])
    if listeners:
        click.echo(f"\nListeners:")
        for l in listeners:
            click.echo(f"  {l.get('name', '?'):12s} {l.get('address', '?')}:{l.get('port', '?')} (tls={l.get('tls_mode', '?')}, auth={l.get('require_auth', False)})")

    # Show relay
    relay = config.get("relay", {})
    if relay.get("enabled"):
        click.echo(f"\nRelay: {relay.get('host', '?')}:{relay.get('port', '?')} (tls={relay.get('tls_mode', '?')})")
    else:
        click.echo("\nRelay: direct delivery (MX lookup)")


@cli.command("reload")
@click.pass_context
def server_reload(ctx: click.Context) -> None:
    """Reload configuration without restart (send SIGHUP)."""
    config = _load_config(ctx)
    pid = _get_pid(config)
    if not pid:
        click.echo("SendQ-MTA is not running.", err=True)
        ctx.exit(1)

    os.kill(pid, signal.SIGHUP)
    click.echo("Configuration reload signal sent.")


# ============================================================================
# User Management Commands
# ============================================================================


@cli.command("list-users")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.pass_context
def user_list(ctx: click.Context, fmt: str) -> None:
    """List all mail users."""
    config = _load_config(ctx)
    from sendq_mta.auth.authenticator import Authenticator

    auth = Authenticator(config)
    users = auth.list_users()

    if fmt == "json":
        click.echo(json.dumps(users, indent=2))
        return

    if not users:
        click.echo("No users configured.")
        return

    click.echo(f"\nMail Users ({len(users)} total):\n")
    _print_table(
        ["USERNAME", "EMAIL", "DISPLAY NAME", "ENABLED", "CREATED", "LAST LOGIN"],
        [
            [
                u["username"],
                u["email"],
                u["display_name"],
                "yes" if u["enabled"] else "NO",
                u.get("created_at", "")[:10],
                u.get("last_login", "")[:10] or "never",
            ]
            for u in users
        ],
    )
    click.echo()


@cli.command("add-user")
@click.argument("username")
@click.option("--password", "-p", prompt=True, hide_input=True, confirmation_prompt=True)
@click.option("--email", "-e", default="", help="User email address.")
@click.option("--display-name", "-d", default="", help="Display name.")
@click.option("--quota", type=int, default=0, help="Mailbox quota in MB (0=unlimited).")
@click.option("--send-limit", type=int, default=0, help="Send limit per hour (0=default).")
@click.pass_context
def user_add(
    ctx: click.Context,
    username: str,
    password: str,
    email: str,
    display_name: str,
    quota: int,
    send_limit: int,
) -> None:
    """Add a new mail user."""
    config = _load_config(ctx)
    from sendq_mta.auth.authenticator import Authenticator

    auth = Authenticator(config)
    try:
        if auth.add_user(
            username=username,
            password=password,
            email=email,
            display_name=display_name,
            quota_mb=quota,
            send_limit_per_hour=send_limit,
        ):
            click.echo(f"User '{username}' added successfully.")
        else:
            click.echo(f"Error: User '{username}' already exists.", err=True)
            ctx.exit(1)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        ctx.exit(1)


@cli.command("edit-user")
@click.argument("username")
@click.option("--email", "-e", default=None, help="New email address.")
@click.option("--display-name", "-d", default=None, help="New display name.")
@click.option("--quota", type=int, default=None, help="New quota in MB.")
@click.option("--send-limit", type=int, default=None, help="New send limit per hour.")
@click.option("--enable/--disable", default=None, help="Enable or disable user.")
@click.pass_context
def user_edit(
    ctx: click.Context,
    username: str,
    email: str | None,
    display_name: str | None,
    quota: int | None,
    send_limit: int | None,
    enable: bool | None,
) -> None:
    """Edit an existing mail user."""
    config = _load_config(ctx)
    from sendq_mta.auth.authenticator import Authenticator

    auth = Authenticator(config)

    kwargs = {}
    if email is not None:
        kwargs["email"] = email
    if display_name is not None:
        kwargs["display_name"] = display_name
    if quota is not None:
        kwargs["quota_mb"] = quota
    if send_limit is not None:
        kwargs["send_limit_per_hour"] = send_limit
    if enable is not None:
        kwargs["enabled"] = enable

    if not kwargs:
        click.echo("No changes specified. Use --help for options.", err=True)
        ctx.exit(1)

    if auth.edit_user(username, **kwargs):
        click.echo(f"User '{username}' updated successfully.")
    else:
        click.echo(f"Error: User '{username}' not found.", err=True)
        ctx.exit(1)


@cli.command("delete-user")
@click.argument("username")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
@click.pass_context
def user_delete(ctx: click.Context, username: str, yes: bool) -> None:
    """Delete a mail user."""
    if not yes:
        click.confirm(f"Are you sure you want to delete user '{username}'?", abort=True)

    config = _load_config(ctx)
    from sendq_mta.auth.authenticator import Authenticator

    auth = Authenticator(config)
    if auth.delete_user(username):
        click.echo(f"User '{username}' deleted.")
    else:
        click.echo(f"Error: User '{username}' not found.", err=True)
        ctx.exit(1)


@cli.command("change-pass")
@click.argument("username")
@click.option("--password", "-p", prompt=True, hide_input=True, confirmation_prompt=True)
@click.pass_context
def user_change_pass(ctx: click.Context, username: str, password: str) -> None:
    """Change a user's password."""
    config = _load_config(ctx)
    from sendq_mta.auth.authenticator import Authenticator

    auth = Authenticator(config)
    try:
        if auth.change_password(username, password):
            click.echo(f"Password changed for user '{username}'.")
        else:
            click.echo(f"Error: User '{username}' not found.", err=True)
            ctx.exit(1)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        ctx.exit(1)


@cli.command("show-user")
@click.argument("username")
@click.pass_context
def user_show(ctx: click.Context, username: str) -> None:
    """Show details for a specific user."""
    config = _load_config(ctx)
    from sendq_mta.auth.authenticator import Authenticator

    auth = Authenticator(config)
    user = auth.get_user(username)
    if not user:
        click.echo(f"Error: User '{username}' not found.", err=True)
        ctx.exit(1)

    click.echo(f"\nUser: {username}")
    click.echo(f"  Email:          {user['email']}")
    click.echo(f"  Display Name:   {user['display_name']}")
    click.echo(f"  Enabled:        {'yes' if user['enabled'] else 'NO'}")
    click.echo(f"  Created:        {user['created_at']}")
    click.echo(f"  Last Login:     {user['last_login'] or 'never'}")
    click.echo(f"  Quota:          {user['quota_mb']} MB" + (" (unlimited)" if not user['quota_mb'] else ""))
    click.echo(f"  Send Limit/hr:  {user['send_limit_per_hour']}" + (" (default)" if not user['send_limit_per_hour'] else ""))
    click.echo()


# ============================================================================
# Domain Management Commands
# ============================================================================


@cli.command("list-domains")
@click.pass_context
def domain_list(ctx: click.Context) -> None:
    """List configured domains."""
    config = _load_config(ctx)

    local = config.get("domains.local_domains", [])
    relay = config.get("domains.relay_domains", [])
    blocked = config.get("domains.blocked_domains", [])

    click.echo("\nLocal Domains:")
    for d in local:
        click.echo(f"  {d}")
    if not local:
        click.echo("  (none)")

    click.echo("\nRelay Domains:")
    for d in relay:
        click.echo(f"  {d}")
    if not relay:
        click.echo("  (none)")

    click.echo("\nBlocked Domains:")
    for d in blocked:
        click.echo(f"  {d}")
    if not blocked:
        click.echo("  (none)")
    click.echo()


@cli.command("add-domain")
@click.argument("domain")
@click.option(
    "--type", "domain_type",
    type=click.Choice(["local", "relay", "blocked"]),
    default="local",
    help="Domain type.",
)
@click.pass_context
def domain_add(ctx: click.Context, domain: str, domain_type: str) -> None:
    """Add a domain."""
    config = _load_config(ctx)
    key = f"domains.{domain_type}_domains"
    domains = config.get(key, [])

    if domain in domains:
        click.echo(f"Domain '{domain}' already in {domain_type} domains.", err=True)
        ctx.exit(1)

    domains.append(domain)
    config.set(key, domains)
    config.save()
    click.echo(f"Domain '{domain}' added to {domain_type} domains.")


@cli.command("remove-domain")
@click.argument("domain")
@click.option(
    "--type", "domain_type",
    type=click.Choice(["local", "relay", "blocked"]),
    default="local",
)
@click.pass_context
def domain_remove(ctx: click.Context, domain: str, domain_type: str) -> None:
    """Remove a domain."""
    config = _load_config(ctx)
    key = f"domains.{domain_type}_domains"
    domains = config.get(key, [])

    if domain not in domains:
        click.echo(f"Domain '{domain}' not found in {domain_type} domains.", err=True)
        ctx.exit(1)

    domains.remove(domain)
    config.set(key, domains)
    config.save()
    click.echo(f"Domain '{domain}' removed from {domain_type} domains.")


# ============================================================================
# Queue Management Commands
# ============================================================================


@cli.command("queue-status")
@click.option("--verbose", "-v", is_flag=True, help="Show individual messages.")
@click.pass_context
def queue_status(ctx: click.Context, verbose: bool) -> None:
    """Show mail queue status."""
    config = _load_config(ctx)

    queue_dir = config.get("queue.directory", "/var/spool/sendq-mta/queue")
    deferred_dir = config.get("queue.deferred_directory", "/var/spool/sendq-mta/deferred")
    failed_dir = config.get("queue.failed_directory", "/var/spool/sendq-mta/failed")

    def _scan_dir(d: str) -> list[dict]:
        msgs = []
        if not os.path.isdir(d):
            return msgs
        for f in sorted(os.listdir(d)):
            if f.endswith(".meta.json"):
                try:
                    with open(os.path.join(d, f)) as fh:
                        msgs.append(json.load(fh))
                except Exception:
                    pass
        return msgs

    active = _scan_dir(queue_dir)
    deferred = _scan_dir(deferred_dir)
    failed = _scan_dir(failed_dir)

    click.echo(f"\nSendQ-MTA Queue Status")
    click.echo(f"  Active:   {len(active)}")
    click.echo(f"  Deferred: {len(deferred)}")
    click.echo(f"  Failed:   {len(failed)}")
    click.echo(f"  Total:    {len(active) + len(deferred) + len(failed)}")

    if verbose and (active or deferred or failed):
        click.echo(f"\nActive Messages:")
        _print_queue_messages(active)
        click.echo(f"\nDeferred Messages:")
        _print_queue_messages(deferred)
        click.echo(f"\nFailed Messages:")
        _print_queue_messages(failed)

    click.echo()


def _print_queue_messages(messages: list[dict]) -> None:
    if not messages:
        click.echo("  (none)")
        return

    _print_table(
        ["MSG ID", "FROM", "RCPTS", "RETRIES", "STATUS", "LAST ERROR"],
        [
            [
                m.get("msg_id", "?")[:24],
                m.get("sender", "?")[:30],
                str(len(m.get("recipients", []))),
                str(m.get("retry_count", 0)),
                m.get("status", "?"),
                (m.get("last_error", "") or "")[:40],
            ]
            for m in messages
        ],
    )


@cli.command("flush-queue")
@click.pass_context
def queue_flush(ctx: click.Context) -> None:
    """Force immediate retry of all deferred messages."""
    config = _load_config(ctx)
    deferred_dir = config.get("queue.deferred_directory", "/var/spool/sendq-mta/deferred")
    queue_dir = config.get("queue.directory", "/var/spool/sendq-mta/queue")

    count = 0
    if os.path.isdir(deferred_dir):
        for f in os.listdir(deferred_dir):
            src = os.path.join(deferred_dir, f)
            dst = os.path.join(queue_dir, f)
            try:
                os.rename(src, dst)
                if f.endswith(".meta.json"):
                    # Update next_retry in metadata
                    with open(dst, "r") as fh:
                        meta = json.load(fh)
                    meta["next_retry"] = 0
                    meta["status"] = "queued"
                    with open(dst, "w") as fh:
                        json.dump(meta, fh, indent=2)
                    count += 1
            except Exception:
                pass

    click.echo(f"Flushed {count} deferred messages to active queue.")

    # Signal running server to process
    pid = _get_pid(config)
    if pid:
        os.kill(pid, signal.SIGUSR1)
        click.echo("Signaled server to process queue.")


@cli.command("delete-msg")
@click.argument("msg_id")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
@click.pass_context
def queue_delete_msg(ctx: click.Context, msg_id: str, yes: bool) -> None:
    """Delete a specific message from the queue."""
    if not yes:
        click.confirm(f"Delete message {msg_id}?", abort=True)

    config = _load_config(ctx)
    dirs = [
        config.get("queue.directory", "/var/spool/sendq-mta/queue"),
        config.get("queue.deferred_directory", "/var/spool/sendq-mta/deferred"),
        config.get("queue.failed_directory", "/var/spool/sendq-mta/failed"),
    ]

    for d in dirs:
        meta = os.path.join(d, f"{msg_id}.meta.json")
        eml = os.path.join(d, f"{msg_id}.eml")
        if os.path.exists(meta):
            os.unlink(meta)
            if os.path.exists(eml):
                os.unlink(eml)
            click.echo(f"Deleted message {msg_id}")
            return

    click.echo(f"Message {msg_id} not found.", err=True)
    ctx.exit(1)


@cli.command("purge-failed")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
@click.pass_context
def queue_purge_failed(ctx: click.Context, yes: bool) -> None:
    """Delete all failed messages."""
    config = _load_config(ctx)
    failed_dir = config.get("queue.failed_directory", "/var/spool/sendq-mta/failed")

    if not os.path.isdir(failed_dir):
        click.echo("No failed messages.")
        return

    files = os.listdir(failed_dir)
    count = sum(1 for f in files if f.endswith(".meta.json"))

    if not count:
        click.echo("No failed messages.")
        return

    if not yes:
        click.confirm(f"Delete {count} failed messages?", abort=True)

    for f in files:
        os.unlink(os.path.join(failed_dir, f))

    click.echo(f"Purged {count} failed messages.")


# ============================================================================
# Configuration Commands
# ============================================================================


@cli.command("validate-config")
@click.pass_context
def config_validate(ctx: click.Context) -> None:
    """Validate the configuration file."""
    config = _load_config(ctx)
    click.echo(f"Config file: {config.path or '(defaults)'}")

    errors = config.validate()
    if errors:
        click.echo(f"\nValidation FAILED ({len(errors)} errors):\n", err=True)
        for err in errors:
            click.echo(f"  - {err}", err=True)
        ctx.exit(1)
    else:
        click.echo("Configuration is valid.")


@cli.command("show-config")
@click.option("--section", "-s", default=None, help="Show specific section only.")
@click.pass_context
def config_show(ctx: click.Context, section: str | None) -> None:
    """Display the current configuration."""
    config = _load_config(ctx)

    if section:
        data = config.get(section)
        if data is None:
            click.echo(f"Section '{section}' not found.", err=True)
            ctx.exit(1)
        click.echo(yaml.dump({section: data}, default_flow_style=False))
    else:
        # Redact sensitive fields
        data = config.as_dict()
        _redact_secrets(data)
        click.echo(yaml.dump(data, default_flow_style=False))


def _redact_secrets(data: dict, _keys_to_redact: set | None = None) -> None:
    """Recursively redact sensitive values in config dict."""
    sensitive = _keys_to_redact or {"password", "api_key", "bind_password", "secret"}
    for key, value in data.items():
        if isinstance(value, dict):
            _redact_secrets(value, sensitive)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _redact_secrets(item, sensitive)
        elif any(s in key.lower() for s in sensitive):
            if value:
                data[key] = "********"


@cli.command("test-relay")
@click.pass_context
def relay_test(ctx: click.Context) -> None:
    """Test connectivity to the configured SMTP relay."""
    config = _load_config(ctx)
    relay = config.get("relay", {})

    if not relay.get("enabled"):
        click.echo("Relay is not enabled. Using direct MX delivery.")
        return

    host = relay.get("host", "")
    port = relay.get("port", 587)
    tls_mode = relay.get("tls_mode", "starttls")

    click.echo(f"Testing relay: {host}:{port} (tls={tls_mode})...")

    async def _test():
        import aiosmtplib
        import ssl as _ssl

        kwargs = {"hostname": host, "port": port, "timeout": 15}

        if tls_mode == "implicit":
            kwargs["use_tls"] = True
            ctx_tls = _ssl.create_default_context()
            if not relay.get("tls_verify", True):
                ctx_tls.check_hostname = False
                ctx_tls.verify_mode = _ssl.CERT_NONE
            kwargs["tls_context"] = ctx_tls

        try:
            smtp = aiosmtplib.SMTP(**kwargs)
            await smtp.connect()

            if tls_mode == "starttls":
                ctx_tls = _ssl.create_default_context()
                if not relay.get("tls_verify", True):
                    ctx_tls.check_hostname = False
                    ctx_tls.verify_mode = _ssl.CERT_NONE
                await smtp.starttls(tls_context=ctx_tls)
                click.echo("  STARTTLS: OK")

            username = relay.get("username", "")
            password = relay.get("password", "")
            if username and password:
                await smtp.login(username, password)
                click.echo("  AUTH: OK")

            await smtp.noop()
            click.echo("  NOOP: OK")

            await smtp.quit()
            click.echo("\nRelay test PASSED.")
        except Exception as e:
            click.echo(f"\nRelay test FAILED: {e}", err=True)
            ctx.exit(1)

    asyncio.run(_test())


# ============================================================================
# DKIM Commands
# ============================================================================


@cli.command("test-send")
@click.option("--to", "recipient", required=True, help="Recipient email address.")
@click.option("--from", "sender", default=None, help="Sender address (default: test@<hostname>).")
@click.option("--subject", "-s", default="SendQ-MTA Test Message", help="Email subject.")
@click.option("--body", "-b", default=None, help="Email body text.")
@click.option("--port", "-p", type=int, default=25, help="SMTP port to connect to (default: 25).")
@click.option("--host", "-h", default="127.0.0.1", help="SMTP host to connect to (default: 127.0.0.1).")
@click.pass_context
def test_send(
    ctx: click.Context,
    recipient: str,
    sender: str | None,
    subject: str,
    body: str | None,
    port: int,
    host: str,
) -> None:
    """Send a test email through the local MTA."""
    config = _load_config(ctx)
    hostname = config.get("server.hostname", "localhost")
    if not sender:
        sender = f"test@{hostname}"
    if not body:
        body = (
            f"This is a test message from SendQ-MTA.\n"
            f"Hostname: {hostname}\n"
            f"If you received this, outbound delivery is working.\n"
        )

    from email.mime.text import MIMEText
    from email.utils import formatdate, make_msgid

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=hostname)

    click.echo(f"Sending test email...")
    click.echo(f"  From:    {sender}")
    click.echo(f"  To:      {recipient}")
    click.echo(f"  Subject: {subject}")
    click.echo(f"  Via:     {host}:{port}")

    async def _send():
        import aiosmtplib

        try:
            smtp = aiosmtplib.SMTP(hostname=host, port=port, timeout=30)
            await smtp.connect()

            # Try STARTTLS if available (opportunistic)
            if port != 465:
                try:
                    import ssl as _ssl
                    tls_ctx = _ssl.create_default_context()
                    tls_ctx.check_hostname = False
                    tls_ctx.verify_mode = _ssl.CERT_NONE
                    await smtp.starttls(tls_context=tls_ctx)
                except Exception:
                    pass  # Continue without TLS

            await smtp.sendmail(sender, [recipient], msg.as_string())
            await smtp.quit()
            click.echo("\nTest email sent successfully! Check the queue with: sendq-mta queue-status -v")
        except Exception as e:
            click.echo(f"\nFailed to send test email: {e}", err=True)
            ctx.exit(1)

    asyncio.run(_send())


@cli.command("generate-dkim")
@click.option("--domain", "-d", required=True, help="Domain to generate DKIM key for.")
@click.option("--selector", "-s", default=None, help="DKIM selector (default: from config).")
@click.option("--bits", "-b", type=int, default=2048, help="RSA key size.")
@click.option("--output-dir", "-o", default="/etc/sendq-mta/dkim", help="Output directory.")
@click.pass_context
def dkim_generate(
    ctx: click.Context, domain: str, selector: str | None, bits: int, output_dir: str
) -> None:
    """Generate DKIM key pair for a domain."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        click.echo("Error: 'cryptography' package required. Install with: pip install cryptography", err=True)
        ctx.exit(1)

    config = _load_config(ctx)
    selector = selector or config.get("dkim.selector", "sendq")

    os.makedirs(output_dir, exist_ok=True)

    # Generate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    import base64

    pub_b64 = base64.b64encode(public_der).decode()

    # Save private key
    key_path = os.path.join(output_dir, f"{domain}.{selector}.private.pem")
    with open(key_path, "wb") as f:
        f.write(private_pem)
    os.chmod(key_path, 0o600)

    # Save DNS record
    dns_path = os.path.join(output_dir, f"{domain}.{selector}.dns.txt")
    dns_record = f'{selector}._domainkey.{domain} IN TXT "v=DKIM1; k=rsa; p={pub_b64}"'
    with open(dns_path, "w") as f:
        f.write(dns_record + "\n")

    click.echo(f"\nDKIM key pair generated for {domain}:")
    click.echo(f"  Private key: {key_path}")
    click.echo(f"  DNS record:  {dns_path}")
    click.echo(f"\nAdd this DNS TXT record:")
    click.echo(f"  {dns_record}")
    click.echo()


# ============================================================================
# Internal Helpers
# ============================================================================


def _run_server(config: Config) -> None:
    """Run the MTA server (blocking)."""
    from sendq_mta.core.server import MTAServer
    from sendq_mta.utils.logging_setup import setup_logging

    setup_logging(config)
    server = MTAServer(config)

    # Write PID
    pid_file = config.get("server.pid_file", "/var/run/sendq-mta/sendq-mta.pid")
    os.makedirs(os.path.dirname(pid_file), exist_ok=True)
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))

    try:
        asyncio.run(server.run_forever())
    finally:
        if os.path.exists(pid_file):
            os.unlink(pid_file)


def _daemonize(config: Config) -> None:
    """Fork into background daemon (proper double-fork)."""
    pid = os.fork()
    if pid > 0:
        click.echo(f"SendQ-MTA started (PID {pid})")
        sys.exit(0)

    os.setsid()
    os.umask(0o027)
    os.chdir("/")

    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    # Redirect standard file descriptors
    sys.stdin.close()

    log_file = config.get("logging.file", "/var/log/sendq-mta/sendq-mta.log")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    log_fd = open(log_file, "a")
    sys.stdout = log_fd
    sys.stderr = log_fd

    _run_server(config)


# ============================================================================
# Entry Point
# ============================================================================


def main() -> None:
    """Main entry point for the sendq-mta CLI."""
    cli(auto_envvar_prefix="SENDQ_MTA")

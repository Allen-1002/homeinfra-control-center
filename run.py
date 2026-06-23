"""Run the HomeInfra stdlib-only API locally."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from homeinfra import create_server


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HomeInfra local backend")
    parser.add_argument("--host", default=os.getenv("APP_HOST", "127.0.0.1"), help="Bind host")
    parser.add_argument("--port", type=int, default=int(os.getenv("APP_PORT", "8010")), help="Bind port")
    parser.add_argument(
        "--static-dir",
        default=os.getenv("STATIC_DIR") or None,
        help="Optional static directory to serve for non-API routes",
    )
    parser.add_argument(
        "--store-mode",
        choices=("sqlite", "mock"),
        default=os.getenv("STORE_MODE", "sqlite"),
        help="Persistence mode. sqlite is the default MVP backend; mock keeps everything in-memory.",
    )
    parser.add_argument(
        "--db-path",
        default=os.getenv("HOMEINFRA_DB_PATH", str(Path("data") / "homeinfra.db")),
        help="SQLite database path when --store-mode=sqlite",
    )
    parser.add_argument(
        "--collector-mode",
        choices=("ssh", "disabled"),
        default=(
            "ssh" if os.getenv("COLLECTOR_MODE") == "ssh"
            else os.getenv("COLLECTOR_MODE", "disabled")
        ),
        help="Collector mode: ssh (real), disabled (no collection)",
    )
    parser.add_argument(
        "--ssh-known-hosts",
        default=os.getenv("SSH_KNOWN_HOSTS") or None,
        help="Path to known_hosts file for SSH host key verification",
    )
    parser.add_argument(
        "--ssh-auto-accept-host-key",
        action="store_true",
        default=env_flag("SSH_AUTO_ACCEPT_HOST_KEY", False),
        help="Auto-accept unknown SSH host keys (use with caution)",
    )
    parser.add_argument(
        "--ssh-retry-max",
        type=int,
        default=int(os.getenv("SSH_RETRY_MAX", "3")),
        help="Maximum SSH connection retry attempts (default: 3)",
    )
    parser.add_argument(
        "--ssh-retry-base-delay",
        type=float,
        default=float(os.getenv("SSH_RETRY_BASE_DELAY", "1.0")),
        help="Base delay in seconds between SSH retries (default: 1.0)",
    )
    parser.add_argument(
        "--enable-ssh",
        action="store_true",
        default=env_flag("SSH_ENABLE_REAL_COLLECTOR", False),
        help="Deprecated: use --collector-mode=ssh instead",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    collector_mode = args.collector_mode
    if args.enable_ssh and collector_mode not in {"ssh"}:
        collector_mode = "ssh"
    server = create_server(
        args.host,
        args.port,
        static_dir=args.static_dir,
        store_mode=args.store_mode,
        db_path=args.db_path,
        collector_mode=collector_mode,
        ssh_known_hosts=args.ssh_known_hosts,
        ssh_auto_accept_host_key=args.ssh_auto_accept_host_key,
        ssh_retry_max=args.ssh_retry_max,
        ssh_retry_base_delay=args.ssh_retry_base_delay,
    )
    print(
        f"HomeInfra API listening on http://{args.host}:{args.port} "
        f"(store_mode={args.store_mode}, collector_mode={collector_mode})"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

# HomeInfra Control Center

HomeInfra Control Center is a lightweight control panel for monitoring and managing home infrastructure devices such as NAS systems, Linux servers, routers, and mini PCs.

This is my first relatively complete personal project. AI tools were used during development to help with code writing, debugging, and structural cleanup, while the requirements, feature decisions, testing, deployment, and final project organization were reviewed and completed by me.

## Project Overview

The project is built as a local-first web application with a small deployment footprint:

- Python backend based on the standard library HTTP stack
- Static HTML, CSS, and JavaScript frontend
- SQLite persistence by default
- Optional SSH-based collection for read-only device monitoring

It is intended for private or lab environments and is not designed to be exposed directly to the public internet.

## Features

- Device CRUD with enable/disable, test connection, and manual refresh
- Device groups for organizing monitored hosts
- Historical collection records with filtering
- Alert generation and resolution flow
- Audit log for key operations
- Local user management with `admin`, `operator`, and `viewer` roles
- Retention settings and cleanup for historical data

## Tech Stack

- Python 3
- SQLite
- Vanilla JavaScript
- HTML/CSS
- Docker Compose
- Paramiko for optional SSH collection

## Deployment

Run locally:

```sh
python3 run.py --host 127.0.0.1 --port 8010 --static-dir static
```

Open:

```text
http://127.0.0.1:8010/
```

Run with Docker:

```sh
docker compose up --build
```

## Configuration

Important defaults:

- Database path: `./data/homeinfra.db`
- Static assets: `./static`
- Example environment variables: [`.env.example`](./.env.example)

You can override the database path at startup:

```sh
python3 run.py --db-path /app/data/homeinfra.db
```

On first startup with an empty database, the app requires creating the first administrator account before normal login is available.

## Collector Modes

Collector behavior is controlled by `COLLECTOR_MODE`.

| Mode | Value | Description |
| --- | --- | --- |
| Disabled | `disabled` | Saves device configuration only and does not perform collection |
| SSH | `ssh` | Connects to target devices through SSH and runs read-only allowlisted commands |

Local run examples:

```sh
python3 run.py --host 127.0.0.1 --port 8010 --static-dir static
COLLECTOR_MODE=ssh python3 run.py --host 127.0.0.1 --port 8010 --static-dir static
```

SSH key example:

```sh
mkdir -p ./ssh-keys
ssh-keygen -t ed25519 -C "homeinfra-monitor" -f ./ssh-keys/id_ed25519
ssh-copy-id -i ./ssh-keys/id_ed25519.pub monitor@example-host
```

Container path example:

```json
{
  "private_key_path": "/app/ssh-keys/id_ed25519"
}
```

## Testing

Core checks:

```sh
python3 -m unittest -v
node --check static/app.js
```

Optional compile check:

```sh
PYTHONPYCACHEPREFIX=/private/tmp/homeinfra-pyc python3 -m compileall homeinfra run.py tests
```

Optional SSH smoke test in a prepared environment:

```sh
chmod +x smoke_test.sh
./smoke_test.sh
```

More details are available in [`TESTING.md`](./TESTING.md).

## Notes

- The project is local-first and should stay behind a trusted network boundary.
- The SSH collector is designed for read-only monitoring and uses an allowlist of commands.
- No VPN management, file synchronization, or other high-risk remote control features are included.
- Additional interface and API details are documented in [`API.md`](./API.md), [`ARCHITECTURE.md`](./ARCHITECTURE.md), and [`前端API调用规则.md`](./前端API调用规则.md).

## License

This project is licensed under the MIT License.

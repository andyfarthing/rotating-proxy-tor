# rotating-proxy-tor

An HTTP/HTTPS rotating proxy that routes every connection through a pool of independent Tor circuits. Each connection is assigned an exclusive Tor instance for its lifetime, distributed in round-robin order. When all instances are busy, new connections wait up to a configurable timeout before receiving a 503.

## How it works

1. On startup, `entrypoint.sh` launches `TOR_INSTANCES` (default **10**) independent `tor` daemons. Each daemon gets its own data directory, SOCKS port, and control port so it builds completely separate circuits with different guard nodes and exit IPs.

2. The script polls each instance's log until it sees `Bootstrapped 100%` (or the timeout elapses), then writes a JSON manifest of SOCKS addresses for the Go proxy.

3. The Go proxy listens for HTTP and HTTPS (`CONNECT`) requests. Each accepted connection is leased one Tor instance from the pool.

4. Outbound traffic is forwarded through the leased instance's SOCKS5 port. DNS resolution happens inside Tor, so there is no DNS leakage. When the connection closes, the instance is returned to the pool.

## Requirements

- Docker (no special capabilities or kernel modules required — Tor runs entirely in userspace)

## Quick start

```sh
docker compose up --build
```

- **Proxy**: `http://localhost:8080` — point your HTTP client here
- **Web UI**: `http://localhost:8088` — live status of all Tor instances

## Using the proxy

### curl

```sh
curl -x http://localhost:8080 https://api4.ipify.org
```

### Python requests

```python
import requests
proxies = {"http": "http://localhost:8080", "https": "http://localhost:8080"}
print(requests.get("https://api4.ipify.org", proxies=proxies).text)
```

### System-wide (macOS / Linux)

Set your system HTTP proxy to `localhost:8080`.

## Environment variables

| Variable                | Default                        | Description                                                      |
| ----------------------- | ------------------------------ | ---------------------------------------------------------------- |
| `TOR_INSTANCES`         | `10`                           | Number of Tor instances (each has its own circuit and exit IP)   |
| `TOR_BASE_SOCKS_PORT`   | `9050`                         | First SOCKS port; subsequent instances use +1 (9050, 9051, …)    |
| `TOR_BASE_CTRL_PORT`    | `10050`                        | First control port; used to query exit IPs for the web UI        |
| `TOR_BOOTSTRAP_TIMEOUT` | `120`                          | Seconds to wait for each instance to bootstrap before continuing |
| `PROXY_PORT`            | `8080`                         | Port the proxy listens on                                        |
| `WEB_UI_PORT`           | `8088`                         | Port the web UI listens on (`0` to disable)                      |
| `LEASE_TIMEOUT`         | `30s`                          | How long to wait for a free instance before returning 503        |
| `DIAL_TIMEOUT`          | `120s`                         | Timeout for dialling upstream through Tor (circuits can be slow) |
| `LOG_LEVEL`             | `info`                         | Log verbosity: `debug`, `info`, `warn`, `error`                  |
| `TOR_DATA_DIR`          | `/var/lib/tor-instances`       | Base directory for per-instance data directories                 |
| `MANIFEST_PATH`         | `/run/tor-proxy/manifest.json` | Path for the SOCKS address manifest written at startup           |
| `TOR_CTRL_BASE_PORT`    | `10050`                        | Go proxy: base control port for exit-IP queries (`0` to disable) |

### Changing the number of instances

```yaml
# docker-compose.yml
environment:
  TOR_INSTANCES: "20"
```

Tor instances take 30–120 seconds to bootstrap depending on network conditions. Startup blocks until all instances are ready (or the timeout elapses).

## Web UI

The web UI (`http://localhost:8088`) auto-refreshes every second and shows:

| Column              | Description                                                    |
| ------------------- | -------------------------------------------------------------- |
| Instance            | Tor instance name (`tor0`–`torN`)                              |
| SOCKS Address       | Internal SOCKS5 port this instance listens on                  |
| Status              | `free` / `busy`                                                |
| Exit Node           | Public IP seen by the outside world (queried via control port) |
| Last Used           | When this instance last finished serving a connection          |
| ↑ Sent / ↓ Received | Cumulative bytes through this instance                         |
| Current Client      | Remote address of the active connection, if busy               |

A JSON API is also available at `http://localhost:8088/api/status`.

## Running tests

```sh
docker compose up -d --build
pip install -r tests/requirements.txt
pytest tests/ -v
```

Tests require the proxy to be running and all instances bootstrapped. See `tests/requirements.txt` for Python dependencies.

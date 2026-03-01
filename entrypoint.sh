#!/bin/sh
# entrypoint.sh — starts N independent Tor instances for the rotating proxy,
# waits for all of them to bootstrap, writes a manifest of SOCKS addresses,
# then execs the Go proxy binary.
#
# Environment variables (all optional):
#   TOR_INSTANCES          — number of Tor instances to start (default: 10)
#   TOR_BASE_SOCKS_PORT    — first SOCKS port; subsequent instances use +1 (default: 9050)
#   TOR_BASE_CTRL_PORT     — first control port (default: 10050)
#   TOR_DATA_DIR           — base directory for per-instance data dirs (default: /var/lib/tor-instances)
#   TOR_BOOTSTRAP_TIMEOUT  — seconds to wait for each instance to bootstrap (default: 120)
#   MANIFEST_PATH          — path to write the interface manifest JSON (default: /run/tor-proxy/manifest.json)

set -e

TOR_INSTANCES="${TOR_INSTANCES:-10}"
TOR_BASE_SOCKS_PORT="${TOR_BASE_SOCKS_PORT:-9050}"
TOR_BASE_CTRL_PORT="${TOR_BASE_CTRL_PORT:-10050}"
TOR_DATA_DIR="${TOR_DATA_DIR:-/var/lib/tor-instances}"
TOR_BOOTSTRAP_TIMEOUT="${TOR_BOOTSTRAP_TIMEOUT:-120}"
MANIFEST_PATH="${MANIFEST_PATH:-/run/tor-proxy/manifest.json}"
MANIFEST_DIR="$(dirname "$MANIFEST_PATH")"
TOR_EXIT_REGION="${TOR_EXIT_REGION:-}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { printf '[entrypoint] %s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

# ---------------------------------------------------------------------------
# Resolve TOR_EXIT_REGION to a comma-separated list of {CC} country codes.
# An empty region means worldwide (no restriction).
# ---------------------------------------------------------------------------

case "$(echo "$TOR_EXIT_REGION" | tr '[:upper:]' '[:lower:'])" in
    europe)
        EXIT_NODES="{gb},{de},{fr},{nl},{se},{no},{ch},{at},{be},{dk},{fi},{ie},{es},{pt},{it}" ;;
    americas)
        EXIT_NODES="{us},{ca},{mx},{br},{ar}" ;;
    us)
        EXIT_NODES="{us}" ;;
    uk)
        EXIT_NODES="{gb}" ;;
    asia)
        EXIT_NODES="{jp},{sg},{hk},{kr},{tw},{in}" ;;
    "" | worldwide)
        EXIT_NODES="" ;;
    *)
        log "WARNING: unknown TOR_EXIT_REGION '${TOR_EXIT_REGION}' — defaulting to worldwide"
        EXIT_NODES="" ;;
esac

[ -n "$EXIT_NODES" ] && log "Restricting exit nodes to: $EXIT_NODES"

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------

command -v tor >/dev/null 2>&1 || die "'tor' not found — is the tor package installed?"

# ---------------------------------------------------------------------------
# Start Tor instances
# ---------------------------------------------------------------------------

mkdir -p "$MANIFEST_DIR"
mkdir -p "$TOR_DATA_DIR"

log "Starting $TOR_INSTANCES Tor instance(s)..."

i=0
while [ "$i" -lt "$TOR_INSTANCES" ]; do
    SOCKS_PORT=$((TOR_BASE_SOCKS_PORT + i))
    CTRL_PORT=$((TOR_BASE_CTRL_PORT + i))
    INST_DIR="${TOR_DATA_DIR}/tor${i}"
    LOG_FILE="${INST_DIR}/notices.log"

    mkdir -p "$INST_DIR"

    log "Starting tor${i}: SocksPort=${SOCKS_PORT} ControlPort=${CTRL_PORT}"

    # Write a torrc for this instance. CookieAuthentication 0 with no
    # HashedControlPassword = null auth on the control port (safe because
    # it only binds to 127.0.0.1 and is never exposed outside the container).
    cat > "${INST_DIR}/torrc" <<EOF
DataDirectory ${INST_DIR}
SocksPort 127.0.0.1:${SOCKS_PORT}
SocksPolicy accept 127.0.0.1
SocksPolicy reject *
ControlPort 127.0.0.1:${CTRL_PORT}
CookieAuthentication 0
User nobody
Log notice file ${LOG_FILE}
# Each instance uses a completely separate data directory → separate guard
# nodes → different circuits and exit IPs from each other.
$([ -n "$EXIT_NODES" ] && printf 'ExitNodes %s\nStrictNodes 1' "$EXIT_NODES")
EOF

    # Truncate the log so we can wait cleanly for bootstrap.
    : > "$LOG_FILE"

    # Tor switches from root to 'nobody' automatically; chown the entire
    # instance directory (including torrc and notices.log) so Tor can write
    # its state files and log after the user switch.
    chmod 700 "$INST_DIR"
    chown -R nobody:nobody "$INST_DIR"

    # Start Tor in the background and save its PID for the watchdog.
    tor -f "${INST_DIR}/torrc" &
    echo $! > "/tmp/tor_pid_${i}"

    i=$((i + 1))
done

# ---------------------------------------------------------------------------
# Wait for all instances to bootstrap (all polled in parallel each tick)
# ---------------------------------------------------------------------------

log "Waiting for all $TOR_INSTANCES instance(s) to bootstrap (timeout: ${TOR_BOOTSTRAP_TIMEOUT}s)..."

STARTED=$(date +%s)
# Bootstrap state per instance: 0 = pending, 1 = done.
# We track this via files in /tmp to avoid arrays (POSIX sh).
i=0
while [ "$i" -lt "$TOR_INSTANCES" ]; do
    rm -f "/tmp/tor_boot_${i}"
    i=$((i + 1))
done

while true; do
    DONE=0
    i=0
    while [ "$i" -lt "$TOR_INSTANCES" ]; do
        if [ ! -f "/tmp/tor_boot_${i}" ]; then
            LOG_FILE="${TOR_DATA_DIR}/tor${i}/notices.log"
            if grep -q "Bootstrapped 100%" "$LOG_FILE" 2>/dev/null; then
                log "tor${i} bootstrapped"
                touch "/tmp/tor_boot_${i}"
            fi
        fi
        [ -f "/tmp/tor_boot_${i}" ] && DONE=$((DONE + 1))
        i=$((i + 1))
    done

    [ "$DONE" -ge "$TOR_INSTANCES" ] && break

    NOW=$(date +%s)
    ELAPSED=$((NOW - STARTED))
    if [ "$ELAPSED" -ge "$TOR_BOOTSTRAP_TIMEOUT" ]; then
        log "WARNING: bootstrap timeout after ${TOR_BOOTSTRAP_TIMEOUT}s ($DONE/$TOR_INSTANCES ready) — continuing anyway"
        break
    fi

    sleep 1
done

# ---------------------------------------------------------------------------
# Write the JSON manifest for the Go proxy
# ---------------------------------------------------------------------------

printf '[' > "$MANIFEST_PATH"
FIRST=1
i=0
while [ "$i" -lt "$TOR_INSTANCES" ]; do
    SOCKS_PORT=$((TOR_BASE_SOCKS_PORT + i))
    if [ "$FIRST" = "1" ]; then
        FIRST=0
    else
        printf ',' >> "$MANIFEST_PATH"
    fi
    printf '{"interface":"tor%d","address":"127.0.0.1:%d"}' "$i" "$SOCKS_PORT" >> "$MANIFEST_PATH"
    i=$((i + 1))
done
printf ']' >> "$MANIFEST_PATH"

log "Manifest written to $MANIFEST_PATH"
log "Tor setup complete. Starting proxy..."

# ---------------------------------------------------------------------------
# Background watchdog — restarts any tor process that dies unexpectedly
# ---------------------------------------------------------------------------

(
    while true; do
        sleep 30
        j=0
        while [ "$j" -lt "$TOR_INSTANCES" ]; do
            PID_FILE="/tmp/tor_pid_${j}"
            if [ -f "$PID_FILE" ]; then
                PID=$(cat "$PID_FILE")
                if ! kill -0 "$PID" 2>/dev/null; then
                    log "tor${j} (PID $PID) died — restarting..."
                    INST_DIR="${TOR_DATA_DIR}/tor${j}"
                    LOG_FILE="${INST_DIR}/notices.log"
                    : > "$LOG_FILE"
                    chown nobody:nobody "$LOG_FILE" 2>/dev/null || true
                    tor -f "${INST_DIR}/torrc" &
                    NEW_PID=$!
                    echo $NEW_PID > "$PID_FILE"
                    log "tor${j} restarted with PID $NEW_PID"
                fi
            fi
            j=$((j + 1))
        done
    done
) &

# ---------------------------------------------------------------------------
# Exec the proxy (replaces this shell so signals propagate correctly)
# ---------------------------------------------------------------------------

exec /app/proxy


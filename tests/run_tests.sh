#!/bin/sh
# run_tests.sh — sets up a venv, installs deps, and runs the test suite.
#
# Usage:
#   ./tests/run_tests.sh              # all fast tests
#   ./tests/run_tests.sh --slow       # include slow (queue/exhaustion) tests
#   ./tests/run_tests.sh -k rotation  # filter by test name

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$SCRIPT_DIR/.venv"

# ── Create / reuse the virtual environment ────────────────────────────────
if [ ! -f "$VENV_DIR/bin/python" ]; then
    echo "Creating test virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"

# ── Build pytest marker flags ─────────────────────────────────────────────
# MARKER_EXPR holds only the expression passed to -m, not the flag itself.
MARKER_EXPR="not slow"
EXTRA_ARGS=""

for arg in "$@"; do
    case "$arg" in
        --slow)
            MARKER_EXPR=""  # run everything including slow tests
            ;;
        *)
            EXTRA_ARGS="$EXTRA_ARGS $arg"
            ;;
    esac
done

# ── Run ───────────────────────────────────────────────────────────────────
cd "$PROJECT_DIR"

echo ""
echo "Testing against proxy at ${PROXY_HOST:-localhost}:${PROXY_PORT:-8080}"
echo "Web UI at ${PROXY_HOST:-localhost}:${WEB_UI_PORT:-8088}"
echo ""

# shellcheck disable=SC2086
"$VENV_DIR/bin/pytest" tests/test_proxy.py \
    -v \
    --tb=short \
    ${MARKER_EXPR:+-m "$MARKER_EXPR"} \
    $EXTRA_ARGS

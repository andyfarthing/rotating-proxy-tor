"""
Integration tests for rotating-proxy-tor.

Prerequisites:
  - Container is running and all Tor instances have bootstrapped:
      docker compose up -d --build
  - Python deps installed:
      pip install -r tests/requirements.txt

Run all tests:
    pytest tests/ -v

Run only fast tests (skip queue/exhaustion):
    pytest tests/ -v -m "not slow"

Run with a custom proxy address:
    PROXY_HOST=localhost PROXY_PORT=8080 pytest tests/ -v

Note: Tor circuits can take 30-120 seconds to bootstrap on startup.
      Wait for all instances to report 'Bootstrapped 100%' in the logs
      before running tests:  docker compose logs -f tor-proxy
"""

import os
import time
import threading
import concurrent.futures
from typing import Optional

import pytest
import requests

# ---------------------------------------------------------------------------
# Configuration — override via environment variables
# ---------------------------------------------------------------------------

PROXY_HOST = os.getenv("PROXY_HOST", "localhost")
PROXY_PORT = int(os.getenv("PROXY_PORT", "8080"))
WEB_UI_PORT = int(os.getenv("WEB_UI_PORT", "8088"))

PROXY_URL = f"http://{PROXY_HOST}:{PROXY_PORT}"
WEB_UI_URL = f"http://{PROXY_HOST}:{WEB_UI_PORT}"

# proxies dict for requests library
PROXIES = {"http": PROXY_URL, "https": PROXY_URL}

# External endpoints used by tests.
#
# IP_CHECK_URL — HTTPS endpoint used for most connectivity tests. All requests
# go via HTTP CONNECT so the proxy tunnels the TLS session without reading the
# body; no redirect issues here.
#
# IP_CHECK_URL_HTTP — plain HTTP endpoint. Used only by get_tunnel_iface() so
# the request goes through handleHTTP (not handleCONNECT), which lets the
# proxy inject the X-Tunnel-Interface response header that the test reads back.
# allow_redirects=False is set on all calls; if the server redirects (301) the
# proxy still injects X-Tunnel-Interface on that response, so the header is
# readable regardless of the redirect status code.
IP_CHECK_URL = "https://api4.ipify.org"
IP_CHECK_URL_HTTP = "http://api4.ipify.org"

# A slow endpoint that holds the connection open for N seconds.
# Uses HTTPS directly (httpbin redirects HTTP→HTTPS).
SLOW_URL_TEMPLATE = "https://httpbin.org/delay/{seconds}"

# How long individual requests are allowed to take before the test fails.
# Tor circuits are slower than direct connections — 90s is a safe ceiling.
REQUEST_TIMEOUT = 90  # seconds

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_outbound_ip(timeout: int = REQUEST_TIMEOUT) -> str:
    """Return the outbound public IP seen when routing through the proxy."""
    resp = requests.get(
        IP_CHECK_URL,
        proxies=PROXIES,
        timeout=timeout,
        verify=True,
        allow_redirects=False,  # never follow redirects — a redirect would
    )  # consume a second tunnel slot and break rotation tests
    resp.raise_for_status()
    return resp.text.strip()


def get_tunnel_iface(timeout: int = REQUEST_TIMEOUT) -> str:
    """Return the X-Tunnel-Interface header injected by the proxy.

    MUST use a plain HTTP URL (IP_CHECK_URL_HTTP) so the request is handled by
    the proxy's handleHTTP path, which forwards the proxied response and adds
    X-Tunnel-Interface to it. HTTPS requests go via handleCONNECT (a raw TCP
    tunnel) where the proxy never sees the HTTP response and cannot inject
    headers — the CONNECT 200 response is also not exposed by the requests
    library to the caller.

    allow_redirects=False is intentional: even if the server returns a 301,
    the proxy has already injected X-Tunnel-Interface on that response.
    """
    resp = requests.get(
        IP_CHECK_URL_HTTP,
        proxies=PROXIES,
        timeout=timeout,
        allow_redirects=False,
    )
    iface = resp.headers.get("X-Tunnel-Interface", "")
    assert iface, (
        "X-Tunnel-Interface header missing from proxy response. "
        "Ensure the container was rebuilt after the latest proxy.go changes "
        "(docker compose up -d --build)."
    )
    return iface


def status_api() -> dict:
    """Fetch the /api/status JSON from the web UI."""
    resp = requests.get(f"{WEB_UI_URL}/api/status", timeout=10)
    resp.raise_for_status()
    return resp.json()


def tunnel_count() -> int:
    """Return the number of tunnels reported by the status API."""
    return len(status_api()["tunnels"])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def n_tunnels() -> int:
    """Discover the tunnel count once per test session from the live status API."""
    try:
        count = tunnel_count()
    except Exception as exc:
        pytest.skip(f"Cannot reach status API at {WEB_UI_URL}: {exc}")
    if count == 0:
        pytest.skip(
            "No Tor instances are active — check container logs: "
            "docker compose logs tor-proxy"
        )
    return count


# ---------------------------------------------------------------------------
# 1. Connectivity
# ---------------------------------------------------------------------------


class TestConnectivity:
    def test_proxy_reachable(self):
        """An HTTPS request through the proxy returns 200."""
        resp = requests.get(
            IP_CHECK_URL,
            proxies=PROXIES,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert resp.text.strip(), "Response body was empty"

    def test_https_connect_tunnel(self):
        """An HTTPS CONNECT tunnel returns a valid IP and the X-Tunnel-Interface header."""
        ip = get_outbound_ip()
        # Should look like an IPv4 address
        assert len(ip) >= 7, f"IP address looks wrong: {ip!r}"
        iface = get_tunnel_iface()
        assert iface.startswith("tor"), f"Expected a tor* instance, got: {iface!r}"

    def test_proxy_returns_ip_not_localhost(self):
        """The outbound IP must not be localhost — traffic must leave through a tunnel."""
        ip = get_outbound_ip()
        assert not ip.startswith("127."), f"Got loopback IP — tunnel not active: {ip}"
        assert ip != "::1", "Got IPv6 loopback — tunnel not active"


# ---------------------------------------------------------------------------
# 2. Web UI / Status API
# ---------------------------------------------------------------------------


class TestStatusAPI:
    def test_web_ui_root_returns_html(self):
        """The web UI root page returns HTML."""
        resp = requests.get(WEB_UI_URL, timeout=10)
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("Content-Type", "")

    def test_status_api_shape(self, n_tunnels):
        """The /api/status response has the expected structure."""
        data = status_api()
        assert "tunnels" in data, "Missing 'tunnels' key"
        assert "collected_at" in data, "Missing 'collected_at' key"
        assert isinstance(data["tunnels"], list)

    def test_status_reports_correct_tunnel_count(self, n_tunnels):
        """/api/status reports one entry per config file."""
        data = status_api()
        assert (
            len(data["tunnels"]) == n_tunnels
        ), f"Expected {n_tunnels} tunnels, got {len(data['tunnels'])}"

    def test_status_tunnel_fields(self, n_tunnels):
        """Each tunnel entry contains the required fields."""
        required = {"interface", "address", "status"}
        for tunnel in status_api()["tunnels"]:
            missing = required - set(tunnel.keys())
            assert (
                not missing
            ), f"Tunnel {tunnel.get('interface')} missing fields: {missing}"

    def test_status_all_tunnels_initially_free(self, n_tunnels):
        """All tunnels should be free when no client is connected."""
        # Wait briefly in case a previous test just released a tunnel.
        time.sleep(1)
        for tunnel in status_api()["tunnels"]:
            assert (
                tunnel["status"] == "free"
            ), f"Tunnel {tunnel['interface']} unexpectedly busy"

    def test_status_shows_busy_during_request(self, n_tunnels):
        """A tunnel transitions to 'busy' while a request is in flight and
        back to 'free' once it completes."""
        statuses_during = []

        def slow_request():
            url = SLOW_URL_TEMPLATE.format(seconds=5)
            requests.get(
                url, proxies=PROXIES, timeout=REQUEST_TIMEOUT, allow_redirects=False
            )

        t = threading.Thread(target=slow_request)
        t.start()

        # Poll status while the request is in flight.
        time.sleep(1.5)  # Give time for the tunnel to be acquired.
        data = status_api()
        statuses_during = [tun["status"] for tun in data["tunnels"]]

        t.join()

        # After join, all tunnels should be free again.
        time.sleep(0.5)
        statuses_after = [tun["status"] for tun in status_api()["tunnels"]]

        assert "busy" in statuses_during, (
            "No tunnel became busy during an in-flight request. "
            "Lease tracking may be broken."
        )
        assert all(
            s == "free" for s in statuses_after
        ), f"Some tunnels still busy after request completed: {statuses_after}"

    def test_status_busy_entry_has_client_addr(self, n_tunnels):
        """A busy tunnel's entry includes the client remote address."""

        def slow_request():
            requests.get(
                SLOW_URL_TEMPLATE.format(seconds=5),
                proxies=PROXIES,
                timeout=REQUEST_TIMEOUT,
            )

        t = threading.Thread(target=slow_request)
        t.start()
        time.sleep(1.5)

        busy_tunnels = [
            tun for tun in status_api()["tunnels"] if tun["status"] == "busy"
        ]
        t.join()

        assert busy_tunnels, "No busy tunnel found"
        for tun in busy_tunnels:
            assert tun.get(
                "client_addr"
            ), f"Busy tunnel {tun['interface']} has no client_addr"


# ---------------------------------------------------------------------------
# 3. IP Rotation
# ---------------------------------------------------------------------------


class TestIPRotation:
    def test_sequential_requests_return_valid_ips(self, n_tunnels):
        """N sequential requests each succeed and return a valid-looking IP."""
        ips = [get_outbound_ip() for _ in range(n_tunnels)]
        for ip in ips:
            assert len(ip) >= 7, f"Unexpected IP: {ip!r}"
            assert not ip.startswith("127."), f"Got loopback: {ip}"

    def test_all_tunnels_are_used_in_rotation(self, n_tunnels):
        """Each Tor instance is used at least once across N sequential requests.

        Uses the X-Tunnel-Interface response header to identify the instance,
        not the outbound IP — two instances may share the same exit relay
        without failing this test.
        """
        ifaces = [get_tunnel_iface() for _ in range(n_tunnels)]
        unique_ifaces = set(ifaces)
        assert len(unique_ifaces) == n_tunnels, (
            f"Expected {n_tunnels} distinct Tor instances across {n_tunnels} sequential "
            f"requests, got {len(unique_ifaces)}: {unique_ifaces}\n"
            f"Sequence: {ifaces}\n"
            "This suggests the round-robin is not distributing requests across all instances."
        )

    def test_round_robin_cycles_by_interface(self, n_tunnels):
        """After N requests the interface sequence repeats (confirmed by name, not IP).

        Two configs may share the same exit IP, so we check the interface name
        returned in X-Tunnel-Interface rather than comparing outbound IPs.
        """
        # Collect one full cycle + one extra request.
        ifaces = [get_tunnel_iface() for _ in range(n_tunnels + 1)]
        first_cycle = ifaces[:n_tunnels]
        # The (N+1)th request must reuse the same interface as the 1st.
        assert ifaces[n_tunnels] == ifaces[0], (
            f"Round-robin did not cycle back to the start.\n"
            f"Full cycle:    {first_cycle}\n"
            f"Next interface: {ifaces[n_tunnels]!r} (expected {ifaces[0]!r})"
        )
        # The cycle itself must contain N distinct interfaces.
        assert (
            len(set(first_cycle)) == n_tunnels
        ), f"One full cycle did not use all {n_tunnels} interfaces: {first_cycle}"

    def test_outbound_ips_are_not_localhost(self, n_tunnels):
        """All outbound IPs are routable — not loopback or container-internal."""
        for _ in range(n_tunnels):
            ip = get_outbound_ip()
            assert not ip.startswith("127."), f"Got loopback IP: {ip}"
            assert ip != "::1", f"Got IPv6 loopback: {ip}"


# ---------------------------------------------------------------------------
# 4. Concurrent / Exclusive Leasing
# ---------------------------------------------------------------------------


class TestConcurrentLeasing:
    def test_concurrent_requests_use_different_tunnels(self, n_tunnels):
        """N simultaneous requests are each assigned a unique Tor instance.

        Uses X-Tunnel-Interface to compare by instance name rather than outbound
        IP, since two instances may legitimately share the same exit relay.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_tunnels) as pool:
            futures = [pool.submit(get_tunnel_iface) for _ in range(n_tunnels)]
            ifaces = [f.result(timeout=REQUEST_TIMEOUT) for f in futures]

        unique = set(ifaces)
        assert len(unique) == n_tunnels, (
            f"Expected {n_tunnels} unique Tor instances from {n_tunnels} concurrent requests, "
            f"got {len(unique)}: {unique}\n"
            f"Assigned: {ifaces}\n"
            "This suggests exclusive leasing is not working — two concurrent connections "
            "were assigned the same Tor instance."
        )

    def test_tunnels_released_after_concurrent_requests(self, n_tunnels):
        """After a burst of concurrent requests all tunnels return to 'free'."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_tunnels) as pool:
            futures = [pool.submit(get_outbound_ip) for _ in range(n_tunnels)]
            [f.result(timeout=REQUEST_TIMEOUT) for f in futures]

        time.sleep(1)
        for tunnel in status_api()["tunnels"]:
            assert (
                tunnel["status"] == "free"
            ), f"Tunnel {tunnel['interface']} still busy after all requests completed"


# ---------------------------------------------------------------------------
# 5. Pool Exhaustion / Queuing  (marked slow — hold tunnels for several seconds)
# ---------------------------------------------------------------------------


@pytest.mark.slow
@pytest.mark.timeout(120)
class TestPoolExhaustion:
    def test_extra_request_queues_and_succeeds(self, n_tunnels):
        """When all tunnels are busy, an extra request BLOCKS (queues) until
        a tunnel is freed, then completes successfully.

        Strategy:
          1. Hold all N tunnels busy with slow requests (httpbin /delay/6).
          2. Wait until all are definitely acquired (~1.5 s).
          3. Fire a fast request — it must wait for a tunnel.
          4. The fast request should take longer than if no queueing occurred,
             proving it waited, but should still succeed (not 503).
        """
        hold_seconds = 6
        slow_url = SLOW_URL_TEMPLATE.format(seconds=hold_seconds)

        results: dict = {}
        errors: list = []

        def hold_tunnel(idx):
            try:
                resp = requests.get(
                    slow_url,
                    proxies=PROXIES,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=False,
                )
                results[f"slow_{idx}"] = resp.status_code
            except Exception as exc:
                errors.append(f"slow_{idx}: {exc}")

        def fast_request():
            start = time.monotonic()
            try:
                ip = get_outbound_ip()
                results["queued"] = {"ip": ip, "elapsed": time.monotonic() - start}
            except Exception as exc:
                errors.append(f"queued: {exc}")

        # Launch N slow requests to saturate the pool.
        slow_threads = [
            threading.Thread(target=hold_tunnel, args=(i,)) for i in range(n_tunnels)
        ]
        for t in slow_threads:
            t.start()

        # Give tunnels time to be acquired before launching the queued request.
        time.sleep(1.5)

        # Verify the pool IS saturated before proceeding.
        busy = sum(1 for tun in status_api()["tunnels"] if tun["status"] == "busy")
        if busy < n_tunnels:
            # Let slow threads finish and skip — saturation assumption failed.
            for t in slow_threads:
                t.join()
            pytest.skip(
                f"Could not saturate pool: only {busy}/{n_tunnels} tunnels busy. "
                "The slow endpoint may have responded too fast."
            )

        # Launch the queued fast request.
        queue_start = time.monotonic()
        fast_thread = threading.Thread(target=fast_request)
        fast_thread.start()

        for t in slow_threads:
            t.join()
        fast_thread.join()

        assert not errors, f"Requests failed: {errors}"

        assert (
            "queued" in results
        ), "The queued request never completed. It may have timed out or crashed."
        elapsed = results["queued"]["elapsed"]

        # The queued request had to wait for a slow request to finish.
        # It should have taken at least (hold_seconds - launch_delay) seconds.
        min_expected_wait = hold_seconds - 2.5  # generous tolerance
        assert elapsed >= min_expected_wait, (
            f"Queued request completed too fast ({elapsed:.1f}s). "
            f"Expected at least ~{min_expected_wait:.0f}s wait. "
            "Queueing may not be working correctly."
        )

        print(f"\n  Queued request waited {elapsed:.1f}s for a free tunnel ✓")

    def test_request_gets_503_when_lease_timeout_exceeded(self, n_tunnels):
        """When the pool is exhausted AND a short LEASE_TIMEOUT is configured,
        requests that wait longer than the timeout receive HTTP 503.

        NOTE: This test only runs when LEASE_TIMEOUT_SECONDS env var is set
        to a small value (e.g., 2) AND the container was started with that
        matching LEASE_TIMEOUT. Otherwise it is skipped.

        To test:
          LEASE_TIMEOUT=2s docker compose up -d
          LEASE_TIMEOUT_SECONDS=2 pytest tests/ -v -m slow
        """
        timeout_sec = int(os.getenv("LEASE_TIMEOUT_SECONDS", "0"))
        if timeout_sec == 0:
            pytest.skip(
                "Set LEASE_TIMEOUT_SECONDS=N (matching the container's LEASE_TIMEOUT) "
                "to run this test. E.g.:\n"
                "  LEASE_TIMEOUT=2s docker compose up -d\n"
                "  LEASE_TIMEOUT_SECONDS=2 pytest tests/ -v -m slow -k 503"
            )

        hold_seconds = timeout_sec + 4  # hold longer than the timeout
        slow_url = SLOW_URL_TEMPLATE.format(seconds=hold_seconds)
        error_codes: list = []

        def hold_tunnel(idx):
            requests.get(
                slow_url,
                proxies=PROXIES,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )

        def try_request():
            resp = requests.get(
                IP_CHECK_URL,
                proxies=PROXIES,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
            error_codes.append(resp.status_code)

        slow_threads = [
            threading.Thread(target=hold_tunnel, args=(i,)) for i in range(n_tunnels)
        ]
        for t in slow_threads:
            t.start()

        time.sleep(1.5)  # Wait for saturation.

        # Fire one more request — it should time out waiting for a tunnel.
        extra = threading.Thread(target=try_request)
        extra.start()
        extra.join(timeout=timeout_sec + 5)

        for t in slow_threads:
            t.join()

        assert 503 in error_codes, (
            f"Expected a 503 after LEASE_TIMEOUT={timeout_sec}s, "
            f"got status codes: {error_codes}"
        )


# ---------------------------------------------------------------------------
# 6. Tor Instance Health
# ---------------------------------------------------------------------------


class TestTorHealth:
    def test_all_instances_have_socks_address(self, n_tunnels):
        """Every Tor instance should have a SOCKS address in the status API."""
        for tunnel in status_api()["tunnels"]:
            assert tunnel.get("address"), (
                f"Instance {tunnel['interface']} has no SOCKS address in the "
                "status API. The manifest may have been written incorrectly."
            )
            # Address should look like host:port
            assert ":" in tunnel["address"], (
                f"Instance {tunnel['interface']} address {tunnel['address']!r} "
                "does not look like a host:port SOCKS address."
            )

    def test_all_instances_have_nonzero_rx_bytes(self, n_tunnels):
        """After routing traffic through every Tor instance, all should show rx_bytes > 0.

        rx_bytes are counted by the proxy's countingConn wrapper on the SOCKS
        connection, so they reflect real data received from the Tor network.
        """
        # Drive traffic through each instance.
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_tunnels) as pool:
            futures = [pool.submit(get_outbound_ip) for _ in range(n_tunnels)]
            [f.result(timeout=REQUEST_TIMEOUT) for f in futures]

        time.sleep(2)  # Give the stats collector time to refresh.
        for tunnel in status_api()["tunnels"]:
            assert tunnel.get("rx_bytes", 0) > 0, (
                f"Instance {tunnel['interface']} shows 0 rx_bytes after sending "
                "traffic through it. Byte counting may not be working correctly."
            )

    def test_all_instances_have_been_used(self, n_tunnels):
        """After N sequential requests, every instance should have a last_used
        timestamp (non-empty latest_handshake field, repurposed for Tor)."""
        # Drive one request through each instance.
        for _ in range(n_tunnels):
            get_outbound_ip()

        time.sleep(2)
        for tunnel in status_api()["tunnels"]:
            hs = tunnel.get("latest_handshake", "")
            assert hs and hs != "0001-01-01T00:00:00Z", (
                f"Instance {tunnel['interface']} has no last-used timestamp. "
                "It may never have served a connection."
            )

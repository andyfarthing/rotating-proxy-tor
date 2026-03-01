package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// InterfaceInfo describes a single Tor instance discovered at startup.
// The JSON shape is identical to the original manifest format so entrypoint.sh
// can write the same format and the pool/proxy code is unchanged.
type InterfaceInfo struct {
	Interface string // e.g. "tor0"
	Address   string // SOCKS5 address, e.g. "127.0.0.1:9050"
}

// TorInstanceStats holds a point-in-time view of one Tor instance.
type TorInstanceStats struct {
	Interface   string
	SocksAddr   string
	ExitAddress string    // IP seen by the outside world (queried via SOCKS to an IP-echo service)
	ExitCountry string    // ISO 3166-1 alpha-2 country code for ExitAddress (e.g. "DE")
	LastUsed    time.Time // last time this slot was released
	TxBytes     int64     // bytes sent through this instance (cumulative)
	RxBytes     int64     // bytes received through this instance (cumulative)
	LastNewnym  time.Time // when SIGNAL NEWNYM was last sent to this instance
}

// TorStats is the full stats snapshot served by the web UI.
type TorStats struct {
	Instances   []TorInstanceStats
	CollectedAt time.Time
}

// StatsCollector manages exit IP resolution for all Tor instances.
// All live data (bytes, status, last-used) is read directly from the pool on
// each Get() call, so there is no periodic cache to keep in sync.
type StatsCollector struct {
	pool       *LeasePool
	ctrlBase   int          // base control port for SIGNAL NEWNYM; 0 = rotation disabled
	exitIPs       sync.Map  // key: slot index (int) → value: string IP
	exitCountries sync.Map  // key: slot index (int) → value: string country code (ISO 3166-1 alpha-2)
	ipCheckURL    string    // URL of an IP-echo service reachable through Tor
	newnymMu   sync.Mutex
	lastNewnym []time.Time  // indexed by slot; when SIGNAL NEWNYM was last sent
	warmup     time.Duration // hold-off after NEWNYM before slot re-enters pool (0 = disabled)
}

// NewStatsCollector initialises the collector, starts a SOCKS health probe, and
// kicks off an initial exit IP resolution shortly after startup.
// ctrlBase: base Tor control port for SIGNAL NEWNYM rotation; 0 to disable.
// ipCheckURL: plain-text IP-echo service reachable through Tor; "" to disable exit IP display.
// warmup: how long to mark a slot as unavailable after NEWNYM while the new circuit builds; 0 to disable.
func NewStatsCollector(pool *LeasePool, ctrlBase int, ipCheckURL string, warmup time.Duration) *StatsCollector {
	n := len(pool.slots)
	now := time.Now()
	initial := make([]time.Time, n)
	for i := range initial {
		initial[i] = now
	}
	sc := &StatsCollector{
		pool:       pool,
		ctrlBase:   ctrlBase,
		ipCheckURL: ipCheckURL,
		warmup:     warmup,
		lastNewnym: initial,
	}
	// Start periodic SOCKS health probe.
	go sc.runHealthProbe()
	// Populate exit IPs shortly after startup (circuits need a few seconds to build).
	if ipCheckURL != "" {
		go func() {
			time.Sleep(5 * time.Second)
			sc.refreshExitIPs()
		}()
	}
	return sc
}

// Get builds a fresh TorStats snapshot on every call. All fields except
// ExitAddress and LastNewnym come directly from live pool state (no caching lag).
func (sc *StatsCollector) Get() TorStats {
	snaps := sc.pool.Snapshots()
	stats := make([]TorInstanceStats, len(snaps))
	for i, snap := range snaps {
		inst := TorInstanceStats{
			Interface: snap.Interface,
			SocksAddr: snap.Address,
			LastUsed:  snap.LastUsed,
			TxBytes:   snap.TxBytes,
			RxBytes:   snap.RxBytes,
		}
		if ip, ok := sc.exitIPs.Load(i); ok {
			inst.ExitAddress = ip.(string)
		}
		if cc, ok := sc.exitCountries.Load(i); ok {
			inst.ExitCountry = cc.(string)
		}
		sc.newnymMu.Lock()
		if i < len(sc.lastNewnym) {
			inst.LastNewnym = sc.lastNewnym[i]
		}
		sc.newnymMu.Unlock()
		stats[i] = inst
	}
	return TorStats{
		Instances:   stats,
		CollectedAt: time.Now(),
	}
}

// refreshExitIPs queries each Tor instance's exit IP by making an HTTP
// request through its SOCKS5 port to the configured IP-echo URL.
// Requests are staggered by 150 ms per instance to avoid hammering the
// IP-echo service with all instances simultaneously (important at high
// instance counts). Results are stored in sc.exitIPs.
func (sc *StatsCollector) refreshExitIPs() {
	if sc.ipCheckURL == "" {
		return
	}
	n := len(sc.pool.slots)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Stagger: each instance waits idx×150ms before querying.
			// 10 instances → spread over 1.5s; 100 instances → 15s.
			time.Sleep(time.Duration(idx) * 150 * time.Millisecond)
			socksAddr := sc.pool.slots[idx].Address
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			ip, err := queryExitAddrViaSocks(ctx, socksAddr, sc.ipCheckURL)
			if err != nil {
				slog.Debug("exit IP query failed", "instance", idx, "err", err)
				return
			}
			sc.exitIPs.Store(idx, ip)
			// Country lookup is decoupled: fire-and-forget so the IP is
			// available immediately and the country fills in asynchronously.
			go func(i int, addr string) {
				if cc := sc.lookupExitCountry(i, addr); cc != "" {
					sc.exitCountries.Store(i, cc)
				}
			}(idx, ip)
		}(i)
	}
	wg.Wait()
}

// refreshExitIPForInstance queries the exit IP for a single Tor instance.
// Used after per-instance circuit rotation so only the rotated instance is
// re-queried rather than the entire pool.
func (sc *StatsCollector) refreshExitIPForInstance(idx int) {
	if sc.ipCheckURL == "" {
		return
	}
	socksAddr := sc.pool.slots[idx].Address
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ip, err := queryExitAddrViaSocks(ctx, socksAddr, sc.ipCheckURL)
	if err != nil {
		slog.Debug("exit IP query failed", "instance", idx, "err", err)
		return
	}
	sc.exitIPs.Store(idx, ip)
	// Country lookup is decoupled: fire-and-forget so the IP is
	// available immediately and the country fills in asynchronously.
	go func() {
		if cc := sc.lookupExitCountry(idx, ip); cc != "" {
			sc.exitCountries.Store(idx, cc)
		}
	}()
}

// lookupExitCountry resolves the 2-letter ISO 3166-1 alpha-2 country code for
// ip. It first queries Tor's built-in geoip database via the control port
// (fast, no external request); if that fails it falls back to ip-api.com via
// the instance's SOCKS5 port (one additional HTTP request through Tor).
func (sc *StatsCollector) lookupExitCountry(idx int, ip string) string {
	if ip == "" {
		return ""
	}
	// Primary: Tor's own geoip via GETINFO ip-to-country/<ip>.
	if sc.ctrlBase != 0 {
		ctrlAddr := fmt.Sprintf("127.0.0.1:%d", sc.ctrlBase+idx)
		if cc, err := queryTorCountry(ctrlAddr, ip); err == nil && cc != "" {
			return strings.ToUpper(cc)
		}
	}
	// Fallback: ip-api.com via SOCKS5 (HTTP only on free tier).
	socksAddr := sc.pool.slots[idx].Address
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if cc, err := queryIPAPICountry(ctx, socksAddr, ip); err == nil && cc != "" {
		return cc
	}
	return ""
}

// queryTorCountry queries Tor's built-in geoip database via the control port
// (GETINFO ip-to-country/<ip>) to resolve the ISO country code for an IP.
// This reuses the existing control-port connection and makes no external requests.
func queryTorCountry(ctrlAddr, ip string) (string, error) {
	conn, err := net.DialTimeout("tcp", ctrlAddr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	fmt.Fprintf(conn, "AUTHENTICATE\r\n") //nolint:errcheck
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "250") {
			break
		}
		if strings.HasPrefix(line, "5") || strings.HasPrefix(line, "4") {
			return "", fmt.Errorf("auth: %s", line)
		}
	}

	fmt.Fprintf(conn, "GETINFO ip-to-country/%s\r\n", ip) //nolint:errcheck
	for scanner.Scan() {
		line := scanner.Text()
		// Response line looks like: 250-ip-to-country/1.2.3.4=de
		if strings.HasPrefix(line, "250-ip-to-country/") {
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
		if strings.HasPrefix(line, "250 OK") {
			break
		}
		if strings.HasPrefix(line, "5") || strings.HasPrefix(line, "4") {
			return "", fmt.Errorf("GETINFO: %s", line)
		}
	}
	return "", fmt.Errorf("no country data returned")
}

// queryIPAPICountry makes an HTTP request to ip-api.com through the given
// SOCKS5 address to resolve the ISO country code for ip. Used as a fallback
// when Tor's built-in geoip data is unavailable.
func queryIPAPICountry(ctx context.Context, socksAddr, ip string) (string, error) {
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return "", err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return "", fmt.Errorf("socks5 dialer does not implement ContextDialer")
	}
	transport := &http.Transport{DialContext: cd.DialContext}
	client := &http.Client{Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://ip-api.com/json/"+ip+"?fields=countryCode", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		CountryCode string `json:"countryCode"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256)).Decode(&result); err != nil {
		return "", err
	}
	return result.CountryCode, nil
}

// queryExitAddrViaSocks makes an HTTP GET request through the given SOCKS5
// address to ipCheckURL and returns the plain-text IP address in the response.
func queryExitAddrViaSocks(ctx context.Context, socksAddr, ipCheckURL string) (string, error) {
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return "", fmt.Errorf("socks5 dialer: %w", err)
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return "", fmt.Errorf("socks5 dialer does not implement ContextDialer")
	}
	transport := &http.Transport{DialContext: cd.DialContext}
	client := &http.Client{Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ipCheckURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("unexpected response: %q", ip)
	}
	return ip, nil
}

// StartCircuitRotation sends SIGNAL NEWNYM to each Tor control port on the
// given interval, staggered evenly so that only one instance rotates at a time.
// With n instances and a 30s interval, one rotation fires every (30/n) seconds,
// preventing all instances from entering the "warming" state simultaneously.
// This method is a no-op when ctrlBase is 0 (control-port queries disabled).
func (sc *StatsCollector) StartCircuitRotation(interval time.Duration) {
	if sc.ctrlBase == 0 {
		slog.Warn("circuit rotation disabled: TOR_CTRL_BASE_PORT not set")
		return
	}
	n := len(sc.pool.slots)
	// Spread initial offsets evenly across the full interval so that rotations
	// are distributed rather than all firing at the same moment.
	stagger := interval / time.Duration(n)
	slog.Info("circuit rotation enabled",
		"interval", interval,
		"instances", n,
		"stagger", stagger,
	)

	rotateOne := func(i int) {
		ctrlAddr := fmt.Sprintf("127.0.0.1:%d", sc.ctrlBase+i)
		if err := sendNewnym(ctrlAddr); err != nil {
			slog.Warn("NEWNYM failed", "instance", i, "err", err)
			return
		}
		slog.Debug("circuit rotated", "instance", i)
		// Record rotation time for circuit-age display in web UI.
		sc.newnymMu.Lock()
		if i < len(sc.lastNewnym) {
			sc.lastNewnym[i] = time.Now()
		}
		sc.newnymMu.Unlock()
		// Hold the slot back while the new circuit builds.
		if sc.warmup > 0 {
			sc.pool.SetWarming(i, true)
			go func() {
				time.Sleep(sc.warmup)
				sc.pool.SetWarming(i, false)
			}()
		}
		// Clear stale exit IP and country; re-query after Tor has built the new circuit.
		sc.exitIPs.Delete(i)
		sc.exitCountries.Delete(i)
		go func() {
			time.Sleep(5 * time.Second)
			sc.refreshExitIPForInstance(i)
		}()
	}

	for idx := 0; idx < n; idx++ {
		i := idx
		go func() {
			// Wait for this instance's initial offset so rotations are spread out.
			time.Sleep(time.Duration(i) * stagger)
			rotateOne(i)
			t := time.NewTicker(interval)
			defer t.Stop()
			for range t.C {
				rotateOne(i)
			}
		}()
	}
}

// sendNewnym connects to a Tor control port and sends SIGNAL NEWNYM, which
// instructs Tor to use a new circuit for subsequent connections.
func sendNewnym(ctrlAddr string) error {
	conn, err := net.DialTimeout("tcp", ctrlAddr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("control port dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	fmt.Fprintf(conn, "AUTHENTICATE\r\n") //nolint:errcheck

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "250") {
			break
		}
		if strings.HasPrefix(line, "5") || strings.HasPrefix(line, "4") {
			return fmt.Errorf("auth failed: %s", line)
		}
	}

	fmt.Fprintf(conn, "SIGNAL NEWNYM\r\n") //nolint:errcheck

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "250") {
			return nil
		}
		if strings.HasPrefix(line, "5") || strings.HasPrefix(line, "4") {
			return fmt.Errorf("NEWNYM rejected: %s", line)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return fmt.Errorf("no response to SIGNAL NEWNYM")
}

// runHealthProbe periodically checks whether each Tor instance's SOCKS port
// is reachable and updates the pool's health state accordingly. Unhealthy
// slots are skipped by Acquire until they recover.
func (sc *StatsCollector) runHealthProbe() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		n := len(sc.pool.slots)
		for i := 0; i < n; i++ {
			addr := sc.pool.slots[i].Address
			wasHealthy := sc.pool.slots[i].Healthy // safe to read — approximate
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				if wasHealthy {
					slog.Warn("tor instance unreachable", "instance", i, "addr", addr, "err", err)
				}
				sc.pool.MarkHealthy(i, false)
			} else {
				conn.Close()
				if !wasHealthy {
					slog.Info("tor instance recovered", "instance", i, "addr", addr)
				}
				sc.pool.MarkHealthy(i, true)
			}
		}
	}
}

// logTorStats logs a summary of Tor instance stats at INFO level.
func logTorStats(stats TorStats) {
	for _, inst := range stats.Instances {
		slog.Info("tor instance",
			"interface", inst.Interface,
			"socks", inst.SocksAddr,
			"exit", inst.ExitAddress,
			"tx", inst.TxBytes,
			"rx", inst.RxBytes,
		)
	}
}

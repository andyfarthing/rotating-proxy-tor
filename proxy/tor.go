package main

import (
	"bufio"
	"context"
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
	LastUsed    time.Time // last time this slot was released
	TxBytes     int64     // bytes sent through this instance (cumulative)
	RxBytes     int64     // bytes received through this instance (cumulative)
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
	ctrlBase   int      // base control port for SIGNAL NEWNYM; 0 = rotation disabled
	exitIPs    sync.Map // key: slot index (int) → value: string IP
	ipCheckURL string   // URL of an IP-echo service reachable through Tor
}

// NewStatsCollector initialises the collector and kicks off an initial exit IP
// resolution shortly after startup.
// ctrlBase is the base Tor control port used for SIGNAL NEWNYM circuit rotation.
// Pass 0 to disable rotation. ipCheckURL is the URL of a plain-text IP-echo
// service (e.g. https://api.ipify.org) reachable through Tor; pass an empty
// string to disable exit IP display.
func NewStatsCollector(pool *LeasePool, ctrlBase int, ipCheckURL string) *StatsCollector {
	sc := &StatsCollector{pool: pool, ctrlBase: ctrlBase, ipCheckURL: ipCheckURL}
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
// ExitAddress come directly from live pool state (no caching lag).
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
		}(i)
	}
	wg.Wait()
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

// StartCircuitRotation sends SIGNAL NEWNYM to every Tor control port on the
// given interval, causing each instance to build a fresh circuit and therefore
// present a new exit IP for subsequent connections.
// After each rotation, exit IPs are re-queried and the web UI is updated.
// This method is a no-op when ctrlBase is 0 (control-port queries disabled).
func (sc *StatsCollector) StartCircuitRotation(interval time.Duration) {
	if sc.ctrlBase == 0 {
		slog.Warn("circuit rotation disabled: TOR_CTRL_BASE_PORT not set")
		return
	}
	n := len(sc.pool.slots)
	slog.Info("circuit rotation enabled", "interval", interval, "instances", n)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			rotated, failed := 0, 0
			for i := 0; i < n; i++ {
				ctrlAddr := fmt.Sprintf("127.0.0.1:%d", sc.ctrlBase+i)
				if err := sendNewnym(ctrlAddr); err != nil {
					slog.Warn("NEWNYM failed", "instance", i, "err", err)
					failed++
				} else {
					rotated++
				}
			}
			slog.Info("circuits rotated", "ok", rotated, "failed", failed)
			// Clear stale exit IPs then re-query once new circuits have built.
			for i := 0; i < n; i++ {
				sc.exitIPs.Delete(i)
			}
			go func() {
				time.Sleep(5 * time.Second) // give Tor time to build new circuits
				sc.refreshExitIPs()
			}()
		}
	}()
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

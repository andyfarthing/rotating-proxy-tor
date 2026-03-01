package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultManifestPath             = "/run/tor-proxy/manifest.json"
	defaultProxyPort                = "8080"
	defaultWebUIPort                = "8088"
	defaultLeaseTimeout             = "30"
	defaultDialTimeout              = "120" // Tor circuits can take a while to establish
	defaultCtrlBasePort             = "10050" // base Tor control port; 0 = disable rotation
	defaultCircuitRotationInterval  = "30"    // how often to rotate circuits via SIGNAL NEWNYM (seconds)
	defaultCircuitWarmup            = "5"     // how long to hold a slot back after NEWNYM while new circuit builds (seconds); 0 = disabled
	defaultIPCheckURL               = "https://api.ipify.org" // plain-text IP-echo service used to determine exit IPs
)

func main() {
	setupLogging()

	manifestPath  := env("MANIFEST_PATH",    defaultManifestPath)
	proxyPort     := env("PROXY_PORT",        defaultProxyPort)
	webuiPort     := env("WEB_UI_PORT",       defaultWebUIPort)
	leaseTimeout  := mustDuration("LEASE_TIMEOUT",  defaultLeaseTimeout)
	dialTimeout   := mustDuration("DIAL_TIMEOUT",   defaultDialTimeout)
	ctrlBasePort        := mustInt("TOR_CTRL_BASE_PORT",            defaultCtrlBasePort)
	circuitRotInterval  := time.Duration(mustInt("TOR_CIRCUIT_ROTATION_INTERVAL", defaultCircuitRotationInterval)) * time.Second
	circuitWarmup       := time.Duration(mustInt("TOR_CIRCUIT_WARMUP",            defaultCircuitWarmup)) * time.Second
	ipCheckURL          := env("TOR_IP_CHECK_URL", defaultIPCheckURL)

	// Read the manifest written by entrypoint.sh (Tor SOCKS addresses).
	slog.Info("reading tor instance manifest", "path", manifestPath)
	ifaces, err := readManifest(manifestPath)
	if err != nil {
		slog.Error("failed to read manifest", "err", err)
		os.Exit(1)
	}
	slog.Info("discovered Tor instances", "count", len(ifaces))
	for _, iface := range ifaces {
		slog.Info("  tor instance", "name", iface.Interface, "socks", iface.Address)
	}

	pool  := NewLeasePool(ifaces, leaseTimeout)
	sc    := NewStatsCollector(pool, ctrlBasePort, ipCheckURL, circuitWarmup)
	sc.StartCircuitRotation(circuitRotInterval)

	// --- Proxy server ---
	// The proxyHandler is used directly as the Handler — NOT via http.ServeMux.
	// Go 1.22+ ServeMux rewrites/redirects requests whose URL doesn't look like
	// a normal path, which breaks HTTP CONNECT requests (e.g. CONNECT host:443)
	// by responding with 301 instead of forwarding them to the handler.
	proxyH := &proxyHandler{pool: pool, timeout: dialTimeout}
	proxySrv := &http.Server{
		Addr:    ":" + proxyPort,
		Handler: proxyH,
	}
	go func() {
		slog.Info("proxy listening", "port", proxyPort)
		if err := proxySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("proxy server error", "err", err)
			os.Exit(1)
		}
	}()

	// --- Web UI server (optional) ---
	var webuiSrv *http.Server
	if webuiPort != "0" {
		uiMux := http.NewServeMux()
		ui := &webUIHandler{pool: pool, stats: sc, exitRegion: env("TOR_EXIT_REGION", "")}
		ui.Register(uiMux)
		webuiSrv = &http.Server{
			Addr:    ":" + webuiPort,
			Handler: uiMux,
		}
		go func() {
			slog.Info("web UI listening", "port", webuiPort)
			if err := webuiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("web UI server error", "err", err)
			}
		}()
	} else {
		slog.Info("web UI disabled (WEB_UI_PORT=0)")
	}

	// --- Graceful shutdown ---
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop

	slog.Info("shutting down…")
	// Allow up to 30s: first drain the HTTP server (non-hijacked handlers),
	// then drain hijacked CONNECT tunnels, then shut down the web UI.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	proxySrv.Shutdown(ctx)  //nolint:errcheck — best-effort
	proxyH.Drain(ctx)        // wait for hijacked CONNECT tunnels
	if webuiSrv != nil {
		webuiSrv.Shutdown(ctx) //nolint:errcheck
	}
	slog.Info("shutdown complete")
}

// readManifest reads the JSON manifest written by entrypoint.sh.
// Format: [{"interface":"tor0","address":"127.0.0.1:9050"}, ...]
func readManifest(path string) ([]InterfaceInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open manifest %q: %w", path, err)
	}
	defer f.Close()

	var ifaces []InterfaceInfo
	if err := json.NewDecoder(f).Decode(&ifaces); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("manifest contains no Tor instances — check that entrypoint.sh started at least one")
	}
	return ifaces, nil
}

// mustInt reads an integer from an env var, falling back to defaultVal.
func mustInt(name, defaultVal string) int {
	v := env(name, defaultVal)
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		slog.Error("invalid integer env var", "name", name, "value", v)
		os.Exit(1)
	}
	return n
}

// setupLogging configures slog based on the LOG_LEVEL environment variable.
func setupLogging() {
	lvl := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustDuration(key, fallback string) time.Duration {
	raw := env(key, fallback)
	// Accept plain integers as seconds (e.g. "30" == "30s") for consistency
	// with other numeric env vars like TOR_CIRCUIT_ROTATION_INTERVAL.
	if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
		return time.Duration(n) * time.Second
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		panic(fmt.Sprintf("invalid duration for %s=%q: %v", key, raw, err))
	}
	return d
}



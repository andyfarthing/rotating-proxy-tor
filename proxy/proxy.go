package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// proxyHandler implements HTTP and HTTPS (CONNECT) proxying with exclusive
// Tor instance leasing. Each accepted connection is assigned one Tor instance
// for its entire lifetime, ensuring traffic isolation per client request.
type proxyHandler struct {
	pool    *LeasePool
	timeout time.Duration // per-connection dial timeout
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleCONNECT(w, r)
	} else {
		h.handleHTTP(w, r)
	}
}

// handleCONNECT handles HTTPS tunneling via the HTTP CONNECT method.
// Acquires a Tor instance, dials the target through its SOCKS5 port,
// sends 200, then copies bidirectionally while counting bytes.
func (h *proxyHandler) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	slot, err := h.pool.Acquire(r.Context(), r.RemoteAddr)
	if err != nil {
		slog.Warn("tor instance acquire failed", "client", r.RemoteAddr, "err", err)
		http.Error(w, "503 no tor instance available: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer h.pool.Release(slot)

	slog.Info("CONNECT", "client", r.RemoteAddr, "target", r.Host, "instance", slot.Interface)

	dialCtx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	rawConn, err := dialViaTor(dialCtx, slot.Address, "tcp", r.Host)
	if err != nil {
		slog.Warn("dial failed", "instance", slot.Interface, "target", r.Host, "err", err)
		http.Error(w, "502 upstream dial failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	// Wrap upstream to count bytes through this Tor instance.
	upstream := &countingConn{Conn: rawConn, slot: slot}
	defer upstream.Close()

	// Signal to the client that the tunnel is established.
	w.WriteHeader(http.StatusOK)

	// Hijack the connection for raw bidirectional copy.
	hj, ok := w.(http.Hijacker)
	if !ok {
		slog.Error("responsewriter does not support hijack")
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		slog.Error("hijack failed", "err", err)
		return
	}
	defer clientConn.Close()

	copyBidirectional(clientConn, upstream)
}

// handleHTTP forwards a plain HTTP request through the leased Tor instance.
func (h *proxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	slot, err := h.pool.Acquire(r.Context(), r.RemoteAddr)
	if err != nil {
		slog.Warn("tor instance acquire failed", "client", r.RemoteAddr, "err", err)
		http.Error(w, "503 no tor instance available: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer h.pool.Release(slot)

	slog.Info("HTTP", "client", r.RemoteAddr, "target", r.URL.Host, "instance", slot.Interface)

	// Build a fresh request without hop-by-hop headers.
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	removeHopByHopHeaders(outReq.Header)

	dialCtx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	outReq = outReq.WithContext(dialCtx)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialViaTor(ctx, slot.Address, network, addr)
			if err != nil {
				return nil, err
			}
			// Wrap to count bytes for this Tor instance.
			return &countingConn{Conn: conn, slot: slot}, nil
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          1,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		slog.Warn("roundtrip failed", "instance", slot.Interface, "err", err)
		http.Error(w, "502 upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	// Expose which Tor instance served this request — used by integration tests
	// and useful for debugging.
	w.Header().Set("X-Tunnel-Interface", slot.Interface)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// dialViaTor dials addr through the Tor SOCKS5 proxy at socksAddr.
// It honours ctx for cancellation and deadline. DNS resolution is handled
// inside Tor so there is no DNS leakage.
func dialViaTor(ctx context.Context, socksAddr, network, addr string) (net.Conn, error) {
	// Use a net.Dialer so the underlying TCP connection to the SOCKS proxy can
	// also be cancelled via ctx.
	baseDialer := &net.Dialer{}
	socks5Dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, baseDialer)
	if err != nil {
		return nil, fmt.Errorf("create socks5 dialer for %s: %w", socksAddr, err)
	}

	// golang.org/x/net proxy.SOCKS5 implements proxy.ContextDialer since v0.1+.
	if cd, ok := socks5Dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}

	// Fallback path: honour context cancellation via a goroutine.
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := socks5Dialer.Dial(network, addr)
		ch <- result{conn, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

// countingConn wraps a net.Conn and accumulates per-slot TX/RX byte counts
// atomically. Writes = bytes sent to upstream (TX); Reads = bytes received
// from upstream (RX).
type countingConn struct {
	net.Conn
	slot *TunnelSlot
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.AddInt64(&c.slot.TxBytes, int64(n))
	}
	return n, err
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(&c.slot.RxBytes, int64(n))
	}
	return n, err
}

// copyBidirectional copies data in both directions between two connections.
//
// When either direction finishes (the client disconnects, the upstream closes,
// or an error occurs), BOTH connections are closed immediately. This unblocks
// the goroutine copying in the other direction, which would otherwise block
// forever waiting for data on a keep-alive connection. Without this, the
// function never returns and the Tor instance lease is never released.
func copyBidirectional(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	// Wait for the first direction to finish, then close both connections so
	// the other goroutine unblocks and the second done is received promptly.
	<-done
	a.Close()
	b.Close()
	<-done
}

// hopByHopHeaders lists headers that must not be forwarded by a proxy.
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding",
	"Upgrade", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailers",
}

func removeHopByHopHeaders(h http.Header) {
	for _, hdr := range hopByHopHeaders {
		h.Del(hdr)
	}
}

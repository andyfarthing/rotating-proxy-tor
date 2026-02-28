package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// TunnelStatus represents the current state of a Tor tunnel slot.
type TunnelStatus int

const (
	TunnelFree TunnelStatus = iota
	TunnelBusy
)

// TunnelSlot holds runtime state for a single Tor instance.
// Status/clientAddr/leaseStart are protected by LeasePool.mu via sync.Cond.
// TxBytes/RxBytes are updated atomically by the proxy handler.
type TunnelSlot struct {
	Index     int
	Interface string // e.g. "tor0"
	Address   string // SOCKS5 address, e.g. "127.0.0.1:9050"

	// Protected by the owning LeasePool's mutex.
	status     TunnelStatus
	clientAddr string
	leaseStart time.Time
	lastUsed   time.Time

	// Updated atomically by the proxy to track cumulative traffic.
	TxBytes int64
	RxBytes int64

	// Health and circuit-ready state (protected by pool mutex).
	Healthy bool // false when SOCKS health probe fails; slot is skipped in Acquire
	Warming bool // true briefly after SIGNAL NEWNYM while new circuit builds
}

// LeaseInfo is a safe point-in-time snapshot of a slot (copied under the lock).
type LeaseInfo struct {
	Interface  string
	Address    string
	Status     TunnelStatus
	ClientAddr string
	LeaseStart time.Time
	LastUsed   time.Time
	TxBytes    int64
	RxBytes    int64
	Healthy    bool
	Warming    bool
}

// LeasePool manages exclusive assignment of Tor instances to proxy clients.
//
// Instances are assigned in round-robin order. When all instances are busy,
// Acquire blocks (up to the configured timeout) until one is released.
// All slot state is protected by a single mutex exposed via a sync.Cond,
// which is the correct pattern for condition-variable waiting in Go.
type LeasePool struct {
	mu      sync.Mutex
	cond    *sync.Cond
	slots   []*TunnelSlot
	next    int           // round-robin cursor (protected by mu)
	timeout time.Duration // maximum wait per Acquire call
}

// NewLeasePool creates a pool from the provided list of Tor instance descriptors.
func NewLeasePool(ifaces []InterfaceInfo, timeout time.Duration) *LeasePool {
	p := &LeasePool{timeout: timeout}
	p.cond = sync.NewCond(&p.mu)
	for i, iface := range ifaces {
		p.slots = append(p.slots, &TunnelSlot{
			Index:     i,
			Interface: iface.Interface,
			Address:   iface.Address,
			Healthy:   true, // assumed healthy until first probe fails
		})
	}
	return p
}

// Acquire claims the next free Tor instance in round-robin order.
//
// It blocks (under the condition variable) until a tunnel is free, the
// configured timeout elapses, or ctx is cancelled.
// A time.AfterFunc timer sends a Broadcast on timeout so that the Wait
// call is woken up immediately rather than relying on polling.
func (p *LeasePool) Acquire(ctx context.Context, clientAddr string) (*TunnelSlot, error) {
	deadline := time.Now().Add(p.timeout)

	// Send a Broadcast when the deadline is reached so blocked callers wake up.
	timer := time.AfterFunc(p.timeout, func() { p.cond.Broadcast() })
	defer timer.Stop()

	// Also broadcast when the context is cancelled.
	ctxWatchStop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			p.cond.Broadcast()
		case <-ctxWatchStop:
		}
	}()
	defer close(ctxWatchStop)

	p.mu.Lock()
	defer p.mu.Unlock()

	for {
		// Check termination conditions first.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no tunnel available after %s", p.timeout)
		}

		// Scan from the round-robin cursor once around the pool.
		n := len(p.slots)
		for i := 0; i < n; i++ {
			idx := (p.next + i) % n
			slot := p.slots[idx]
			if slot.status == TunnelFree && slot.Healthy && !slot.Warming {
				slot.status = TunnelBusy
				slot.clientAddr = clientAddr
				slot.leaseStart = time.Now()
				p.next = (idx + 1) % n
				return slot, nil
			}
		}

		// No free slot -- Wait atomically releases p.mu and suspends the goroutine
		// until Broadcast/Signal is called (by Release, the timer, or ctx watcher).
		p.cond.Wait()
	}
}

// Release returns a previously acquired slot to the pool and wakes all waiters.
func (p *LeasePool) Release(slot *TunnelSlot) {
	p.mu.Lock()
	slot.status = TunnelFree
	slot.clientAddr = ""
	slot.leaseStart = time.Time{}
	slot.lastUsed = time.Now()
	p.mu.Unlock()
	p.cond.Broadcast()
}

// MarkHealthy updates the health state of the slot at idx.
// Marking healthy broadcasts to wake any Acquire callers waiting for a free slot.
func (p *LeasePool) MarkHealthy(idx int, healthy bool) {
	p.mu.Lock()
	if idx >= 0 && idx < len(p.slots) {
		p.slots[idx].Healthy = healthy
	}
	p.mu.Unlock()
	if healthy {
		p.cond.Broadcast()
	}
}

// SetWarming marks or clears the warming-up state of the slot at idx.
// When cleared, broadcasts to wake Acquire callers waiting for a usable slot.
func (p *LeasePool) SetWarming(idx int, warming bool) {
	p.mu.Lock()
	if idx >= 0 && idx < len(p.slots) {
		p.slots[idx].Warming = warming
	}
	p.mu.Unlock()
	if !warming {
		p.cond.Broadcast()
	}
}

// Snapshots returns a point-in-time view of all slots (safe to read without
// holding the lock by copying under it). Byte counters are read atomically.
func (p *LeasePool) Snapshots() []LeaseInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]LeaseInfo, len(p.slots))
	for i, s := range p.slots {
		out[i] = LeaseInfo{
			Interface:  s.Interface,
			Address:    s.Address,
			Status:     s.status,
			ClientAddr: s.clientAddr,
			LeaseStart: s.leaseStart,
			LastUsed:   s.lastUsed,
			TxBytes:    atomic.LoadInt64(&s.TxBytes),
			RxBytes:    atomic.LoadInt64(&s.RxBytes),
			Healthy:    s.Healthy,
			Warming:    s.Warming,
		}
	}
	return out
}

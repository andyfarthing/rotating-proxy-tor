package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// webUIHandler serves the status web UI and JSON API.
type webUIHandler struct {
	pool       *LeasePool
	stats      *StatsCollector
	exitRegion string // value of TOR_EXIT_REGION env var (empty = worldwide)
}

// Register mounts the web UI routes on the supplied mux.
func (h *webUIHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/", h.handleIndex)
	mux.HandleFunc("/api/status", h.handleStatus)
}

// StatusResponse is the JSON structure returned by GET /api/status.
type StatusResponse struct {
	CollectedAt time.Time           `json:"collected_at"`
	ExitRegion  string              `json:"exit_region"` // TOR_EXIT_REGION value; empty = worldwide
	Tunnels     []TunnelStatusEntry `json:"tunnels"`
}

// TunnelStatusEntry combines lease pool state with Tor instance telemetry.
type TunnelStatusEntry struct {
	Interface       string `json:"interface"`
	Address         string `json:"address"`
	Status          string `json:"status"` // "free" | "busy" | "warming" | "degraded"
	ClientAddr      string `json:"client_addr,omitempty"`
	LeaseDuration   string `json:"lease_duration,omitempty"`
	PeerEndpoint    string `json:"peer_endpoint,omitempty"`
	LatestHandshake string `json:"latest_handshake,omitempty"`
	LastNewnym      string `json:"last_newnym,omitempty"` // RFC3339 timestamp of last SIGNAL NEWNYM
	TxBytes         int64  `json:"tx_bytes"`
	RxBytes         int64  `json:"rx_bytes"`
}

func (h *webUIHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	leases := h.pool.Snapshots()
	torStats := h.stats.Get()

	// Index Tor instance stats by interface name for O(1) lookup.
	instByIface := make(map[string]TorInstanceStats)
	for _, inst := range torStats.Instances {
		instByIface[inst.Interface] = inst
	}

	response := StatusResponse{
		CollectedAt: torStats.CollectedAt,
		ExitRegion:  h.exitRegion,
		Tunnels:     make([]TunnelStatusEntry, len(leases)),
	}

	for i, lease := range leases {
		entry := TunnelStatusEntry{
			Interface: lease.Interface,
			Address:   lease.Address,
		}

		switch {
		case !lease.Healthy:
			entry.Status = "degraded"
		case lease.Warming:
			entry.Status = "warming"
		case lease.Status == TunnelBusy:
			entry.Status = "busy"
			entry.ClientAddr = lease.ClientAddr
			if !lease.LeaseStart.IsZero() {
				entry.LeaseDuration = time.Since(lease.LeaseStart).Round(time.Millisecond).String()
			}
		default:
			entry.Status = "free"
		}

		// Byte counters come directly from the live pool snapshot (atomic reads),
		// so they are always current without waiting for the stats cache to refresh.
		entry.TxBytes = lease.TxBytes
		entry.RxBytes = lease.RxBytes
		// LatestHandshake repurposed as last-used timestamp (from pool, not cache).
		if !lease.LastUsed.IsZero() {
			entry.LatestHandshake = lease.LastUsed.Format(time.RFC3339)
		}

		if inst, ok := instByIface[lease.Interface]; ok {
			// PeerEndpoint repurposed as exit node IP.
			entry.PeerEndpoint = inst.ExitAddress
			if !inst.LastNewnym.IsZero() {
				entry.LastNewnym = inst.LastNewnym.Format(time.RFC3339)
			}
		}

		response.Tunnels[i] = entry
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(response); err != nil {
		slog.Warn("status encode error", "err", err)
	}
}

func (h *webUIHandler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := uiTemplate.Execute(w, nil); err != nil {
		slog.Warn("template render error", "err", err)
	}
}

// formatBytes returns a human-readable byte count (e.g. "12.3 MB").
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

var uiTemplate = template.Must(template.New("ui").Funcs(template.FuncMap{
	"formatBytes": formatBytes,
	"join":        strings.Join,
}).Parse(uiHTML))

const uiHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Tor Proxy — Status</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:#0f1117;color:#e2e8f0;padding:2rem}
  h1{font-size:1.5rem;font-weight:700;margin-bottom:1.5rem;color:#f8fafc}
  h1 span{font-size:.9rem;font-weight:400;color:#64748b;margin-left:.5rem}
  table{width:100%;border-collapse:collapse;background:#1e2433;border-radius:10px;overflow:hidden}
  thead tr{background:#161b27}
  th{padding:.75rem 1rem;text-align:left;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8;font-weight:600}
  td{padding:.75rem 1rem;font-size:.85rem;border-top:1px solid #23293a}
  tr:hover td{background:#232a3b}
  .badge{display:inline-block;padding:.2em .6em;border-radius:999px;font-size:.75rem;font-weight:600}
  .free{background:#14532d;color:#86efac}
  .busy{background:#7c2d12;color:#fca5a5}
  .warming{background:#713f12;color:#fde68a}
  .degraded{background:#1e293b;color:#94a3b8}
  .region-badge{display:inline-block;padding:.2em .75em;border-radius:999px;font-size:.8rem;font-weight:600;background:#1e3a5f;color:#7dd3fc;margin-left:.75rem;vertical-align:middle}
  .iface{font-family:monospace;font-weight:700;color:#93c5fd}
  .addr{font-family:monospace;color:#a5b4fc}
  .endpoint{font-family:monospace;font-size:.8rem;color:#67e8f9}
  .bytes{font-family:monospace;font-size:.8rem}
  .ts{color:#64748b;font-size:.78rem}
  .footer{margin-top:1rem;color:#475569;font-size:.78rem}
  .client{font-family:monospace;font-size:.8rem;color:#fbbf24}
</style>
</head>
<body>
<h1>Tor Proxy <span id="ts"></span><span id="region-badge"></span></h1>
<table>
<thead><tr>
  <th>Instance</th>
  <th>SOCKS Address</th>
  <th>Status</th>
  <th>Exit Node</th>
  <th>Circuit Age</th>
  <th>Last Used</th>
  <th>↑ Sent</th>
  <th>↓ Received</th>
  <th>Current Client</th>
</tr></thead>
<tbody id="tbody"><tr><td colspan="9" style="text-align:center;padding:2rem;color:#64748b">Loading…</td></tr></tbody>
</table>
<div class="footer">Auto-refreshes every second &bull; <a href="/api/status" style="color:#475569">JSON API</a></div>

<script>
function fmt(b){
  if(b===0)return'—';
  const u=['B','KB','MB','GB','TB'];
  let i=0;
  while(b>=1024&&i<u.length-1){b/=1024;i++}
  return b.toFixed(1)+' '+u[i];
}
function ago(ts){
  if(!ts)return'—';
  const s=Math.floor((Date.now()-new Date(ts))/1000);
  if(s<60)return s+'s ago';
  if(s<3600)return Math.floor(s/60)+'m ago';
  return Math.floor(s/3600)+'h ago';
}
const regionLabel={
  '':'Worldwide','worldwide':'Worldwide',
  'europe':'Europe','americas':'Americas',
  'us':'US Only','uk':'UK Only','asia':'Asia'
};
function setRegionBadge(r){
  const el=document.getElementById('region-badge');
  if(!el)return;
  const label=regionLabel[r]||(r?r:'Worldwide');
  el.innerHTML='<span class="region-badge">Exit Region: '+label+'</span>';
}
async function refresh(){
  try{
    const r=await fetch('/api/status');
    const d=await r.json();
    document.getElementById('ts').textContent='as of '+new Date(d.collected_at).toLocaleTimeString();
    setRegionBadge(d.exit_region||'');
    const rows=d.tunnels.map(function(t){
      return '<tr>'+
        '<td><span class="iface">'+t.interface+'</span></td>'+
        '<td><span class="addr">'+(t.address||'—')+'</span></td>'+
        '<td><span class="badge '+t.status+'">'+t.status+'</span></td>'+
        '<td><span class="endpoint">'+(t.peer_endpoint||'—')+'</span></td>'+
        '<td><span class="ts">'+ago(t.last_newnym)+'</span></td>'+
        '<td><span class="ts">'+ago(t.latest_handshake)+'</span></td>'+
        '<td><span class="bytes">'+fmt(t.tx_bytes)+'</span></td>'+
        '<td><span class="bytes">'+fmt(t.rx_bytes)+'</span></td>'+
        '<td><span class="client">'+(t.client_addr||(t.lease_duration?t.lease_duration:'\u2014'))+'</span></td>'+
        '</tr>';
    }).join('');
    document.getElementById('tbody').innerHTML=rows||'<tr><td colspan="9" style="text-align:center;padding:2rem;color:#64748b">No tunnels active</td></tr>';
  }catch(e){console.error(e)}
}
refresh();
setInterval(refresh,1000);
</script>
</body>
</html>
`

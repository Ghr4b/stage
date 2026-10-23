package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"tijeri/internal/models"
	"tijeri/internal/remediation"
	"tijeri/internal/risk"
	"tijeri/internal/siem"
	"tijeri/internal/store"
)

// Publisher abstracts the NATS message broker.
type Publisher interface {
	Publish(subject string, data []byte) error
}

// Server holds the API state.
type Server struct {
	mux             *http.ServeMux
	db              store.Store
	objStore        store.ObjectStore
	publisher       Publisher
	oidc            *OIDCAuthenticator
	webhookSubs     []WebhookSubscription
	auditLog        []AuditEntry
	rbacRules       map[string]map[string]bool
	cdbList         map[string]string // current CDB map for SIEM lookups
	discoverLimiter *rateLimiter
}

type WebhookSubscription struct {
	URL       string
	EventType string
}

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Actor     string    `json:"actor"`
	Resource  string    `json:"resource"`
	Details   string    `json:"details"`
}

type WebhookEvent struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

func NewServer(db store.Store, objStore store.ObjectStore, pub Publisher) *Server {
	return NewServerWithOIDC(db, objStore, pub, nil)
}

func NewServerWithOIDC(db store.Store, objStore store.ObjectStore, pub Publisher, oidc *OIDCAuthenticator) *Server {
	s := &Server{
		mux:             http.NewServeMux(),
		db:              db,
		objStore:        objStore,
		publisher:       pub,
		oidc:            oidc,
		rbacRules:       make(map[string]map[string]bool),
		cdbList:         make(map[string]string),
		discoverLimiter: newRateLimiter(0.033, 1, true), // ~1 discovery per 30s per IP
	}
	s.registerRoutes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.securityHeaders(s.mux).ServeHTTP(w, r)
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/", s.handleDashboard)
	s.mux.HandleFunc("/api/v1/findings", s.authMiddleware(s.handleFindings))
	s.mux.HandleFunc("/api/v1/assets", s.authMiddleware(s.handleAssets))
	s.mux.HandleFunc("/api/v1/risk/score", s.authMiddleware(s.handleRiskScore))
	s.mux.HandleFunc("/api/v1/query/vulnerable-reachable", s.authMiddleware(s.handleVulnerableReachableQuery))
	s.mux.HandleFunc("/api/v1/webhooks/subscribe", s.authMiddleware(s.handleWebhookSubscribe))
	s.mux.HandleFunc("/api/v1/audit", s.authMiddleware(s.handleAuditTrail))
	s.mux.HandleFunc("/api/v1/dashboard/kpis", s.authMiddleware(s.handleDashboardKPIs))
	wazuhWebhook := http.HandlerFunc(s.handleWazuhWebhook)
	defectDojoWebhook := http.HandlerFunc(s.handleDefectDojoWebhook)
	if strings.EqualFold(os.Getenv("WEBHOOK_AUTH_REQUIRED"), "true") {
		wazuhWebhook = s.serviceAuthMiddleware(s.handleWazuhWebhook)
		defectDojoWebhook = s.serviceAuthMiddleware(s.handleDefectDojoWebhook)
	}
	s.mux.Handle("/api/v1/webhooks/wazuh", wazuhWebhook)
	s.mux.Handle("/api/v1/webhooks/defectdojo", defectDojoWebhook)
	s.mux.HandleFunc("/api/v1/vex/", s.authMiddleware(s.handleVexRead))
	s.mux.HandleFunc("/api/v1/network/info", s.authMiddleware(s.handleNetworkInfo))
	s.mux.HandleFunc("/api/v1/discover", s.authMiddleware(s.handleDiscover))
	s.mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	if s.oidc != nil {
		s.mux.HandleFunc("/auth/login", s.oidc.handleLogin)
		s.mux.HandleFunc("/auth/callback", s.oidc.handleCallback)
		s.mux.HandleFunc("/auth/logout", s.oidc.handleLogout)
	}
	s.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	s.mux.HandleFunc("/ready", s.handleReadiness)
}

func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.db.ListAssets(r.Context(), 1, 0); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	if checker, ok := s.publisher.(interface{ Connected() bool }); ok && !checker.Connected() {
		http.Error(w, "message bus unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("READY"))
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	page := dashboardHTML
	if s.oidc != nil {
		session, ok := s.oidc.sessionFromRequest(r)
		if !ok {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		page = strings.ReplaceAll(page, "__TIJERI_CSRF_TOKEN__", session.CSRF)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func parsePagination(r *http.Request) (int, int) {
	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	return limit, offset
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	limit, offset := parsePagination(r)

	findings, total, err := s.db.ListFindings(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list findings: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"findings": findings,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
	})
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	limit, offset := parsePagination(r)

	assets, total, err := s.db.ListAssets(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list assets: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"assets": assets,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) handleRiskScore(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	findingID := r.URL.Query().Get("finding_id")

	if findingID == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"bod_tier":             90,
			"criticality_override": nil,
			"epss_rank":            0.0,
			"ssvc_bucket":          "",
		})
		return
	}

	finding, err := s.db.GetFinding(r.Context(), findingID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Finding not found: %v", err), http.StatusNotFound)
		return
	}

	asset, err := s.db.GetAsset(r.Context(), finding.AssetID)
	if err != nil {
		// If asset not found, use defaults
		asset = models.Asset{CriticalityTier: "standard"}
	}

	// Compute real risk score
	exposure := true
	kev := finding.KEVListed
	automatable := true
	techImpact := finding.CVSS != nil && finding.CVSS.Score >= 7.0

	var epssScore float64
	if finding.EPSS != nil {
		epssScore = finding.EPSS.Score
	}

	ssvcBucket := "attend"
	if finding.SSVC != nil {
		ssvcBucket = *finding.SSVC
	}

	recomputed, err := risk.RecomputeScore(&exposure, kev, &automatable, techImpact, asset.CriticalityTier, epssScore, ssvcBucket)
	if err != nil {
		recomputed = risk.ExplainabilityOutput{BODTier: 90, EPSSRank: epssScore, SSVCBucket: ssvcBucket}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"finding_id":           findingID,
		"bod_tier":             recomputed.BODTier,
		"criticality_override": recomputed.CriticalityOverride,
		"epss_rank":            recomputed.EPSSRank,
		"ssvc_bucket":          recomputed.SSVCBucket,
	})
}

func (s *Server) handleVulnerableReachableQuery(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cve := r.URL.Query().Get("cve")

	if host == "" || cve == "" {
		http.Error(w, "host and cve query params required", http.StatusBadRequest)
		return
	}

	// Check the CDB list for this host
	vulnerable := s.cdbList[host] == "vulnerable"
	reachable := vulnerable // If in CDB, it's reachable

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"host":       host,
		"cve":        cve,
		"vulnerable": vulnerable,
		"reachable":  reachable,
	})
}

func (s *Server) handleWebhookSubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var sub WebhookSubscription
	if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.webhookSubs = append(s.webhookSubs, sub)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleAuditTrail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	limit, offset := parsePagination(r)

	logs, err := s.db.ListAuditLogs(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list audit logs: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(logs)
}

func (s *Server) handleDashboardKPIs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Compute real KPIs from the database
	history, err := s.db.GetTicketHistory(r.Context())
	if err != nil {
		history = nil
	}

	mttr := remediation.ComputeMTTR(history)
	openPastSLA := remediation.CountOpenPastSLA(history, time.Now())
	windowEnd := time.Now()
	windowStart := windowEnd.AddDate(0, -1, 0) // last 30 days
	eliminationRate := remediation.ComputeEliminationRate(history, windowStart, windowEnd)

	// Count total open and resolved findings
	openFindings, _, err := s.db.ListFindings(r.Context(), 1, 0)
	totalOpen := len(openFindings)
	if err != nil {
		totalOpen = 0
	}

	// Format MTTR by tier as string keys for JSON
	mttrByTier := make(map[string]float64)
	for tier, val := range mttr {
		mttrByTier[strconv.Itoa(tier)] = math.Round(val*10) / 10
	}
	if len(mttrByTier) == 0 {
		mttrByTier = map[string]float64{"3": 0, "7": 0, "14": 0, "30": 0, "90": 0}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"mttr_by_tier":     mttrByTier,
		"open_past_sla":    openPastSLA,
		"elimination_rate": math.Round(eliminationRate*100) / 100,
		"total_open":       totalOpen,
	})
}

func (s *Server) handleDefectDojoWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var payload struct {
		Status    string `json:"status"`
		FindingID string `json:"finding_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid webhook payload", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.FindingID) == "" {
		http.Error(w, "finding_id is required", http.StatusBadRequest)
		return
	}

	if payload.Status == "False Positive" {
		feedback := models.AnalystFeedback{
			FeedbackID:    fmt.Sprintf("fb-%s-%d", payload.FindingID, time.Now().UnixNano()),
			FindingID:     payload.FindingID,
			AnalystID:     "defectdojo-system",
			FeedbackType:  "status_override",
			OverrideValue: "false_positive",
			RecordedAt:    time.Now(),
			Source:        "defectdojo",
		}

		if err := s.db.SaveAnalystFeedback(r.Context(), feedback); err != nil {
			http.Error(w, "Failed to persist feedback", http.StatusInternalServerError)
			return
		}

		if s.publisher != nil {
			msg, _ := json.Marshal(map[string]string{"feedback_id": feedback.FeedbackID})
			if err := s.publisher.Publish("vamp.risk.feedback_recorded", msg); err != nil {
				http.Error(w, "feedback saved but event could not be queued", http.StatusServiceUnavailable)
				return
			}
		}

		s.RecordAudit("ml_feedback", "defectdojo", payload.FindingID, "Recorded analyst feedback; automatic retraining is disabled")
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleVexRead(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/api/v1/vex/")
	if key == "" {
		http.Error(w, "Missing VEX key", http.StatusBadRequest)
		return
	}

	key = filepath.Clean(key)
	if strings.HasPrefix(key, "..") || strings.Contains(key, "/") {
		http.Error(w, "Invalid key", http.StatusBadRequest)
		return
	}

	data, err := s.objStore.Get(r.Context(), key)
	if err != nil {
		http.Error(w, "VEX document not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *Server) handleNetworkInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	type networkInfo struct {
		Interface string `json:"interface"`
		IP        string `json:"ip"`
		Subnet    string `json:"subnet"`
		CIDR      string `json:"cidr"`
	}

	var networks []networkInfo

	ifaces, err := net.Interfaces()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"networks": []networkInfo{}})
		return
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil {
				continue
			}
			if ip[0] == 169 && ip[1] == 254 {
				continue
			}
			ones, _ := ipNet.Mask.Size()
			network := ip.Mask(ipNet.Mask).String()
			cidr := fmt.Sprintf("%s/%d", network, ones)

			networks = append(networks, networkInfo{
				Interface: iface.Name,
				IP:        ip.String(),
				Subnet:    fmt.Sprintf("%s - %s", ip.Mask(ipNet.Mask), broadcastIP(ip, ipNet.Mask)),
				CIDR:      cidr,
			})
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"networks": networks})
}

func broadcastIP(ip net.IP, mask net.IPMask) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ip.String()
	}
	b := make(net.IP, len(ip4))
	copy(b, ip4)
	for i := range b {
		if i >= len(mask) {
			break
		}
		b[i] |= ^mask[i]
	}
	return b.String()
}

// UpdateCDBList refreshes the in-memory CDB map from the database.
func (s *Server) UpdateCDBList(hosts []string) {
	newList := make(map[string]string, len(hosts))
	for _, h := range hosts {
		newList[h] = "vulnerable"
	}
	s.cdbList = newList
}

// GenerateCDBContent produces the raw CDB file content from the current list.
func (s *Server) GenerateCDBContent() string {
	var ips []string
	for ip := range s.cdbList {
		ips = append(ips, ip)
	}
	return siem.GenerateCDBList(ips)
}

// RecordAudit adds an immutable audit entry.
func (s *Server) RecordAudit(action, actor, resource, details string) {
	err := s.db.SaveAuditLog(context.Background(), action, actor, resource, details)
	if err != nil {
		fmt.Printf("[Audit Error] Failed to save audit log: %v\n", err)
	}
}

// CheckRBAC verifies that a role is authorized for a resource.
func (s *Server) CheckRBAC(role, resource string) bool {
	perms, ok := s.rbacRules[role]
	if !ok {
		return false
	}
	if allowed, ok := perms[resource]; ok {
		return allowed
	}
	for pattern, allowed := range perms {
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(resource, prefix) {
				return allowed
			}
		}
	}
	return false
}

// SetRBACRule configures an RBAC allow/deny rule.
func (s *Server) SetRBACRule(role, resource string, allowed bool) {
	if s.rbacRules[role] == nil {
		s.rbacRules[role] = make(map[string]bool)
	}
	s.rbacRules[role][resource] = allowed
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="csrf-token" content="__TIJERI_CSRF_TOKEN__">
<title>Tijeri - Vulnerability Management</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #e0e0e0; min-height: 100vh; }
  .topbar { background: #16213e; border-bottom: 1px solid #0f3460; padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; }
  .topbar h1 { font-size: 20px; font-weight: 600; color: #e94560; }
  .topbar h1 span { color: #e0e0e0; font-weight: 400; }
  .topbar a { color: #53a8b6; text-decoration: none; font-size: 13px; margin-left: 20px; }
  .topbar a:hover { color: #79c9ec; }
  .container { max-width: 1100px; margin: 0 auto; padding: 24px; }
  .card { background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
  .card h2 { font-size: 15px; font-weight: 600; color: #53a8b6; margin-bottom: 14px; text-transform: uppercase; letter-spacing: 0.5px; }
  .form-row { display: flex; gap: 12px; align-items: flex-end; }
  .form-group { display: flex; flex-direction: column; flex: 1; }
  .form-group label { font-size: 12px; color: #8892b0; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
  .form-group input, .form-group select { background: #1a1a2e; border: 1px solid #0f3460; color: #e0e0e0; padding: 10px 12px; border-radius: 4px; font-size: 14px; outline: none; }
  .form-group input:focus, .form-group select:focus { border-color: #e94560; }
  .btn { padding: 10px 24px; border: none; border-radius: 4px; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 0.2s; }
  .btn-primary { background: #e94560; color: #fff; }
  .btn-primary:hover { background: #c73652; }
  .btn-primary:disabled { background: #555; cursor: not-allowed; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px; }
  .stat { background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 16px; text-align: center; }
  .stat .num { font-size: 28px; font-weight: 700; color: #e94560; }
  .stat .label { font-size: 11px; color: #8892b0; text-transform: uppercase; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 10px 12px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #8892b0; border-bottom: 1px solid #0f3460; }
  td { padding: 10px 12px; font-size: 13px; border-bottom: 1px solid #0f3460; }
  tr:hover td { background: rgba(233,69,96,0.05); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; }
  .badge-critical { background: #e94560; color: #fff; }
  .badge-high { background: #e67e22; color: #fff; }
  .badge-medium { background: #f1c40f; color: #1a1a2e; }
  .badge-low { background: #2ecc71; color: #fff; }
  .badge-info { background: #3498db; color: #fff; }
  .status { font-size: 12px; color: #8892b0; margin-top: 10px; }
  .status.ok { color: #2ecc71; }
  .status.err { color: #e94560; }
  .log { background: #1a1a2e; border: 1px solid #0f3460; border-radius: 4px; padding: 12px; max-height: 300px; overflow-y: auto; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px; line-height: 1.6; display: none; }
  .log .line { color: #8892b0; }
  .log .line.info { color: #53a8b6; }
  .log .line.ok { color: #2ecc71; }
  .log .line.err { color: #e94560; }
  .empty { text-align: center; padding: 40px; color: #555; font-size: 13px; }
  .presets { display: flex; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
  .preset { background: #1a1a2e; border: 1px solid #0f3460; color: #8892b0; padding: 4px 10px; border-radius: 3px; font-size: 11px; cursor: pointer; transition: all 0.2s; }
  .preset:hover { border-color: #e94560; color: #e94560; }
</style>
</head>
<body>
<div class="topbar">
  <h1>Tijeri <span>| Vulnerability & Asset Management</span></h1>
  <div>
    <a href="/api/v1/assets">API: Assets</a>
    <a href="/api/v1/findings">API: Findings</a>
    <a href="/api/v1/dashboard/kpis">API: KPIs</a>
    <a id="logout-link" href="/auth/logout" style="display:none">Sign out</a>
  </div>
</div>
<div class="container">
  <div class="stats" id="stats">
    <div class="stat"><div class="num" id="stat-assets">-</div><div class="label">Assets</div></div>
    <div class="stat"><div class="num" id="stat-findings">-</div><div class="label">Findings</div></div>
    <div class="stat"><div class="num" id="stat-open">-</div><div class="label">Open Past SLA</div></div>
    <div class="stat"><div class="num" id="stat-discovered">-</div><div class="label">Discovered</div></div>
  </div>

  <div class="card">
    <h2>Network Discovery</h2>
    <div class="form-row">
      <div class="form-group" style="flex:2">
        <label>Target Network</label>
        <input type="text" id="target" placeholder="e.g. 10.20.0.0/24, 172.30.20.0/24, 10.30.10.0/24">
      </div>
      <div class="form-group" style="flex:1">
        <label>Asset Type</label>
        <select id="asset-type">
          <option value="host">Host</option>
          <option value="repo">Repository</option>
          <option value="container">Container</option>
        </select>
      </div>
      <div class="form-group" style="flex:1">
        <label>Criticality</label>
        <select id="criticality">
          <option value="standard">Standard</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </div>
      <button class="btn btn-primary" id="discover-btn" onclick="runDiscover()">Discover & Scan</button>
    </div>
    <div class="presets" id="presets">
      <span class="preset" style="color:#555">Detecting network...</span>
    </div>
    <div id="status-msg" class="status"></div>
  </div>

  <div class="card">
    <h2>Activity Log</h2>
    <div class="log" id="log"></div>
    <div class="empty" id="log-empty">No activity yet. Run a discovery to get started.</div>
  </div>

  <div class="card">
    <h2>Discovered Hosts</h2>
    <table>
      <thead><tr><th>IP Address</th><th>Status</th><th>Type</th><th>Criticality</th><th>Discovered</th></tr></thead>
      <tbody id="hosts-body">
        <tr><td colspan="5" class="empty">No hosts discovered yet.</td></tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Recent Findings</h2>
    <table>
      <thead><tr><th>Vulnerability</th><th>Asset</th><th>Tool</th><th>Severity</th><th>EPSS</th><th>Status</th></tr></thead>
      <tbody id="findings-body">
        <tr><td colspan="6" class="empty">No findings yet. Discover and scan a network first.</td></tr>
      </tbody>
    </table>
  </div>
</div>

<script>
let discoveredHosts = [];

function setTarget(t) { document.getElementById('target').value = t; }

function addLog(msg, cls) {
  const log = document.getElementById('log');
  const empty = document.getElementById('log-empty');
  empty.style.display = 'none';
  log.style.display = 'block';
  const line = document.createElement('div');
  line.className = 'line ' + (cls || '');
  const ts = new Date().toLocaleTimeString();
  line.textContent = '[' + ts + '] ' + msg;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function severityBadge(f) {
  const badge = document.createElement('span');
  badge.className = 'badge';
  if (!f.cvss || !Number.isFinite(Number(f.cvss.score))) {
    badge.classList.add('badge-info');
    badge.textContent = 'N/A';
    return badge;
  }
  const score = Number(f.cvss.score);
  if (score >= 9.0) {
    badge.classList.add('badge-critical');
    badge.textContent = 'Critical';
  } else if (score >= 7.0) {
    badge.classList.add('badge-high');
    badge.textContent = 'High';
  } else if (score >= 4.0) {
    badge.classList.add('badge-medium');
    badge.textContent = 'Medium';
  } else {
    badge.classList.add('badge-low');
    badge.textContent = 'Low';
  }
  return badge;
}

function textCell(value) {
  const cell = document.createElement('td');
  cell.textContent = value == null || value === '' ? '-' : String(value);
  return cell;
}

const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
if (csrfToken !== '__TIJERI_CSRF_TOKEN__') {
  const logoutLink = document.getElementById('logout-link');
  logoutLink.style.display = 'inline';
  logoutLink.addEventListener('click', async (event) => {
    event.preventDefault();
    await apiFetch('/auth/logout', { method: 'POST' });
    window.location.assign('/');
  });
}

function apiFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (csrfToken !== '__TIJERI_CSRF_TOKEN__' && options.method && options.method !== 'GET') {
    headers.set('X-CSRF-Token', csrfToken);
  }
  return fetch(url, { ...options, headers, credentials: 'same-origin' });
}

async function loadStats() {
  try {
    const [aRes, fRes, kRes] = await Promise.all([
      apiFetch('/api/v1/assets?limit=1'),
      apiFetch('/api/v1/findings?limit=1'),
      apiFetch('/api/v1/dashboard/kpis')
    ]);
    const a = await aRes.json();
    const f = await fRes.json();
    const k = await kRes.json();
    document.getElementById('stat-assets').textContent = a.total || 0;
    document.getElementById('stat-findings').textContent = f.total || 0;
    document.getElementById('stat-open').textContent = k.open_past_sla || 0;
    document.getElementById('stat-discovered').textContent = discoveredHosts.length;
  } catch(e) {}
}

async function loadFindings() {
  try {
    const res = await apiFetch('/api/v1/findings?limit=50');
    const data = await res.json();
    const body = document.getElementById('findings-body');
    body.replaceChildren();
    if (!data.findings || data.findings.length === 0) {
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 6;
      cell.className = 'empty';
      cell.textContent = 'No findings yet.';
      row.appendChild(cell);
      body.appendChild(row);
      return;
    }
    for (const finding of data.findings) {
      const row = document.createElement('tr');
      row.appendChild(textCell(finding.vulnerability_id));
      row.appendChild(textCell(finding.asset_id));
      row.appendChild(textCell(finding.source_tool));
      const severity = document.createElement('td');
      severity.appendChild(severityBadge(finding));
      row.appendChild(severity);
      const epss = finding.epss && Number.isFinite(Number(finding.epss.score))
        ? (Number(finding.epss.score) * 100).toFixed(1) + '%'
        : '-';
      row.appendChild(textCell(epss));
      row.appendChild(textCell(finding.status || 'open'));
      body.appendChild(row);
    }
  } catch(e) {}
}

async function runDiscover() {
  const target = document.getElementById('target').value.trim();
  if (!target) { alert('Enter a target network'); return; }

  const btn = document.getElementById('discover-btn');
  const statusEl = document.getElementById('status-msg');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  statusEl.className = 'status';
  statusEl.textContent = 'Running nmap discovery on ' + target + '...';
  addLog('Starting discovery on ' + target, 'info');

  try {
    const res = await apiFetch('/api/v1/discover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: target,
        asset_type: document.getElementById('asset-type').value,
        criticality: document.getElementById('criticality').value
      })
    });
    const data = await res.json();

    if (!res.ok) {
      addLog('Discovery failed: ' + (data.error || data), 'err');
      statusEl.className = 'status err';
      statusEl.textContent = 'Scan failed. Check the log below.';
      btn.disabled = false;
      btn.textContent = 'Discover & Scan';
      return;
    }

    addLog(data.message, 'ok');
    statusEl.className = 'status ok';
    statusEl.textContent = data.message;

    if (data.discovered && data.discovered.length > 0) {
      discoveredHosts = data.discovered;
      document.getElementById('stat-discovered').textContent = discoveredHosts.length;
      const tbody = document.getElementById('hosts-body');
      tbody.replaceChildren();
      const assetType = document.getElementById('asset-type').value;
      const criticality = document.getElementById('criticality').value;
      for (const ip of data.discovered) {
        const row = document.createElement('tr');
        row.appendChild(textCell(ip));
        const status = document.createElement('td');
        const badge = document.createElement('span');
        badge.className = 'badge badge-low';
        badge.textContent = 'Published';
        status.appendChild(badge);
        row.appendChild(status);
        row.appendChild(textCell(assetType));
        row.appendChild(textCell(criticality));
        row.appendChild(textCell(new Date().toLocaleTimeString()));
        tbody.appendChild(row);
      }
      addLog('Scans queued for ' + data.published + ' hosts. Results will appear in DefectDojo.', 'info');
      setTimeout(loadFindings, 5000);
    }
  } catch(e) {
    addLog('Request failed: ' + e.message, 'err');
    statusEl.className = 'status err';
    statusEl.textContent = 'Connection error.';
  }

  btn.disabled = false;
  btn.textContent = 'Discover & Scan';
}

async function detectNetwork() {
  try {
    const res = await apiFetch('/api/v1/network/info');
    const data = await res.json();
    if (data.networks && data.networks.length > 0) {
      const n = data.networks[0];
      document.getElementById('target').placeholder = n.CIDR + ' (' + n.Interface + ': ' + n.IP + ')';
      document.getElementById('target').value = n.CIDR;
      const presets = document.getElementById('presets');
      presets.replaceChildren();
      for (const network of data.networks) {
        const preset = document.createElement('button');
        preset.type = 'button';
        preset.className = 'preset';
        preset.textContent = network.Interface + ' (' + network.CIDR + ')';
        preset.addEventListener('click', () => {
          document.getElementById('target').value = network.CIDR;
        });
        presets.appendChild(preset);
      }
      addLog('Detected network: ' + n.CIDR + ' on ' + n.Interface, 'info');
    }
  } catch(e) {
    addLog('Could not detect network: ' + e.message, 'err');
  }
}

loadStats();
loadFindings();
detectNetwork();
setInterval(loadStats, 15000);
</script>
</body>
</html>`

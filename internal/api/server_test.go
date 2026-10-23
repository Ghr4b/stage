package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"tijeri/internal/models"
	"tijeri/internal/remediation"
)

type mockStore struct{ logs []map[string]interface{} }

func (m *mockStore) SaveFinding(ctx context.Context, f models.Finding) error { return nil }
func (m *mockStore) GetFinding(ctx context.Context, id string) (models.Finding, error) {
	return models.Finding{}, nil
}
func (m *mockStore) ListFindings(ctx context.Context, limit, offset int) ([]models.Finding, int, error) {
	return []models.Finding{}, 0, nil
}
func (m *mockStore) SaveAnalystFeedback(ctx context.Context, f models.AnalystFeedback) error {
	return nil
}
func (m *mockStore) GetAnalystFeedback(ctx context.Context) ([]models.AnalystFeedback, error) {
	return nil, nil
}
func (m *mockStore) SaveAsset(ctx context.Context, a models.Asset) error { return nil }
func (m *mockStore) GetAsset(ctx context.Context, id string) (models.Asset, error) {
	return models.Asset{}, nil
}
func (m *mockStore) ListAssets(ctx context.Context, limit, offset int) ([]models.Asset, int, error) {
	return []models.Asset{}, 0, nil
}
func (m *mockStore) GetVulnerableHosts(ctx context.Context) ([]string, error) { return nil, nil }
func (m *mockStore) GetTicketHistory(ctx context.Context) ([]remediation.TicketHistory, error) {
	return nil, nil
}
func (m *mockStore) Migrate(migrationsDir string) error { return nil }
func (m *mockStore) Close() error                       { return nil }

type mockObjStore struct{}

func (m *mockObjStore) Put(ctx context.Context, key string, data []byte) error { return nil }
func (m *mockObjStore) Get(ctx context.Context, key string) ([]byte, error)    { return nil, nil }

type mockPublisher struct{}

func (m *mockPublisher) Publish(subject string, data []byte) error { return nil }

type failingPublisher struct{}

func (p *failingPublisher) Publish(subject string, data []byte) error {
	return errors.New("queue unavailable")
}

type recordingPublisher struct {
	subject string
	data    []byte
}

func (p *recordingPublisher) Publish(subject string, data []byte) error {
	p.subject = subject
	p.data = append([]byte(nil), data...)
	return nil
}

func authorizeAdminRequest(t *testing.T, authenticator *OIDCAuthenticator, request *http.Request) {
	t.Helper()
	session := oidcSession{
		Subject:   "admin-test-user",
		Role:      "admin",
		CSRF:      "admin-test-csrf",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	value, err := authenticator.sign(session)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: value})
	request.Header.Set("X-CSRF-Token", session.CSRF)
}

func doAuthRequest(tsURL string, method string, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, tsURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	return http.DefaultClient.Do(req)
}

func setupTestServer() *Server {
	os.Setenv("TIJERI_API_TOKEN", "0123456789abcdef0123456789abcdef")
	return NewServer(&mockStore{}, &mockObjStore{}, &mockPublisher{})
}

func TestAPIEndpointsSchemaConformance(t *testing.T) {
	s := setupTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	endpoints := []struct {
		method   string
		path     string
		wantCode int
		required []string // required top-level fields
	}{
		{"GET", "/api/v1/findings", 200, []string{"findings", "total"}},
		{"GET", "/api/v1/assets", 200, []string{"assets", "total"}},
		{"GET", "/api/v1/risk/score", 200, []string{"bod_tier", "epss_rank", "ssvc_bucket"}},
		{"GET", "/api/v1/dashboard/kpis", 200, []string{"mttr_by_tier", "open_past_sla", "elimination_rate"}},
	}

	for _, ep := range endpoints {
		req, _ := http.NewRequest("GET", ts.URL+ep.path, nil)
		req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("[%s %s] request failed: %v", ep.method, ep.path, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != ep.wantCode {
			t.Errorf("[%s %s] expected %d, got %d", ep.method, ep.path, ep.wantCode, resp.StatusCode)
			continue
		}

		var body map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&body)

		for _, field := range ep.required {
			if _, ok := body[field]; !ok {
				t.Errorf("[%s %s] missing required field %q in response", ep.method, ep.path, field)
			}
		}
	}
}

func TestVulnerableReachableQuery(t *testing.T) {
	s := setupTestServer()
	ts := httptest.NewServer(s)
	defer ts.Close()

	// Missing params -> 400
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/query/vulnerable-reachable", nil)
	req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 400 {
		t.Errorf("Expected 400 for missing params, got %d", resp.StatusCode)
	}

	// With params -> 200
	req2, _ := http.NewRequest("GET", ts.URL+"/api/v1/query/vulnerable-reachable?host=10.0.1.42&cve=CVE-2023-1234", nil)
	req2.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	resp, _ = http.DefaultClient.Do(req2)
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	if body["host"] != "10.0.1.42" || body["cve"] != "CVE-2023-1234" {
		t.Errorf("Response doesn't echo query params correctly: %+v", body)
	}
}

func TestWebhookEvents(t *testing.T) {
	s := setupTestServer()
	s.oidc = testOIDCAuthenticator()
	ts := httptest.NewServer(s)
	defer ts.Close()

	eventTypes := []string{
		"finding_created",
		"sla_breached",
		"verification_failed",
		"new_asset_discovered",
		"kev_addition_rescored",
	}

	for _, et := range eventTypes {
		sub := WebhookSubscription{URL: "http://test.local/hook", EventType: et}
		body, _ := json.Marshal(sub)
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/webhooks/subscribe", bytes.NewReader(body))
		authorizeAdminRequest(t, s.oidc, req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("[%s] subscribe failed: %v", et, err)
		}
		if resp.StatusCode != 201 {
			t.Errorf("[%s] expected 201, got %d", et, resp.StatusCode)
		}
	}

	// Verify all 5 subscriptions registered
	if len(s.webhookSubs) != 5 {
		t.Errorf("Expected 5 webhook subscriptions, got %d", len(s.webhookSubs))
	}
}

func TestWazuhWebhookPersistsAndQueuesSyscheckAlert(t *testing.T) {
	t.Setenv("TIJERI_API_TOKEN", "0123456789abcdef0123456789abcdef")
	t.Setenv("WEBHOOK_AUTH_REQUIRED", "true")
	t.Setenv("DISCOVER_ALLOWLIST", "192.0.2.0/24")
	store := &mockStore{}
	publisher := &recordingPublisher{}
	server := NewServer(store, &mockObjStore{}, publisher)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/wazuh", bytes.NewBufferString(`{"syscheck":{"path":"/etc/hosts","event":"modified"},"agent":{"id":"001","name":"host-a","ip":"192.0.2.4"}}`))
	request.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("expected %d, got %d: %s", http.StatusAccepted, response.Code, response.Body.String())
	}
	if publisher.subject != "tijeri.scan.requested" {
		t.Fatalf("expected scan request publication, got %q", publisher.subject)
	}
	var asset models.Asset
	if err := json.Unmarshal(publisher.data, &asset); err != nil {
		t.Fatalf("decode queued asset: %v", err)
	}
	if asset.AssetID != "wazuh-agent-001" || asset.Metadata["fim_path"] != "/etc/hosts" || asset.Metadata["ip"] != "192.0.2.4" {
		t.Fatalf("unexpected queued asset: %+v", asset)
	}
	if len(store.logs) != 1 || store.logs[0]["action"] != "wazuh_rescan_queued" {
		t.Fatalf("expected Wazuh audit record before acceptance, got %+v", store.logs)
	}
}

func TestRBACAuthorizationMatrix(t *testing.T) {
	s := setupTestServer()

	// Configure roles
	s.SetRBACRule("admin", "findings:*", true)
	s.SetRBACRule("admin", "assets:*", true)
	s.SetRBACRule("admin", "audit:*", true)
	s.SetRBACRule("admin", "config:*", true)

	s.SetRBACRule("analyst", "findings:read", true)
	s.SetRBACRule("analyst", "findings:update", true)
	s.SetRBACRule("analyst", "assets:read", true)
	s.SetRBACRule("analyst", "config:write", false)

	s.SetRBACRule("viewer", "findings:read", true)
	s.SetRBACRule("viewer", "findings:update", false)
	s.SetRBACRule("viewer", "assets:read", true)
	s.SetRBACRule("viewer", "config:write", false)

	s.SetRBACRule("scanner", "findings:write", true)
	s.SetRBACRule("scanner", "findings:read", false)
	s.SetRBACRule("scanner", "assets:write", true)
	s.SetRBACRule("scanner", "config:write", false)

	// Authorization matrix: role × resource → expected allow/deny
	matrix := []struct {
		role     string
		resource string
		expected bool
	}{
		// Admin: full access
		{"admin", "findings:read", true},
		{"admin", "assets:write", true},
		{"admin", "audit:read", true},
		{"admin", "config:write", true},

		// Analyst: read/update findings, read assets, no config
		{"analyst", "findings:read", true},
		{"analyst", "findings:update", true},
		{"analyst", "assets:read", true},
		{"analyst", "config:write", false},

		// Viewer: read only
		{"viewer", "findings:read", true},
		{"viewer", "findings:update", false},
		{"viewer", "assets:read", true},
		{"viewer", "config:write", false},

		// Scanner: write findings/assets, no read, no config
		{"scanner", "findings:write", true},
		{"scanner", "findings:read", false},
		{"scanner", "assets:write", true},
		{"scanner", "config:write", false},
	}

	for _, tc := range matrix {
		result := s.CheckRBAC(tc.role, tc.resource)
		if result != tc.expected {
			t.Errorf("RBAC[%s][%s]: expected %t, got %t", tc.role, tc.resource, tc.expected, result)
		}
	}
}

func TestAuditTrailCompleteness(t *testing.T) {
	s := setupTestServer()

	// Scripted scenario: one of each action type
	actions := []struct {
		action   string
		actor    string
		resource string
		details  string
	}{
		{"escalation", "system", "finding-001", "BOD tier tightened by criticality override"},
		{"suppression", "analyst-1", "finding-002", "VEX not_affected applied"},
		{"elimination_policy", "system", "ticket-100", "Auto-closed on confirmed patch"},
		{"criticality_override", "admin-1", "asset-50", "Changed from standard to mission_critical"},
	}

	for _, a := range actions {
		s.RecordAudit(a.action, a.actor, a.resource, a.details)
	}

	// Audit table row count must match action count exactly
	if len(s.db.(*mockStore).logs) != len(actions) {
		t.Errorf("Expected %d audit entries, got %d", len(actions), len(s.db.(*mockStore).logs))
	}

	// Verify no action type is unaccounted for
	for i, a := range actions {
		if s.db.(*mockStore).logs[i]["action"].(string) != a.action {
			t.Errorf("Audit entry %d: expected action %q, got %q", i, a.action, s.db.(*mockStore).logs[i]["action"].(string))
		}
	}

	// Verify via API endpoint
	ts := httptest.NewServer(s)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	resp, _ := http.DefaultClient.Do(req)
	var entries []AuditEntry
	json.NewDecoder(resp.Body).Decode(&entries)

	if len(entries) != len(actions) {
		t.Errorf("API returned %d audit entries, expected %d", len(entries), len(actions))
	}
}

func (m *mockStore) SaveAuditLog(ctx context.Context, action, actor, resource, details string) error {
	m.logs = append(m.logs, map[string]interface{}{"action": action, "actor": actor, "resource": resource, "details": details})
	return nil
}
func (m *mockStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]map[string]interface{}, error) {
	return m.logs, nil
}

func TestAuthRejectsMissingToken(t *testing.T) {
	os.Setenv("TIJERI_API_TOKEN", "0123456789abcdef0123456789abcdef")
	s := NewServer(&mockStore{}, &mockObjStore{}, &mockPublisher{})
	ts := httptest.NewServer(s)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/findings")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}

	resp2, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 health (unauthenticated), got %d", resp2.StatusCode)
	}
}

func TestDiscoverTargetValidation(t *testing.T) {
	os.Setenv("TIJERI_API_TOKEN", "0123456789abcdef0123456789abcdef")
	os.Setenv("DISCOVER_ALLOWLIST", "172.30.20.0/24,127.0.0.1/32")

	// Fresh server per request so the per-IP rate limit doesn't interfere with
	// validating each rejection path.
	postWith := func(payload string, limiter *rateLimiter) int {
		s := NewServer(&mockStore{}, &mockObjStore{}, &mockPublisher{})
		s.oidc = testOIDCAuthenticator()
		s.discoverLimiter = limiter
		ts := httptest.NewServer(s)
		defer ts.Close()

		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/discover", bytes.NewReader([]byte(payload)))
		authorizeAdminRequest(t, s.oidc, req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	unlimited := newRateLimiter(1000, 1000, true)

	if code := postWith(`{"target": "; reboot"}`, unlimited); code != http.StatusBadRequest {
		t.Errorf("expected 400 for shell injection, got %d", code)
	}
	if code := postWith(`{"target": "172.30.20.1; }"}`, unlimited); code != http.StatusBadRequest {
		t.Errorf("expected 400 for smuggled target, got %d", code)
	}
	if code := postWith(`{"target": "8.8.8.8/32"}`, unlimited); code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-allowlisted target, got %d", code)
	}
	if code := postWith(`{not json`, unlimited); code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad JSON, got %d", code)
	}
	if code := postWith(`{"target": "127.0.0.1/32"}`, unlimited); code == http.StatusBadRequest {
		t.Fatalf("allowlisted target rejected: got 400")
	}
}

func TestDiscoverReportsQueueFailure(t *testing.T) {
	toolDir := t.TempDir()
	toolPath := toolDir + "/nmap"
	if err := os.WriteFile(toolPath, []byte("#!/bin/sh\nprintf '%s\\n' 'Nmap scan report for 127.0.0.1'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", toolDir+":"+os.Getenv("PATH"))
	t.Setenv("DISCOVER_ALLOWLIST", "127.0.0.1/32")
	server := NewServer(&mockStore{}, &mockObjStore{}, &failingPublisher{})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/discover", bytes.NewBufferString(`{"target":"127.0.0.1/32"}`))
	response := httptest.NewRecorder()
	server.handleDiscover(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("queue failure returned %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if !bytes.Contains(response.Body.Bytes(), []byte("not all assets could be queued")) {
		t.Fatalf("queue failure response did not explain incomplete acceptance: %s", response.Body.String())
	}
}

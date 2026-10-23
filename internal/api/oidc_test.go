package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testOIDCAuthenticator() *OIDCAuthenticator {
	return &OIDCAuthenticator{
		config: OIDCConfig{
			AdminGroups:    []string{"security-admins"},
			OperatorGroups: []string{"security-operators"},
			ViewerGroups:   []string{"security-viewers"},
		},
		secret: []byte(strings.Repeat("s", 32)),
	}
}

func TestOIDCConfigFromEnv(t *testing.T) {
	t.Setenv("OIDC_ENABLED", "true")
	t.Setenv("OIDC_ISSUER_URL", "https://id.example.test/tenant")
	t.Setenv("OIDC_CLIENT_ID", "tijeri")
	t.Setenv("OIDC_CLIENT_SECRET", "client-secret")
	t.Setenv("OIDC_REDIRECT_URL", "https://tijeri.example.test/auth/callback")
	t.Setenv("OIDC_SESSION_SECRET", strings.Repeat("s", 32))
	t.Setenv("OIDC_GROUPS_CLAIM", "groups")
	t.Setenv("OIDC_ADMIN_GROUPS", "security-admins")
	t.Setenv("OIDC_OPERATOR_GROUPS", "security-operators")
	t.Setenv("OIDC_VIEWER_GROUPS", "security-viewers")

	config, enabled, err := OIDCConfigFromEnv()
	if err != nil {
		t.Fatalf("valid OIDC configuration rejected: %v", err)
	}
	if !enabled || config.GroupsClaim != "groups" || len(config.AdminGroups) != 1 {
		t.Fatalf("unexpected OIDC configuration: enabled=%v config=%+v", enabled, config)
	}

	t.Setenv("OIDC_REDIRECT_URL", "http://tijeri.example.test/auth/callback")
	if _, _, err := OIDCConfigFromEnv(); err == nil {
		t.Fatal("insecure HTTP redirect URL was accepted")
	}
}

func TestOIDCRoleMappingUsesHighestAssignedRole(t *testing.T) {
	auth := testOIDCAuthenticator()
	if role := auth.roleForGroups([]string{"security-viewers", "security-admins"}); role != "admin" {
		t.Fatalf("expected admin role, got %q", role)
	}
	if role := auth.roleForGroups([]string{"unmapped"}); role != "" {
		t.Fatalf("expected unmapped group to have no role, got %q", role)
	}
}

func TestOIDCSessionSignatureAndExpiry(t *testing.T) {
	auth := testOIDCAuthenticator()
	session := oidcSession{
		Subject:   "user-123",
		Role:      "viewer",
		CSRF:      "csrf-value",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	value, err := auth.sign(session)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: value})
	if _, ok := auth.sessionFromRequest(request); !ok {
		t.Fatal("valid session was rejected")
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: value + "tampered"})
	if _, ok := auth.sessionFromRequest(request); ok {
		t.Fatal("tampered session was accepted")
	}

	session.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	value, err = auth.sign(session)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: value})
	if _, ok := auth.sessionFromRequest(request); ok {
		t.Fatal("expired session was accepted")
	}
}

func TestOIDCLogoutRevokesSessionUntilExpiry(t *testing.T) {
	auth := testOIDCAuthenticator()
	session := oidcSession{
		Subject:   "user-logout",
		Role:      "viewer",
		CSRF:      "logout-csrf",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	value, err := auth.sign(session)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: value})
	request.Header.Set("X-CSRF-Token", session.CSRF)
	recorder := httptest.NewRecorder()
	auth.handleLogout(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("logout returned %d, want %d", recorder.Code, http.StatusSeeOther)
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: value})
	if _, ok := auth.sessionFromRequest(request); ok {
		t.Fatal("logged-out session remained valid")
	}
}

func TestOIDCAuthMiddlewareEnforcesRolesAndCSRF(t *testing.T) {
	auth := testOIDCAuthenticator()
	server := &Server{oidc: auth}
	protected := server.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	requestFor := func(method, path, role, csrf string) *http.Request {
		session := oidcSession{
			Subject:   "user-123",
			Role:      role,
			CSRF:      "expected-csrf",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		}
		value, err := auth.sign(session)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(method, path, nil)
		request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: value})
		if csrf != "" {
			request.Header.Set("X-CSRF-Token", csrf)
		}
		return request
	}
	check := func(request *http.Request, status int) {
		recorder := httptest.NewRecorder()
		protected.ServeHTTP(recorder, request)
		if recorder.Code != status {
			t.Errorf("%s %s returned %d, wanted %d", request.Method, request.URL.Path, recorder.Code, status)
		}
	}

	check(requestFor(http.MethodGet, "/api/v1/findings", "viewer", ""), http.StatusNoContent)
	check(requestFor(http.MethodPost, "/api/v1/findings", "viewer", "expected-csrf"), http.StatusForbidden)
	check(requestFor(http.MethodPost, "/api/v1/findings", "operator", ""), http.StatusForbidden)
	check(requestFor(http.MethodPost, "/api/v1/findings", "operator", "expected-csrf"), http.StatusNoContent)
	check(requestFor(http.MethodPost, "/api/v1/discover", "operator", "expected-csrf"), http.StatusForbidden)
	check(requestFor(http.MethodPost, "/api/v1/discover", "admin", "expected-csrf"), http.StatusNoContent)

	t.Setenv("TIJERI_API_TOKEN", strings.Repeat("t", 32))
	tokenRequest := httptest.NewRequest(http.MethodPost, "/api/v1/discover", nil)
	tokenRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	check(tokenRequest, http.StatusForbidden)
	tokenRequest = httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	tokenRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	check(tokenRequest, http.StatusForbidden)
}

func TestOIDCDashboardRequiresSessionAndEmbedsCSRFToken(t *testing.T) {
	auth := testOIDCAuthenticator()
	server := &Server{oidc: auth}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	server.handleDashboard(recorder, request)
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/auth/login" {
		t.Fatalf("unauthenticated dashboard request returned %d and location %q", recorder.Code, recorder.Header().Get("Location"))
	}

	session := oidcSession{
		Subject:   "user-123",
		Role:      "viewer",
		CSRF:      "csrf-value",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	value, err := auth.sign(session)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: value})
	recorder = httptest.NewRecorder()
	server.handleDashboard(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `content="csrf-value"`) {
		t.Fatal("authenticated dashboard did not receive its CSRF token")
	}
	if strings.Contains(recorder.Body.String(), "__TIJERI_CSRF_TOKEN__") {
		t.Fatal("CSRF token placeholder was not replaced")
	}
}

func TestDashboardDoesNotInsertDynamicDataAsHTML(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	server.handleDashboard(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if strings.Contains(recorder.Body.String(), "innerHTML") {
		t.Fatal("dashboard uses HTML string insertion for dynamic API data")
	}
}

func TestServiceAuthDoesNotAcceptOIDCBrowserSession(t *testing.T) {
	t.Setenv("TIJERI_API_TOKEN", strings.Repeat("a", 32))
	server := &Server{oidc: testOIDCAuthenticator()}
	protected := server.serviceAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	session := oidcSession{
		Subject:   "user-123",
		Role:      "admin",
		CSRF:      "csrf-value",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	value, err := server.oidc.sign(session)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/wazuh", nil)
	request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: value})
	recorder := httptest.NewRecorder()
	protected.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("browser session was accepted for a service webhook: %d", recorder.Code)
	}
}

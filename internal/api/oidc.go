package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	oidcSessionCookie = "tijeri_session"
	oidcStateCookie   = "tijeri_oidc_state"
	oidcSessionTTL    = 8 * time.Hour
)

type OIDCConfig struct {
	IssuerURL      string
	ClientID       string
	ClientSecret   string
	RedirectURL    string
	SessionSecret  string
	GroupsClaim    string
	AdminGroups    []string
	OperatorGroups []string
	ViewerGroups   []string
}

type OIDCAuthenticator struct {
	config    OIDCConfig
	oauth     oauth2.Config
	verifier  *oidc.IDTokenVerifier
	secret    []byte
	sessionMu sync.Mutex
	revoked   map[string]time.Time
}

type oidcState struct {
	State     string `json:"state"`
	Nonce     string `json:"nonce"`
	Verifier  string `json:"verifier"`
	ExpiresAt int64  `json:"expires_at"`
}

type oidcSession struct {
	Subject   string `json:"sub"`
	Email     string `json:"email,omitempty"`
	Role      string `json:"role"`
	CSRF      string `json:"csrf"`
	ExpiresAt int64  `json:"expires_at"`
}

type oidcPrincipalKey struct{}

func OIDCConfigFromEnv() (OIDCConfig, bool, error) {
	enabled := strings.EqualFold(strings.TrimSpace(os.Getenv("OIDC_ENABLED")), "true")
	if !enabled {
		for _, name := range []string{"OIDC_ISSUER_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URL", "OIDC_SESSION_SECRET"} {
			if os.Getenv(name) != "" {
				return OIDCConfig{}, false, errors.New("OIDC settings are present but OIDC_ENABLED is not true")
			}
		}
		return OIDCConfig{}, false, nil
	}

	config := OIDCConfig{
		IssuerURL:      strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL")),
		ClientID:       strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID")),
		ClientSecret:   os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:    strings.TrimSpace(os.Getenv("OIDC_REDIRECT_URL")),
		SessionSecret:  os.Getenv("OIDC_SESSION_SECRET"),
		GroupsClaim:    strings.TrimSpace(os.Getenv("OIDC_GROUPS_CLAIM")),
		AdminGroups:    splitGroups(os.Getenv("OIDC_ADMIN_GROUPS")),
		OperatorGroups: splitGroups(os.Getenv("OIDC_OPERATOR_GROUPS")),
		ViewerGroups:   splitGroups(os.Getenv("OIDC_VIEWER_GROUPS")),
	}
	if config.GroupsClaim == "" {
		config.GroupsClaim = "groups"
	}
	if err := validateOIDCConfig(config); err != nil {
		return OIDCConfig{}, false, err
	}
	return config, true, nil
}

func NewOIDCAuthenticator(ctx context.Context, config OIDCConfig) (*OIDCAuthenticator, error) {
	if err := validateOIDCConfig(config); err != nil {
		return nil, err
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(discoveryCtx, config.IssuerURL)
	if err != nil {
		return nil, errors.New("could not discover the configured OIDC provider")
	}
	return &OIDCAuthenticator{
		config: config,
		oauth: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  config.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
		secret:   []byte(config.SessionSecret),
		revoked:  make(map[string]time.Time),
	}, nil
}

func validateOIDCConfig(config OIDCConfig) error {
	if config.IssuerURL == "" || config.ClientID == "" || config.ClientSecret == "" || config.RedirectURL == "" {
		return errors.New("OIDC issuer, client ID, client secret, and redirect URL are required")
	}
	if len(config.SessionSecret) < 32 {
		return errors.New("OIDC_SESSION_SECRET must contain at least 32 characters")
	}
	for _, rawURL := range []string{config.IssuerURL, config.RedirectURL} {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return errors.New("OIDC issuer and redirect URLs must be absolute HTTPS URLs without user information or fragments")
		}
	}
	if config.GroupsClaim == "" {
		return errors.New("OIDC groups claim must not be empty")
	}
	if len(config.AdminGroups)+len(config.OperatorGroups)+len(config.ViewerGroups) == 0 {
		return errors.New("at least one OIDC role group mapping is required")
	}
	return nil
}

func splitGroups(value string) []string {
	var groups []string
	for _, group := range strings.Split(value, ",") {
		if group = strings.TrimSpace(group); group != "" {
			groups = append(groups, group)
		}
	}
	return groups
}

func (a *OIDCAuthenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := randomURLToken(32)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	verifier, err := randomURLToken(32)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	loginState := oidcState{State: state, Nonce: nonce, Verifier: verifier, ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}
	value, err := a.sign(loginState)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: value, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 300,
	})
	http.Redirect(w, r, a.oauth.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	), http.StatusFound)
}

func (a *OIDCAuthenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("error") != "" {
		a.clearCookie(w, oidcStateCookie)
		http.Error(w, "identity provider rejected login", http.StatusUnauthorized)
		return
	}
	stateCookie, err := r.Cookie(oidcStateCookie)
	var loginState oidcState
	if err != nil || a.verify(stateCookie.Value, &loginState) != nil || loginState.ExpiresAt <= time.Now().Unix() {
		a.clearCookie(w, oidcStateCookie)
		http.Error(w, "invalid or expired login state", http.StatusUnauthorized)
		return
	}
	state := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(state), []byte(loginState.State)) != 1 {
		a.clearCookie(w, oidcStateCookie)
		http.Error(w, "invalid login state", http.StatusUnauthorized)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		a.clearCookie(w, oidcStateCookie)
		http.Error(w, "authorization code is missing", http.StatusBadRequest)
		return
	}
	a.clearCookie(w, oidcStateCookie)

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	token, err := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(loginState.Verifier))
	if err != nil {
		http.Error(w, "could not complete login", http.StatusUnauthorized)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "identity provider returned no ID token", http.StatusUnauthorized)
		return
	}
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "identity provider returned an invalid ID token", http.StatusUnauthorized)
		return
	}
	var claims map[string]json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "identity token claims are invalid", http.StatusUnauthorized)
		return
	}
	var nonce string
	if json.Unmarshal(claims["nonce"], &nonce) != nil || subtle.ConstantTimeCompare([]byte(nonce), []byte(loginState.Nonce)) != 1 {
		http.Error(w, "identity token nonce does not match", http.StatusUnauthorized)
		return
	}
	var groups []string
	if json.Unmarshal(claims[a.config.GroupsClaim], &groups) != nil {
		http.Error(w, "identity token has no valid role groups", http.StatusForbidden)
		return
	}
	role := a.roleForGroups(groups)
	if role == "" {
		http.Error(w, "user is not assigned a Tijeri role", http.StatusForbidden)
		return
	}
	if idToken.Subject == "" || !idToken.Expiry.After(time.Now()) {
		http.Error(w, "identity token is expired or incomplete", http.StatusUnauthorized)
		return
	}
	csrfToken, err := randomURLToken(32)
	if err != nil {
		http.Error(w, "could not create a session", http.StatusInternalServerError)
		return
	}
	var email string
	_ = json.Unmarshal(claims["email"], &email)
	sessionExpiry := time.Now().Add(oidcSessionTTL)
	if idToken.Expiry.Before(sessionExpiry) {
		sessionExpiry = idToken.Expiry
	}
	session := oidcSession{Subject: idToken.Subject, Email: email, Role: role, CSRF: csrfToken, ExpiresAt: sessionExpiry.Unix()}
	sessionValue, err := a.sign(session)
	if err != nil {
		http.Error(w, "could not create a session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oidcSessionCookie, Value: sessionValue, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode, Expires: sessionExpiry, MaxAge: int(time.Until(sessionExpiry).Seconds()),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *OIDCAuthenticator) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, ok := a.sessionFromRequest(r)
	if !ok || !a.validCSRF(session, r.Header.Get("X-CSRF-Token")) {
		http.Error(w, "invalid session or CSRF token", http.StatusForbidden)
		return
	}
	a.sessionMu.Lock()
	if a.revoked == nil {
		a.revoked = make(map[string]time.Time)
	}
	now := time.Now()
	for id, expiry := range a.revoked {
		if !expiry.After(now) {
			delete(a.revoked, id)
		}
	}
	a.revoked[session.CSRF] = time.Unix(session.ExpiresAt, 0)
	a.sessionMu.Unlock()
	a.clearCookie(w, oidcSessionCookie)
	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
}

func (a *OIDCAuthenticator) sessionFromRequest(r *http.Request) (oidcSession, bool) {
	cookie, err := r.Cookie(oidcSessionCookie)
	if err != nil {
		return oidcSession{}, false
	}
	var session oidcSession
	if a.verify(cookie.Value, &session) != nil || session.Subject == "" || session.CSRF == "" || session.ExpiresAt <= time.Now().Unix() {
		return oidcSession{}, false
	}
	a.sessionMu.Lock()
	if expiry, revoked := a.revoked[session.CSRF]; revoked {
		if expiry.After(time.Now()) {
			a.sessionMu.Unlock()
			return oidcSession{}, false
		}
		delete(a.revoked, session.CSRF)
	}
	a.sessionMu.Unlock()
	if session.Role != "viewer" && session.Role != "operator" && session.Role != "admin" {
		return oidcSession{}, false
	}
	return session, true
}

func (a *OIDCAuthenticator) validCSRF(session oidcSession, candidate string) bool {
	return candidate != "" && subtle.ConstantTimeCompare([]byte(session.CSRF), []byte(candidate)) == 1
}

func (a *OIDCAuthenticator) roleForGroups(groups []string) string {
	groupSet := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		groupSet[group] = struct{}{}
	}
	for _, group := range a.config.AdminGroups {
		if _, ok := groupSet[group]; ok {
			return "admin"
		}
	}
	for _, group := range a.config.OperatorGroups {
		if _, ok := groupSet[group]; ok {
			return "operator"
		}
	}
	for _, group := range a.config.ViewerGroups {
		if _, ok := groupSet[group]; ok {
			return "viewer"
		}
	}
	return ""
}

func (a *OIDCAuthenticator) sign(payload any) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(encoded))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + signature, nil
}

func (a *OIDCAuthenticator) verify(value string, payload any) error {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return errors.New("invalid signed value")
	}
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(parts[0]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return errors.New("invalid signature")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	return json.Unmarshal(data, payload)
}

func (a *OIDCAuthenticator) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0),
	})
}

func randomURLToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

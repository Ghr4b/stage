package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"tijeri/internal/models"
)

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

// apiToken returns the configured bearer token (TIJERI_API_TOKEN). The token
// must be non-empty and at least 32 chars to be considered "secure".
func apiToken() string {
	t := os.Getenv("TIJERI_API_TOKEN")
	if len(t) < 32 {
		return ""
	}
	return t
}

// authMiddleware uses OIDC roles for production browser/API access. The shared
// token remains a local-development fallback; production integrations use the
// service-only middleware on webhook routes.
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := apiToken()
		authHeader := r.Header.Get("Authorization")
		reqKey := ""
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			reqKey = strings.TrimSpace(authHeader[len("Bearer "):])
		} else if authHeader == "" {
			reqKey = r.Header.Get("X-API-Key")
		}
		if reqKey != "" {
			if token == "" {
				http.Error(w, "API not configured securely", http.StatusForbidden)
				return
			}
			if subtle.ConstantTimeCompare([]byte(reqKey), []byte(token)) != 1 {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if s.oidc != nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next(w, r)
			return
		}
		if authHeader != "" || r.Header.Get("X-API-Key") != "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if s.oidc == nil {
			if token == "" {
				http.Error(w, "API not configured securely", http.StatusForbidden)
			} else {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
			return
		}
		session, ok := s.oidc.sessionFromRequest(r)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		requiredRole := "viewer"
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			requiredRole = "operator"
		}
		if r.URL.Path == "/api/v1/discover" || r.URL.Path == "/api/v1/webhooks/subscribe" {
			requiredRole = "admin"
		} else if r.URL.Path == "/api/v1/audit" && requiredRole == "viewer" {
			requiredRole = "operator"
		}
		if !roleAtLeast(session.Role, requiredRole) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions &&
			!s.oidc.validCSRF(session, r.Header.Get("X-CSRF-Token")) {
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), oidcPrincipalKey{}, session)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) serviceAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := apiToken()
		authHeader := r.Header.Get("Authorization")
		reqKey := ""
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			reqKey = strings.TrimSpace(authHeader[len("Bearer "):])
		} else if authHeader == "" {
			reqKey = r.Header.Get("X-API-Key")
		}
		if token == "" {
			http.Error(w, "API not configured securely", http.StatusForbidden)
			return
		}
		if reqKey == "" || subtle.ConstantTimeCompare([]byte(reqKey), []byte(token)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func roleAtLeast(actual, required string) bool {
	levels := map[string]int{"viewer": 1, "operator": 2, "admin": 3}
	return levels[actual] >= levels[required] && levels[required] != 0
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

type rateLimiter struct {
	mu     sync.Mutex
	tokens map[string]*bucket
	rate   float64 // tokens per second
	burst  int
	perIP  bool
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newRateLimiter creates a per-IP token bucket limiter. When perIP is false a
// single global bucket is used.
func newRateLimiter(rate float64, burst int, perIP bool) *rateLimiter {
	return &rateLimiter{
		tokens: make(map[string]*bucket),
		rate:   rate,
		burst:  burst,
		perIP:  perIP,
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	ip := "global"
	if rl.perIP {
		if host, _, err := net.SplitHostPort(key); err == nil {
			ip = host
		} else {
			ip = key
		}
	}

	b, ok := rl.tokens[ip]
	if !ok {
		b = &bucket{tokens: float64(rl.burst), last: now}
		rl.tokens[ip] = b
	}

	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Discovery (validated + allowlisted + rate limited)
// ---------------------------------------------------------------------------

type discoverRequest struct {
	Target string `json:"target"`
}

// isTargetAllowed returns true when target is a single IP or CIDR that falls
// fully inside one of the allowed CIDRs from DISCOVER_ALLOWLIST.
func isTargetAllowed(target string) (bool, string) {
	allowList := os.Getenv("DISCOVER_ALLOWLIST")
	if allowList == "" {
		return false, "DISCOVER_ALLOWLIST is not configured"
	}

	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(target))
	if err != nil {
		// Maybe a bare IP
		ip := net.ParseIP(strings.TrimSpace(target))
		if ip == nil {
			return false, "target must be an IP address or CIDR block"
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		_, ipNet, err = net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), bits))
		if err != nil {
			return false, "invalid target"
		}
	}

	for _, entry := range strings.Split(allowList, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, allowed, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		allowedPrefix, addressBits := allowed.Mask.Size()
		targetPrefix, targetBits := ipNet.Mask.Size()
		if addressBits == targetBits && targetPrefix >= allowedPrefix && allowed.Contains(ipNet.IP) {
			return true, ""
		}
	}
	return false, "target is not within the configured allowlist"
}

// handleDiscover runs an nmap host discovery against an allowlisted target and
// publishes each discovered host to the scrutiny pipeline via NATS.
func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	if !s.discoverLimiter.allow(r.RemoteAddr) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req discoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	ok, reason := isTargetAllowed(req.Target)
	if !ok {
		http.Error(w, fmt.Sprintf("target rejected: %s", reason), http.StatusBadRequest)
		return
	}

	// Reject anything that could be smuggled into the shell command.
	if req.Target != strings.TrimSpace(req.Target) || strings.ContainsAny(req.Target, ";&|`$(){}[]'\"") {
		http.Error(w, "target rejected: only IP/CIDR allowed", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nmap", "-sn", "-T4", req.Target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// nmap -sn returns non-zero when no hosts are up; surface the stdout.
		if len(out) == 0 {
			http.Error(w, "nmap discovery failed", http.StatusInternalServerError)
			return
		}
	}

	ips := parseNmapIPs(out)
	published := 0

	for _, ipStr := range ips {
		if s.publisher == nil {
			http.Error(w, "scan queue is unavailable", http.StatusServiceUnavailable)
			return
		}
		asset := models.Asset{
			AssetID:         ipStr,
			CanonicalName:   ipStr,
			Type:            "host",
			CriticalityTier: "standard",
			Exposure:        "unknown",
			State:           "discovered",
			Metadata: map[string]string{
				"source": "dashboard",
				"ip":     ipStr,
			},
		}
		data, err := json.Marshal(asset)
		if err != nil {
			http.Error(w, "could not encode discovered asset", http.StatusInternalServerError)
			return
		}
		if err := s.publisher.Publish("tijeri.asset.discovered", data); err != nil {
			fmt.Printf("[API] Failed to publish discovery for %s: %v\n", ipStr, err)
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":     "discovery completed but not all assets could be queued",
				"published": published,
				"count":     len(ips),
			})
			return
		}
		published++
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"target":     req.Target,
		"discovered": ips,
		"count":      len(ips),
		"published":  published,
	})
}

func parseNmapIPs(out []byte) []string {
	var ips []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Nmap scan report for") {
			parts := strings.Split(line, " ")
			if len(parts) < 5 {
				continue
			}
			candidate := strings.Trim(parts[4], "()")
			if ip := net.ParseIP(candidate); ip != nil {
				ips = append(ips, candidate)
			}
		}
	}
	return ips
}

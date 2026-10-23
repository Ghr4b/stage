import re

with open("internal/api/server.go", "r") as f:
    content = f.read()

# Add imports
if '"path/filepath"' not in content:
    content = content.replace('"math"', '"math"\n\t"os"\n\t"path/filepath"')

# Add authMiddleware function
auth_middleware = """
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := os.Getenv("TIJERI_API_KEY")
		if apiKey == "" {
			http.Error(w, "API not configured securely", http.StatusForbidden)
			return
		}
		
		authHeader := r.Header.Get("Authorization")
		reqKey := strings.TrimPrefix(authHeader, "Bearer ")
		if reqKey == "" {
			reqKey = r.Header.Get("X-API-Key")
		}

		if reqKey != apiKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		next(w, r)
	}
}
"""

if "authMiddleware" not in content:
    # insert before registerRoutes
    content = content.replace("func (s *Server) registerRoutes() {", auth_middleware + "\nfunc (s *Server) registerRoutes() {")

# Wrap routes
routes_to_wrap = [
    "handleFindings", "handleAssets", "handleRiskScore", 
    "handleVulnerableReachableQuery", "handleWebhookSubscribe", 
    "handleAuditTrail", "handleDashboardKPIs", "handleVexRead", 
    "handleNetworkInfo"
]

for route in routes_to_wrap:
    content = re.sub(
        r's\.mux\.HandleFunc\("([^"]+)", s\.' + route + r'\)',
        f's.mux.HandleFunc("\\1", s.authMiddleware(s.{route}))',
        content
    )

# Remove discover route
content = re.sub(r's\.mux\.HandleFunc\("/api/v1/discover", s\.handleDiscover\)\n?', '', content)

# Add health route
if '"/health"' not in content:
    health_route = """	s.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})"""
    content = content.replace('s.mux.HandleFunc("/api/v1/network/info", s.authMiddleware(s.handleNetworkInfo))', 's.mux.HandleFunc("/api/v1/network/info", s.authMiddleware(s.handleNetworkInfo))\n' + health_route)

# Fix Vex path traversal
vex_fix = """	key = filepath.Clean(key)
	if strings.HasPrefix(key, "..") || strings.Contains(key, "/") {
		http.Error(w, "Invalid key", http.StatusBadRequest)
		return
	}"""
content = re.sub(
    r'(key := strings\.TrimPrefix\(r\.URL\.Path, "/api/v1/vex/"\)\n\s+if key == "" \{\n\s+http\.Error\(w, "Missing VEX key", http\.StatusBadRequest\)\n\s+return\n\s+\})',
    r'\1\n\n' + vex_fix,
    content
)

# Remove handleDiscover func
content = re.sub(r'func \(s \*Server\) handleDiscover\(w http\.ResponseWriter, r \*http\.Request\) \{.*?\n\}\n\nfunc \(s \*Server\) handleNetworkInfo', 'func (s *Server) handleNetworkInfo', content, flags=re.DOTALL)

with open("internal/api/server.go", "w") as f:
    f.write(content)

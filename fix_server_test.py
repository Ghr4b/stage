import re

with open("internal/api/server_test.go", "r") as f:
    content = f.read()

# Make the mock store track audit logs
if "type mockStore struct" in content:
    content = content.replace("type mockStore struct{}", "type mockStore struct{ logs []map[string]interface{} }")
    content = content.replace("func (m *mockStore) SaveAuditLog(ctx context.Context, action, actor, resource, details string) error { return nil }", """func (m *mockStore) SaveAuditLog(ctx context.Context, action, actor, resource, details string) error {
	m.logs = append(m.logs, map[string]interface{}{"action": action, "actor": actor, "resource": resource, "details": details})
	return nil
}""")
    content = content.replace("func (m *mockStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]map[string]interface{}, error) { return nil, nil }", """func (m *mockStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]map[string]interface{}, error) {
	return m.logs, nil
}""")

# Helper function to inject auth
if "func setupTestServer() *Server" in content:
    content = content.replace("func setupTestServer() *Server {", """import "os"

func doAuthRequest(tsURL string, method string, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, tsURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer testkey")
	return http.DefaultClient.Do(req)
}

func setupTestServer() *Server {""")
    content = content.replace("import \"os\"", "")

# Inject os.Setenv into setupTestServer
content = content.replace("return NewServer(&mockStore{}, &mockObjStore{}, &mockPublisher{})", """os.Setenv("TIJERI_API_KEY", "testkey")
	return NewServer(&mockStore{}, &mockObjStore{}, &mockPublisher{})""")

# Fix http.Get calls
content = re.sub(
    r'resp, err := http\.Get\(ts\.URL \+ ep\.path\)',
    r'req, _ := http.NewRequest("GET", ts.URL+ep.path, nil)\n\t\treq.Header.Set("Authorization", "Bearer testkey")\n\t\tresp, err := http.DefaultClient.Do(req)',
    content
)

content = re.sub(
    r'resp, _ := http\.Get\(ts\.URL \+ "/api/v1/query/vulnerable-reachable"\)',
    r'req, _ := http.NewRequest("GET", ts.URL+"/api/v1/query/vulnerable-reachable", nil)\n\treq.Header.Set("Authorization", "Bearer testkey")\n\tresp, _ := http.DefaultClient.Do(req)',
    content
)

content = re.sub(
    r'resp, _ = http\.Get\(ts\.URL \+ "/api/v1/query/vulnerable-reachable\?host=10\.0\.1\.42&cve=CVE-2023-1234"\)',
    r'req2, _ := http.NewRequest("GET", ts.URL+"/api/v1/query/vulnerable-reachable?host=10.0.1.42&cve=CVE-2023-1234", nil)\n\treq2.Header.Set("Authorization", "Bearer testkey")\n\tresp, _ = http.DefaultClient.Do(req2)',
    content
)

content = re.sub(
    r'resp, err := http\.Post\(ts\.URL\+"\/(webhooks|api\/v1\/webhooks)\/subscribe", "application\/json", bytes\.NewReader\(body\)\)',
    r'req, _ := http.NewRequest("POST", ts.URL+"/api/v1/webhooks/subscribe", bytes.NewReader(body))\n\t\treq.Header.Set("Authorization", "Bearer testkey")\n\t\tresp, err := http.DefaultClient.Do(req)',
    content
)

content = re.sub(
    r'resp, err := http\.Get\(ts\.URL \+ "/api\/v1\/audit"\)',
    r'req, _ := http.NewRequest("GET", ts.URL+"/api/v1/audit", nil)\n\treq.Header.Set("Authorization", "Bearer testkey")\n\tresp, err := http.DefaultClient.Do(req)',
    content
)

content = re.sub(
    r'resp, _ := http\.Post\(ts\.URL\+"/api\/v1\/discover", "application\/json", bytes\.NewReader\(body\)\)',
    r'req, _ := http.NewRequest("POST", ts.URL+"/api/v1/discover", bytes.NewReader(body))\n\treq.Header.Set("Authorization", "Bearer testkey")\n\tresp, _ := http.DefaultClient.Do(req)',
    content
)

with open("internal/api/server_test.go", "w") as f:
    f.write(content)

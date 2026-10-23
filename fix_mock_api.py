with open("internal/api/server_test.go", "r") as f:
    content = f.read()

mock_methods = """
func (m *mockStore) SaveAuditLog(ctx context.Context, action, actor, resource, details string) error { return nil }
func (m *mockStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]map[string]interface{}, error) { return nil, nil }
"""

if "SaveAuditLog" not in content:
    content += mock_methods

with open("internal/api/server_test.go", "w") as f:
    f.write(content)

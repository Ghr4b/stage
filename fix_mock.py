import re
with open("internal/ml/retrainer_test.go", "r") as f:
    content = f.read()

mock_methods = """
func (m *mockStore) SaveAuditLog(ctx context.Context, action, actor, resource, details string) error { return nil }
func (m *mockStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]map[string]interface{}, error) { return nil, nil }
"""

if "SaveAuditLog" not in content:
    content += mock_methods

with open("internal/ml/retrainer_test.go", "w") as f:
    f.write(content)

import os
if os.path.exists("tests/contract/fake_impls.go"):
    with open("tests/contract/fake_impls.go", "r") as f:
        content = f.read()
    if "type FakeStore struct" in content and "SaveAuditLog" not in content:
        fake_methods = """
func (f *FakeStore) SaveAuditLog(ctx context.Context, action, actor, resource, details string) error { return nil }
func (f *FakeStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]map[string]interface{}, error) { return nil, nil }
"""
        content += fake_methods
        with open("tests/contract/fake_impls.go", "w") as f:
            f.write(content)

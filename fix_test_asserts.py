import re

# Fix defectdojo_webhook_test.go
with open("internal/api/defectdojo_webhook_test.go", "r") as f:
    content = f.read()

content = content.replace('len(s.auditLog)', 'len(s.db.(*mockStore).logs)')
content = content.replace('s.auditLog[0].Action', 's.db.(*mockStore).logs[0]["action"].(string)')

with open("internal/api/defectdojo_webhook_test.go", "w") as f:
    f.write(content)

# Fix server_test.go
with open("internal/api/server_test.go", "r") as f:
    content = f.read()

content = content.replace('len(s.auditLog)', 'len(s.db.(*mockStore).logs)')
content = content.replace('s.auditLog[0].Action', 's.db.(*mockStore).logs[0]["action"].(string)')

with open("internal/api/server_test.go", "w") as f:
    f.write(content)


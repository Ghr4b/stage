import re
with open("internal/api/server_test.go", "r") as f:
    content = f.read()

content = content.replace("s.auditLog[i].Action", 's.db.(*mockStore).logs[i]["action"].(string)')
content = content.replace('resp, _ := http.Get(ts.URL + "/api/v1/audit")', 'req, _ := http.NewRequest("GET", ts.URL+"/api/v1/audit", nil)\n\treq.Header.Set("Authorization", "Bearer testkey")\n\tresp, _ := http.DefaultClient.Do(req)')

with open("internal/api/server_test.go", "w") as f:
    f.write(content)

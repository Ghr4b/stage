import re

with open("internal/api/server.go", "r") as f:
    content = f.read()

# Replace RecordAudit implementation
old_record_audit = """func (s *Server) RecordAudit(action, actor, resource, details string) {
	s.auditLog = append(s.auditLog, AuditEntry{
		Timestamp: time.Now(),
		Action:    action,
		Actor:     actor,
		Resource:  resource,
		Details:   details,
	})
}"""

new_record_audit = """func (s *Server) RecordAudit(action, actor, resource, details string) {
	err := s.db.SaveAuditLog(context.Background(), action, actor, resource, details)
	if err != nil {
		fmt.Printf("[Audit Error] Failed to save audit log: %v\\n", err)
	}
}"""

if old_record_audit in content:
    content = content.replace(old_record_audit, new_record_audit)
else:
    # Use regex
    content = re.sub(
        r'func \(s \*Server\) RecordAudit\(action, actor, resource, details string\) \{.*?\n\}',
        new_record_audit,
        content,
        flags=re.DOTALL
    )

# Fix handleAuditTrail to read from DB instead of memory
old_handle_audit = """func (s *Server) handleAuditTrail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.auditLog)
}"""

new_handle_audit = """func (s *Server) handleAuditTrail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	limit, offset := parsePagination(r)
	
	logs, err := s.db.ListAuditLogs(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list audit logs: %v", err), http.StatusInternalServerError)
		return
	}
	
	json.NewEncoder(w).Encode(logs)
}"""

if old_handle_audit in content:
    content = content.replace(old_handle_audit, new_handle_audit)
else:
    content = re.sub(
        r'func \(s \*Server\) handleAuditTrail\(w http\.ResponseWriter, r \*http\.Request\) \{.*?\n\}',
        new_handle_audit,
        content,
        flags=re.DOTALL
    )

with open("internal/api/server.go", "w") as f:
    f.write(content)

import re

with open("internal/store/db.go", "r") as f:
    content = f.read()

# Add Store interface methods
old_interface = """	GetTicketHistory(ctx context.Context) ([]remediation.TicketHistory, error)
	Migrate(migrationsDir string) error
	Close() error
}"""
new_interface = """	GetTicketHistory(ctx context.Context) ([]remediation.TicketHistory, error)
	SaveAuditLog(ctx context.Context, action, actor, resource, details string) error
	ListAuditLogs(ctx context.Context, limit, offset int) ([]map[string]interface{}, error)
	Migrate(migrationsDir string) error
	Close() error
}"""
content = content.replace(old_interface, new_interface)

# Fix SaveFinding
# Remove the old findingID logic
old_save_start = """	findingID := f.FindingID
	if findingID == "" {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", f.AssetID, f.VulnerabilityID, f.Component)))
		findingID = hex.EncodeToString(h[:])
	}"""
new_save_start = """	findingID := f.FindingID
	if findingID == "" {
		// Use DedupHash to generate a stable finding ID
		if f.DedupHash == "" {
			// Fallback if DedupHash is not set before calling SaveFinding
			f.DedupHash = fmt.Sprintf("%s|%s|%s", f.AssetID, f.VulnerabilityID, f.Component)
		}
		findingID = normalizeUUID(f.DedupHash)
	} else {
		findingID = normalizeUUID(findingID)
	}"""
content = content.replace(old_save_start, new_save_start)

# Change ON CONFLICT (finding_id) to ON CONFLICT (dedup_hash) if that's the unique constraint causing issues, or use finding_id. The audit said: "Cross-run dedup relies solely on the dedup_hash UNIQUE constraint; on collision the row is silently dropped"
# Wait, if finding_id is a UUID, and dedup_hash is UNIQUE, let's use ON CONFLICT (dedup_hash)
content = content.replace("ON CONFLICT (finding_id)", "ON CONFLICT (dedup_hash)")

# Replace the normalizeUUID call in ExecContext since we did it above
content = content.replace("normalizeUUID(findingID), normalizeUUID(f.AssetID),", "findingID, normalizeUUID(f.AssetID),")

# Add AuditLog methods at the end
audit_methods = """
func (s *pgStore) SaveAuditLog(ctx context.Context, action, actor, resource, details string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO audit_logs (action, actor, resource, details) VALUES ($1, $2, $3, $4)", action, actor, resource, details)
	return err
}

func (s *pgStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]map[string]interface{}, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, timestamp, action, actor, resource, details FROM audit_logs ORDER BY timestamp DESC LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var id int
		var ts time.Time
		var action, actor, resource string
		var details *string
		if err := rows.Scan(&id, &ts, &action, &actor, &resource, &details); err != nil {
			continue
		}
		log := map[string]interface{}{
			"id":        id,
			"timestamp": ts,
			"action":    action,
			"actor":     actor,
			"resource":  resource,
		}
		if details != nil {
			log["details"] = *details
		}
		logs = append(logs, log)
	}
	return logs, nil
}
"""
content += audit_methods

with open("internal/store/db.go", "w") as f:
    f.write(content)

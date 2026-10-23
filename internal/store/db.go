package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"tijeri/internal/models"
	"tijeri/internal/remediation"
)

// Store defines the persistent storage layer for Tijeri, abstracting Postgres interactions.
type Store interface {
	SaveFinding(ctx context.Context, f models.Finding) error
	GetFinding(ctx context.Context, id string) (models.Finding, error)
	ListFindings(ctx context.Context, limit, offset int) ([]models.Finding, int, error)
	SaveAnalystFeedback(ctx context.Context, f models.AnalystFeedback) error
	GetAnalystFeedback(ctx context.Context) ([]models.AnalystFeedback, error)
	SaveAsset(ctx context.Context, a models.Asset) error
	GetAsset(ctx context.Context, id string) (models.Asset, error)
	ListAssets(ctx context.Context, limit, offset int) ([]models.Asset, int, error)
	GetVulnerableHosts(ctx context.Context) ([]string, error)
	GetTicketHistory(ctx context.Context) ([]remediation.TicketHistory, error)
	SaveAuditLog(ctx context.Context, action, actor, resource, details string) error
	ListAuditLogs(ctx context.Context, limit, offset int) ([]map[string]interface{}, error)
	Migrate(migrationsDir string) error
	Close() error
}

// Migrate applies pending .sql migrations against the underlying database.
func (s *pgStore) Migrate(migrationsDir string) error {
	return RunMigrations(s.db, migrationsDir)
}

type pgStore struct {
	db *sql.DB
}

// NewPostgresStore establishes a connection to Postgres.
func NewPostgresStore(dsn string) (Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &pgStore{db: db}, nil
}

func (s *pgStore) Close() error {
	return s.db.Close()
}

func (s *pgStore) SaveFinding(ctx context.Context, f models.Finding) error {
	// Findings produced by adapters may not carry an explicit FindingID; derive
	// a stable one from the dedup hash so each unique finding gets its own row
	// instead of every empty ID colliding on the SHA1-of-"" UUID.
	findingID := f.FindingID
	if findingID == "" {
		// Use DedupHash to generate a stable finding ID
		if f.DedupHash == "" {
			// Fallback if DedupHash is not set before calling SaveFinding
			f.DedupHash = fmt.Sprintf("%s|%s|%s", f.AssetID, f.VulnerabilityID, f.Component)
		}
		findingID = normalizeUUID(f.DedupHash)
	} else {
		findingID = normalizeUUID(findingID)
	}

	query := `
		INSERT INTO findings (
			finding_id, asset_id, source_tool, vulnerability_id, component, component_version,
			cvss_score, cvss_version, cvss_vector, cvss_source, nvd_enrichment_status,
			epss_score, epss_percentile, kev_listed, ssvc, vex_status, vex_justification,
			first_seen, last_seen, status, dedup_hash
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
		)
		ON CONFLICT (dedup_hash) DO UPDATE SET
			cvss_score = EXCLUDED.cvss_score,
			cvss_version = EXCLUDED.cvss_version,
			cvss_vector = EXCLUDED.cvss_vector,
			nvd_enrichment_status = EXCLUDED.nvd_enrichment_status,
			epss_score = EXCLUDED.epss_score,
			epss_percentile = EXCLUDED.epss_percentile,
			kev_listed = EXCLUDED.kev_listed,
			ssvc = EXCLUDED.ssvc,
			vex_status = EXCLUDED.vex_status,
			vex_justification = EXCLUDED.vex_justification,
			last_seen = EXCLUDED.last_seen,
			status = EXCLUDED.status,
			dedup_hash = EXCLUDED.dedup_hash;
	`

	var cvssScore *float64
	var cvssVersion *string
	var cvssVector *string
	var cvssSource *string
	if f.CVSS != nil {
		cvssScore = &f.CVSS.Score
		cvssVersion = &f.CVSS.Version
		cvssVector = &f.CVSS.Vector
		cvssSource = f.CVSS.Source
	}

	var epssScore *float64
	var epssPercentile *float64
	if f.EPSS != nil {
		epssScore = &f.EPSS.Score
		epssPercentile = &f.EPSS.Percentile
	}

	nvdStatus := f.NVDEnrichmentStatus
	if nvdStatus == "" {
		nvdStatus = "pending"
	}

	_, err := s.db.ExecContext(ctx, query,
		findingID, normalizeUUID(f.AssetID), f.SourceTool, f.VulnerabilityID, f.Component, f.ComponentVersion,
		cvssScore, cvssVersion, cvssVector, cvssSource, nvdStatus,
		epssScore, epssPercentile, f.KEVListed, f.SSVC, f.VEXStatus, f.VEXJustification,
		f.FirstSeen, f.LastSeen, f.Status, f.DedupHash,
	)

	if err != nil {
		return fmt.Errorf("failed to save finding: %w", err)
	}
	return nil
}

func (s *pgStore) GetFinding(ctx context.Context, id string) (models.Finding, error) {
	query := `
		SELECT finding_id, asset_id, source_tool, vulnerability_id, component, component_version,
		cvss_score, cvss_version, cvss_vector, cvss_source, nvd_enrichment_status,
		epss_score, epss_percentile, kev_listed, ssvc, vex_status, vex_justification,
		first_seen, last_seen, status, dedup_hash
		FROM findings WHERE finding_id = $1
	`

	var f models.Finding
	var cvssScore *float64
	var cvssVersion *string
	var cvssVector *string
	var cvssSource *string
	var epssScore *float64
	var epssPercentile *float64

	row := s.db.QueryRowContext(ctx, query, normalizeUUID(id))

	err := row.Scan(
		&f.FindingID, &f.AssetID, &f.SourceTool, &f.VulnerabilityID, &f.Component, &f.ComponentVersion,
		&cvssScore, &cvssVersion, &cvssVector, &cvssSource, &f.NVDEnrichmentStatus,
		&epssScore, &epssPercentile, &f.KEVListed, &f.SSVC, &f.VEXStatus, &f.VEXJustification,
		&f.FirstSeen, &f.LastSeen, &f.Status, &f.DedupHash,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return models.Finding{}, fmt.Errorf("finding not found")
		}
		return models.Finding{}, fmt.Errorf("failed to scan finding: %w", err)
	}

	if cvssScore != nil {
		f.CVSS = &models.CVSS{
			Score:   *cvssScore,
			Version: *cvssVersion,
			Vector:  *cvssVector,
			Source:  cvssSource,
		}
	}
	if epssScore != nil {
		f.EPSS = &models.EPSS{
			Score:      *epssScore,
			Percentile: *epssPercentile,
		}
	}

	return f, nil
}

func (s *pgStore) ListFindings(ctx context.Context, limit, offset int) ([]models.Finding, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	var total int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings").Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count findings: %w", err)
	}

	query := `
		SELECT finding_id, asset_id, source_tool, vulnerability_id, component, component_version,
		cvss_score, cvss_version, cvss_vector, cvss_source, nvd_enrichment_status,
		epss_score, epss_percentile, kev_listed, ssvc, vex_status, vex_justification,
		first_seen, last_seen, status, dedup_hash
		FROM findings
		ORDER BY last_seen DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		var cvssScore *float64
		var cvssVersion *string
		var cvssVector *string
		var cvssSource *string
		var epssScore *float64
		var epssPercentile *float64

		if err := rows.Scan(
			&f.FindingID, &f.AssetID, &f.SourceTool, &f.VulnerabilityID, &f.Component, &f.ComponentVersion,
			&cvssScore, &cvssVersion, &cvssVector, &cvssSource, &f.NVDEnrichmentStatus,
			&epssScore, &epssPercentile, &f.KEVListed, &f.SSVC, &f.VEXStatus, &f.VEXJustification,
			&f.FirstSeen, &f.LastSeen, &f.Status, &f.DedupHash,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan finding row: %w", err)
		}
		if cvssScore != nil {
			f.CVSS = &models.CVSS{Score: *cvssScore, Version: *cvssVersion, Vector: *cvssVector, Source: cvssSource}
		}
		if epssScore != nil {
			f.EPSS = &models.EPSS{Score: *epssScore, Percentile: *epssPercentile}
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return findings, total, nil
}

func (s *pgStore) SaveAnalystFeedback(ctx context.Context, f models.AnalystFeedback) error {
	query := `
		INSERT INTO analyst_feedback (
			feedback_id, finding_id, analyst_id, feedback_type, override_value, recorded_at, source
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)
		ON CONFLICT (feedback_id) DO NOTHING;
	`
	_, err := s.db.ExecContext(ctx, query,
		f.FeedbackID, f.FindingID, f.AnalystID, f.FeedbackType, f.OverrideValue, f.RecordedAt, f.Source,
	)
	if err != nil {
		return fmt.Errorf("failed to save analyst feedback: %w", err)
	}
	return nil
}

func (s *pgStore) GetAnalystFeedback(ctx context.Context) ([]models.AnalystFeedback, error) {
	query := `
		SELECT feedback_id, finding_id, analyst_id, feedback_type, override_value, recorded_at, source
		FROM analyst_feedback
		ORDER BY recorded_at ASC;
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query analyst feedback: %w", err)
	}
	defer rows.Close()

	var results []models.AnalystFeedback
	for rows.Next() {
		var f models.AnalystFeedback
		err := rows.Scan(
			&f.FeedbackID, &f.FindingID, &f.AnalystID,
			&f.FeedbackType, &f.OverrideValue, &f.RecordedAt, &f.Source,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan feedback row: %w", err)
		}
		results = append(results, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func (s *pgStore) SaveAsset(ctx context.Context, a models.Asset) error {
	query := `
		INSERT INTO assets (asset_id, canonical_name, criticality_tier, exposure, state, asset_type, metadata, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (asset_id) DO UPDATE SET
			canonical_name = EXCLUDED.canonical_name,
			criticality_tier = EXCLUDED.criticality_tier,
			exposure = EXCLUDED.exposure,
			state = EXCLUDED.state,
			asset_type = EXCLUDED.asset_type,
			metadata = EXCLUDED.metadata,
			last_seen = EXCLUDED.last_seen;
	`
	now := time.Now()

	metaJSON := "{}"
	if a.Metadata != nil {
		metaBytes, err := json.Marshal(a.Metadata)
		if err == nil {
			metaJSON = string(metaBytes)
		}
	}

	_, err := s.db.ExecContext(ctx, query,
		normalizeUUID(a.AssetID), a.CanonicalName, a.CriticalityTier, a.Exposure, a.State,
		a.Type, metaJSON, now, now,
	)
	if err != nil {
		return fmt.Errorf("failed to save asset: %w", err)
	}
	return nil
}

func (s *pgStore) GetAsset(ctx context.Context, id string) (models.Asset, error) {
	query := `
		SELECT asset_id, canonical_name, criticality_tier, exposure, state, asset_type, metadata
		FROM assets WHERE asset_id = $1
	`
	var a models.Asset
	var metaBytes []byte
	err := s.db.QueryRowContext(ctx, query, normalizeUUID(id)).Scan(
		&a.AssetID, &a.CanonicalName, &a.CriticalityTier, &a.Exposure, &a.State, &a.Type, &metaBytes,
	)
	if len(metaBytes) > 0 && string(metaBytes) != "null" {
		var meta map[string]string
		if err2 := json.Unmarshal(metaBytes, &meta); err2 == nil {
			a.Metadata = meta
		}
	}
	if err != nil {
		if err == sql.ErrNoRows {
			return models.Asset{}, fmt.Errorf("asset not found")
		}
		return models.Asset{}, fmt.Errorf("failed to get asset: %w", err)
	}
	return a, nil
}

func (s *pgStore) ListAssets(ctx context.Context, limit, offset int) ([]models.Asset, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	var total int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM assets").Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count assets: %w", err)
	}

	query := `
		SELECT asset_id, canonical_name, criticality_tier, exposure, state, asset_type, metadata
		FROM assets
		ORDER BY last_seen DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query assets: %w", err)
	}
	defer rows.Close()

	var assets []models.Asset
	for rows.Next() {
		var a models.Asset
		var metaBytes []byte
		if err := rows.Scan(&a.AssetID, &a.CanonicalName, &a.CriticalityTier, &a.Exposure, &a.State, &a.Type, &metaBytes); err != nil {
			return nil, 0, fmt.Errorf("failed to scan asset row: %w", err)
		}
		if len(metaBytes) > 0 && string(metaBytes) != "null" {
			var meta map[string]string
			if err := json.Unmarshal(metaBytes, &meta); err == nil {
				a.Metadata = meta
			}
		}
		assets = append(assets, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return assets, total, nil
}

func (s *pgStore) GetVulnerableHosts(ctx context.Context) ([]string, error) {
	query := `
		SELECT DISTINCT a.canonical_name
		FROM assets a
		JOIN findings f ON a.asset_id = f.asset_id
		WHERE f.status = 'open' AND a.asset_type = 'host'
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerable hosts: %w", err)
	}
	defer rows.Close()

	var hosts []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	return hosts, rows.Err()
}

func (s *pgStore) GetTicketHistory(ctx context.Context) ([]remediation.TicketHistory, error) {
	query := `
		SELECT ticket_id, COALESCE(bod_tier, 90), created_at, resolved_at, sla
		FROM tickets
		ORDER BY created_at DESC
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()

	var history []remediation.TicketHistory
	for rows.Next() {
		var t remediation.TicketHistory
		if err := rows.Scan(&t.TicketID, &t.BODTier, &t.CreatedAt, &t.ResolvedAt, &t.SLA); err != nil {
			return nil, err
		}
		history = append(history, t)
	}
	return history, rows.Err()
}

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

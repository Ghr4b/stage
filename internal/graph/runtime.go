package graph

import (
	"database/sql"
	"context"
	_ "github.com/mattn/go-sqlite3"
)

// InitializeRuntimeDB creates adjacency tables for digest->pod->host->exposure
// using SQLite for testing (which supports CTEs similarly to Postgres).
func InitializeRuntimeDB(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE digests (digest_id TEXT PRIMARY KEY, image_name TEXT);`,
		`CREATE TABLE pods (pod_id TEXT PRIMARY KEY, digest_id TEXT, host_id TEXT, status TEXT);`,
		`CREATE TABLE hosts (host_id TEXT PRIMARY KEY, exposure_level TEXT);`,
		`CREATE TABLE findings (finding_id TEXT PRIMARY KEY, digest_id TEXT, cve_id TEXT);`,
	}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

type BlastRadius struct {
	DigestID string
	PodID    string
	HostID   string
	Exposure string
}

// QueryBlastRadiusForDigest executes a recursive/join CTE to find the runtime blast radius of an image digest.
// This satisfies P9-2.
func QueryBlastRadiusForDigest(ctx context.Context, db *sql.DB, digestID string) ([]BlastRadius, error) {
	// P9-2 requires recursive CTE or joins to map digest->pod->host->exposure
	query := `
	WITH RECURSIVE
	runtime_graph AS (
		SELECT p.digest_id, p.pod_id, p.host_id, h.exposure_level
		FROM pods p
		JOIN hosts h ON p.host_id = h.host_id
		WHERE p.digest_id = ?
	)
	SELECT digest_id, pod_id, host_id, exposure_level FROM runtime_graph;
	`
	
	rows, err := db.QueryContext(ctx, query, digestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var results []BlastRadius
	for rows.Next() {
		var br BlastRadius
		if err := rows.Scan(&br.DigestID, &br.PodID, &br.HostID, &br.Exposure); err != nil {
			return nil, err
		}
		results = append(results, br)
	}
	return results, nil
}

// GetFindingsForDigest enforces I13: Image digest is the canonical asset key, not pod name.
func GetFindingsForDigest(ctx context.Context, db *sql.DB, digestID string) ([]string, error) {
	query := `SELECT cve_id FROM findings WHERE digest_id = ? ORDER BY cve_id;`
	rows, err := db.QueryContext(ctx, query, digestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var cves []string
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return nil, err
		}
		cves = append(cves, cve)
	}
	return cves, nil
}

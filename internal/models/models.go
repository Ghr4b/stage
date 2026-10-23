package models

import "time"

type Asset struct {
	AssetID         string
	CanonicalName   string
	Type            string // "host", "repo", "container"
	Metadata        map[string]string // Key-value metadata (e.g., ecosystems, environment)
	CriticalityTier string
	Exposure        string
	State           string
}

type CVSS struct {
	Score   float64 `json:"score"`
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
	Source  *string `json:"source"`
}

type EPSS struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

type Finding struct {
	FindingID           string    `json:"finding_id"`
	AssetID             string    `json:"asset_id"`
	SourceTool          string    `json:"source_tool"`
	VulnerabilityID     string    `json:"vulnerability_id"`
	Component           string    `json:"component"`
	ComponentVersion    string    `json:"component_version"`
	CVSS                *CVSS     `json:"cvss"`
	NVDEnrichmentStatus string    `json:"nvd_enrichment_status"`
	EPSS                *EPSS     `json:"epss"`
	KEVListed           bool      `json:"kev_listed"`
	SSVC                *string   `json:"ssvc"`
	VEXStatus           *string   `json:"vex_status"`
	VEXJustification    *string   `json:"vex_justification"`
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
	Status              string    `json:"status"`
	DedupHash           string    `json:"dedup_hash"`
}

type FindingsBatch struct {
	Findings []Finding
}

type TicketUpdate struct {
	Status string
	Note   string
}

type AnalystFeedback struct {
	FeedbackID    string    `json:"feedback_id"`
	FindingID     string    `json:"finding_id"`
	AnalystID     string    `json:"analyst_id"`
	FeedbackType  string    `json:"feedback_type"`
	OverrideValue string    `json:"override_value"`
	RecordedAt    time.Time `json:"recorded_at"`
	Source        string    `json:"source"`
}


CREATE TABLE assets (
    asset_id UUID PRIMARY KEY,
    canonical_name TEXT NOT NULL,
    criticality_tier TEXT NOT NULL,
    exposure TEXT NOT NULL,
    state TEXT NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE identity_signals (
    signal_id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    signal_type TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence NUMERIC NOT NULL
);

CREATE TABLE findings (
    finding_id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    source_tool TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    component TEXT NOT NULL,
    component_version TEXT NOT NULL,
    cvss_score NUMERIC,
    cvss_version TEXT,
    cvss_vector TEXT,
    cvss_source TEXT,
    nvd_enrichment_status TEXT NOT NULL,
    epss_score NUMERIC,
    epss_percentile NUMERIC,
    kev_listed BOOLEAN NOT NULL DEFAULT FALSE,
    ssvc TEXT,
    vex_status TEXT,
    vex_justification TEXT,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    status TEXT NOT NULL,
    dedup_hash TEXT NOT NULL UNIQUE
);

CREATE TABLE scan_jobs (
    job_id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    adapter TEXT NOT NULL,
    status TEXT NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    findings_count INTEGER,
    error_reason TEXT
);

CREATE TABLE tickets (
    ticket_id UUID PRIMARY KEY,
    finding_id UUID NOT NULL REFERENCES findings(finding_id),
    provider TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE criticality_tags (
    tag_id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    label TEXT NOT NULL,
    source TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL
);

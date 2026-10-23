CREATE TABLE IF NOT EXISTS analyst_feedback (
    feedback_id UUID PRIMARY KEY,
    finding_id UUID NOT NULL REFERENCES findings(finding_id),
    analyst_id TEXT NOT NULL,
    feedback_type TEXT NOT NULL,
    override_value TEXT NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE NOT NULL,
    source TEXT NOT NULL
);

-- Add missing columns to tickets table for risk context
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS bod_tier INTEGER DEFAULT 90;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS sla INTEGER DEFAULT 90;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP WITH TIME ZONE;

-- Make nvd_enrichment_status have a default since adapters don't set it yet
ALTER TABLE findings ALTER COLUMN nvd_enrichment_status SET DEFAULT 'pending';

-- Add type column to assets for the query to filter by host type
ALTER TABLE assets ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'unknown';

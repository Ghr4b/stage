-- 1. Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    resource TEXT NOT NULL,
    details TEXT
);

-- 2. Consolidate assets.type and assets.asset_type
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='assets' AND column_name='asset_type') THEN
        UPDATE assets SET type = asset_type WHERE type IS NULL AND asset_type IS NOT NULL;
        ALTER TABLE assets DROP COLUMN asset_type;
    END IF;
END $$;

-- 3. Add missing indexes
CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
CREATE INDEX IF NOT EXISTS idx_tickets_finding_id ON tickets(finding_id);

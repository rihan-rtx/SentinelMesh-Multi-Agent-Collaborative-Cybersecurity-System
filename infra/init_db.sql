-- ==========================================================================
-- SentinelMesh — PostgreSQL schema initialization (Section 10.9)
-- Runs automatically on first postgres container start.
-- ==========================================================================

CREATE TABLE IF NOT EXISTS detections (
    detection_id UUID PRIMARY KEY,
    flow_id UUID NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    classification TEXT NOT NULL,
    confidence REAL NOT NULL,
    attack_type TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id UUID PRIMARY KEY,
    ts_opened TIMESTAMPTZ NOT NULL,
    ts_updated TIMESTAMPTZ NOT NULL,
    src_ip TEXT,
    incident_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actions (
    action_id UUID PRIMARY KEY,
    incident_id UUID REFERENCES incidents(incident_id),
    ts TIMESTAMPTZ NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT
);

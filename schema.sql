CREATE TABLE IF NOT EXISTS clients (
    client_id   SERIAL PRIMARY KEY,
    client_name TEXT        NOT NULL,
    domain      TEXT,
    api_key     TEXT        NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threats (
    id           SERIAL PRIMARY KEY,
    ip_address   TEXT        NOT NULL,
    threat_level INT         NOT NULL DEFAULT 0,
    description  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id      TEXT,
    client_id    INT REFERENCES clients(client_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id             SERIAL PRIMARY KEY,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at      TIMESTAMPTZ,
    status         TEXT        NOT NULL DEFAULT 'open',
    severity       TEXT,
    detection_type TEXT,
    reason         TEXT,
    src_ip         TEXT,
    dst_ip         TEXT,
    protocol       TEXT,
    src_port       INT,
    dst_port       INT,
    sensor_id      TEXT,
    client_id      INT REFERENCES clients(client_id) ON DELETE SET NULL,
    event_payload  JSONB
);

CREATE TABLE IF NOT EXISTS ip_blocklist (
    id         SERIAL PRIMARY KEY,
    client_id  INT REFERENCES clients(client_id) ON DELETE CASCADE,
    ip_address TEXT        NOT NULL,
    reason     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, ip_address)
);

CREATE TABLE IF NOT EXISTS traffic_events (
    id             SERIAL PRIMARY KEY,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_ts       TIMESTAMPTZ,
    src_ip         TEXT,
    dst_ip         TEXT,
    protocol       TEXT,
    src_port       INT,
    dst_port       INT,
    level          TEXT,
    detection_type TEXT,
    reason         TEXT,
    sensor_id      TEXT,
    src_zone       TEXT,
    dst_zone       TEXT,
    network_scope  TEXT,
    dns            TEXT,
    direction      TEXT,
    event_payload  JSONB
);

CREATE TABLE IF NOT EXISTS network_assets (
    id           SERIAL PRIMARY KEY,
    client_id    INT         NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    ip_address   INET        NOT NULL,
    display_name TEXT,
    notes        TEXT,
    trust_status TEXT        NOT NULL DEFAULT 'unknown',
    last_seen    TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, ip_address)
);

CREATE TABLE IF NOT EXISTS tracked_ips (
    id         SERIAL PRIMARY KEY,
    ip         TEXT        NOT NULL,
    user_agent TEXT,
    client_id  INT REFERENCES clients(client_id) ON DELETE CASCADE,
    page       TEXT,
    timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    log_id    SERIAL PRIMARY KEY,
    action    TEXT        NOT NULL,
    user_id   TEXT,
    target_id INT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_client   ON alerts(client_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created  ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_created ON traffic_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_src     ON traffic_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_dst     ON traffic_events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_threats_client  ON threats(client_id);
CREATE INDEX IF NOT EXISTS idx_tracked_client  ON tracked_ips(client_id);
CREATE INDEX IF NOT EXISTS idx_assets_client   ON network_assets(client_id);
CREATE INDEX IF NOT EXISTS idx_blocklist_ip    ON ip_blocklist(ip_address);

INSERT INTO clients (client_name, domain, api_key)
VALUES ('Default', 'localhost', 'dev-client-key-change-me')
ON CONFLICT (api_key) DO NOTHING;

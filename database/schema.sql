PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'uploaded'
        CHECK (status IN ('uploaded', 'analyzing', 'completed', 'failed')),
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    analyzed_at TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL UNIQUE
        REFERENCES investigations(id) ON DELETE CASCADE,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    uploaded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL UNIQUE
        REFERENCES investigations(id) ON DELETE CASCADE,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL
        REFERENCES investigations(id) ON DELETE CASCADE,
    ioc_type TEXT,
    value TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    raw_json TEXT
);

CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL
        REFERENCES investigations(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    domain TEXT,
    is_suspicious INTEGER NOT NULL DEFAULT 0 CHECK (is_suspicious IN (0, 1)),
    raw_json TEXT
);

CREATE TABLE IF NOT EXISTS ip_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL
        REFERENCES investigations(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    hop_index INTEGER,
    source TEXT,
    raw_json TEXT
);

CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL
        REFERENCES investigations(id) ON DELETE CASCADE,
    filename TEXT,
    content_type TEXT,
    size_bytes INTEGER,
    sha256 TEXT,
    is_suspicious INTEGER NOT NULL DEFAULT 0 CHECK (is_suspicious IN (0, 1)),
    raw_json TEXT
);

CREATE TABLE IF NOT EXISTS suspicious_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL
        REFERENCES investigations(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    reason TEXT,
    raw_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_iocs_investigation ON iocs(investigation_id);
CREATE INDEX IF NOT EXISTS idx_urls_investigation ON urls(investigation_id);
CREATE INDEX IF NOT EXISTS idx_ip_addresses_investigation ON ip_addresses(investigation_id);
CREATE INDEX IF NOT EXISTS idx_attachments_investigation ON attachments(investigation_id);
CREATE INDEX IF NOT EXISTS idx_suspicious_domains_investigation ON suspicious_domains(investigation_id);
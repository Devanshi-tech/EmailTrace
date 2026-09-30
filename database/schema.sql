CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    original_filename TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'uploaded',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    uploaded_at TEXT NOT NULL,
    FOREIGN KEY (investigation_id)
        REFERENCES investigations(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL,
    result_json TEXT NOT NULL,
    analyzed_at TEXT NOT NULL,
    FOREIGN KEY (investigation_id)
        REFERENCES investigations(id)
        ON DELETE CASCADE
);
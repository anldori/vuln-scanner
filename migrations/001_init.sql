-- The `scans` table doubles as the job queue (status = queued -> running -> done|failed).
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    finished_at TEXT,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status, created_at);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    host        TEXT NOT NULL,
    port        INTEGER,
    protocol    TEXT,
    service     TEXT,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    cve         TEXT NOT NULL DEFAULT '[]',
    cvss        REAL,
    epss        REAL,
    kev         INTEGER NOT NULL DEFAULT 0,
    priority    REAL NOT NULL DEFAULT 0,
    evidence    TEXT NOT NULL DEFAULT '',
    tool        TEXT NOT NULL,
    UNIQUE (scan_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL
);

-- Cache of CVE enrichment so repeated scans do not hammer EPSS/NVD.
CREATE TABLE IF NOT EXISTS cve_cache (
    cve        TEXT PRIMARY KEY,
    cvss       REAL,
    epss       REAL,
    kev        INTEGER NOT NULL DEFAULT 0,
    fetched_at TEXT NOT NULL
);

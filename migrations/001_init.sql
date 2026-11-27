-- The `scans` table doubles as the job queue (status = queued -> running -> done|failed).
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    finished_at TEXT,
    error       TEXT,
    -- Deep (authenticated, Vuls) scan. Only non-secret login info is stored; the key lives in memory.
    deep        INTEGER NOT NULL DEFAULT 0,
    ssh_user    TEXT,
    ssh_port    INTEGER,
    ssh_auth    TEXT
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
    fix_available INTEGER,
    vendor_priority TEXT,
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

-- Live progress log of a scan (shown in the web UI). Never contains secrets.
CREATE TABLE IF NOT EXISTS scan_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ts      TEXT NOT NULL,
    level   TEXT NOT NULL,
    phase   TEXT,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_events ON scan_events(scan_id, id);

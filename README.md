# vuln-scanner

A vulnerability scanner written in Rust. It is an **orchestrator**: it runs proven external tools
(RustScan, nuclei, Vuls), normalizes their output into one finding model, enriches CVEs with
NVD / EPSS / CISA KEV data, ranks findings by risk, and shows everything in a small web UI with
exportable reports.

> **Use it only on systems you own or are explicitly authorized to test.**

## Features

- **Basic scan** – open ports and services (RustScan + banner grabbing), web checks (nuclei).
- **Deep scan** – logs in over SSH and matches installed OS packages against the Vuls vulnerability
  database. Supports private keys, encrypted keys (passphrase) and passwords.
- **Connection check phase** – a deep scan first verifies the SSH login and reports clearly why it
  failed (wrong credentials, connection refused, timeout) before doing any work.
- **Several hosts at once** – paste a list of hosts; each becomes its own scan.
- **Live progress** – a phase stepper (check connection → vulnerability scan → network scan →
  enrich → save) and a streaming log with heartbeats, so a long scan never looks stuck.
- **Risk-based priority (0–100)** – CVSS 50 % + EPSS 30 % + CISA KEV 20 %. KEV membership raises a
  finding to at least *High*.
- **Noise control** – "Hide unfixed" filter for vulnerabilities that have no vendor fix yet.
- **Reports** – HTML, JSON and CSV.
- **Scan history** – findings carry a stable fingerprint (host, port, vulnerability id) so scans
  can be compared over time.

## Architecture

```
crates/core/      domain model (Target, Scan, Finding, Severity), Scanner trait, scope checks, SSH credential type
crates/scanners/  plugins: rustscan, portscan (pure Rust), nmap (optional), nuclei, vuls
crates/enrich/    EPSS + CISA KEV + NVD CVSS lookups (only CVE ids leave the machine)
crates/server/    axum web UI + JSON API, SQLite (sqlx), background worker
crates/report/    HTML / JSON / CSV rendering
migrations/       SQLite schema (applied at startup)
```

- The `scans` table doubles as the job queue (`queued → running → done | failed`); there is no Redis.
- External tools are run with `tokio::process`, argument arrays (never a shell) and hard timeouts.
- Enrichment is best effort: a failure becomes a warning on the scan, never a failed scan.

## Quick start

Linux or macOS (x86_64 / arm64). The installer needs `curl`, a C compiler and `unzip` or `python3`.

```bash
./install.sh            # installs Rust, RustScan, Vuls, nuclei (+ templates), builds, starts the portal
```

Then open <http://127.0.0.1:8080>.

Useful installer options:

| Option | Meaning |
|---|---|
| `--scope VALUE` | Scope for the server (default: `any`, see [Security](#security-model)) |
| `--no-run` | Install only, do not start the portal |
| `--no-vuls` | Skip Vuls (deep scan) |
| `--no-rustscan`, `--no-nuclei`, `--no-rust` | Skip those components |
| `--with-nmap` | Also install nmap (optional scanner) |
| `--check`, `--dry-run` | Show what is installed / what would be done |

Manual run (after installing the tools yourself):

```bash
cargo run --release -p vs-server
```

## Using the web UI

1. Click **+ New scan**.
2. Enter one or more hosts (IP, hostname or CIDR – one per line or comma separated).
3. Choose **Basic** or **Deep**. For Deep, enter the SSH user, port and a private key (plus
   passphrase if it is encrypted) or a password.
4. Open a scan to follow its phases and log; findings appear when it finishes.

Deep scans work on single hosts only (no CIDR). The first deep scan downloads the Vuls
vulnerability database (about 15 GB).

## Configuration

All configuration is through environment variables.

| Variable | Default | Description |
|---|---|---|
| `BIND` | `127.0.0.1:8080` | Listen address. Deep scan is only offered on a loopback address. |
| `DATABASE_URL` | `sqlite://vuln-scanner.db` | SQLite database |
| `SCOPE` | `127.0.0.0/8,::1` | Allowed targets: comma-separated IPs, CIDRs, hostnames, or `any` |
| `SCANNERS` | `rustscan,nuclei` | Scanner plugins, in order: `rustscan`, `portscan`, `nmap`, `nuclei` |
| `PORTS` | all 65535 (rustscan) | Port list/ranges, e.g. `22,80,8000-8100` |
| `RUSTSCAN_BIN`, `NUCLEI_BIN`, `NMAP_BIN` | binary names | Paths to the tools |
| `NMAP_SCRIPTS` | – | Extra nmap scripts, e.g. `vulners` (**sends banners to vulners.com**, opt-in) |
| `VULS_BIN` | `vuls` | Path to Vuls |
| `VULS_DB` | `~/.local/share/vuln-scanner/vuls.db` | Vuls vulnerability database (~15 GB) |
| `VULS_SKIP_DB_UPDATE` | – | `1` skips the database update check on every deep scan |
| `ENRICH` | on | `0` disables enrichment (offline use) |
| `NVD_API_KEY` | – | Raises the NVD rate limit |

Scanner notes:

- `rustscan` (default) finds open ports on all 65535 ports, then banner-probes each open port
  for service and version.
- `portscan` is a pure-Rust TCP connect scanner (about 130 common ports) that needs no external tool.
- `nmap` is optional and kept for `-sV` and NSE scripts.

## Security model

- **Scope allowlist** – only targets inside `SCOPE` can be scanned; everything else is rejected, both
  when the scan is submitted and again when the worker runs it. The server's own default is
  loopback only. `install.sh` starts the portal with `SCOPE=any`; pass `--scope` to restrict it.
- **Input validation** – targets must be an IP, CIDR or hostname and may not start with `-`;
  they are passed to external tools as separate arguments, never through a shell.
- **Credentials stay in memory** – SSH passwords, keys and passphrases are never written to the
  database, logs or audit trail (the audit log records only user, port and auth method). They are
  wiped from memory when the scan ends. Temporary key files are mode 0600 in a private temp
  directory that is deleted even on errors or timeouts. If the server restarts, queued deep scans
  fail and must be submitted again.
- **Deep scan only on loopback** – because the UI has no login yet, deep scan is disabled when
  `BIND` is not a loopback address.
- **Audit log** – every scan is recorded.
- **Data leaving the machine** – enrichment sends only CVE ids to EPSS, NVD and the CISA KEV
  mirror. Vuls downloads its database from GitHub Container Registry.
- **No authentication yet** – do not expose the web UI to untrusted networks.

## Development

```bash
cargo build
cargo test
cargo clippy --all-targets
cargo test -p vs-scanners -- --ignored   # live test; needs the rustscan binary
```

Parser tests use fixtures in `crates/scanners/tests/fixtures/`. The database schema is pre-release:
`migrations/001_init.sql` is edited in place, so delete old dev databases (`rm *.db`) after pulling
schema changes.

## Roadmap

- Login / authentication and RBAC for the web UI
- Scheduled scans and diffs between scans
- PDF and SARIF reports
- Trivy for library scanning
- Per-host credentials in one submission
- Opt-in exploit verification (explicit confirmation, audited)

See `PROGRESS.md` for detailed status.

## License

No license has been chosen yet.

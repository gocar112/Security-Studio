# Security Studio

<p align="center">
  <img src="assets/security-studio-icon.png" alt="Security Studio logo" width="140">
</p>

<p align="center">
  <strong>A local testing and defense signal room for YARA detections, IOC pivots, CVE context, triage, and guarded remediation.</strong>
</p>

![Security Studio dashboard overview](docs/images/dashboard.png)

Security Studio is a local defensive tool arena. It watches local folders,
scans files against **1,500 YARA rules**,
correlates detections with authentication telemetry, extracts indicators,
enriches CVE findings with NVD/CISA context, and streams everything into a live
browser dashboard.

## Included In This Release

- Updated Security Studio README and operator quick start.
- Live dashboard and localhost API.
- Security Studio logo and Windows desktop icons.
- Security books, home-defense guidance, and printable field guide.
- Exactly **1,500 compiled YARA rules**: 73 hand-written detection rules and
  1,427 generated rules derived from CISA Known Exploited Vulnerabilities.
- Smoke, API, frontend-wiring, and GitHub Actions checks.

Regenerate the exact rule count from current NVD data with:

```powershell
python generate_rules.py --total-rules 1500
```

Generated candidates must compile and must not fire on the repository's benign
test corpus. The count is a release target, not a reason to bypass those gates.

## Security Studio Books

<p align="center">
  <img src="assets/security-studio.png" alt="Security Studio shield, radar, and secured hangar artwork" width="460">
</p>

| Book | Use it for |
| --- | --- |
| [Security Studio Operator Guide](book/Security-Studio-Operator-Guide.md) | Running the console, investigating findings, and using guarded remediation. |
| [Home SOC Defense Guide](book/Home-SOC-Defense-Guide.md) | Building a practical layered security system for home users. |
| [Read-Only Briefing Guide](book/Security-Studio-Read-Only-Briefing.md) | Sharing local security visibility without granting control access. |
| [Detection Engineering in Practice](book/Detection-Engineering-in-Practice.pdf) | A printable field guide in PDF format. |

## Quick Links

- Operator guide: [book/Security-Studio-Operator-Guide.md](book/Security-Studio-Operator-Guide.md)
- Home SOC defense book: [book/Home-SOC-Defense-Guide.md](book/Home-SOC-Defense-Guide.md)
- Home security quickstart: [docs/Home-User-Security-System-Quickstart.md](docs/Home-User-Security-System-Quickstart.md)
- Detection engineering field guide: [book/Detection-Engineering-in-Practice.pdf](book/Detection-Engineering-in-Practice.pdf)
- Database summary: [docs/database-summary.md](docs/database-summary.md)
- ML scanner reference review: [docs/ML-Vulnerability-Scanner-Reference-Review.md](docs/ML-Vulnerability-Scanner-Reference-Review.md)
- Main dashboard screenshot: [docs/images/dashboard.png](docs/images/dashboard.png)
- Read-only security briefing: [open locally at `/briefing`](http://127.0.0.1:8900/briefing)
- API key setup: [open locally at `/settings`](http://127.0.0.1:8900/settings)

## At A Glance

| Capability | What it does |
| --- | --- |
| Detect | Scans files with 1,500 YARA rules across malware, web shell, ransomware, credential theft, C2, supply-chain, Linux, Windows, and vulnerable-component namespaces. |
| Correlate | Pulls nearby failed-logon telemetry from Windows Security log, macOS unified log, Linux auth logs, or journald. |
| Pivot | Extracts URLs, domains, IPs, wallets, CVEs, hashes, registry keys, and file paths; dashboard values are defanged. |
| Enrich | Uses NVD, OSV, CISA KEV, and optional VirusTotal hash lookups for context. |
| Triage | Acknowledge, resolve, mark false positive, reopen, and clear dashboard lines with backup. |
| Remediate | Quarantine, restore, delete, and purge detection targets behind hash checks, path confinement, and an audit trail. |
| Observe | Shows server requests, detection behavior, remediation outcomes, and local firewall events when OS logging is enabled. |

## Quick Start

```powershell
python run.py
```

Then open:

```text
http://127.0.0.1:8900
```

The server is built on Python's standard `http.server`, and the dashboard is
plain HTML/CSS/JS. There is no frontend build step.

The first screen is the **Tool Arena**. Use it to open the Detection Console,
read-only Briefing, local API Key Setup, and operator guides without mixing
their privileges.

Fresh machine setup:

```powershell
pip install -r requirements.txt
python run.py
```

Recommended verification before release:

```powershell
python -m compileall securitysuite tools
node --check web\app.js
python tools\summarize_database.py
```

## Requirements

| Package | Status | Needed for |
| --- | --- | --- |
| `yara-python` | Required | YARA compile and scan engine |
| `certifi` | Recommended | Current CA bundle for NVD TLS requests |
| `pywin32` | Optional, Windows only | Windows Security event-log telemetry |

Python 3.10 or newer is recommended.

## Optional API Keys

Open `http://127.0.0.1:8900/settings` and paste an NVD or VirusTotal key. The
form saves supported keys to the local, git-ignored `.env` file and activates
them immediately. Saved values are never returned to the browser.

- **NVD:** optional; raises the CVE API rate limit.
- **VirusTotal:** optional; enables file-hash reputation lookups. Files are
  never uploaded.
- Use **Clear fields** to erase unsaved text without removing stored keys.
- Select **Remove saved key** and save to remove a configured key.

For unattended installation, the equivalent file is:

```dotenv
NVD_API_KEY=replace_with_your_key
VIRUSTOTAL_API_KEY=replace_with_your_key
```

Never commit `.env` or expose the local control plane to the internet. GitHub
hosts the source code and guides; the running security service remains bound to
`127.0.0.1` unless authentication and TLS are added by the operator.

## How To Use It

### 1. Start The Console

```powershell
python run.py
```

The console prints the loaded rule count, watched folders, telemetry source, and
whether auto-remediation is armed.

### 2. Drop A Test File

```powershell
copy samples\README_RESTORE.txt SecurityDrop\
```

On macOS or Linux:

```bash
cp samples/README_RESTORE.txt SecurityDrop/
```

The finding should appear in the dashboard within a few seconds.

![Findings table](docs/images/findings.png)

### 3. Open The Finding

Click the row to inspect the detection.

The drawer shows:

- Verdict, severity, and trigger.
- File path, SHA-256, size, entropy, and target state.
- Every matched rule and matched string offset.
- CVE, KEV, and patch guidance when available.
- Extracted indicators.
- Triage and remediation actions.

![Finding detail drawer](docs/images/finding-drawer.png)

### 4. Pivot Indicators

The indicator panel aggregates observables across all detected files.

![Extracted indicators](docs/images/indicators.png)

Use **Export CSV** when you want to hand the observable set to a SIEM or ticket.

### 5. Prioritize A Vulnerability

Use **Risk recommendation** to score verified vulnerability evidence. The form
accepts a vulnerability type, impact, affected device, exposure, CVSS, and
optional CVE, package URL, or SHA-256. Identifier fields request NVD, OSV, or
VirusTotal context when the matching adapter is available.

The score is an explainable deterministic estimate. It is not proof that a
vulnerability exists and is not presented as a machine-learning probability.

### 6. Remediate Carefully

![Remediation panel](docs/images/remediation-panel.png)

Use **Quarantine** first when evidence might matter. Use **Delete** only when
the file is confirmed malicious or disposable.

## Remediation Safety

Remediation is the destructive part of the suite. Everything else is read-first.

| Action | Meaning | Reversible? |
| --- | --- | --- |
| `quarantine` | Move the detected file into quarantine with metadata. | Yes |
| `restore` | Move a quarantined file back to its original path. | Usually |
| `delete` | Permanently remove the detected file. | No |
| `purge` | Permanently remove a quarantined copy. | No |

A remediation action proceeds only when the safety rails pass:

1. Target path comes from the stored finding, not from the browser request.
2. SHA-256 is re-checked immediately before action.
3. Resolved path must stay inside permitted roots.
4. Suite-owned paths are refused.
5. Directories are refused unless explicitly allowed.
6. Confirmation is required.
7. Already-handled targets are refused.
8. Attempts and refusals are written to the audit trail.

Auto-remediation is off by default. If enabled, the default action should remain
`quarantine`, not delete.

### Why rail 4 exists

Pointed at this repository, the current ruleset flags **27 of 55 tracked files,
16 of them critical** — including `rules/c2_network.yar` and
`rules/credential_theft.yar`. A rule that hunts for `sekurlsa::logonpasswords`
necessarily contains that string. Without the suite-owned-path rail, an
auto-delete-at-critical run would delete the detector's own ruleset.

An earlier version of that rail listed protected directories instead of
protecting the tree, and a test deleted this README. Enumerating what to protect
produces a list that is never complete.

> **Expect false positives.** 1,500 rules, 1,427 of them generated and never run
> against your data. One rule in this repo raised *critical* on a reading list
> containing the word *Exodus*. Prefer `quarantine` until a rule has earned your
> trust; `delete` cannot be undone.

## Clear Lines

**Clear lines** resets the active dashboard stream after backing it up.

It clears:

- `data/findings.ndjson`
- `data/triage.json`
- the live dashboard table/feed state

It does not clear:

- watched files
- quarantined files
- YARA rules
- Git history
- secrets or environment variables

Backups are written under:

```text
data/log-backups/
```

## Samples

Each sample is harmless text and is designed to trip one rule.

| Sample | Rule | Severity |
| --- | --- | --- |
| `README_RESTORE.txt` | `Ransom_Note_Template` | critical |
| `cleanup_commands.txt` | `Defense_Evasion_Commands` | critical |
| `dump_notes.txt` | `Credential_Dumper_Indicators` | critical |
| `task_setup.log` | `PowerShell_Encoded_Command` | high |
| `update_helper.txt` | `PowerShell_Download_Cradle` | high |
| `mail_body.txt` | `Suspicious_Double_Extension` | medium |
| `report_q3.txt` | clean scan | none |

## Intelligence And Database

The source lattice separates live adapters from reference links.

| Source | Credential | Purpose |
| --- | --- | --- |
| NVD | Optional | CVE lookup, keyword search, modification-window sync |
| OSV | None | Commit, package, version, and purl vulnerability lookup |
| VirusTotal | Required | Hash reputation; no file upload |
| CISA KEV | None | Known exploited vulnerability context |
| GitHub Advisories | None | Reference link |
| Vuls | None | Reference link |

Summarize the local database:

```powershell
python tools\summarize_database.py
```

Sync a trailing NVD window while the server is running:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8900/api/nvd/sync -ContentType "application/json" -Body '{"days":3}'
```

## CLI

```powershell
python run.py
python run.py --watch D:\ftp --watch E:\inbox
python run.py --port 9000 --no-browser
python run.py --scan .\uploads
python run.py --headless
python run.py --scan-existing
```

## Configuration

Defaults live in [securitysuite/config.py](securitysuite/config.py). To override
them, create `config.json` in the project root.

```json
{
  "watch_paths": ["SecurityDrop"],
  "recursive": true,
  "poll_interval": 2.0,
  "settle_seconds": 1.0,
  "max_file_mb": 64,
  "lookback_minutes": 5,
  "host": "127.0.0.1",
  "port": 8900,
  "auto_remediate": true,
  "auto_remediate_severity": "critical",
  "auto_remediate_action": "quarantine"
}
```

Watch `Downloads` only if you understand that normal installers may trigger.
The default `SecurityDrop` folder is safer: copy only suspicious files into it.
Automatic remediation is armed for critical detections and uses quarantine;
permanent deletion remains a manual, confirmed action. Use **Clear lines** after
a test run to reset the active room while retaining the remediation audit.

## API Snapshot

All endpoints are intended for localhost use. The server rejects non-loopback
`Host` headers.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/state` | Current stats, monitor status, engine info, telemetry, config |
| GET | `/api/logs` | Behavior counters, recent server requests, and local firewall events |
| GET | `/api/model` | Risk model mode, fields, and score meaning |
| POST | `/api/model/predict` | Explainable risk recommendation with optional NVD/OSV/VT context |
| GET | `/api/findings` | Filtered findings |
| POST | `/api/findings/clear` | Back up and clear active dashboard lines |
| GET | `/api/rules` | Loaded rules and compile errors |
| POST | `/api/rules/reload` | Recompile the YARA ruleset |
| POST | `/api/scan` | Scan a file or directory |
| POST | `/api/monitor` | Pause or resume monitoring |
| POST | `/api/triage` | Acknowledge, resolve, false-positive, or reopen a finding |
| GET | `/api/iocs` | Extracted indicators, JSON or CSV |
| GET | `/api/remediate` | Remediation status and recent actions |
| GET | `/api/remediate/guidance` | Guidance for a finding |
| POST | `/api/remediate` | Quarantine, restore, delete, or purge one finding |
| POST | `/api/remediate/bulk` | Preview or execute bulk remediation |
| GET | `/api/nvd` | NVD cache status |
| POST | `/api/nvd/sync` | Sync a trailing NVD modification window |
| GET / POST | `/api/osv/query` | OSV lookup |
| GET | `/api/vt/file` | VirusTotal hash reputation |
| GET | `/api/stream` | Server-Sent Events stream |

## Project Layout

```text
run.py                         launcher
config.json                    optional local overrides
securitysuite/                 scanner, store, server, APIs
rules/                         YARA rules
rules/generated/               generated vulnerable-component rules
samples/                       harmless test files
uploads/                       optional legacy watched folder
SecurityDrop/                  default suspicious-file drop zone
web/                           dashboard HTML/CSS/JS
assets/                        app logo and desktop icon
book/                          operator and field-guide documentation
book/Home-SOC-Defense-Guide.md home-user defense strategy book
docs/images/                   README screenshots
docs/Home-User-Security-System-Quickstart.md  home security checklist
docs/ML-Vulnerability-Scanner-Reference-Review.md  external prototype assessment
docs/database-summary.md       generated local database summary
data/findings.ndjson           active finding log
data/triage.json               active triage state
data/remediation.json          remediation audit/state
data/log-backups/              Clear lines backups
quarantine/                    quarantined files and metadata
nvds/                          local NVD cache
```

## Documentation

Use the README for setup and release checks. Use the operator guide for daily
workflow:

- [Security Studio Operator Guide](book/Security-Studio-Operator-Guide.md)
- [Security Studio Read-Only Briefing Guide](book/Security-Studio-Read-Only-Briefing.md)
- [Home SOC Defense Guide](book/Home-SOC-Defense-Guide.md)
- [Home User Security System Quickstart](docs/Home-User-Security-System-Quickstart.md)
- [Detection Engineering In Practice PDF](book/Detection-Engineering-in-Practice.pdf)
- [Detection Engineering In Practice DOCX](book/Detection-Engineering-in-Practice.docx)

## Security Notes

- Keep the server bound to `127.0.0.1` unless you add authentication.
- Run as Administrator on Windows only if you need Security event-log telemetry.
- Never paste API keys, GitHub tokens, passwords, or private keys into commits,
  issues, README files, or chat.
- This client never uploads files to VirusTotal. Hash reputation is lookup-only.
- Critical detections in `SecurityDrop` are auto-quarantined by default; delete
  remains manual and confirmed. Test rules against your own data before adding
  any broader remediation root.

## What Changed From `YARA_scanning.py`

| Original | Security Studio |
| --- | --- |
| One directory, non-recursive scan loop | Recursive watcher with settle checks |
| Rule compile failure could hide behind fallback behavior | Compile errors are surfaced by rule file |
| Rule matches were just names | Full rule metadata, strings, offsets, severity, and namespace |
| No file identity | SHA-256, size, mtime, entropy, and target state |
| Own logs could be rescanned | Suite output and protected paths are excluded |
| No pause or reload | Pause/resume monitor and hot-reload rules |
| Print/log output | Live dashboard, triage workflow, IOC panel, JSON API |
| Detection only | Guarded quarantine, restore, delete, purge, and clear lines |

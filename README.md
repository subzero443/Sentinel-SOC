# Sentinel SOC — Threat Detection & Incident Response Lab

A **local, educational** cybersecurity portfolio project: FastAPI + SQLite backend, React/Vite frontend, Framer Motion animations, Recharts, and Sigma-style YAML detection metadata with an explicit **custom correlation extension**.

![Status](https://img.shields.io/badge/status-educational_portfolio_demo-44dccb) ![Python](https://img.shields.io/badge/Python-3.10%2B-blue)

# Screenshots
<img src="Screenshot 2026-10-12 174820.png">
<img src="Screenshot 2026-10-12 174834.png">
<img src="Screenshot 2026-10-12 174849.png">
<img src="Screenshot 2026-10-12 174910.png">
<img src="Screenshot 2026-10-12 173548.png">
<img src="Screenshot 2026-10-12 174656.png">

## Live portfolio deployment

To deploy the safe, read-only demonstration to Render's free web hosting,
follow [DEPLOY_RENDER.md](DEPLOY_RENDER.md). The Dockerfile serves React and FastAPI
on one URL and automatically seeds fictional incidents after a restart.
**Do not deploy the interactive local-only version directly to the internet.**

## Features
- Responsive dark command-center dashboard with animated threat radar, counters, activity chart and incident drawer.
- Normalized authentication events; limited import of Linux `auth.log` SSH lines and Windows 4624/4625 JSON exports, plus normalized JSON arrays.
- Detect >=5 failures from the same IP within 10 minutes, and a successful sign-in after >=3 failures within 15 minutes.
- Incident status workflow (open, investigating, resolved, false positive), analyst notes, downloadable Markdown incident report.
- Repeatable demo seed and reset; pytest detection and false-positive tests.

## Requirements
- Python 3.10+ (Python 3.11 or 3.12 recommended)
- Node.js 20+ and npm
- Windows PowerShell or VS Code terminal

## Start backend (PowerShell terminal 1)
```powershell
cd "C:\path\to\soc-sentinel\backend"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
If activation is blocked by PowerShell policy, skip activation and use:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
API documentation: http://127.0.0.1:8000/docs

## Start frontend (PowerShell terminal 2)
```powershell
cd "C:\path\to\soc-sentinel\frontend"
npm install
npm run dev
```
Open http://127.0.0.1:5173 . Click **Load demo data** to populate incidents. Click a row to investigate, add notes, change status and download a report. Event Explorer allows importing small log files (max 1 MB).

## Run tests
```powershell
cd "C:\path\to\soc-sentinel\backend"
.\.venv\Scripts\python.exe -m pytest -v
```

## Import JSON format
Normalized array example:
```json
[{"timestamp":"2026-10-12T12:00:00Z","source":"windows:4625","username":"alice","source_ip":"203.0.113.5","outcome":"failure"}]
```
Windows array example:
```json
[{"timestamp":"2026-10-12T12:00:00Z","EventID":4625,"TargetUserName":"alice","IpAddress":"203.0.113.5"}]
```
The importer does **not** support raw `.evtx` files; export selected events to the documented JSON shape first. Linux parser accepts standard SSH `Failed password` and `Accepted password` auth.log lines with traditional `Oct 12 12:00:00` prefix; year is inferred as current UTC year, so old files may have inaccurate dates.

## Detection limitations / false positives
- Detection rules are **Sigma-inspired YAML**, but the app does **not** implement the full Sigma specification or correlation grammar. `x_demo_correlation` is a custom extension consumed by the Python engine.
- The same-IP grouping can generate false positives for NAT gateways, shared networks, password managers, or legitimate failed login retries.
- Time-window alerts are grouped into fixed time buckets, which may split one incident across buckets. Repeated demo seeding adds new events.
- This lab uses a small SQLite database, no authentication, no authorization, no retention policies, no background queue, and no enterprise-grade event normalization. **Bind to localhost only; do not deploy publicly or ingest sensitive production logs.**
- AI-style visual animations are **interface design**, not machine-learning-based detection. Detection is transparent, deterministic, rule-based correlation.

## Suggested portfolio evidence
1. Screenshot of overview with synthetic alerts.
2. Screenshot of an incident investigation with an analyst note.
3. Run `pytest -v` and screenshot successful tests.
4. Download an incident report and add a redacted sample to `docs/`.
5. Document a false positive (e.g. shared IP with many legitimate retries), its root cause, and tuning suggestions.

## License
Educational use; test only with logs you own or are authorized to analyze.

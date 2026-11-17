# SentinelAI — AI Security Operations Assistant

A complete, demo-ready SOC dashboard built with Python and Streamlit. SentinelAI provides simulated Microsoft Sentinel-style alerts, evidence-led investigation guidance, local threat-intelligence triage, incident tracking, CSV/JSON log analysis, and an analyst audit trail.

> **Demo and safety notice:** All bundled telemetry and threat-intelligence results are synthetic. SentinelAI does not connect to Microsoft Sentinel or any live security service. The “AI” assistant is a transparent, local rule-based triage helper—not a hosted LLM—and its guidance must be validated by an analyst. Uploaded files are parsed as data only, never executed.

## Features

- Dark, responsive SOC dashboard with alert severity and incident charts
- Alert investigation with evidence-based MITRE ATT&CK mappings and suggested checks
- IOC triage for IPs, domains, URLs, and hashes, using a local demo indicator catalog
- Incident management: create incidents and update status/owner/severity
- CSV and JSON security-log upload, validation, previews, summaries, and severity charts
- Local investigation assistant that summarizes indicators, suggests next steps, and maps supported techniques
- Session audit trail for analyst actions
- Synthetic sample alert and event datasets
- Unit tests for parsing, validation, severity metrics, and investigation analysis

## Run locally

Requires Python 3.10 or later.

```bash
git clone https://github.com/Data54inc/SentinelAI.git
cd SentinelAI
python -m venv .venv
```

Activate the virtual environment:

- macOS/Linux: `source .venv/bin/activate`
- Windows PowerShell: `.venv\\Scripts\\Activate.ps1`

Install packages and launch:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Then visit the local URL printed by Streamlit (normally http://localhost:8501). No API key or cloud account is required. `.env.example` is only a placeholder template; the app does not load or require credentials.

## Run tests

```bash
pytest -q
```

## Using the application

1. Open **Dashboard** for alert and incident metrics.
2. Go to **Alert Investigation** and select an alert to review its evidence, ATT&CK mapping, and analyst checklist.
3. Use **Threat Intelligence** to triage an indicator against the bundled synthetic catalog. Unknown indicators are reported as unknown, not looked up externally.
4. Use **Incident Management** to create incidents and change their status or ownership. State is held in the current Streamlit session.
5. In **Log Analysis**, upload a `.csv` or `.json` file (up to 5 MB). Accepted JSON is an array of records, an object, or an object containing a `records` array.
6. Use **AI Assistant** to analyze an event description. Treat the results as triage suggestions, not a confirmed verdict.
7. **Audit Trail** shows actions recorded in the current session.

## Project layout

- `app.py` — Streamlit interface and connected dashboard modules
- `sentinelai_lib.py` — reusable validation, parsing, triage, and ATT&CK logic
- `data/sample_alerts.json` — simulated alert records
- `data/sample_security_events.csv` and `.json` — synthetic log examples
- `tests/test_security_logic.py` — core unit tests
- `requirements.txt` — runtime/test dependencies
- `.env.example` — placeholder environment configuration; no real credentials

## Security and production considerations

Uploaded data is size-limited, extension-checked, decoded, and parsed; it is never evaluated or executed. Do not upload sensitive production logs to a public demo. The session audit trail and incident state are in-memory and reset when a session ends. Before any production use, add authentication and authorization, durable storage, privacy controls, secure deployment configuration, robust audit persistence, and validated integrations. Never put secrets in source control.

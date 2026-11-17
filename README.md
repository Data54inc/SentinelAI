# SentinelAI — AI Security Operations Assistant

SentinelAI is a Python/Streamlit SOC dashboard demonstrating simulated alert triage, incident tracking, local IOC triage, uploaded log review, and a rule-based investigation helper.

> **Demo and safety notice:** Bundled telemetry and threat-intelligence results are synthetic. SentinelAI does not connect to Microsoft Sentinel or any live security service. The “AI” assistant is a local keyword/rule-based triage helper—not a hosted LLM—and its guidance must be validated by an analyst. Uploaded files are parsed as data only and are never executed.

## Features

- Dark SOC dashboard with alert severity and incident charts
- Alert investigation with heuristic MITRE ATT&CK technique hypotheses and suggested analyst checks
- IOC triage against a small local synthetic indicator catalog; no external lookup
- Incident management: create incidents with severity and update status or owner
- CSV/JSON upload, validation, previews, record summaries, duplicate/null counts, and severity chart when a recognized severity column exists
- Local rule-based event investigation suggestions and ATT&CK mapping hypotheses
- Session-only analyst audit trail with CSV export
- Synthetic sample alert and event datasets

## Run locally

Requires Python 3.10 or later.

```bash
git clone https://github.com/Data54inc/SentinelAI.git
cd SentinelAI
python -m venv .venv
```

Activate the virtual environment:

- macOS/Linux: `source .venv/bin/activate`
- Windows PowerShell: `.venv\Scripts\Activate.ps1`

Install packages and launch:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Open the local URL printed by Streamlit, normally http://localhost:8501. No API key or cloud account is required. `.env.example` contains placeholders only and is not read by the application.

## Run tests

```bash
pytest -q
```

## Using the application

1. Open **Dashboard** for synthetic alert and in-session incident metrics.
2. In **Alert Investigation**, select an alert to review its description, evidence, possible ATT&CK techniques, and suggested checks.
3. In **Threat Intelligence**, submit an indicator for lookup in the bundled synthetic catalog. Unmatched indicators remain unknown; no external reputation source is queried.
4. In **Incident Management**, create an incident with a severity and optionally change its owner or status. Data persists only in the current Streamlit session.
5. In **Log Analysis**, upload a `.csv` or `.json` file up to 5 MB. CSV should have a header row. JSON can be an array of event objects, an object, or an object containing a `records` array of objects. Data is parsed and displayed; content is not executed.
6. In **AI Assistant**, submit an event narrative for local rule-based triage suggestions. This is not a real AI model, a detection verdict, or an automated response.
7. **Audit Trail** displays actions held in the current session and offers CSV export.

## Project layout

- `app.py` — Streamlit interface and dashboard modules
- `sentinelai_lib.py` — upload validation, parsing, triage, and ATT&CK hypothesis logic
- `data/sample_alerts.json` — simulated alert records
- `data/sample_security_events.csv` and `.json` — synthetic log examples
- `tests/test_security_logic.py` — unit tests for core logic
- `requirements.txt` — runtime and test dependencies
- `.env.example` — placeholder configuration; no real credentials

## Security and production limitations

Uploaded data is limited to 5 MB and checked by filename extension, decoded as UTF-8, and parsed as CSV/JSON. File contents are never evaluated or executed. Extension checks are not a complete content-security boundary. Avoid uploading sensitive production logs to a public demo.

This is a demonstration, not a production SOC tool: there is no authentication/authorization, live Sentinel integration, external threat-intelligence lookup, LLM, durable database, or persistent audit storage. Incidents, assistant results, and audit events are held in Streamlit session state and reset with the session. ATT&CK mappings and risk scores are keyword-based hypotheses and may be incomplete or incorrect. Validate all findings with trusted telemetry and established incident-response procedures. Never commit secrets; use a secure secret manager if adding integrations.

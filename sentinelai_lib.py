import ipaddress
import io
import json
import re
from pathlib import Path

import pandas as pd

MAX_FILE_SIZE = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".csv", ".json"}
SEVERITIES = ("Critical", "High", "Medium", "Low")


def get_sample_alerts():
    path = Path(__file__).resolve().parent / "data" / "sample_alerts.json"
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def get_sample_incidents():
    return [
        {"incident_id": "INC-0001", "name": "Credential stuffing against cloud accounts", "severity": "High", "owner": "Nora Patel", "status": "Investigating"},
        {"incident_id": "INC-0002", "name": "Suspicious script on finance endpoint", "severity": "Critical", "owner": "Evan Chen", "status": "Contained"},
        {"incident_id": "INC-0003", "name": "Sign-in from an unfamiliar device", "severity": "Medium", "owner": "Maya Scott", "status": "Monitoring"},
    ]


def parse_alerts_to_dataframe(alerts):
    frame = pd.DataFrame(alerts)
    if not frame.empty and "timestamp" in frame.columns:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    return frame


def compute_severity_distribution(alert_df):
    counts = alert_df["severity"].value_counts().to_dict() if not alert_df.empty and "severity" in alert_df else {}
    return {severity: int(counts.get(severity, 0)) for severity in SEVERITIES}


def validate_uploaded_file(uploaded_file):
    if uploaded_file is None:
        raise ValueError("Please select a file.")
    name = str(getattr(uploaded_file, "name", ""))
    if Path(name).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported file type. Upload a CSV or JSON file.")
    size = getattr(uploaded_file, "size", None)
    if size is None:
        content = uploaded_file.getvalue()
        size = len(content)
    if size > MAX_FILE_SIZE:
        raise ValueError("Uploaded file exceeds the 5 MB limit.")
    return True


def load_uploaded_log(uploaded_file):
    validate_uploaded_file(uploaded_file)
    raw = uploaded_file.getvalue()
    if len(raw) > MAX_FILE_SIZE:
        raise ValueError("Uploaded file exceeds the 5 MB limit.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("File must use UTF-8 text encoding.") from exc
    extension = Path(uploaded_file.name).suffix.lower()
    if extension == ".csv":
        return pd.read_csv(io.StringIO(text))
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno}).") from exc
    if isinstance(payload, list):
        if any(not isinstance(item, dict) for item in payload):
            raise ValueError("JSON arrays must contain objects (security event records).")
        return pd.DataFrame(payload)
    if isinstance(payload, dict):
        if "records" in payload:
            if not isinstance(payload["records"], list) or any(not isinstance(item, dict) for item in payload["records"]):
                raise ValueError("The JSON 'records' property must be an array of objects.")
            return pd.DataFrame(payload["records"])
        return pd.json_normalize(payload)
    raise ValueError("JSON must contain an object or an array of event objects.")


def summarize_log_dataframe(frame):
    return {
        "rows": int(len(frame)),
        "columns": int(len(frame.columns)),
        "null_values": int(frame.isna().sum().sum()),
        "duplicate_rows": int(frame.duplicated().sum()),
    }


def infer_mitre_from_alert(alert):
    text = " ".join(str(alert.get(key, "")) for key in ("title", "description", "category", "event_summary")).lower()
    mapping = []
    steps = []
    if any(term in text for term in ("password spray", "password spraying", "credential stuffing", "failed login", "brute force", "password guessing")):
        mapping.append("T1110.001 — Brute Force: Password Guessing")
        steps.extend(["Review identity sign-in and MFA telemetry for the targeted accounts.", "Check for successful sign-ins after the failures and revoke suspicious sessions.", "Apply account protections and reset credentials when compromise is confirmed."])
    if any(term in text for term in ("powershell", "script execution", "encoded command")):
        mapping.append("T1059.001 — Command and Scripting Interpreter: PowerShell")
        steps.extend(["Review process lineage, command-line evidence, and script-block logs.", "Collect endpoint evidence and check for persistence before remediation."])
    if any(term in text for term in ("smb", "lateral movement", "remote service")):
        mapping.append("T1021.002 — Remote Services: SMB/Windows Admin Shares")
        steps.extend(["Correlate SMB sessions with source process and account activity.", "Check whether the same account accessed additional hosts."])
    if any(term in text for term in ("exfiltration", "outbound transfer", "data transfer")):
        mapping.append("T1041 — Exfiltration Over C2 Channel (hypothesis; validate channel evidence)")
        steps.extend(["Review destination, transfer volume, and data access preceding the connection.", "Preserve network and endpoint evidence; contain egress under incident policy."])
    if any(term in text for term in ("phishing", "spearphishing")):
        mapping.append("T1566.001 — Phishing: Spearphishing Attachment")
        steps.extend(["Inspect the message and attachments in a safe analysis environment.", "Search for delivery to other recipients and any resulting account or endpoint activity."])
    if any(term in text for term in ("new sign-in", "untrusted device", "valid account")):
        mapping.append("T1078 — Valid Accounts (only if unauthorized account use is established)")
        steps.extend(["Validate the sign-in with the account owner and expected travel/device context.", "Review session, MFA, and conditional-access outcomes."])
    if not mapping:
        steps = ["Correlate the event with identity, endpoint, and network telemetry.", "Identify the affected assets and preserve relevant evidence.", "Escalate if impact or confidence increases; avoid assigning a technique without supporting evidence."]
    return {"mapping": "; ".join(mapping), "recommended_steps": list(dict.fromkeys(steps))}


_DEMO_IOCS = {
    "198.51.100.24": {"reputation": "Suspicious (synthetic)", "confidence": "High", "tags": ["demo brute-force source", "documentation-only IP range"]},
    "203.0.113.18": {"reputation": "Unverified (synthetic)", "confidence": "Low", "tags": ["sample sign-in indicator", "documentation-only IP range"]},
    "updates-example.invalid": {"reputation": "Malicious (synthetic demo label)", "confidence": "Medium", "tags": ["sample domain", "not a real threat-intel verdict"]},
}


def _indicator_type(indicator):
    value = indicator.strip()
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
        return "Hash"
    try:
        ipaddress.ip_address(value)
        return "IP address"
    except ValueError:
        pass
    if value.lower().startswith(("http://", "https://")):
        return "URL"
    if "." in value and " " not in value:
        return "Domain or hostname"
    return "Unknown"


def analyze_indicator(indicator):
    value = str(indicator or "").strip()
    kind = _indicator_type(value) if value else "Unknown"
    record = _DEMO_IOCS.get(value.lower(), _DEMO_IOCS.get(value))
    if not value:
        return {"type": "Unknown", "reputation": "Not analyzed", "confidence": "None", "tags": [], "summary": "Enter an indicator to analyze.", "recommended_steps": ["Provide an IP, domain, URL, or hash."]}
    if record:
        reputation, confidence, tags = record["reputation"], record["confidence"], record["tags"]
        summary = "Indicator matched the bundled synthetic demo catalog; this is not an external reputation check."
    else:
        reputation, confidence, tags = "Unknown", "None", []
        summary = "No match in the local synthetic catalog. No external lookup was performed."
    return {"type": kind, "reputation": reputation, "confidence": confidence, "tags": tags, "summary": summary, "recommended_steps": ["Correlate the indicator with local DNS, proxy, identity, and endpoint telemetry.", "Check first/last-seen times and affected assets before blocking.", "Preserve relevant evidence and use approved incident response procedures."]}


def ai_investigation_recommendation(event_text):
    text = str(event_text or "").lower()
    techniques = infer_mitre_from_alert({"title": text, "description": text})
    findings = []
    cases = [
        (("failed login", "failed logins", "credential", "password spray", "brute force"), "Possible credential attack", 82,
         ["Review sign-in outcomes, targeted accounts, and MFA events.", "Check for successful authentication and revoke sessions if compromise is confirmed.", "Apply account protections and credential reset procedures as appropriate."]),
        (("powershell", "encoded command", "script execution"), "Possible script-based execution", 88,
         ["Review process tree, command line, and script-block telemetry.", "Collect endpoint evidence and look for persistence or follow-on activity.", "Contain the host according to response policy if malicious execution is corroborated."]),
        (("exfiltration", "outbound transfer", "large outbound", "data transfer"), "Possible suspicious data transfer", 91,
         ["Validate destination and transfer volume against business context.", "Correlate outbound activity with file access and identity events.", "Preserve evidence and coordinate containment through incident response."]),
        (("phishing", "suspicious email", "email attachment"), "Possible phishing activity", 79,
         ["Review message headers, sender, links, and attachments in a safe environment.", "Search for other recipients and resulting account or endpoint events.", "Quarantine or report the message using approved processes."]),
        (("smb", "lateral movement", "remote service"), "Possible lateral movement", 86,
         ["Correlate remote sessions with source host, account, and process activity.", "Review neighboring hosts for related authentication or execution events.", "Preserve endpoint and identity evidence before containment."]),
    ]
    for terms, label, score, steps in cases:
        if any(term in text for term in terms):
            findings.append((label, score, steps))
    if not findings:
        label, score = "Unclassified activity — needs analyst validation", 48
        steps = ["Establish a timeline and identify affected users, hosts, and resources.", "Correlate the event with endpoint, identity, and network telemetry.", "Document uncertainty and escalate based on potential impact."]
    else:
        label = " + ".join(item[0] for item in findings)
        score = max(item[1] for item in findings)
        steps = [step for item in findings for step in item[2]]
    return {"summary": "Rule-based triage based only on keywords in the supplied event; validate every finding with telemetry.", "likely_attack": label, "risk_score": score, "recommended_steps": list(dict.fromkeys(steps)), "mitre_mapping": techniques["mapping"]}


__all__ = ["MAX_FILE_SIZE", "ALLOWED_EXTENSIONS", "SEVERITIES", "get_sample_alerts", "get_sample_incidents", "parse_alerts_to_dataframe", "compute_severity_distribution", "validate_uploaded_file", "load_uploaded_log", "summarize_log_dataframe", "infer_mitre_from_alert", "analyze_indicator", "ai_investigation_recommendation"]

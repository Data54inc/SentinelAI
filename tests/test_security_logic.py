import json

import pandas as pd
import pytest

from sentinelai_lib import (
    MAX_FILE_SIZE,
    ai_investigation_recommendation,
    analyze_indicator,
    compute_severity_distribution,
    infer_mitre_from_alert,
    load_uploaded_log,
    parse_alerts_to_dataframe,
    validate_uploaded_file,
)


class Upload:
    def __init__(self, name, content):
        self.name = name
        self.content = content
        self.size = len(content)

    def getvalue(self):
        return self.content


def test_sample_alert_data_and_severity_counts():
    frame = parse_alerts_to_dataframe([{"timestamp": "2026-11-17T09:00:00Z", "severity": "Critical"}, {"timestamp": "invalid", "severity": "High"}])
    assert len(frame) == 2
    assert frame["timestamp"].isna().sum() == 1
    assert compute_severity_distribution(frame) == {"Critical": 1, "High": 1, "Medium": 0, "Low": 0}


def test_validate_upload_rejects_bad_extension_and_large_file():
    with pytest.raises(ValueError, match="Unsupported"):
        validate_uploaded_file(Upload("payload.exe", b"x"))
    large = Upload("events.csv", b"x" * (MAX_FILE_SIZE + 1))
    with pytest.raises(ValueError, match="5 MB"):
        validate_uploaded_file(large)


def test_load_csv_and_json_records():
    csv = Upload("events.csv", b"user,severity\nalice,High\n")
    assert load_uploaded_log(csv).iloc[0]["user"] == "alice"
    js = Upload("events.json", json.dumps({"records": [{"user": "bob", "severity": "Low"}]}).encode())
    assert load_uploaded_log(js).iloc[0]["user"] == "bob"


def test_json_rejects_non_object_array_items():
    with pytest.raises(ValueError, match="objects"):
        load_uploaded_log(Upload("events.json", b'["not a record"]'))


def test_mitre_mapping_requires_evidence_and_supports_multiple_techniques():
    none = infer_mitre_from_alert({"title": "Unusual activity", "description": "Needs analyst review"})
    assert none["mapping"] == ""
    mapped = infer_mitre_from_alert({"title": "Password spraying and encoded PowerShell", "description": "SMB lateral movement"})
    assert "T1110.001" in mapped["mapping"]
    assert "T1059.001" in mapped["mapping"]
    assert "T1021.002" in mapped["mapping"]


def test_threat_intelligence_local_catalog_only():
    known = analyze_indicator("198.51.100.24")
    unknown = analyze_indicator("203.0.113.200")
    assert known["confidence"] == "High"
    assert unknown["reputation"] == "Unknown"
    assert "No external lookup" in unknown["summary"]


def test_ai_assistant_detects_patterns_and_provides_steps():
    result = ai_investigation_recommendation("Failed logins and encoded PowerShell execution were observed")
    assert "Possible credential attack" in result["likely_attack"]
    assert "Possible script-based execution" in result["likely_attack"]
    assert "T1110.001" in result["mitre_mapping"]
    assert result["risk_score"] >= 80
    assert result["recommended_steps"]


def test_csv_malformed_and_json_malformed_errors():
    with pytest.raises((ValueError, pd.errors.ParserError)):
        load_uploaded_log(Upload("broken.json", b"{bad"))

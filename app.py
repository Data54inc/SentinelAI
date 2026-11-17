import json
from pathlib import Path

import pandas as pd
import streamlit as st

from sentinelai_lib import (
    MAX_FILE_SIZE,
    ai_investigation_recommendation,
    analyze_indicator,
    compute_severity_distribution,
    get_sample_alerts,
    get_sample_incidents,
    infer_mitre_from_alert,
    load_uploaded_log,
    parse_alerts_to_dataframe,
    summarize_log_dataframe,
    validate_uploaded_file,
)

BASE_DIR = Path(__file__).resolve().parent

st.set_page_config(page_title="SentinelAI | SOC", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
:root { color-scheme: dark; }
.stApp { background: #080e18; color: #e6edf7; }
[data-testid="stSidebar"] { background: #0d1725; border-right: 1px solid #1e2d40; }
.block-container { padding-top: 1.4rem; max-width: 1500px; }
div[data-testid="stMetric"] { background: #101b2a; border: 1px solid #22354c; border-radius: 12px; padding: 14px; }
div[data-testid="stMetricLabel"] { color: #9fb3ca; }
.hero { padding: 20px 24px; border: 1px solid #1b5794; border-radius: 14px; background: linear-gradient(110deg,#102641,#112d4d 55%,#101a2b); margin-bottom: 18px; }
.hero h1 { margin: 0; font-size: 1.8rem; color: #f0f7ff; }
.hero p { margin: 5px 0 0; color: #9acfff; font-size: .9rem; letter-spacing: .04em; }
.badge { display:inline-block; padding:3px 9px; border-radius:20px; background:#183753; color:#a9d8ff; font-size:.78rem; }
.small-note { color:#91a5bd; font-size:.82rem; }
</style>
""", unsafe_allow_html=True)


def audit(action: str) -> None:
    st.session_state.setdefault("audit", []).insert(0, {
        "time_utc": pd.Timestamp.now(tz="UTC").strftime("%Y-%m-%d %H:%M:%S"),
        "analyst_action": action,
    })


def initialize_state() -> None:
    st.session_state.setdefault("audit", [])
    st.session_state.setdefault("incidents", get_sample_incidents())


def severity_color(value: str) -> str:
    return {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(value, "⚪")


initialize_state()
alerts = get_sample_alerts()
alert_df = parse_alerts_to_dataframe(alerts)

st.sidebar.markdown("# 🛡️ SentinelAI")
st.sidebar.caption("AI Security Operations Assistant")
page = st.sidebar.radio("Workspace", ["Dashboard", "Alert Investigation", "Threat Intelligence", "Incident Management", "Log Analysis", "AI Assistant", "Audit Trail"], label_visibility="collapsed")
st.sidebar.divider()
st.sidebar.markdown("**Environment**  `DEMO / SIMULATED`")
st.sidebar.caption("Mock Sentinel-style data only. No live Sentinel connection.")
st.sidebar.caption("Uploaded content is treated as data, never executed.")

st.markdown("<div class='hero'><h1>SentinelAI <span class='badge'>SOC COMMAND CENTER</span></h1><p>SIMULATED SECURITY TELEMETRY · MOCK MICROSOFT SENTINEL DATA · NO LIVE ENVIRONMENT</p></div>", unsafe_allow_html=True)

if page == "Dashboard":
    st.subheader("Security Operations Overview")
    distribution = compute_severity_distribution(alert_df)
    incident_df = pd.DataFrame(st.session_state.incidents)
    open_count = int((incident_df["status"] != "Resolved").sum()) if not incident_df.empty else 0
    cols = st.columns(5)
    cols[0].metric("Alerts", len(alert_df))
    cols[1].metric("Critical", distribution["Critical"])
    cols[2].metric("High", distribution["High"])
    cols[3].metric("Open incidents", open_count)
    cols[4].metric("Resolved", int((incident_df["status"] == "Resolved").sum()) if not incident_df.empty else 0)
    left, right = st.columns(2)
    with left:
        st.markdown("#### Alert severity")
        st.bar_chart(pd.Series(distribution, name="Alerts"), color="#3b9eff")
    with right:
        st.markdown("#### Incident status")
        if not incident_df.empty:
            st.bar_chart(incident_df["status"].value_counts(), color="#36c7b5")
        else:
            st.info("No incidents recorded.")
    st.markdown("#### Recent simulated alerts")
    view = alert_df.copy()
    view["severity"] = view["severity"].map(lambda v: f"{severity_color(v)} {v}")
    st.dataframe(view.sort_values("timestamp", ascending=False)[["timestamp", "alert_id", "severity", "title", "source", "status"]], use_container_width=True, hide_index=True)
    audit("Viewed dashboard")

elif page == "Alert Investigation":
    st.subheader("Alert Investigation")
    alert_id = st.selectbox("Select simulated alert", alert_df["alert_id"].tolist(), format_func=lambda value: f"{value} — {alert_df.loc[alert_df.alert_id == value, 'title'].iloc[0]}")
    alert = alert_df.loc[alert_df.alert_id == alert_id].iloc[0].to_dict()
    c1, c2, c3 = st.columns(3)
    c1.metric("Severity", f"{severity_color(alert['severity'])} {alert['severity']}")
    c2.metric("Status", alert["status"])
    c3.metric("Detection source", alert["source"])
    st.markdown(f"### {alert['title']}")
    st.write(alert["description"])
    with st.expander("Evidence", expanded=True):
        evidence = {k: alert.get(k, "Not provided") for k in ["timestamp", "source_ip", "host", "user", "country"]}
        st.json(evidence)
    mapping = infer_mitre_from_alert(alert)
    st.markdown("#### MITRE ATT&CK (hypothesis based on alert text)")
    st.info(mapping["mapping"] if mapping["mapping"] else "No technique mapped: evidence is insufficient.")
    st.markdown("#### Suggested analyst checks")
    for item in mapping["recommended_steps"]:
        st.markdown(f"- {item}")
    if st.button("Record investigation review", type="primary"):
        audit(f"Reviewed alert {alert_id}")
        st.success("Review recorded in the session audit trail.")

elif page == "Threat Intelligence":
    st.subheader("Threat Intelligence Triage")
    st.caption("Local synthetic indicator catalog only; no external lookup is performed.")
    with st.form("ioc_form"):
        indicator = st.text_input("Indicator of compromise (IP, domain, URL, or hash)", placeholder="e.g. 198.51.100.24")
        submitted = st.form_submit_button("Analyze indicator", type="primary")
    if submitted:
        result = analyze_indicator(indicator)
        st.session_state["ioc_result"] = result
        audit(f"Triaged indicator {indicator.strip() or '(empty)'}")
    result = st.session_state.get("ioc_result")
    if result:
        col1, col2, col3 = st.columns(3)
        col1.metric("Reputation", result["reputation"])
        col2.metric("Confidence", result["confidence"])
        col3.metric("Indicator type", result["type"])
        st.write(result["summary"])
        if result["tags"]:
            st.markdown("**Tags:** " + " · ".join(result["tags"]))
        st.markdown("**Analyst guidance**")
        for step in result["recommended_steps"]:
            st.markdown(f"- {step}")
        st.caption("Catalog matches are illustrative and are not a real-world reputation verdict.")

elif page == "Incident Management":
    st.subheader("Incident Management")
    incident_df = pd.DataFrame(st.session_state.incidents)
    if not incident_df.empty:
        st.dataframe(incident_df, use_container_width=True, hide_index=True)
    with st.expander("Create incident", expanded=False):
        with st.form("new_incident", clear_on_submit=True):
            name = st.text_input("Incident title")
            sev = st.selectbox("Severity", ["Critical", "High", "Medium", "Low"])
            owner = st.text_input("Assigned analyst")
            create = st.form_submit_button("Create incident", type="primary")
        if create:
            if not name.strip():
                st.error("Enter an incident title.")
            else:
                incident_id = f"INC-{(len(st.session_state.incidents) + 1):04d}"
                st.session_state.incidents.append({"incident_id": incident_id, "name": name.strip(), "severity": sev, "owner": owner.strip() or "Unassigned", "status": "Open"})
                audit(f"Created incident {incident_id}")
                st.success(f"Created {incident_id}.")
                st.rerun()
    st.markdown("#### Update incident")
    if st.session_state.incidents:
        choices = {item["incident_id"]: item for item in st.session_state.incidents}
        chosen_id = st.selectbox("Incident", list(choices))
        selected = choices[chosen_id]
        a, b = st.columns(2)
        with a:
            new_status = st.selectbox("Status", ["Open", "Investigating", "Contained", "Monitoring", "Resolved"], index=["Open", "Investigating", "Contained", "Monitoring", "Resolved"].index(selected["status"]) if selected["status"] in ["Open", "Investigating", "Contained", "Monitoring", "Resolved"] else 0)
        with b:
            new_owner = st.text_input("Owner", value=selected["owner"])
        if st.button("Save incident update"):
            selected["status"] = new_status
            selected["owner"] = new_owner.strip() or "Unassigned"
            audit(f"Updated incident {chosen_id}: {new_status}")
            st.success("Incident updated.")
            st.rerun()

elif page == "Log Analysis":
    st.subheader("Security Log Analysis")
    st.caption(f"Accepted formats: CSV and JSON · Maximum upload size: {MAX_FILE_SIZE // (1024 * 1024)} MB. Files are parsed as data only.")
    upload = st.file_uploader("Upload security events", type=["csv", "json"], help="CSV with a header row or JSON array/object. Maximum 5 MB.")
    if upload is not None:
        try:
            validate_uploaded_file(upload)
            frame = load_uploaded_log(upload)
            st.success(f"Loaded {len(frame):,} records from {upload.name}.")
            if frame.empty:
                st.warning("The file contains no records.")
            else:
                st.markdown("#### Preview")
                st.dataframe(frame.head(100), use_container_width=True, hide_index=True)
                summary = summarize_log_dataframe(frame)
                m1, m2, m3 = st.columns(3)
                m1.metric("Rows", summary["rows"])
                m2.metric("Columns", summary["columns"])
                m3.metric("Duplicate rows", summary["duplicate_rows"])
                st.caption(f"Missing values: {summary['null_values']}")
                severity_col = next((col for col in frame.columns if col.lower() in {"severity", "level", "alertseverity"}), None)
                if severity_col:
                    st.markdown("#### Severity distribution")
                    st.bar_chart(frame[severity_col].fillna("Unknown").astype(str).value_counts(), color="#3b9eff")
            audit(f"Analyzed uploaded log file {upload.name}")
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, pd.errors.ParserError) as exc:
            st.error(f"Could not analyze uploaded file: {exc}")
    st.markdown("#### Bundled sample events (synthetic)")
    sample_path = BASE_DIR / "data" / "sample_security_events.csv"
    st.dataframe(pd.read_csv(sample_path), use_container_width=True, hide_index=True)
    st.download_button("Download sample JSON", data=(BASE_DIR / "data" / "sample_security_events.json").read_bytes(), file_name="sample_security_events.json", mime="application/json")

elif page == "AI Assistant":
    st.subheader("AI Investigation Assistant")
    st.warning("Local rule-based demo assistant. It does not call an AI service, and recommendations are not a confirmed detection.")
    event_text = st.text_area("Describe the security event", placeholder="Include observed activity, affected asset/account, and relevant indicators…", height=150)
    if st.button("Analyze event", type="primary"):
        if not event_text.strip():
            st.error("Enter an event description to analyze.")
        else:
            result = ai_investigation_recommendation(event_text)
            st.session_state["analysis_result"] = result
            audit("Analyzed event with the local investigation assistant")
    result = st.session_state.get("analysis_result")
    if result:
        st.markdown("#### Triage assessment")
        st.write(result["summary"])
        c1, c2 = st.columns(2)
        c1.metric("Likely pattern", result["likely_attack"])
        c2.metric("Triage score", f"{result['risk_score']}/100")
        st.markdown("**Evidence-matched MITRE ATT&CK techniques**")
        st.write(result["mitre_mapping"] or "No mapping: evidence is insufficient.")
        st.markdown("**Recommended investigation steps**")
        for step in result["recommended_steps"]:
            st.markdown(f"- {step}")
        st.caption("Risk score is a heuristic for prioritization, not a probability or confirmed finding.")

else:
    st.subheader("Analyst Audit Trail")
    if st.session_state.audit:
        st.dataframe(pd.DataFrame(st.session_state.audit), use_container_width=True, hide_index=True)
        st.download_button("Export audit trail (CSV)", data=pd.DataFrame(st.session_state.audit).to_csv(index=False), file_name="sentinelai_audit.csv", mime="text/csv")
    else:
        st.info("No analyst actions have been recorded in this session yet.")

st.divider()
st.caption("SentinelAI is a demonstration application using synthetic data. It does not connect to or monitor a live Microsoft Sentinel environment.")

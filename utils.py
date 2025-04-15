import pandas as pd
import streamlit as st
import plotly.express as px

custom_colors = {
    "Critical": "red",
    "High": "orange",
    "Medium": "gold",
    "Low": "blue"
}

def build_chart_data(matches):
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for item in matches:
        vulns = item["vulnerabilities"]
        severities_found = set(v.get("sir", "").capitalize() for v in vulns)
        for sev in severities_found:
            if sev in severity_counts:
                severity_counts[sev] += 1

    df = pd.DataFrame([
        {"Severity": k, "Affected Devices": v} for k, v in severity_counts.items()
    ])
    df["Severity"] = pd.Categorical(df["Severity"], categories=["Critical", "High", "Medium", "Low"], ordered=True)
    return df.sort_values("Severity")

def render_chart(df):
    if df.empty:
        st.info("No chartable data available.")
        return

    fig = px.bar(
        df,
        x="Severity",
        y="Affected Devices",
        color="Severity",
        text="Affected Devices",
        color_discrete_map=custom_colors,
        title="Devices Affected by Vulnerability Severity"
    )
    fig.update_traces(textposition="outside")
    fig.update_layout(yaxis_title="Device Count", xaxis_title="Severity")
    st.plotly_chart(fig, use_container_width=True)

def calculate_risk(vulns):
    """
    Calculate a risk score based on the severity of vulnerabilities.
    """
    score = 0
    for v in vulns:
        severity = v.get("sir", "").lower()
        if severity == "critical":
            score += 5
        elif severity == "high":
            score += 3
        elif severity == "medium":
            score += 1
        elif severity == "low":
            score += 0.5
    return score

custom_colors = {
    "Critical": "red",
    "High": "gold",
    "Medium": "orange",
    "Low": "deepskyblue"
}

import streamlit as st

def render_filtered_devices(matches):
    selected_severity = st.selectbox(
        "Select a severity level:",
        options=["Critical", "High", "Medium", "Low"]
    )

    filtered = []
    for item in matches:
        device = item["device"]
        vulns = item["vulnerabilities"]
        matching = [v for v in vulns if v.get("sir", "").lower() == selected_severity.lower()]
        if matching:
            filtered.append((device, matching))

    if filtered:
        st.markdown(f"### Devices with **{selected_severity}** vulnerabilities")
        for device, vulns in filtered:
            hostname = device["hostname"]
            version = device["softwareVersion"]
            with st.expander(f"🔧 {hostname} ({version}) — {len(vulns)} {selected_severity} vulnerabilities"):
                for v in vulns:
                    st.markdown(
                        f"- **[{v.get('advisoryTitle', 'Untitled')}]({v.get('advisoryUrl', '#')})**  \n"
                        f"  Severity: `{v.get('sir', 'N/A')}`"
                    )
    else:
        st.info(f"No devices found with {selected_severity} vulnerabilities.")

def render_full_device_list(matches):
    for item in matches:
        device = item["device"]
        vulns = item["vulnerabilities"]
        hostname = device["hostname"]
        version = device["softwareVersion"]

        with st.expander(f"🔧 {hostname} ({version}) — {len(vulns)} vulnerabilities"):
            if not vulns:
                st.success("✅ No known vulnerabilities for this version.")
            else:
                for v in vulns:
                    st.markdown(
                        f"- **[{v.get('advisoryTitle', 'Untitled')}]({v.get('advisoryUrl', '#')})**  \n"
                        f"  Severity: `{v.get('sir', 'N/A')}`"
                    )

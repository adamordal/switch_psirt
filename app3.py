import streamlit as st
import pandas as pd
import plotly.express as px
import json
import os
from cisco_api import get_psirt_token, correlate_vulnerabilities
from gpt_utils import summarize_with_gpt
from utils import custom_colors

def main():
    """
    Main function to run the Streamlit app for visualizing Cisco switch vulnerabilities.
    """
    # Mock inventory for testing purposes.
    mock_inventory = [
        {
            "hostname": "core-sw1",
            "managementIpAddress": "10.1.1.1",
            "platformId": "C9300-24T",
            "softwareVersion": "17.3.6",
            "serialNumber": "FDO1234A1BC"
        },
        {
            "hostname": "dist-sw2",
            "managementIpAddress": "10.1.1.2",
            "platformId": "C9200L-48P-4G",
            "softwareVersion": "17.6.4",
            "serialNumber": "FDO5678B2CD"
        },
        {
            "hostname": "access-sw3",
            "managementIpAddress": "10.1.1.3",
            "platformId": "C9300-48P",
            "softwareVersion": "17.9.3",
            "serialNumber": "FDO1111C3EF"
        }
    ]

    # Count devices affected by at least one vulnerability of each severity.
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    # Convert severity counts to a DataFrame for visualization.
    df = pd.DataFrame([
        {"Severity": sev, "Affected Devices": count}
        for sev, count in severity_counts.items()
    ])

    # Consistent severity order
    df["Severity"] = pd.Categorical(df["Severity"], categories=["Critical", "High", "Medium", "Low"], ordered=True)
    df = df.sort_values("Severity")

    # Set up Streamlit page configuration.
    st.set_page_config(
        page_title="Cisco Vulnerability Dashboard",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    st.markdown("""
    <style>
        .block-container {
            padding-top: 1rem;
            padding-bottom: 1rem;
        }
    </style>
    """, unsafe_allow_html=True)

    st.title("🔐 Cisco Switch Vulnerability Dashboard")

    # === Inventory Loading ===
    # Allow users to use mock inventory or upload their own JSON file.
    use_mock = st.sidebar.checkbox("Use Mock Inventory", value=True)
    if use_mock:
        inventory = mock_inventory
    else:
        uploaded = st.file_uploader("Upload inventory JSON", type="json")
        if uploaded:
            inventory = json.load(uploaded)
            if "last_uploaded_filename" not in st.session_state or uploaded.name != st.session_state["last_uploaded_filename"]:
                st.session_state["last_uploaded_filename"] = uploaded.name
                if "gpt_summary" in st.session_state:
                    del st.session_state["gpt_summary"]
        else:
            st.stop()

    # === Token + Correlation ===
    # Retrieve Cisco PSIRT token and correlate vulnerabilities with inventory.
    token = get_psirt_token(
        client_id=os.environ["CISCO_CLIENT_ID"],
        client_secret=os.environ["CISCO_CLIENT_SECRET"]
    )
    matches = correlate_vulnerabilities(inventory, token)

    # === GPT Summary ===
    # Generate and display an executive summary using GPT.
    if "gpt_summary" not in st.session_state:
        st.session_state.gpt_summary = summarize_with_gpt(matches)

    # === Risk Chart Data Prep ===
    # Prepare data for the bar chart showing affected devices by severity.
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for item in matches:
        vulns = item["vulnerabilities"]
        severities_found = set(v.get("sir", "").capitalize() for v in vulns)
        for s in severities_found:
            if s in severity_counts:
                severity_counts[s] += 1

    df = pd.DataFrame([
        {"Severity": k, "Affected Devices": v} for k, v in severity_counts.items()
    ])
    df["Severity"] = pd.Categorical(df["Severity"], categories=["Critical", "High", "Medium", "Low"], ordered=True)
    df = df.sort_values("Severity")

    # === Top Section: Summary and Chart ===
    # Display GPT summary and bar chart side by side.
    col1, col2 = st.columns([1.5, 1.5])

    with col1:
        st.markdown("## 🧠 GPT Executive Summary")
        with st.expander("📋 View Summary", expanded=True):
            st.markdown(st.session_state.gpt_summary, unsafe_allow_html=True)

    with col2:
        if not df.empty:
            st.markdown("## 📊 Affected Devices by Severity")
            fig = px.bar(
                df,
                x="Severity",
                y="Affected Devices",
                color="Severity",
                text="Affected Devices",
                color_discrete_map=custom_colors,
                title="Devices with at Least One Vulnerability by Severity"
            )
            fig.update_traces(textposition="outside")
            fig.update_layout(yaxis_title="Device Count", xaxis_title="Severity")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No chartable data available.")

    # === Filter Section ===
    # Allow users to filter vulnerabilities by severity.
    st.markdown("## 🔎 Explore Vulnerabilities by Severity")
    col1, col2 = st.columns([1, 2])

    with col1:
        selected_severity = st.selectbox("Select a severity level:", options=["Critical", "High", "Medium", "Low"])

    with col2:
        filtered = []
        for item in matches:
            device = item["device"]
            vulns = item["vulnerabilities"]
            matching_vulns = [v for v in vulns if v.get("sir", "").lower() == selected_severity.lower()]
            if matching_vulns:
                filtered.append((device, matching_vulns))

        if filtered:
            st.markdown(f"### Devices with **{selected_severity}** vulnerabilities")
            for device, matching_vulns in filtered:
                hostname = device["hostname"]
                version = device["softwareVersion"]
                with st.expander(f"🔧 {hostname} ({version}) — {len(matching_vulns)} {selected_severity} vulnerabilities"):
                    for v in matching_vulns:
                        st.markdown(
                            f"- **[{v.get('advisoryTitle', 'Untitled')}]({v.get('advisoryUrl', '#')})**  \\n                          Severity: `{v.get('sir', 'N/A')}`"
                        )
        else:
            st.info(f"No devices found with {selected_severity} vulnerabilities.")

    # === Full List ===
    # Display all matched vulnerabilities grouped by device.
    st.markdown("## 📋 All Matched Vulnerabilities by Device")
    for item in matches:
        dev = item['device']
        vulns = item['vulnerabilities']
        hostname = dev['hostname']
        version = dev['softwareVersion']
        with st.expander(f"🔧 {hostname} ({version}) — {len(vulns)} vulnerabilities"):
            if not vulns:
                st.success("✅ No known vulnerabilities for this version.")
            else:
                for v in vulns:
                    st.markdown(
                        f"- **[{v.get('advisoryTitle', 'Untitled')}]({v.get('advisoryUrl', '#')})**  \\n                      Severity: `{v.get('sir', 'N/A')}`"
                    )

if __name__ == "__main__":
    main()
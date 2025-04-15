import streamlit as st
import os
import asyncio
from gpt_utils import summarize_with_gpt
from utils import build_chart_data, render_chart, render_filtered_devices, render_full_device_list
from cisco_api import get_psirt_token, correlate_vulnerabilities
from dnac_inventory import load_inventory_from_dnac

st.set_page_config(page_title="Cisco Vulnerability Dashboard", layout="wide", initial_sidebar_state="collapsed")
st.title("🔐 Cisco Switch Vulnerability Dashboard")

# === Load Inventory from DNAC ===
with st.spinner("🔄 Loading inventory from Cisco DNA Center..."):
    inventory = asyncio.run(load_inventory_from_dnac())


# === Get Cisco PSIRT Token ===
psirt_token = get_psirt_token(os.environ["CISCO_CLIENT_ID"], os.environ["CISCO_CLIENT_SECRET"])

# === Correlate Vulnerabilities ===
matches = correlate_vulnerabilities(inventory, psirt_token)

# === GPT Summary ===
if "gpt_summary" not in st.session_state:
    st.session_state.gpt_summary = summarize_with_gpt(matches)

col1, col2 = st.columns([1.5, 1.5])
with col1:
    st.markdown("## 🧠 GPT Executive Summary")
    with st.expander("📋 View Summary", expanded=True):
        st.markdown(st.session_state.gpt_summary, unsafe_allow_html=True)

with col2:
    chart_data = build_chart_data(matches)
    render_chart(chart_data)

# === Filtered View ===
st.markdown("## 🔎 Explore Vulnerabilities by Severity")
render_filtered_devices(matches)

# === Full Details ===
st.markdown("## 📋 All Matched Vulnerabilities by Device")
render_full_device_list(matches)

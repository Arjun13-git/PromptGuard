import os
import sys
import time
from datetime import datetime
from typing import Optional

import streamlit as st
import pandas as pd
import altair as alt

try:
    from streamlit_option_menu import option_menu
except ImportError:
    option_menu = None

# 1. PATH CONFIG
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.core import config
from ui.components import (
    BackendClient, fetch_summary_cached, kpi_cards,
    render_time_series, render_donut_and_vectors,
    render_logs_table, offline_screen, SOC_THEME
)

# 2. THEME & SESSION INITIALIZATION
st.set_page_config(page_title="PromptGuard SOC", page_icon="🛡️", layout="wide")
st.markdown(SOC_THEME, unsafe_allow_html=True)

if "console_history" not in st.session_state:
    st.session_state.console_history = []

# 3. BACKEND INIT
API_BASE = config.api_base_url()
client = BackendClient(f"{API_BASE}/v1")

# 4. SIDEBAR (Health & Config)
def render_sidebar():
    with st.sidebar:
        st.image("https://img.icons8.com/fluency/96/shield.png", width=80)
        st.title("Cyber Intelligence")

        # Health Check
        summary = fetch_summary_cached(f"{API_BASE}/v1")
        is_online = bool(summary)

        status_color = "green" if is_online else "red"
        st.markdown(f"**System Status:** <span style='color:{status_color}'>{'● ONLINE' if is_online else '● OFFLINE'}</span>", unsafe_allow_html=True)

        if is_online:
            st.success(f"LLM Node: {summary.get('llm_status', 'Active')}")

        st.divider()
        st.subheader("Console Settings")
        limit = st.select_slider("Log Buffer", options=[50, 100, 250, 500], value=100)
        auto_refresh = st.toggle("Live Feed", value=True)

        if st.button("Clear Cache & Reload", use_container_width=True):
            st.cache_data.clear()
            st.rerun()

        return limit, auto_refresh

log_limit, auto_refresh_on = render_sidebar()

# 5. HEADER & NAVIGATION
st.title("🛡️ PromptGuard Security Operations")
if option_menu:
    selected = option_menu(
        menu_title=None,
        options=["Threat Dashboard", "AI Research Lab"],
        icons=["activity", "terminal"],
        orientation="horizontal",
        styles={"container": {"background-color": "#0b101b"}}
    )
else:
    selected = st.radio("Mode", ["Threat Dashboard", "AI Research Lab"], horizontal=True)

# 6. DASHBOARD PAGE
def show_dashboard():
    # Fetch Data
    raw_logs = client.fetch_data("logs", params={"limit": log_limit})
    if raw_logs is None:
        offline_screen(retry_callback=st.rerun)
        return

    df = pd.DataFrame(raw_logs)

    # KPI Row
    kpi_cards(df)

    # Timeline
    render_time_series(df)

    # Distribution Rows
    render_donut_and_vectors(df)

    # Forensic Table
    render_logs_table(df)

# 7. CONSOLE PAGE (The Lab)
def show_console():
    st.markdown("### 🧪 Prompt Injection Sandbox")
    st.caption("Execute adversarial payloads to validate firewall heuristics and LLM risk scoring.")

    with st.container(border=True):
        prompt_input = st.text_area("Adversarial Payload", height=180, placeholder="Enter prompt to test...")
        c1, c2 = st.columns([1, 5])
        if c1.button("Analyze Payload", type="primary", use_container_width=True):
            if prompt_input:
                with st.spinner("Analyzing semantics..."):
                    result = client.evaluate(prompt_input)
                    if result:
                        st.session_state.console_history.insert(0, {
                            "timestamp": datetime.now().strftime("%H:%M:%S"),
                            "input": prompt_input,
                            "output": result
                        })
            else:
                st.warning("Payload empty.")

    # Results Display
    if st.session_state.console_history:
        latest = st.session_state.console_history[0]
        res = latest['output']

        # Risk Gauge Header
        score = res.get('final_score', 0.0)
        verdict = res.get('verdict', 'SAFE')
        v_color = "#ff4b4b" if verdict == "MALICIOUS" else "#ffa113" if verdict == "SUSPICIOUS" else "#00e5ff"

        st.markdown(f"### Current Result: <span style='color:{v_color}'>{verdict} ({score:.2f})</span>", unsafe_allow_html=True)

        col_a, col_b = st.columns(2)
        with col_a:
            st.info(f"**Reasoning:**\n\n{res.get('reasoning', 'N/A')}")
        with col_b:
            with st.expander("Safe Output / Sanitized View", expanded=True):
                st.code(res.get("safe_prompt", "N/A"), language="text")

# 8. MAIN EXECUTION
if "Dashboard" in selected:
    show_dashboard()
else:
    show_console()

# 9. AUTO-REFRESH LOGIC (Non-blocking)
if auto_refresh_on and "Dashboard" in selected:
    time.sleep(10)
    st.rerun()

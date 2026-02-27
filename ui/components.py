import streamlit as st
import pandas as pd
import altair as alt
import json
import requests
from datetime import datetime
from typing import Dict, Any

# --- CUSTOM CSS FOR SOC THEME ---
SOC_THEME = """
<style>
    /* Metric Card Styling with Glassmorphism */
    div[data-testid="metric-container"] {
        background: rgba(17, 25, 40, 0.75);
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        backdrop-filter: blur(8px);
    }
    div[data-testid="stMetricValue"] {
        color: #00e5ff;
        font-family: 'JetBrains Mono', monospace;
        font-size: 2.2rem !important;
    }
    /* Section Headers with Cyan Accent */
    .soc-header {
        font-family: 'Inter', sans-serif;
        font-weight: 700;
        color: #f1f5f9;
        border-left: 4px solid #00e5ff;
        padding-left: 10px;
        margin-top: 1.5rem;
        margin-bottom: 1rem;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
</style>
"""

class BackendClient:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")

    # ADD THIS METHOD
    def fetch_data(self, endpoint: str, params: dict = None) -> list:
        """Fetches a list of records from a specific endpoint (e.g., 'logs')."""
        try:
            r = requests.get(f"{self.base}/{endpoint}", params=params, timeout=5)
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def ping(self, timeout: int = 3) -> Dict[str, Any]:
        """Always returns a dictionary."""
        try:
               r = requests.get(f"{self.base}/summary", timeout=timeout)
               data = r.json()
               return data if isinstance(data, dict) else {}
        except Exception:
               return {}

    def evaluate(self, prompt: str, session_id: str = "soc_console") -> dict:
        """Always returns a dictionary."""
        try:
            r = requests.post(
                f"{self.base}/evaluate",
                json={"session_id": session_id, "prompt": prompt},
                timeout=10
            )
            data = r.json()
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

# --- CACHED UTILITIES ---

@st.cache_data(ttl=5)
def fetch_summary_cached(base_url: str) -> Dict[str, Any]:
    c = BackendClient(base_url)
    res: Dict[str, Any] = c.ping()
    return res if res else {}


# --- UI COMPONENTS ---

def kpi_cards(df: pd.DataFrame):
    st.markdown(SOC_THEME, unsafe_allow_html=True)

    total = len(df)
    malicious = (df['verdict'] == 'MALICIOUS').sum() if 'verdict' in df.columns else 0
    block_rate = (malicious / total * 100) if total > 0 else 0
    avg_lat = df['latency_ms'].mean() if 'latency_ms' in df.columns else 0
    avg_score = df['final_score'].mean() if 'final_score' in df.columns else 0.0

    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("TOTAL SCANS", f"{total:,}")
    with c2: st.metric("BLOCK RATE", f"{block_rate:.1f}%", delta=f"{malicious} Threats", delta_color="inverse")
    with c3: st.metric("AVG RISK", f"{avg_score:.2f}")
    with c4: st.metric("LATENCY", f"{int(avg_lat)}ms")

def render_time_series(df: pd.DataFrame):
    st.markdown('<p class="soc-header">Threat Activity Timeline</p>', unsafe_allow_html=True)

    if df.empty or 'timestamp' not in df.columns:
        st.info("Insufficient data for timeline.")
        return

    df['timestamp'] = pd.to_datetime(df['timestamp'])
    chart_data = df.groupby([pd.Grouper(key='timestamp', freq='1min'), 'verdict']).size().reset_index(name='counts')

    # Selection for interactive filtering
    selection = alt.selection_point(fields=['verdict'], bind='legend')

    chart = alt.Chart(chart_data).mark_area(
        line={'color':'#00e5ff', 'strokeWidth': 2},
        color=alt.Gradient(
            gradient='linear',
            stops=[alt.GradientStop(color='#00e5ff', offset=0),
                   alt.GradientStop(color='transparent', offset=1)],
            x1=1, x2=1, y1=1, y2=0
        )
    ).encode(
        x=alt.X('timestamp:T', title=None),
        y=alt.Y('counts:Q', title='Events / Min'),
        color=alt.Color('verdict:N',
                        scale=alt.Scale(domain=['MALICIOUS', 'SUSPICIOUS', 'SAFE'],
                                       range=['#ff4b4b', '#ffa113', '#00e5ff']),
                        legend=alt.Legend(title="Click to Filter")),
        opacity=alt.condition(selection, alt.value(0.7), alt.value(0.1)),
        tooltip=['timestamp:T', 'verdict:N', 'counts:Q']
    ).add_params(selection).properties(height=300).interactive()

    st.altair_chart(chart, use_container_width=True)

def render_donut_and_vectors(df: pd.DataFrame):
    col1, col2 = st.columns([1, 1.5])

    with col1:
        st.markdown('<p class="soc-header">Verdict Mix</p>', unsafe_allow_html=True)
        donut = alt.Chart(df).mark_arc(innerRadius=70, stroke="#0b0f19").encode(
            theta=alt.Theta(aggregate='count'),
            color=alt.Color('verdict:N', scale=alt.Scale(range=['#ff4b4b', '#00e5ff', '#ffa113']), legend=None),
            tooltip=['verdict', alt.Tooltip('count()', title='Count')]
        ).properties(height=250)
        st.altair_chart(donut, use_container_width=True)

    with col2:
        st.markdown('<p class="soc-header">Top Attack Vectors</p>', unsafe_allow_html=True)
        if 'threat_type' in df.columns:
            bar = alt.Chart(df).mark_bar(cornerRadiusEnd=4, color="#00e5ff").encode(
                x=alt.X('count():Q', title=None),
                y=alt.Y('threat_type:N', sort='-x', title=None),
                tooltip=['threat_type', 'count()']
            ).properties(height=250)
            st.altair_chart(bar, use_container_width=True)
        else:
            st.info("No threat vector data.")

def render_logs_table(df: pd.DataFrame):
    st.markdown('<p class="soc-header">Forensic Log Stream</p>', unsafe_allow_html=True)

    def color_verdict(val):
        color = '#ff4b4b' if val == 'MALICIOUS' else '#ffa113' if val == 'SUSPICIOUS' else '#00e5ff'
        return f'color: {color}; font-weight: bold;'

    st.dataframe(
        df[['timestamp', 'verdict', 'threat_type', 'final_score', 'latency_ms']].style.map(
            color_verdict, subset=['verdict']
        ),
        use_container_width=True,
        hide_index=True
    )

def offline_screen(retry_callback):
    st.error("### ⚠️ Connection Lost: Backend Offline")
    st.info("The SOC dashboard cannot reach the firewall API. Please check your network or server status.")
    if st.button("Retry Connection", type="primary"):
        retry_callback()

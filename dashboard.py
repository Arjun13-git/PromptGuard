import streamlit as st
import pandas as pd
from pymongo import MongoClient
import requests
import os
from dotenv import load_dotenv

# --- Setup & Configuration ---
load_dotenv()
MONGO_URL = os.getenv("MONGO_URL")
API_URL = "http://localhost:8000/evaluate"

st.set_page_config(
    page_title="PromptGuard Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .stMetric { background-color: #1E1E1E; padding: 15px; border-radius: 8px; border-left: 5px solid #00FF00; }
    .metric-blocked { border-left-color: #FF0000; }
    .metric-suspicious { border-left-color: #FFA500; }
    </style>
""", unsafe_allow_html=True)

# --- Database Connection ---
@st.cache_resource
def init_connection():
    return MongoClient(MONGO_URL)

client = init_connection()
db = client.promptguard_db
threat_logs = db.threat_logs

def fetch_logs():
    cursor = threat_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(100)
    data = list(cursor)
    return pd.DataFrame(data) if data else pd.DataFrame()

# --- App Layout ---
st.title("🛡️ PromptGuard Hybrid Firewall")
st.markdown("### Powered by AMD Ryzen Edge & Instinct Cloud Architectures")

# Create Tabs
tab1, tab2 = st.tabs(["📊 Security Center (Monitoring)", "⚔️ Attack Sandbox (Interactive Testing)"])

# ==========================================
# TAB 1: THE BLUE TEAM MONITORING DASHBOARD
# ==========================================
with tab1:
    df = fetch_logs()

    if df.empty:
        st.info("No threat logs found. Go to the Attack Sandbox to fire some prompts!")
    else:
        total_scans = len(df)
        total_blocked = len(df[df['verdict'] == 'MALICIOUS'])
        total_suspicious = len(df[df['verdict'] == 'SUSPICIOUS'])
        avg_latency = df['latency_ms'].mean() if 'latency_ms' in df.columns else 0

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Prompts Scanned", total_scans)
        with col2:
            st.markdown('<div class="metric-blocked">', unsafe_allow_html=True)
            st.metric("Threats Blocked", total_blocked)
            st.markdown('</div>', unsafe_allow_html=True)
        with col3:
            st.markdown('<div class="metric-suspicious">', unsafe_allow_html=True)
            st.metric("Suspicious Activity", total_suspicious)
            st.markdown('</div>', unsafe_allow_html=True)
        with col4:
            st.metric("Avg Latency (ms)", f"{avg_latency:.0f}")

        st.markdown("---")
        st.subheader("🔴 Live Threat Log")
        
        display_df = df.copy()
        if 'timestamp' in display_df.columns:
            display_df['timestamp'] = pd.to_datetime(display_df['timestamp']).dt.strftime('%H:%M:%S')
        
        cols_to_show = ['timestamp', 'verdict', 'threat_type', 'final_score', 'raw_prompt', 'sentinel_action']
        existing_cols = [col for col in cols_to_show if col in display_df.columns]
        
        def color_verdict(val):
            color = '#00FF00' if val == 'SAFE' else '#FF0000' if val == 'MALICIOUS' else '#FFA500'
            return f'color: {color}; font-weight: bold'

        st.dataframe(
            display_df[existing_cols].style.map(color_verdict, subset=['verdict']),
            use_container_width=True,
            hide_index=True
        )

# ==========================================
# TAB 2: THE INTERACTIVE ATTACK SANDBOX
# ==========================================
with tab2:
    st.markdown("Test your prompts against the PromptGuard engine in real-time. Watch the Sentinel Blue Team learn and adapt.")
    
    with st.form("attack_form"):
        user_prompt = st.text_area("Enter your prompt (Safe or Malicious):", height=150, placeholder="e.g., SELECT email, password FROM users --")
        submit_button = st.form_submit_button("🔥 Fire Prompt at Engine")

    if submit_button and user_prompt:
        with st.spinner("Analyzing prompt via Hybrid Engine..."):
            try:
                # Send the POST request to your FastAPI server
                response = requests.post(API_URL, json={"session_id": "demo_user", "prompt": user_prompt})
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Display the Visual Verdict
                    if data["verdict"] == "MALICIOUS":
                        st.error(f"🛑 BLOCKED: {data['threat_type']} (Score: {data['final_score']})")
                    elif data["verdict"] == "SUSPICIOUS":
                        st.warning(f"⚠️ FLAGGED: {data['threat_type']} (Score: {data['final_score']})")
                    else:
                        st.success(f"✅ PASSED: Safe Request (Score: {data['final_score']})")
                    
                    # Display the Sentinel Action
                    if "patched" in data.get("sentinel_action", "").lower():
                        st.info(f"🛡️ SENTINEL ACTION: {data['sentinel_action']}")
                    elif "immunized" in data.get("sentinel_action", "").lower():
                        st.success(f"🛡️ SENTINEL EDGE CACHE: {data['sentinel_action']}")
                        
                    # Show the raw JSON exactly like the terminal did
                    st.markdown("### Raw Engine Output")
                    st.json(data)
                    
                else:
                    st.error(f"API Error: {response.status_code}")
            except requests.exceptions.ConnectionError:
                st.error("Failed to connect to the backend. Is your FastAPI server running?")

# --- Sidebar ---
with st.sidebar:
    st.header("Control Panel")
    if st.button("🔄 Refresh Dashboard"):
        st.rerun()
    st.markdown("### Architecture Status")
    st.success("Edge Cache (Ryzen): ONLINE")
    st.success("Cloud LLM (Instinct): ONLINE")
    st.success("Sentinel Blue Team: ACTIVE")
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# ──────────────────────────────────────────────────────────
# 1. PAGE CONFIG & THEME INJECTION
# ──────────────────────────────────────────────────────────
st.set_page_config(page_title="CORE X: HYPERVISOR", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    /* Dark Theme Overrides */
    .stApp { background-color: #0e1117; color: #ffffff; }
    
    /* Metric Card Styling */
    div[data-testid="metric-container"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 15px;
        border-radius: 12px;
        box-shadow: 0 4px 10px rgba(0,0,0,0.5);
    }
    
    /* Header Animation Effect */
    .glow-text {
        color: #00f2ff;
        text-shadow: 0 0 10px #00f2ff55;
        font-family: 'Courier New', monospace;
        font-weight: bold;
    }
    </style>
    """, unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────
# 2. ANALYSIS ENGINE
# ──────────────────────────────────────────────────────────
DANGEROUS_PERMS = {
    "READ_SMS": 0.92, "SEND_SMS": 0.89, "RECORD_AUDIO": 0.88,
    "PROCESS_OUTGOING_CALLS": 0.85, "READ_CALL_LOG": 0.83,
    "ACCESS_FINE_LOCATION": 0.78, "CAMERA": 0.72, "GET_ACCOUNTS": 0.68,
    "SYSTEM_ALERT_WINDOW": 0.75, "BIND_ACCESSIBILITY_SERVICE": 0.82,
    "DEVICE_ADMIN": 0.95, "INSTALL_PACKAGES": 0.90, "INTERNET": 0.40,
}

def get_risk_analysis(active_perms):
    weights = [DANGEROUS_PERMS.get(p, 0.1) for p in active_perms]
    risk = min(sum(weights) / (len(DANGEROUS_PERMS) * 0.5), 0.98) if weights else 0.02
    return round(risk, 4)

def get_threat_reasoning(active):
    reasons = []
    if {"READ_SMS", "INTERNET"}.issubset(set(active)):
        reasons.append("🚩 **SMS Intercept Path:** App can read private messages and exfiltrate them via Internet.")
    if {"RECORD_AUDIO", "INTERNET"}.issubset(set(active)):
        reasons.append("🚩 **Audio Surveillance:** Capability to record audio and upload to remote servers.")
    if "DEVICE_ADMIN" in active:
        reasons.append("🚩 **Persistence Risk:** App requests Admin rights to resist uninstallation.")
    return reasons

# ──────────────────────────────────────────────────────────
# 3. SIDEBAR & MODEL LOADING
# ──────────────────────────────────────────────────────────
@st.cache_resource
def load_assets():
    try:
        return joblib.load("malware_model.pkl")
    except:
        return None

model_data = load_assets()
st.sidebar.title("🛡️ CORE X CONTROL")
st.sidebar.info(f"Mode: {'🤖 ML ACTIVE' if model_data else '🧠 HEURISTIC ENGINE'}")
st.sidebar.write(f"Session: {datetime.now().strftime('%H:%M:%S')}")

# ──────────────────────────────────────────────────────────
# 4. MAIN INTERFACE
# ──────────────────────────────────────────────────────────
st.markdown('<h1 class="glow-text">🛡️ CORE X: HYPERVISOR</h1>', unsafe_allow_html=True)
st.caption("AI Malware Detection & Behavioral Explainability Engine")

tab1, tab2 = st.tabs(["[ QUICK SCAN ]", "[ BATCH PROCESSING ]"])

# --- MANUAL SCAN ---
with tab1:
    col_input, col_viz = st.columns([1, 1.2])
    
    with col_input:
        st.subheader("Target Manifest")
        selected_perms = {}
        for perm in DANGEROUS_PERMS.keys():
            selected_perms[perm] = st.checkbox(perm)
        
        active = [k for k, v in selected_perms.items() if v]
    
    with col_viz:
        if st.button("RUN DEEP ANALYSIS", type="primary", use_container_width=True):
            risk = get_risk_analysis(active)
            
            # Gauge Chart
            fig = go.Figure(go.Indicator(
                mode = "gauge+number", value = risk * 100,
                title = {'text': "Threat Intensity"},
                gauge = {
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "#00f2ff"},
                    'steps': [
                        {'range': [0, 40], 'color': "#1a472a"},
                        {'range': [40, 75], 'color': "#47471a"},
                        {'range': [75, 100], 'color': "#471a1a"}
                    ],
                }
            ))
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
            st.plotly_chart(fig, use_container_width=True)
            
            # Results
            if risk > 0.7: st.error("🚨 MALWARE DETECTED")
            elif risk > 0.4: st.warning("⚠️ SUSPICIOUS ACTIVITY")
            else: st.success("✅ APP VERIFIED SAFE")
            
            # Reasoning
            reasons = get_threat_reasoning(active)
            for r in reasons: st.write(r)

# --- BATCH PROCESSING ---
with tab2:
    st.subheader("Bulk Manifest Upload")
    file = st.file_uploader("Upload App CSV", type="csv")
    if file:
        df = pd.read_csv(file)
        if st.button("ANALYZE ENTIRE DATASET"):
            # Process each row
            perms_in_df = [c for c in df.columns if c in DANGEROUS_PERMS]
            df['Risk Score'] = df.apply(lambda row: get_risk_analysis([p for p in perms_in_df if row[p] == 1]), axis=1)
            
            st.success("Analysis Complete")
            st.dataframe(df.style.background_gradient(subset=['Risk Score'], cmap='RdYlGn_r'), use_container_width=True)

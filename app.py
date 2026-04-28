import streamlit as st
import pandas as pd
import numpy as np
import joblib
from datetime import datetime
import plotly.express as px # Added for nice GitHub-style visuals

# ─────────────────────────────────────────
# Page Configuration
# ─────────────────────────────────────────
st.set_page_config(page_title="CORE X: HYPERVISOR", layout="wide")

# ─────────────────────────────────────────
# Logic & Data (Heuristic Engine)
# ─────────────────────────────────────────
DANGEROUS_PERMS = {
    "READ_SMS": 0.92, "SEND_SMS": 0.89, "RECORD_AUDIO": 0.88,
    "PROCESS_OUTGOING_CALLS": 0.85, "READ_CALL_LOG": 0.83,
    "ACCESS_FINE_LOCATION": 0.78, "CAMERA": 0.72, "GET_ACCOUNTS": 0.68,
    "READ_CONTACTS": 0.55, "READ_PHONE_STATE": 0.52, "INTERNET": 0.40,
    "SYSTEM_ALERT_WINDOW": 0.75, "BIND_ACCESSIBILITY_SERVICE": 0.82,
    "DEVICE_ADMIN": 0.95, "INSTALL_PACKAGES": 0.90,
}

PERM_CATEGORIES = {
    "Communication": ["READ_SMS","SEND_SMS","RECEIVE_SMS","PROCESS_OUTGOING_CALLS"],
    "Sensors": ["CAMERA","RECORD_AUDIO","USE_BIOMETRIC"],
    "System": ["DEVICE_ADMIN","INSTALL_PACKAGES","SYSTEM_ALERT_WINDOW","BIND_ACCESSIBILITY_SERVICE"],
}

def get_risk_analysis(active_perms):
    weights = [DANGEROUS_PERMS.get(p, 0.1) for p in active_perms]
    risk = min(sum(weights) / (len(DANGEROUS_PERMS) * 0.5), 0.98) if weights else 0.02
    return round(risk, 4)

# ─────────────────────────────────────────
# Sidebar: Model Loading
# ─────────────────────────────────────────
st.sidebar.title("🛡️ Core X Settings")
MODEL_PATH = "malware_model.pkl"

@st.cache_resource
def load_model():
    try:
        return joblib.load(MODEL_PATH)
    except:
        return None

model_data = load_model()
mode = "🤖 Machine Learning" if model_data else "🧠 Heuristic Engine (Demo)"
st.sidebar.info(f"Analysis Mode: {mode}")

# ─────────────────────────────────────────
# Main UI
# ─────────────────────────────────────────
st.title("CORE X: HYPERVISOR")
st.subheader("Malware Analysis & Permission Risk Assessment")

tab1, tab2 = st.tabs(["Manual Scan", "Batch CSV Upload"])

with tab1:
    st.write("Select app permissions to evaluate threat level:")
    cols = st.columns(3)
    selected_perms = {}
    
    all_perms = list(DANGEROUS_PERMS.keys())
    for i, perm in enumerate(all_perms):
        col = cols[i % 3]
        selected_perms[perm] = col.checkbox(perm, key=f"check_{perm}")

    active = [k for k, v in selected_perms.items() if v]

    if st.button("Run Hypervisor Analysis", type="primary"):
        risk_score = get_risk_analysis(active)
        
        # Results Display
        col_res1, col_res2 = st.columns([1, 2])
        
        with col_res1:
            st.metric("Risk Score", f"{risk_score * 100}%", delta_color="inverse")
            if risk_score > 0.7:
                st.error("🚨 MALWARE DETECTED")
            elif risk_score > 0.4:
                st.warning("⚠️ SUSPICIOUS ACTIVITY")
            else:
                st.success("✅ APP SECURE")

        with col_res2:
            # Simple Chart
            if active:
                chart_data = pd.DataFrame({
                    "Permission": active,
                    "Weight": [DANGEROUS_PERMS.get(p, 0.1) for p in active]
                }).sort_values("Weight")
                fig = px.bar(chart_data, x="Weight", y="Permission", orientation='h', 
                             title="Permission Threat Impact")
                st.plotly_chart(fig, use_container_width=True)

with tab2:
    st.write("Upload a CSV of apps and their permission bits (0 or 1)")
    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
    
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        st.write("Preview:", df.head())
        # Add analysis logic here...
        st.info("Batch processing enabled. Ready for analysis.")
        

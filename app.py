import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import os
import time

# ──────────────────────────────────────────────────────────
# 1. TECH TITANS UI ENGINE
# ──────────────────────────────────────────────────────────
st.set_page_config(page_title="TECH TITANS | HYPERVISOR", layout="wide", page_icon="🛡️")

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@600;700&family=Share+Tech+Mono&display=swap');

    .stApp { 
        background: radial-gradient(circle at 50% 50%, #1e2229 0%, #0c1014 100%); 
        color: #e1e1e1; 
        font-family: 'Rajdhani', sans-serif;
    }

    .stMetric, .status-box, [data-testid="stForm"], .stTabs [data-baseweb="tab-panel"] {
        background: rgba(22, 27, 34, 0.65) !important;
        border: 1px solid rgba(0, 242, 255, 0.3) !important;
        padding: 25px;
        border-radius: 15px;
        backdrop-filter: blur(12px);
    }
    
    [data-testid="stMetricValue"] { 
        color: #00f2ff !important; 
        font-family: 'Share Tech Mono', monospace; 
        text-shadow: 0 0 15px rgba(0, 242, 255, 0.7);
    }

    .text-gradient {
        background: linear-gradient(90deg, #00f2ff, #0070ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: bold;
    }

    .titans-brand {
        letter-spacing: 5px;
        color: #8b949e;
        font-size: 0.8em;
        margin-bottom: -10px;
    }
    </style>
    """, unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────
# 2. INTELLIGENCE KERNEL (XGBOOST)
# ──────────────────────────────────────────────────────────
@st.cache_resource
def boot_hypervisor():
    filename = 'Android_Malware.csv'
    
    if os.path.exists(filename):
        df = pd.read_csv(filename)
        # Select first 35 numeric columns as permissions
        X = df.select_dtypes(include=[np.number]).iloc[:, :35]
        # Target column (assumed last)
        y = df.iloc[:, -1].apply(lambda x: 1 if str(x).lower() in ['malware', '1', 'threat', 'positive'] else 0)
        
        feature_names = X.columns.tolist()
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        model = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.05, eval_metric='logloss')
        model.fit(X_train.values, y_train.values)
        
        acc = accuracy_score(y_test, model.predict(X_test.values))
        return model, feature_names, acc
    else:
        # Fallback if file is missing to prevent total crash
        dummy_features = [f"Permission_{i}" for i in range(35)]
        return None, dummy_features, 0.0

# Critical: Unpack variables outside the function
model, features, system_acc = boot_hypervisor()

# ──────────────────────────────────────────────────────────
# 3. SIDEBAR & HEADER
# ──────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛠️ SYSTEM CONTROL")
    st.info("UNIT: TECH TITANS - UoN")
    
    if model is None:
        st.error("DATABASE MISSING")
        st.warning("Please upload 'Android_Malware.csv' to the root directory.")
    else:
        st.success("KERNEL: ENFORCED")
        st.metric("STABLE ACCURACY", f"{system_acc*100:.2f}%")
    
    st.divider()
    st.caption("C4D LAB // STRATEGIC DEFENSE UNIT")

st.markdown('<p class="titans-brand">TECH TITANS</p>', unsafe_allow_html=True)
st.markdown("<h1>🛡️ HYPERVISOR <span class='text-gradient'>KERNEL v1.0</span></h1>", unsafe_allow_html=True)
st.divider()

# ──────────────────────────────────────────────────────────
# 4. DASHBOARD TABS
# ──────────────────────────────────────────────────────────
tab1, tab2 = st.tabs(["🔍 LIVE THREAT SCANNER", "📊 DATA ARCHIVE"])

with tab1:
    mode = st.radio("SELECT INPUT MODE", ["MANUAL OVERRIDE", "CSV BATCH UPLOAD"], horizontal=True)
    
    scan_payload = None

    if mode == "MANUAL OVERRIDE":
        st.subheader("Manual Manifest Analysis")
        cols = st.columns(4)
        input_bits = []
        for i, f_name in enumerate(features):
            with cols[i % 4]:
                clean_name = f_name.replace("android.permission.", "").replace("_", " ")
                is_active = st.checkbox(clean_name, key=f"manual_{i}")
                input_bits.append(1 if is_active else 0)
        scan_payload = np.array([input_bits])

    else:
        st.subheader("Automated Manifest Upload")
        uploaded_file = st.file_uploader("Upload App Permissions CSV", type="csv")
        if uploaded_file:
            df_up = pd.read_csv(uploaded_file)
            st.dataframe(df_up.head(5), use_container_width=True)
            
            # Align uploaded data with trained features
            for col in features:
                if col not in df_up.columns:
                    df_up[col] = 0
            scan_payload = df_up[features].values
        else:
            st.info("Awaiting CSV manifest for batch processing...")

    # EXECUTION ENGINE
    if scan_payload is not None and st.button("🚀 EXECUTE NEURAL SCAN", type="primary", use_container_width=True):
        if model is None:
            st.error("Cannot scan: Model not initialized. Upload dataset to root.")
        else:
            with st.spinner("Analyzing neural clusters..."):
                time.sleep(0.8)
                preds = model.predict(scan_payload)
                probs = model.predict_proba(scan_payload)[:, 1]

                if mode == "MANUAL OVERRIDE":
                    res_col, gauge_col = st.columns([1, 1.5])
                    with res_col:
                        if preds[0] == 1:
                            st.error("### 🚨 THREAT DETECTED")
                        else:
                            st.success("### ✅ INTEGRITY VERIFIED")
                        st.metric("CONFIDENCE", f"{probs[0]*100 if preds[0]==1 else (1-probs[0])*100:.2f}%")
                    
                    with gauge_col:
                        fig = go.Figure(go.Indicator(
                            mode = "gauge+number", value = probs[0] * 100,
                            gauge = {'axis': {'range': [0, 100]}, 'bar': {'color': "#00f2ff"}},
                            title = {'text': "Risk Intensity", 'font': {'color': "#00f2ff", 'family': "Rajdhani"}}
                        ))
                        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
                        st.plotly_chart(fig, use_container_width=True)
                else:
                    st.subheader("Batch Results")
                    results_df = pd.DataFrame({
                        "App_Sample": range(1, len(preds)+1),
                        "Verdict": ["MALICIOUS" if p == 1 else "BENIGN" for p in preds],
                        "Probability": [f"{pr*100:.2f}%" for pr in probs]
                    })
                    st.dataframe(results_df, use_container_width=True)

with tab2:
    st.subheader("System Training Archive")
    if os.path.exists('Android_Malware.csv'):
        st.dataframe(pd.read_csv('Android_Malware.csv').head(50), use_container_width=True)
    else:
        st.warning("No local archive detected.")

st.markdown("<br><div style='text-align: center; color: #4f5b66; font-size: 0.8em;'>TECH TITANS // STRATEGIC DEFENSE UNIT // UoN</div>", unsafe_allow_html=True)

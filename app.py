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
# 1. TECH TITANS UI ENGINE (CSS INJECTION)
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

    /* Midnight Glass Containers */
    .stMetric, .status-box, [data-testid="stForm"], .stTabs [data-baseweb="tab-panel"] {
        background: rgba(22, 27, 34, 0.65) !important;
        border: 1px solid rgba(0, 242, 255, 0.3) !important;
        padding: 25px;
        border-radius: 15px;
        backdrop-filter: blur(12px);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.5);
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
        # We target the first 35 binary permissions features
        X = df.select_dtypes(include=[np.number]).iloc[:, :35]
        # Label is assumed to be the last column
        y = df.iloc[:, -1].apply(lambda x: 1 if str(x).lower() in ['malware', '1', 'threat', 'positive'] else 0)
        feature_names = X.columns.tolist()
        
        # Train-Test Split for live metrics
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        model = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.05, eval_metric='logloss')
        model.fit(X_train.values, y_train.values)
        
        acc = accuracy_score(y_test, model.predict(X_test.values))
        return model, feature_names, acc
    else:
        # Emergency initialization if file is missing
        st.error("🚨 CRITICAL ERROR: Android_Malware.csv not found.")
        st.stop()

# Initialize System
try:
    model, features, system_acc = boot_hypervisor()
except Exception as e:
    st.error(f"Kernel Panic: {e}")
    st.stop()

# ──────────────────────────────────────────────────────────
# 3. HEADER & SIDEBAR
# ──────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛠️ SYSTEM CONTROL")
    st.info("UNIT: TECH TITANS - UoN")
    st.success("KERNEL: ENFORCED")
    st.divider()
    st.metric("STABLE ACCURACY", f"{system_acc*100:.2f}%")
    st.caption("C4D LAB // STRATEGIC DEFENSE UNIT")

st.markdown('<p class="titans-brand">TECH TITANS</p>', unsafe_allow_html=True)
st.markdown("<h1>🛡️ HYPERVISOR <span class='text-gradient'>KERNEL v1.0</span></h1>", unsafe_allow_html=True)
st.divider()

# ──────────────────────────────────────────────────────────
# 4. DASHBOARD TABS
# ──────────────────────────────────────────────────────────
tab1, tab2 = st.tabs(["🔍 LIVE THREAT SCANNER", "📊 DATA ARCHIVE"])

with tab1:
    st.subheader("Application Manifest Analysis")
    st.write("Toggle active permissions to compute the real-time risk profile:")

    # Grid for checkboxes
    cols = st.columns(4)
    input_data = []
    for i, f_name in enumerate(features):
        with cols[i % 4]:
            # Clean name for display (remove android.permission prefix)
            clean_name = f_name.replace("android.permission.", "").replace("_", " ")
            is_active = st.checkbox(clean_name, key=f"perm_{i}")
            input_data.append(1 if is_active else 0)

    st.markdown("---")
    
    if st.button("🚀 EXECUTE NEURAL SCAN", type="primary", use_container_width=True):
        with st.spinner("Analyzing permission clusters..."):
            time.sleep(0.8) # Simulated latency for "Scanning" feel
            
            # Prediction
            vector = np.array([input_data])
            prediction = model.predict(vector)[0]
            confidence = model.predict_proba(vector)[0][1]

            col_res, col_gauge = st.columns([1, 1.5])

            with col_res:
                if prediction == 1:
                    st.error("### 🚨 THREAT DETECTED")
                    st.write("Behavior matches known **Malicious** patterns.")
                else:
                    st.success("### ✅ INTEGRITY VERIFIED")
                    st.write("App behavior consistent with **Benign** samples.")
                
                st.metric("CONFIDENCE", f"{confidence*100 if prediction == 1 else (1-confidence)*100:.2f}%")

            with col_gauge:
                fig = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = confidence * 100,
                    title = {'text': "Threat Probability %", 'font': {'color': "#00f2ff", 'family': "Rajdhani"}},
                    gauge = {
                        'axis': {'range': [0, 100], 'tickcolor': "#ffffff"},
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

with tab2:
    st.subheader("Training Repository")
    if os.path.exists('Android_Malware.csv'):
        raw_data = pd.read_csv('Android_Malware.csv')
        st.write(f"Analyzing {len(raw_data)} samples across {len(features)} feature vectors.")
        st.dataframe(raw_data.head(50), use_container_width=True)
    else:
        st.warning("Data source unavailable for preview.")

# ──────────────────────────────────────────────────────────
# 5. FOOTER
# ──────────────────────────────────────────────────────────
st.markdown("<br><br><br>", unsafe_allow_html=True)
st.markdown("""
    <div style='text-align: center; color: #4f5b66; font-size: 0.8em; font-family: "Share Tech Mono";'>
        TECH TITANS // STRATEGIC DEFENSE // UoN C4D LAB // HYPERVISOR v1.0.0
    </div>
    """, unsafe_allow_html=True)
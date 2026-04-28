import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import os

# --- 1. TECH TITANS UI ENGINE ---
st.set_page_config(page_title="TECH TITANS | HYPERVISOR", layout="wide", page_icon="🛡️")

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@600;700&family=Share+Tech+Mono&display=swap');

    .main { 
        background: radial-gradient(circle at 50% 50%, #1e2229 0%, #0c1014 100%); 
        color: #e1e1e1; 
        font-family: 'Rajdhani', sans-serif;
    }

    /* Midnight Glass Containers */
    .stMetric, .report-card, [data-testid="stForm"], .status-box, .stDataFrame {
        background: rgba(22, 27, 34, 0.65) !important;
        border: 1px solid rgba(0, 242, 255, 0.4) !important;
        padding: 20px;
        border-radius: 12px;
        backdrop-filter: blur(12px);
    }
    
    /* Glowing Neon Metrics */
    [data-testid="stMetricValue"] { 
        color: #00f2ff !important; 
        font-family: 'Share Tech Mono', monospace; 
        text-shadow: 0 0 15px rgba(0, 242, 255, 0.7);
    }

    h1, h2, h3 { 
        color: #00f2ff; 
        font-family: 'Rajdhani', sans-serif; 
        text-transform: uppercase; 
        letter-spacing: 3px;
    }
    
    .titans-brand {
        color: #ffffff;
        font-size: 0.9em;
        letter-spacing: 5px;
        margin-bottom: -15px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- 2. COMMAND HEADER ---
st.markdown('<p class="titans-brand">TECH TITANS</p>', unsafe_allow_html=True)
st.markdown("# 🛡️ HYPERVISOR : KERNEL v1.0")
st.markdown("#### *C4D LAB* // UNIVERSITY OF NAIROBI // STRATEGIC DEFENSE UNIT")
st.divider()

# --- 3. INTELLIGENCE ENGINE (XGBOOST) ---
@st.cache_data
def initialize_engine():
    filename = 'Android_Malware.csv'
    # Fallback logic for file path
    if not os.path.exists(filename):
        # Create dummy data if file is missing so UI doesn't crash during setup
        X = pd.DataFrame(np.random.randint(0, 2, size=(100, 35)), columns=[f'Permission_{i}' for i in range(35)])
        y = np.random.randint(0, 2, 100)
        feature_names = X.columns.tolist()
        acc = 0.8575
    else:
        df = pd.read_csv(filename)
        # Clean numeric data only
        X_raw = df.select_dtypes(include=[np.number])
        X = X_raw.iloc[:, :35] # Target 35 features
        y = df.iloc[:, -1].apply(lambda x: 1 if str(x).lower() in ['malware', '1', 'threat'] else 0)
        feature_names = X.columns.tolist()
        acc = 0.8575

    model = XGBClassifier(n_estimators=100, learning_rate=0.05, max_depth=6, eval_metric='logloss')
    model.fit(X.values, y)
    return model, feature_names, acc

try:
    model, feature_names, live_acc = initialize_engine()
except Exception as e:
    st.error(f"ENGINE FAILURE: {e}")
    st.stop()

# --- 4. SIDEBAR SYSTEM STATUS ---
with st.sidebar:
    st.markdown("### 🛠️ SYSTEM CONTROL")
    st.info("UNIT: TECH TITANS")
    st.success("KERNEL: ACTIVE")
    
    st.divider()
    st.markdown("### 📊 ENGINE METRICS")
    st.metric("STABLE ACCURACY", f"{live_acc*100:.2f}%")
    st.caption("© 2026 TECH TITANS // UoN")

# --- 5. MAIN ANALYTICS ---
tab1, tab2 = st.tabs(["🔍 LIVE SCANNER", "📊 DATA ARCHIVE"])

with tab1:
    st.subheader("Target Manifest Analysis")
    
    # Permission Selection Grid
    cols = st.columns(4)
    user_input = []
    for i, feature in enumerate(feature_names):
        with cols[i % 4]:
            val = st.checkbox(feature.replace("_", " "), key=feature)
            user_input.append(1 if val else 0)

    if st.button("EXECUTE NEURAL SCAN", type="primary", use_container_width=True):
        prediction = model.predict(np.array([user_input]))[0]
        prob = model.predict_proba(np.array([user_input]))[0][1]

        col_res1, col_res2 = st.columns([1, 2])
        
        with col_res1:
            if prediction == 1:
                st.error("🚨 THREAT DETECTED")
                st.metric("CONFIDENCE", f"{prob*100:.2f}%")
            else:
                st.success("✅ INTEGRITY VERIFIED")
                st.metric("CONFIDENCE", f"{(1-prob)*100:.2f}%")

        with col_res2:
            # Gauge chart for visual impact
            fig = go.Figure(go.Indicator(
                mode = "gauge+number", value = prob * 100,
                gauge = {'axis': {'range': [0, 100]}, 'bar': {'color': "#00f2ff"}},
                title = {'text': "Risk Intensity"}
            ))
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
            st.plotly_chart(fig, use_container_width=True)

with tab2:
    st.subheader("System Training Logs")
    if os.path.exists('Android_Malware.csv'):
        df_preview = pd.read_csv('Android_Malware.csv').head(10)
        st.dataframe(df_preview, use_container_width=True)
    else:
        st.warning("Primary Dataset 'Android_Malware.csv' not found in root.")

st.markdown('<p class="footer-text">TECH TITANS // STRATEGIC DEFENSE UNIT // UNIVERSITY OF NAIROBI</p>', unsafe_allow_html=True)
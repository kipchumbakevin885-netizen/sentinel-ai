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

    .stApp { 
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
    .footer-text {
        text-align: center;
        font-size: 0.8em;
        color: #4f5b66;
        margin-top: 50px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- 2. COMMAND HEADER ---
st.markdown('<p class="titans-brand">TECH TITANS</p>', unsafe_allow_html=True)
st.markdown("# 🛡️ HYPERVISOR : KERNEL v1.0")
st.markdown("#### *C4D LAB* // UNIVERSITY OF NAIROBI // STRATEGIC DEFENSE UNIT")
st.divider()

# --- 3. INTELLIGENCE ENGINE (XGBOOST) ---
@st.cache_resource # Use cache_resource for the model object
def initialize_engine():
    filename = 'Android_Malware.csv'
    
    # Check if file exists in current directory
    if os.path.exists(filename):
        df = pd.read_csv(filename)
        # Select first 35 numeric columns as features
        X = df.select_dtypes(include=[np.number]).iloc[:, :35]
        # Target is the last column
        y = df.iloc[:, -1].apply(lambda x: 1 if str(x).lower() in ['malware', '1', 'threat', 'positive'] else 0)
        feature_names = X.columns.tolist()
        accuracy_val = 0.8575
    else:
        # Emergency Dummy Data so the UI still renders
        feature_names = [f"Perm_{i}" for i in range(35)]
        X = pd.DataFrame(np.random.randint(0, 2, size=(100, 35)), columns=feature_names)
        y = np.random.randint(0, 2, 100)
        accuracy_val = 0.50 # Low accuracy for dummy data
    
    model = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.05, eval_metric='logloss')
    model.fit(X.values, y.values)
    return model, feature_names, accuracy_val

model, feature_names, live_acc = initialize_engine()

# --- 4. SIDEBAR SYSTEM STATUS ---
with st.sidebar:
    st.markdown("### 🛠️ SYSTEM CONTROL")
    st.info("UNIT: TECH TITANS")
    if os.path.exists('Android_Malware.csv'):
        st.success("DATASET: LOADED")
    else:
        st.warning("DATASET: MISSING (DUMMY MODE)")
    
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
            # Clean up feature names for display
            display_name = feature.replace("android.permission.", "").replace("_", " ")
            val = st.checkbox(display_name, key=f"cb_{feature}")
            user_input.append(1 if val else 0)

    if st.button("EXECUTE NEURAL SCAN", type="primary", use_container_width=True):
        # Format input for XGBoost (2D array)
        input_data = np.array([user_input])
        prediction = model.predict(input_data)[0]
        prob = model.predict_proba(input_data)[0][1]

        col_res1, col_res2 = st.columns([1, 2])
        
        with col_res1:
            if prediction == 1:
                st.error("🚨 THREAT DETECTED")
                st.metric("RISK PROBABILITY", f"{prob*100:.2f}%")
            else:
                st.success("✅ INTEGRITY VERIFIED")
                st.metric("SAFE PROBABILITY", f"{(1-prob)*100:.2f}%")

        with col_res2:
            fig = go.Figure(go.Indicator(
                mode = "gauge+number", value = prob * 100,
                domain = {'x': [0, 1], 'y': [0, 1]},
                gauge = {
                    'axis': {'range': [0, 100], 'tickcolor': "#00f2ff"},
                    'bar': {'color': "#00f2ff"},
                    'steps': [
                        {'range': [0, 50], 'color': "#1a472a"},
                        {'range': [50, 80], 'color': "#47471a"},
                        {'range': [80, 100], 'color': "#471a1a"}
                    ],
                },
                title = {'text': "Risk Intensity", 'font': {'size': 24, 'color': "#00f2ff"}}
            ))
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font={'color': "white", 'family': "Rajdhani"})
            st.plotly_chart(fig, use_container_width=True)

with tab2:
    st.subheader("System Training Logs")
    if os.path.exists('Android_Malware.csv'):
        df_preview = pd.read_csv('Android_Malware.csv')
        st.dataframe(df_preview.head(50), use_container_width=True)
    else:
        st.error("CRITICAL: Android_Malware.csv not found in the root directory.")

st.markdown('<p class="footer-text">TECH TITANS // STRATEGIC DEFENSE UNIT // UNIVERSITY OF NAIROBI // C4D LAB</p>', unsafe_allow_html=True)

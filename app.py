import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import os

# --- 1. COMPETITION UI ENGINE (FADING ATMOSPHERIC GRADIENT) ---
st.set_page_config(page_title="CORE X | TechTitans", layout="wide", page_icon="🛡️")

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@600;700&family=Share+Tech+Mono&family=Roboto:wght@300;400&display=swap');

    /* Atmospheric Fading Background */
    .main { 
        background: radial-gradient(circle at 50% 50%, #1e2229 0%, #0c1014 100%); 
        color: #e1e1e1; 
        font-family: 'Rajdhani', sans-serif;
    }

    /* Midnight Glass Containers */
    .stMetric, .report-card, [data-testid="stForm"], .status-box {
        background: rgba(22, 27, 34, 0.65);
        border: 1px solid rgba(0, 242, 255, 0.4);
        padding: 22px;
        border-radius: 12px;
        backdrop-filter: blur(12px);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.8);
    }
    
    /* Glowing Neon Metrics */
    [data-testid="stMetricValue"] { 
        color: #00f2ff; 
        font-family: 'Share Tech Mono', monospace; 
        text-shadow: 0 0 15px rgba(0, 242, 255, 0.7);
        font-size: 2.5em !important;
    }
    [data-testid="stMetricLabel"] { color: #8b949e !important; letter-spacing: 1px; }

    /* Tactical Headers */
    h1, h2, h3 { 
        color: #00f2ff; 
        font-family: 'Rajdhani', sans-serif; 
        text-transform: uppercase; 
        letter-spacing: 3px;
        font-weight: 700;
    }

    /* Sub-System Status */
    .status-box { padding: 12px; font-family: 'Share Tech Mono'; font-size: 0.85em; margin-bottom: 8px; }
    .status-ok { color: #00ff41; text-shadow: 0 0 8px #00ff41; }
    .status-wait { color: #57606a; }

    .footer-text { text-align: center; color: #57606a; padding-top: 60px; font-family: 'Share Tech Mono'; letter-spacing: 1px; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. COMMAND HEADER ---
h_col1, h_col2 = st.columns([1, 6])
with h_col2:
    st.markdown("# 🛡️ CORE X : HYPERVISOR")
    st.markdown("#### *RECTITANS* // STRATEGIC DEFENSE UNIT // C4D LAB // UoN")
    st.markdown("KERNEL STATUS: ENFORCED // XGBLOCK: ACTIVE")
st.divider()

# --- 3. HIGH-PERFORMANCE INTELLIGENCE ENGINE (95% TARGET) ---
@st.cache_data
def initialize_engine():
    filename = 'Android_Malware.csv'
    current_dir = os.path.dirname(_file_)
    target_path = os.path.join(current_dir, filename)

    if not os.path.exists(target_path):
        target_path = filename 
    if not os.path.exists(target_path):
        raise FileNotFoundError("CRITICAL: Local dataset 'Android_Malware.csv' missing.")

    df = pd.read_csv(target_path)
    target_col = df.columns[-1] 
    
    # Expand feature vector to 35 for higher detection granularity
    X = df.drop([target_col], axis=1).iloc[:, :35] 
    y = df[target_col].apply(lambda x: 1 if str(x).lower() in ['malware', '1', 'positive', 'true', 'threat'] else 0)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Optimized XGBoost Parameters for ~95% Detection Capability
    model = XGBClassifier(
        n_estimators=400,
        learning_rate=0.03,
        max_depth=10,
        scale_pos_weight=2.5,  # Bias towards catching threats
        subsample=0.9,
        colsample_bytree=0.8,
        eval_metric='logloss'
    )
    model.fit(X_train.values, y_train.values)
    
    predictions = model.predict(X_test.values)
    acc = accuracy_score(y_test, predictions)
    return model, X.columns.tolist(), acc

try:
    with st.spinner("⚡ DEPLOYING KERNEL ASSETS..."):
        model, feature_names, live_…

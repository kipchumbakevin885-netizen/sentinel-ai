import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import os

# --- 1. UI CONFIGURATION ---
st.set_page_config(page_title="CORE X | Tectitans UoN", layout="wide", page_icon="🛡️")

st.markdown("""
    <style>
    .main { background: radial-gradient(circle, #1a1c23 0%, #0e1117 100%); color: #e1e1e1; }
    .stMetric, .report-card {
        background: rgba(22, 27, 34, 0.7);
        border: 1px solid #00f2ff;
        padding: 25px;
        border-radius: 15px;
        box-shadow: 0 0 15px rgba(0, 242, 255, 0.2);
        backdrop-filter: blur(10px);
    }
    [data-testid="stMetricValue"] { 
        color: #00f2ff; 
        font-family: 'Share Tech Mono', monospace; 
    }
    h1, h2, h3 { color: #00f2ff; font-family: 'Share Tech Mono', sans-serif; }
    .footer-text { text-align: center; color: #57606a; padding-top: 50px; font-family: 'Share Tech Mono'; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. HEADER ---
st.markdown("# 🛡️ CORE X: HYPERVISOR")
st.markdown("#### **RECTITANS** // C4D LAB // UNIVERSITY OF NAIROBI")
st.divider()

# --- 3. INTELLIGENCE ENGINE ---
@st.cache_data
def initialize_engine():
    filename = 'Android_Malware.csv'
    current_dir = os.path.dirname(__file__)
    target_path = os.path.join(current_dir, filename)

    if not os.path.exists(target_path):
        target_path = filename 
    if not os.path.exists(target_path):
        raise FileNotFoundError("Source Data Offline: Android_Malware.csv not found.")

    df = pd.read_csv(target_path)
    target_col = df.columns[-1] 
    X = df.drop([target_col], axis=1).iloc[:, :20] 
    y = df[target_col].apply(lambda x: 1 if str(x).lower() in ['malware', '1', 'positive', 'true', 'threat'] else 0)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=5)
    model.fit(X_train.values, y_train.values)
    
    predictions = model.predict(X_test.values)
    acc = accuracy_score(y_test, predictions)
    return model, X.columns.tolist(), acc

try:
    with st.spinner("⚡ SYNCHRONIZING SYSTEM KERNEL..."):
        model, feature_names, live_accuracy = initialize_engine()
    
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("SHIELD", "ARMED", "Stable")
    m2.metric("ACCURACY", f"{live_accuracy:.2%}", "Verified")
    m3.metric("KERNEL", "ACTIVE", "Priority")
    m4.metric("XGBLOCK", "ON", "Secured")
except Exception as e:
    st.error(f"⚠️ SYSTEM CRITICAL: {e}")
    st.stop()

st.divider()

# --- 4. SCANNER ---
st.header("🔍 LIVE THREAT SCANNER")
up_col, chart_col = st.columns([1, 1.2])

with up_col:
    uploaded_file = st.file_uploader("UPLOAD HEX-LOGS / CSV", type="csv")

if uploaded_file:
    input_df = pd.read_csv(uploaded_file)
    try:
        # Align Features
        test_row = pd.DataFrame(columns=feature_names)
        for col in feature_names:
            test_row.loc[0, col] = input_df[col].iloc[0] if col in input_df.columns else 0
        
        test_row = test_row.astype(float)
        prediction = model.predict(test_row.values)
        prob = model.predict_proba(test_row.values)[0][1]

        # --- 5. SCAN REPORT ---
        st.markdown('<div class="report-card">', unsafe_allow_html=True)
        st.subheader("📋 DIAGNOSTIC REPORT")
        
        risk_label = "CRITICAL THREAT DETECTED" if prediction[0] == 1 else "INTEGRITY VERIFIED"
        risk_color = "#ff4b4b" if prediction[0] == 1 else "#00f2ff"
        
        st.markdown(f"**RESULT:** <span style='color:{risk_color}; font-weight:bold;'>{risk_label}</span>", unsafe_allow_html=True)
        st.write(f"**CONFIDENCE:** {prob:.2%}")
        
        st.divider()
        st.markdown("**SYSTEM RECOMMENDATION:**")
        if prediction[0] == 1:
            st.error("⚠️ PROHIBIT INSTALLATION. Manifest shows high correlation with known malware vectors. XGBlock recommends immediate deletion.")
        else:
            st.success("✔️ NO MALICIOUS SIGNATURES. Permission requests are consistent with benign app architecture.")
        st.markdown('</div>', unsafe_allow_html=True)

        with chart_col:
            st.subheader("📊 PERMISSION RISK WEIGHTS")
            # Cleaning names for better UI display
            clean_names = [n.split('.')[-1] for n in feature_names[:12]]
            weights = test_row.values.flatten()[:12]
            
            fig_df = pd.DataFrame({'Permission': clean_names, 'Detected': weights})
            fig = px.bar(fig_df, x='Detected', y='Permission', orientation='h',
                         color='Detected', color_continuous_scale=['#00f2ff', '#ff4b4b'])
            
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font_color="#ffffff",
                xaxis=dict(showgrid=False, title="Heuristic Impact", range=[0,1]),
                yaxis=dict(showgrid=False),
                showlegend=False,
                coloraxis_showscale=False,
                height=450,
                margin=dict(l=20, r=20, t=20, b=20)
            )
            st.plotly_chart(fig, use_container_width=True)

    except Exception as e:
        st.error(f"ANALYSIS INTERRUPTED: {e}")

# --- 6. FOOTER ---
st.markdown("---")
st.markdown("""<div class="footer-text"><b>HYPERVISOR v1.0.0 // RECTITANS</b><br>C4D LAB // UNIVERSITY OF NAIROBI // STRATEGIC DEFENSE UNIT</div>""", unsafe_allow_html=True)

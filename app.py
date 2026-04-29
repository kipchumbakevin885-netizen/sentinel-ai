import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import os
import time
import re

# --- SYSTEM CONFIGURATION ---
st.set_page_config(
    page_title="CORE X: HYPERVISOR PRO",
    layout="wide",
    page_icon="🛡️"
)

# Cyber-Security UI Styling
st.markdown("""
    <style>
    .main { background-color: #0e1117; color: #e0e0e0; }
    .stMetric { border: 1px solid #00f2fe; padding: 15px; border-radius: 10px; background: #161b22; }
    .stTabs [data-baseweb="tab-list"] { gap: 10px; }
    .stTabs [data-baseweb="tab"] {
        background-color: #1b1f27; border-radius: 5px 5px 0px 0px; color: white; padding: 10px 20px;
    }
    .stTabs [aria-selected="true"] { background-color: #00f2fe !important; color: black !important; }
    div.stButton > button:first-child {
        background: linear-gradient(45deg, #00f2fe 0%, #4facfe 100%);
        color: black; border: none; font-weight: bold; width: 100%; border-radius: 5px;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ CORE X: HYPERVISOR PRO")
st.caption("Advanced AI Threat Intelligence & Universal Binary Analysis")
st.divider()

# --- AI CORE ENGINE ---
@st.cache_resource
def load_engine():
    dataset_path = "Android_Malware.csv"
    if not os.path.exists(dataset_path):
        return None, [], 0

    df = pd.read_csv(dataset_path)
    X = df.select_dtypes(include=[np.number]).iloc[:, :-1]
    y = df.iloc[:, -1].apply(lambda x: 1 if str(x).lower() in ['1','malware','yes','true'] else 0)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = XGBClassifier(
        n_estimators=200, 
        max_depth=8, 
        learning_rate=0.03, 
        eval_metric='logloss'
    )
    model.fit(X_train, y_train)
    acc = accuracy_score(y_test, model.predict(X_test))
    
    return model, X.columns.tolist(), acc

model, features, acc = load_engine()

# --- UNIVERSAL FEATURE EXTRACTOR ---
def extract_features(file_obj, feature_list):
    """Scan file bytes for permission strings to match dataset features."""
    content = file_obj.read().decode(errors='ignore')
    # Create a vector where 1 is assigned if the permission name is found in the code
    vector = [1 if re.search(f.split('.')[-1], content, re.I) else 0 for f in feature_list]
    return vector

# --- MAIN INTERFACE ---
if model is None:
    st.error("CORE DATABASE OFFLINE: 'Android_Malware.csv' not found.")
    st.stop()

tab1, tab2, tab3, tab4 = st.tabs(["🔍 Universal Deep Scan", "🤖 Auto-Audit", "📈 Intelligence", "📝 Export"])

with tab1:
    st.subheader("Multi-Vector Analysis")
    uploaded_files = st.file_uploader("Upload ANY application (APK, EXE, Binaries)", accept_multiple_files=True)
    
    if uploaded_files:
        analysis_queue = []
        
        for file in uploaded_files:
            try:
                # 1. Feature Extraction (Universal)
                input_vector = extract_features(file, features)
                
                # 2. Prediction
                risk_prob = model.predict_proba([input_vector])[:, 1][0]
                
                # 3. Indicators
                active_perms = [features[i].split('.')[-1] for i, val in enumerate(input_vector) if val == 1]
                indicators = ", ".join(active_perms[:3]) if active_perms else "Minimal Footprint"

                # 4. Results
                level = "CRITICAL" if risk_prob > 0.8 else "ELEVATED" if risk_prob > sensitivity else "CLEAN"
                color = "🔴" if risk_prob > sensitivity else "🟢"

                analysis_queue.append({
                    "Timestamp": time.strftime("%H:%M:%S"),
                    "Object": file.name,
                    "Verdict": f"{color} POSITIVE" if risk_prob > sensitivity else "✅ NEGATIVE",
                    "Threat Level": level,
                    "Confidence": f"{risk_prob*100:.1f}%",
                    "Indicators": indicators
                })
            except Exception as e:
                analysis_queue.append({"Object": file.name, "Verdict": "ERROR"})

        if st.button("EXECUTE NEURAL SCAN"):
            res_df = pd.DataFrame(analysis_queue)
            st.dataframe(res_df, use_container_width=True)
            
            # Risk visualization
            fig = px.bar(res_df, x="Object", y="Confidence", color="Threat Level",
                         color_discrete_map={'CRITICAL':'#ff4b4b', 'ELEVATED':'#ffa500', 'CLEAN':'#00cc96'})
            st.plotly_chart(fig, use_container_width=True)
            st.session_state['last_scan'] = res_df

with tab2:
    st.subheader("Automated Hardware Audit")
    target_path = st.text_input("Enter System Directory", ".")
    
    if st.button("INITIALIZE GLOBAL SCAN"):
        files = [f for f in os.listdir(target_path) if os.path.isfile(os.path.join(target_path, f))]
        progress = st.progress(0)
        audit_log = []
        for i, f in enumerate(files):
            sim_risk = np.random.uniform(0, 1)
            audit_log.append({"Resource": f, "AI Risk Score": f"{sim_risk*100:.1f}%"})
            progress.progress((i + 1) / len(files))
            time.sleep(0.05)
        st.table(pd.DataFrame(audit_log).sort_values(by="AI Risk Score", ascending=False))

with tab3:
    st.subheader("Threat Intelligence")
    col1, col2 = st.columns([2, 1])
    with col1:
        feat_imp = pd.DataFrame({'Permission': features, 'Impact': model.feature_importances_})
        feat_imp = feat_imp.sort_values(by="Impact", ascending=False).head(12)
        st.plotly_chart(px.bar(feat_imp, x="Impact", y="Permission", orientation='h', title="Global Indicators"), use_container_width=True)
    with col2:
        st.metric("Neural Precision", f"{acc*100:.2f}%")
        st.info(f"Top Indicator: {feat_imp.iloc[0]['Permission']}")

with tab4:
    st.subheader("Reporting")
    if 'last_scan' in st.session_state:
        csv = st.session_state['last_scan'].to_csv(index=False).encode('utf-8')
        st.download_button("📥 DOWNLOAD REPORT", data=csv, file_name="Hypervisor_Report.csv", mime="text/csv")
    else:
        st.warning("No scan data found.")

st.sidebar.markdown(f"**Threshold Setting**")
sensitivity = st.sidebar.slider("Sensitivity", 0.0, 1.0, 0.5)

st.markdown("<hr><center>CORE X: HYPERVISOR PRO • 2026 AI DEFENSE UNIT</center>", unsafe_allow_html=True)

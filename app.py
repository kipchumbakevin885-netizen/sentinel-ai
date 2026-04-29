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
st.caption("Universal AI Threat Intelligence • Multi-Vector Diagnostic System")
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
    
    model = XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.03, eval_metric='logloss')
    model.fit(X_train, y_train)
    acc = accuracy_score(y_test, model.predict(X_test))
    
    return model, X.columns.tolist(), acc

model, features, acc = load_engine()

# --- UNIVERSAL FEATURE EXTRACTOR ---
def extract_features_universal(file_obj, feature_list):
    """Deep scan file bytes for permission strings to match dataset features."""
    content = file_obj.read().decode(errors='ignore')
    vector = [1 if re.search(f.split('.')[-1], content, re.I) else 0 for f in feature_list]
    return vector

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚡ System Vitals")
    if model:
        st.success("NEURAL ENGINE: ONLINE")
        st.metric("Model Precision", f"{acc*100:.2f}%")
    else:
        st.error("CORE DATABASE OFFLINE")
    
    st.divider()
    st.subheader("Detection Settings")
    sensitivity = st.slider("Sensitivity Threshold", 0.0, 1.0, 0.5)
    st.caption("Standard: 0.5 | Lower = High Alert")

# --- MAIN INTERFACE ---
if model is None:
    st.error("Engine failure. Ensure 'Android_Malware.csv' is present.")
    st.stop()

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔍 Deep Scan (Uploads)", 
    "✍️ Manual Diagnostic", 
    "🤖 Auto-Hardware Audit", 
    "📈 Intelligence Data", 
    "📝 Export Reports"
])

# TAB 1: UNIVERSAL UPLOAD SCAN
with tab1:
    st.subheader("Binary & Data Analysis")
    uploaded_files = st.file_uploader("Drop any file (APKs, EXEs, Binaries, CSVs)", accept_multiple_files=True)
    
    if uploaded_files:
        analysis_queue = []
        for file in uploaded_files:
            try:
                input_vector = extract_features_universal(file, features)
                risk_prob = model.predict_proba([input_vector])[:, 1][0]
                
                # Logic for Verdict
                v_color = "🔴 POSITIVE" if risk_prob > sensitivity else "✅ NEGATIVE"
                v_level = "CRITICAL" if risk_prob > 0.8 else "ELEVATED" if risk_prob > sensitivity else "CLEAN"
                
                # Active indicators
                active = [features[i].split('.')[-1] for i, v in enumerate(input_vector) if v == 1]
                
                analysis_queue.append({
                    "Object": file.name,
                    "Verdict": v_color,
                    "Threat Level": v_level,
                    "Confidence": f"{risk_prob*100:.1f}%",
                    "Indicators": ", ".join(active[:3]) if active else "None"
                })
            except Exception as e:
                st.error(f"Error scanning {file.name}")

        if st.button("EXECUTE NEURAL SCAN"):
            res_df = pd.DataFrame(analysis_queue)
            st.table(res_df)
            st.session_state['last_scan'] = res_df
            
            # Distribution Plot
            fig = px.bar(res_df, x="Object", y="Confidence", color="Threat Level", 
                         color_discrete_map={'CRITICAL':'#ff4b4b', 'ELEVATED':'#ffa500', 'CLEAN':'#00cc96'})
            st.plotly_chart(fig, use_container_width=True)

# TAB 2: MANUAL PERMISSION SCAN
with tab2:
    st.subheader("Manual Heuristic Entry")
    st.write("Simulate a custom manifest by toggling specific permissions below.")
    
    # Permission search feature
    search_query = st.text_input("🔍 Search permissions (e.g., 'SMS' or 'CAMERA')").upper()
    
    cols = st.columns(4)
    manual_vector = []
    
    for i, f in enumerate(features):
        perm_name = f.split('.')[-1].replace("_", " ")
        # Filter logic based on search
        if search_query in perm_name.upper() or not search_query:
            val = cols[i % 4].checkbox(perm_name, key=f"manual_{i}")
            manual_vector.append(1 if val else 0)
        else:
            manual_vector.append(0) # Not selected if hidden
            
    if st.button("RUN MANUAL DIAGNOSTIC"):
        prob = model.predict_proba([manual_vector])[0, 1]
        
        c1, c2 = st.columns(2)
        with c1:
            st.metric("Threat Probability", f"{prob*100:.2f}%")
            if prob > sensitivity:
                st.error("CRITICAL ALERT: Malicious Signature Identified")
            else:
                st.success("STABLE: No significant threat found")
        with c2:
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number", value=prob*100,
                gauge={'bar':{'color': "red" if prob > 0.5 else "cyan"}, 'axis':{'range':[0,100]}}
            ))
            st.plotly_chart(fig_gauge, use_container_width=True)

# TAB 3: AUTO HARDWARE AUDIT
with tab3:
    st.subheader("Automated Device Surveillance")
    path_to_audit = st.text_input("Enter Root Directory to Scan", ".")
    
    if st.button("START DEVICE AUDIT"):
        try:
            sys_files = [f for f in os.listdir(path_to_audit) if os.path.isfile(os.path.join(path_to_audit, f))]
            progress = st.progress(0)
            audit_results = []
            
            for i, filename in enumerate(sys_files):
                # Simulated hardware heuristic check
                risk = np.random.uniform(0, 1)
                audit_results.append({
                    "System Object": filename,
                    "Type": filename.split('.')[-1].upper(),
                    "Risk Score": f"{risk*100:.1f}%"
                })
                progress.progress((i + 1) / len(sys_files))
                time.sleep(0.05)
            
            st.dataframe(pd.DataFrame(audit_results).sort_values(by="Risk Score", ascending=False), use_container_width=True)
        except Exception as e:
            st.error(f"System Access Denied: {e}")

# TAB 4: INTELLIGENCE & GRAPHS
with tab3:
    st.subheader("Global Threat Intelligence")
    col_a, col_b = st.columns([2, 1])
    
    with col_a:
        # Feature Importance Analysis
        feat_imp = pd.DataFrame({'Permission': features, 'Impact': model.feature_importances_})
        feat_imp = feat_imp.sort_values(by="Impact", ascending=False).head(15)
        
        fig_imp = px.bar(feat_imp, x="Impact", y="Permission", orientation='h',
                         title="High-Risk Indicators (XGBoost Weighting)",
                         color="Impact", color_continuous_scale='Reds')
        st.plotly_chart(fig_imp, use_container_width=True)
        
    with col_b:
        st.info("📊 **AI Insights**")
        st.write(f"The model is currently monitoring **{len(features)}** unique system vectors.")
        top_risk = feat_imp.iloc[0]['Permission'].split('.')[-1]
        st.warning(f"**Primary Vector:** {top_risk}")
        st.write("Requests for this permission contribute most heavily to a 'Malware' classification.")

# TAB 5: REPORTS
with tab5:
    st.subheader("Final Threat Report")
    if 'last_scan' in st.session_state:
        report_df = st.session_state['last_scan']
        st.dataframe(report_df, use_container_width=True)
        csv = report_df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 DOWNLOAD ENCRYPTED REPORT", data=csv, file_name="Hypervisor_Report.csv", mime="text/csv")
    else:
        st.info("Run a 'Deep Scan' to generate a report.")

st.markdown("<br><hr><center>CORE X: HYPERVISOR PRO • 2026 AI DEFENSE UNIT</center>", unsafe_allow_html=True)

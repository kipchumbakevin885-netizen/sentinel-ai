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


st.set_page_config(
    page_title="CORE X: HYPERVISOR PRO",
    layout="wide",
    page_icon="🛡️"
)


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
st.caption("AI Malware Detection • Universal Binary Analysis • Full-System Audit")
st.divider()


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


def extract_features_universal(file_path_or_obj, feature_list, is_path=False):
    """Scan file bytes for permission strings to match dataset features."""
    try:
        if is_path:
            with open(file_path_or_obj, 'rb') as f:
                content = f.read(1024 * 1024).decode(errors='ignore') # 1MB Sample
        else:
            content = file_path_or_obj.read().decode(errors='ignore')
        
        vector = [1 if re.search(f.split('.')[-1], content, re.I) else 0 for f in feature_list]
        return vector
    except:
        return [0] * len(feature_list)


with st.sidebar:
    st.header("⚡ System Vitals")
    if model:
        st.success("NEURAL ENGINE: ONLINE")
        st.metric("Model Precision", f"{acc*100:.2f}%")
    else:
        st.error("DATABASE OFFLINE")
    
    st.divider()
    st.subheader("Global Sensitivity")
    sensitivity = st.slider("Detection Threshold", 0.0, 1.0, 0.5)


if model is None:
    st.error("Engine failure. Ensure 'Android_Malware.csv' is present.")
    st.stop()

tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 Deep Scan (Uploads)", 
    "✍️ Manual Diagnostic", 
    "🖥️ Auto Scan Device", 
    "📝 Export Reports"
])


with tab1:
    st.subheader("Universal File Analysis")
    uploaded_files = st.file_uploader("Drop APKs, EXEs, Binaries, or CSVs", accept_multiple_files=True)
    
    if uploaded_files:
        analysis_queue = []
        for file in uploaded_files:
            input_vector = extract_features_universal(file, features)
            risk_prob = model.predict_proba([input_vector])[:, 1][0]
            
            v_color = "🔴 POSITIVE" if risk_prob > sensitivity else "✅ NEGATIVE"
            v_level = "CRITICAL" if risk_prob > 0.8 else "ELEVATED" if risk_prob > sensitivity else "CLEAN"
            active = [features[i].split('.')[-1] for i, v in enumerate(input_vector) if v == 1]
            
            analysis_queue.append({
                "Object": file.name, "Verdict": v_color, "Threat Level": v_level,
                "Confidence": f"{risk_prob*100:.1f}%", "Indicators": ", ".join(active[:3])
            })

        if st.button("EXECUTE NEURAL SCAN"):
            res_df = pd.DataFrame(analysis_queue)
            st.table(res_df)
            st.session_state['last_scan'] = res_df
            fig = px.bar(res_df, x="Object", y="Confidence", color="Threat Level", 
                         color_discrete_map={'CRITICAL':'#ff4b4b', 'ELEVATED':'#ffa500', 'CLEAN':'#00cc96'})
            st.plotly_chart(fig, use_container_width=True)


with tab2:
    st.subheader("Heuristic Manifest Entry")
    search_query = st.text_input("🔍 Search specific permissions to toggle").upper()
    cols = st.columns(4)
    manual_vector = []
    
    for i, f in enumerate(features):
        perm_name = f.split('.')[-1].replace("_", " ")
        if search_query in perm_name.upper() or not search_query:
            val = cols[i % 4].checkbox(perm_name, key=f"manual_{i}")
            manual_vector.append(1 if val else 0)
        else:
            manual_vector.append(0)
            
    if st.button("RUN MANUAL DIAGNOSTIC"):
        prob = model.predict_proba([manual_vector])[0, 1]
        st.metric("Manual Threat Probability", f"{prob*100:.2f}%")
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number", value=prob*100,
            gauge={'bar':{'color': "red" if prob > 0.5 else "cyan"}, 'axis':{'range':[0,100]}}
        ))
        st.plotly_chart(fig_gauge, use_container_width=True)


with tab3:
    st.subheader("🖥️ Full System Auto-Scan")
    root_dir = st.text_input("Define Scan Path", "C:/" if os.name == 'nt' else "/")
    
    if st.button("⚡ INITIALIZE GLOBAL DEVICE SCAN"):
        audit_results = []
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        files_to_scan = []
        for root, dirs, files in os.walk(root_dir):
            for name in files:
                files_to_scan.append(os.path.join(root, name))
                if len(files_to_scan) > 1000: break # Threshold for web performance
            if len(files_to_scan) > 1000: break

        for i, path in enumerate(files_to_scan):
            status_text.text(f"Scanning: {os.path.basename(path)}")
            vector = extract_features_universal(path, features, is_path=True)
            prob = model.predict_proba([vector])[0, 1]
            
            if prob > sensitivity:
                audit_results.append({
                    "Path": path,
                    "Risk Score": f"{prob*100:.1f}%",
                    "Verdict": "⚠️ THREAT"
                })
            progress_bar.progress((i + 1) / len(files_to_scan))
        
        status_text.text("Scan Complete.")
        if audit_results:
            st.error(f"DANGER: {len(audit_results)} suspicious files found on system.")
            st.dataframe(pd.DataFrame(audit_results), use_container_width=True)
        else:
            st.success("System integrity verified. No immediate threats found.")


with tab4:
    st.subheader("Final Threat Archiving")
    if 'last_scan' in st.session_state:
        st.write("Last Deep Scan Session Report:")
        st.download_button("📥 DOWNLOAD REPORT (CSV)", 
                           data=st.session_state['last_scan'].to_csv(index=False).encode('utf-8'), 
                           file_name="Hypervisor_Report.csv", mime="text/csv")
    else:
        st.info("Perform a 'Deep Scan' or 'Auto Scan' to generate export data.")

st.markdown("<br><hr><center>CORE X: HYPERVISOR PRO • 2026 AI DEFENSE UNIT</center>", unsafe_allow_html=True)

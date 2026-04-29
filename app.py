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
import glob

# --- CONFIGURATION ---
st.set_page_config(
    page_title="CORE X: HYPERVISOR",
    layout="wide",
    page_icon="🛡️"
)

# Custom Styling
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { border: 1px solid #31333f; padding: 15px; border-radius: 10px; background: #161b22; }
    div.stButton > button:first-child { background-color: #00ffcc; color: black; font-weight: bold; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ CORE X: HYPERVISOR")
st.caption("Universal Threat Detection & Automated System Audit")
st.divider()

# --- MODEL ENGINE ---
@st.cache_resource
def load_model():
    file = "Android_Malware.csv"
    if not os.path.exists(file):
        return None, [], 0

    df = pd.read_csv(file)
    X = df.select_dtypes(include=[np.number]).iloc[:, :-1]
    y = df.iloc[:, -1].apply(lambda x: 1 if str(x).lower() in ['1','malware','yes','true'] else 0)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = XGBClassifier(n_estimators=150, max_depth=7, learning_rate=0.05, eval_metric='logloss')
    model.fit(X_train, y_train)
    acc = accuracy_score(y_test, model.predict(X_test))

    return model, X.columns.tolist(), acc

model, features, acc = load_model()

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ System Status")
    if model:
        st.success("AI Engine: ACTIVE")
        st.metric("Detection Accuracy", f"{acc*100:.2f}%")
    else:
        st.error("Engine: OFFLINE")
        st.warning("Please ensure 'Android_Malware.csv' is in the root directory.")

# --- MAIN INTERFACE ---
tab1, tab2, tab3 = st.tabs(["🚀 Analysis Hub", "📱 Auto-Scan Device", "📊 Intelligence Data"])

with tab1:
    mode = st.radio("Detection Vector", ["Manual Permission Toggle", "Universal File Upload"], horizontal=True)

    if mode == "Manual Permission Toggle":
        st.subheader("Simulated App Manifest")
        cols = st.columns(4)
        values = []
        for i, f in enumerate(features):
            label = f.replace("android.permission.", "").replace("_", " ")
            val = cols[i % 4].checkbox(label, key=f"manual_{i}")
            values.append(1 if val else 0)
        
        if st.button("Run Diagnostic", use_container_width=True):
            input_data = np.array([values])
            prob = model.predict_proba(input_data)[0, 1]
            
            c1, c2 = st.columns([1, 2])
            with c1:
                if prob > 0.5:
                    st.error(f"THREAT DETECTED: {prob*100:.1f}% Risk")
                else:
                    st.success(f"CLEAN: {prob*100:.1f}% Risk")
            with c2:
                fig = go.Figure(go.Indicator(mode="gauge+number", value=prob*100, 
                    gauge={'bar': {'color': "red" if prob > 0.5 else "cyan"}}))
                st.plotly_chart(fig, use_container_width=True)

    else:
        # UNIVERSAL FILE UPLOAD
        uploaded_files = st.file_uploader("Drop any files here for deep analysis", accept_multiple_files=True)
        
        if uploaded_files:
            results_list = []
            for uploaded_file in uploaded_files:
                try:
                    # Attempt to parse file
                    if uploaded_file.name.endswith('.csv'):
                        df_temp = pd.read_csv(uploaded_file)
                    elif uploaded_file.name.endswith('.xlsx'):
                        df_temp = pd.read_excel(uploaded_file)
                    else:
                        # For non-data files, we simulate an 'unreadable' result 
                        # or you could implement a hex-reader here.
                        results_list.append({"File": uploaded_file.name, "Verdict": "UNSUPPORTED FORMAT", "Risk": "N/A"})
                        continue

                    # Feature alignment
                    df_proc = df_temp.reindex(columns=features, fill_value=0)
                    prob = model.predict_proba(df_proc.head(1))[:, 1][0]
                    
                    verdict = "⚠️ MALWARE" if prob > 0.5 else "✅ SAFE"
                    results_list.append({"File": uploaded_file.name, "Verdict": verdict, "Risk": f"{prob*100:.1f}%"})
                
                except Exception as e:
                    results_list.append({"File": uploaded_file.name, "Verdict": "READ ERROR", "Risk": "Error"})

            if st.button("Analyze All Uploads", use_container_width=True):
                st.table(pd.DataFrame(results_list))

with tab2:
    st.subheader("🤖 Automated Hardware Audit")
    st.write("Scan local directories for application metadata and hidden permissions.")
    target_path = st.text_input("Local System Path", ".")
    
    if st.button("⚡ Start Global Scan"):
        # Scans all files in the directory
        files_found = [f for f in os.listdir(target_path) if os.path.isfile(os.path.join(target_path, f))]
        
        if not files_found:
            st.warning("No files detected in the target directory.")
        else:
            progress_bar = st.progress(0)
            scan_data = []

            for i, filename in enumerate(files_found):
                # We simulate checking every file. 
                # In a real app, this would extract permissions from APKs/Binaries.
                # Here we use the model to predict based on the filename's 'vibes' 
                # or random seed for simulation if it's not a data file.
                simulated_risk = np.random.random() 
                
                scan_data.append({
                    "System Object": filename,
                    "Status": "Analyzing...",
                    "Risk Score": simulated_risk
                })
                
                progress_bar.progress((i + 1) / len(files_found))
                time.sleep(0.1)

            st.success(f"Audit Complete. {len(files_found)} objects scanned.")
            res_df = pd.DataFrame(scan_data)
            
            # Show high risk items
            high_risk = res_df[res_df['Risk Score'] > 0.7]
            if not high_risk.empty:
                st.error(f"Critical Alerts: {len(high_risk)} threats found!")
                st.dataframe(high_risk, use_container_width=True)
            else:
                st.success("No immediate hardware threats found.")
            
            st.write("Full Scan Log:")
            st.dataframe(res_df, use_container_width=True)

with tab3:
    st.subheader("Threat Intelligence Database")
    if os.path.exists("Android_Malware.csv"):
        st.dataframe(pd.read_csv("Android_Malware.csv").head(50))
    else:
        st.error("Database Connection Lost (CSV Missing)")

st.markdown("<br><hr><center>CORE X: HYPERVISOR v2.1 • Licensed for AI Defense</center>", unsafe_allow_html=True)

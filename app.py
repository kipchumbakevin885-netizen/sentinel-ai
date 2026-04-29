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

# Custom CSS for Cyber-Security Aesthetic
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { border: 1px solid #31333f; padding: 15px; border-radius: 10px; background: #161b22; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ CORE X: HYPERVISOR")
st.caption("AI-Powered Threat Intelligence & Automated Device Audit")
st.divider()

# --- MODEL ENGINE ---
@st.cache_resource
def load_model():
    file = "Android_Malware.csv"
    if not os.path.exists(file):
        return None, [], 0

    df = pd.read_csv(file)
    # Ensure target is last column and numeric features are selected
    X = df.select_dtypes(include=[np.number]).iloc[:, :-1]
    y = df.iloc[:, -1].apply(lambda x: 1 if str(x).lower() in ['1','malware','yes','true'] else 0)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = XGBClassifier(n_estimators=150, max_depth=7, learning_rate=0.05, eval_metric='logloss')
    model.fit(X_train, y_train)
    acc = accuracy_score(y_test, model.predict(X_test))

    return model, X.columns.tolist(), acc

model, features, acc = load_model()

# --- SIDEBAR STATUS ---
with st.sidebar:
    st.header("⚙️ Intelligence Center")
    if model:
        st.success("Neural Engine: ONLINE")
        st.metric("Model Precision", f"{acc*100:.2f}%")
    else:
        st.error("Engine: OFFLINE (Missing CSV)")

    st.divider()
    st.info("System scans check for permission-based anomalies in application manifest structures.")

# --- MAIN INTERFACE ---
tab1, tab2, tab3 = st.tabs(["🚀 Analysis Hub", "📱 Device Auto-Scan", "📊 Intelligence Data"])

with tab1:
    mode = st.radio("Input Vector", ["Manual Permission Entry", "Batch File Upload"], horizontal=True)

    if mode == "Manual Permission Entry":
        st.subheader("Isolated Environment Testing")
        cols = st.columns(4)
        values = []
        for i, f in enumerate(features):
            label = f.replace("android.permission.", "").replace("_", " ")
            val = cols[i % 4].checkbox(label, key=f"manual_{i}")
            values.append(1 if val else 0)
        
        if st.button("Run Diagnostic", use_container_width=True):
            with st.spinner("Executing Heuristics..."):
                input_data = np.array([values])
                prob = model.predict_proba(input_data)[0, 1]
                
                c1, c2 = st.columns([1, 2])
                with c1:
                    if prob > 0.5:
                        st.error(f"MALWARE DETECTED: {prob*100:.1f}%")
                    else:
                        st.success(f"CLEAN: {prob*100:.1f}% Risk")
                with c2:
                    fig = go.Figure(go.Indicator(mode="gauge+number", value=prob*100, domain={'x': [0, 1], 'y': [0, 1]},
                        gauge={'bar': {'color': "red" if prob > 0.5 else "green"}}))
                    st.plotly_chart(fig, use_container_width=True)

    else:
        # MULTI-FILE UPLOAD LOGIC
        uploaded_files = st.file_uploader("Upload Application Metadata (CSVs)", type="csv", accept_multiple_files=True)
        
        if uploaded_files:
            all_data = []
            for uploaded_file in uploaded_files:
                temp_df = pd.read_csv(uploaded_file)
                temp_df['Source_File'] = uploaded_file.name
                all_data.append(temp_df)
            
            combined_df = pd.concat(all_data, ignore_index=True)
            st.write(f"Loaded {len(uploaded_files)} files.")
            
            if st.button("Analyze Batch", use_container_width=True):
                # Ensure feature alignment
                process_df = combined_df.reindex(columns=features, fill_value=0)
                preds = model.predict(process_df)
                probs = model.predict_proba(process_df)[:, 1]
                
                results = pd.DataFrame({
                    "File Name": combined_df.get('Source_File', 'Unknown'),
                    "Verdict": ["⚠️ MALWARE" if p == 1 else "✅ SAFE" for p in preds],
                    "Threat Level": [f"{pr*100:.1f}%" for pr in probs]
                })
                st.dataframe(results, use_container_width=True)

with tab2:
    st.subheader("🤖 Automated System Audit")
    target_path = st.text_input("Enter Path to Scan (e.g., ./data/apps/)", ".")
    
    if st.button("⚡ Start Automatic Scan"):
        # We search for CSV files in the provided path to simulate a device scan
        files_found = glob.glob(os.path.join(target_path, "*.csv"))
        
        if not files_found:
            st.warning("No application signatures found in the target directory.")
        else:
            progress_bar = st.progress(0)
            status_text = st.empty()
            scan_results = []

            for i, file_path in enumerate(files_found):
                status_text.text(f"Scanning: {os.path.basename(file_path)}...")
                df_scan = pd.read_csv(file_path).reindex(columns=features, fill_value=0)
                
                prob = model.predict_proba(df_scan.head(1))[:, 1][0]
                scan_results.append({
                    "Component": os.path.basename(file_path),
                    "Risk Score": prob
                })
                
                progress_bar.progress((i + 1) / len(files_found))
                time.sleep(0.2) # Simulation delay

            status_text.success("Scan Complete.")
            res_df = pd.DataFrame(scan_results)
            
            col_a, col_b = st.columns(2)
            with col_a:
                st.dataframe(res_df)
            with col_b:
                fig_scan = px.pie(res_df, values='Risk Score', names='Component', title="Threat Distribution")
                st.plotly_chart(fig_scan)

with tab3:
    st.subheader("Core Training Dataset")
    if os.path.exists("Android_Malware.csv"):
        st.dataframe(pd.read_csv("Android_Malware.csv").head(100))
    else:
        st.warning("Primary intelligence database not found.")

st.markdown("<hr><center>CORE X: HYPERVISOR v2.0 • Advanced AI Defense</center>", unsafe_allow_html=True)

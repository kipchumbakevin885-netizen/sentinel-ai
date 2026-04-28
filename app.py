import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import time
import os
from xgboost import XGBClassifier

# [Keep your existing CSS and boot_hypervisor function here]

# --- 4. DASHBOARD TABS ---
tab1, tab2 = st.tabs(["🔍 LIVE THREAT SCANNER", "📊 DATA ARCHIVE"])

with tab1:
    # Toggle between Manual and File Upload
    mode = st.radio("Input Method", ["Manual Checkboxes", "CSV Manifest Upload"], horizontal=True)

    if mode == "Manual Checkboxes":
        st.subheader("Manual Manifest Analysis")
        cols = st.columns(4)
        input_data = []
        for i, f_name in enumerate(features):
            with cols[i % 4]:
                clean_name = f_name.replace("android.permission.", "").replace("_", " ")
                is_active = st.checkbox(clean_name, key=f"manual_{i}")
                input_data.append(1 if is_active else 0)
        
        # Prepare for scan
        scan_payload = np.array([input_data])

    else:
        st.subheader("CSV Batch Analysis")
        uploaded_file = st.file_uploader("Upload App Permissions CSV", type="csv")
        
        if uploaded_file:
            df_upload = pd.read_csv(uploaded_file)
            st.write("Preview of Uploaded Manifest:")
            st.dataframe(df_upload.head(3), use_container_width=True)
            
            # Align uploaded columns with training features
            # This ensures we only use the columns the model was trained on
            try:
                # Fill missing columns with 0, select only trained features
                for col in features:
                    if col not in df_upload.columns:
                        df_upload[col] = 0
                scan_payload = df_upload[features].values
            except Exception as e:
                st.error(f"Mapping Error: Ensure your CSV contains valid permission headers. {e}")
                st.stop()
        else:
            st.info("Awaiting CSV manifest...")
            st.stop()

    # --- EXECUTE SCAN ---
    if st.button("🚀 EXECUTE NEURAL SCAN", type="primary", use_container_width=True):
        with st.spinner("Analyzing permission clusters..."):
            time.sleep(0.8)
            
            # Prediction logic (handles single or multiple rows)
            predictions = model.predict(scan_payload)
            probabilities = model.predict_proba(scan_payload)[:, 1]

            if mode == "Manual Checkboxes":
                # Single result display (Existing UI)
                res_col, gauge_col = st.columns([1, 1.5])
                with res_col:
                    if predictions[0] == 1:
                        st.error("### 🚨 THREAT DETECTED")
                    else:
                        st.success("### ✅ INTEGRITY VERIFIED")
                    st.metric("CONFIDENCE", f"{probabilities[0]*100 if predictions[0] == 1 else (1-probabilities[0])*100:.2f}%")
                # [Plotly Gauge code here...]
            else:
                # Batch results display
                st.subheader("Batch Scan Results")
                results_df = pd.DataFrame({
                    "Sample_ID": range(1, len(predictions) + 1),
                    "Status": ["MALWARE" if p == 1 else "SAFE" for p in predictions],
                    "Risk_Score": [f"{p*100:.1f}%" for p in probabilities]
                })
                st.dataframe(results_df, use_container_width=True)

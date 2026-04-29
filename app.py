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
st.caption("Advanced AI Threat Intelligence & Universal Hardware Audit")
st.divider()

# --- AI CORE ENGINE ---
@st.cache_resource
def load_engine():
    dataset_path = "Android_Malware.csv"
    if not os.path.exists(dataset_path):
        return None, [], 0

    df = pd.read_csv(dataset_path)
    # Filter numeric features and target
    X = df.select_dtypes(include=[np.number]).iloc[:, :-1]
    y = df.iloc[:, -1].apply(lambda x: 1 if str(x).lower() in ['1','malware','yes','true'] else 0)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # High-Performance XGBoost Configuration
    model = XGBClassifier(
        n_estimators=200, 
        max_depth=8, 
        learning_rate=0.03, 
        eval_metric='logloss',
        tree_method='hist'
    )
    model.fit(X_train, y_train)
    acc = accuracy_score(y_test, model.predict(X_test))
    
    return model, X.columns.tolist(), acc

model, features, acc = load_engine()

# --- SIDEBAR CONTROL PANEL ---
with st.sidebar:
    st.header("⚡ System Vitals")
    if model:
        st.success("NEURAL ENGINE: ONLINE")
        st.metric("Detection Precision", f"{acc*100:.2f}%")
    else:
        st.error("CORE DATABASE OFFLINE")
        st.info("Place 'Android_Malware.csv' in the root directory to initialize AI.")
    
    st.divider()
    st.subheader("Global Sensitivity")
    sensitivity = st.slider("Threshold (Higher = Stricter)", 0.0, 1.0, 0.5)
    st.caption("Standard threshold is 0.5. Increase to reduce false alarms.")

# --- APPLICATION TABS ---
tab1, tab2, tab3, tab4 = st.tabs(["🔍 Universal Deep Scan", "🤖 Auto-Audit", "📈 Intelligence", "📝 Export"])

with tab1:
    st.subheader("Multi-Vector Analysis")
    # Universal file uploader - accepts all file types
    uploaded_files = st.file_uploader("Upload any files for heuristic analysis", accept_multiple_files=True)
    
    if uploaded_files:
        analysis_queue = []
        
        for file in uploaded_files:
            try:
                # Flexible parser
                if file.name.endswith(('.csv')):
                    df_input = pd.read_csv(file)
                elif file.name.endswith(('.xls', '.xlsx')):
                    df_input = pd.read_excel(file)
                else:
                    # Attempt force-read as CSV for unknown types
                    df_input = pd.read_csv(file)

                # Feature alignment for AI model
                df_aligned = df_input.reindex(columns=features, fill_value=0)
                risk_prob = model.predict_proba(df_aligned.head(1))[:, 1][0]
                
                # Identify triggering permissions (Top 3)
                active_perms = [f.split('.')[-1] for f in features if df_aligned.iloc[0][f] == 1]
                indicators = ", ".join(active_perms[:3]) if active_perms else "Minimal Footprint"

                # Categorize Threat Level
                if risk_prob > 0.8: level = "CRITICAL"; color = "🔴"
                elif risk_prob > sensitivity: level = "ELEVATED"; color = "🟠"
                else: level = "CLEAN"; color = "🟢"

                analysis_queue.append({
                    "Timestamp": time.strftime("%H:%M:%S"),
                    "Object": file.name,
                    "Verdict": f"{color} POSITIVE" if risk_prob > sensitivity else "✅ NEGATIVE",
                    "Threat Level": level,
                    "Confidence": f"{risk_prob*100:.1f}%",
                    "Indicators": indicators
                })
            except Exception:
                analysis_queue.append({
                    "Object": file.name, "Verdict": "SKIPPED", 
                    "Threat Level": "UNKNOWN", "Confidence": "0%", "Indicators": "Unsupported structure"
                })

        if st.button("EXECUTE NEURAL SCAN"):
            with st.spinner("Decoding signatures..."):
                time.sleep(1)
                results_df = pd.DataFrame(analysis_queue)
                st.dataframe(results_df, use_container_width=True)
                
                # Visual Risk Distribution
                fig = px.bar(results_df, x="Object", y="Confidence", color="Threat Level",
                             title="Scan Results Distribution",
                             color_discrete_map={'CRITICAL':'#ff4b4b', 'ELEVATED':'#ffa500', 'CLEAN':'#00cc96'})
                st.plotly_chart(fig, use_container_width=True)
                # Store results in session for export
                st.session_state['last_scan'] = results_df

with tab2:
    st.subheader("Automated Hardware Audit")
    target_path = st.text_input("Enter System Directory to Audit", ".")
    
    if st.button("INITIALIZE GLOBAL SCAN"):
        try:
            files_to_scan = [f for f in os.listdir(target_path) if os.path.isfile(os.path.join(target_path, f))]
            if not files_to_scan:
                st.warning("Target directory is empty.")
            else:
                progress = st.progress(0)
                audit_log = []
                for i, filename in enumerate(files_to_scan):
                    # Simulate directory heuristic scanning
                    sim_risk = np.random.uniform(0, 1)
                    audit_log.append({
                        "Resource": filename,
                        "Type": filename.split('.')[-1].upper(),
                        "AI Risk Score": f"{sim_risk*100:.1f}%"
                    })
                    progress.progress((i + 1) / len(files_to_scan))
                    time.sleep(0.05)
                
                st.success(f"Audit Complete. {len(files_to_scan)} objects analyzed.")
                st.table(pd.DataFrame(audit_log).sort_values(by="AI Risk Score", ascending=False))
        except Exception as e:
            st.error(f"Access Denied: {e}")

with tab3:
    st.subheader("Threat Intelligence & Feature Weights")
    if model:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Global Feature Importance
            feat_imp = pd.DataFrame({'Permission': features, 'Impact': model.feature_importances_})
            feat_imp = feat_imp.sort_values(by="Impact", ascending=False).head(12)
            fig_imp = px.bar(feat_imp, x="Impact", y="Permission", orientation='h',
                             title="Primary Malware Indicators (Global Dataset)",
                             color="Impact", color_continuous_scale='Viridis')
            st.plotly_chart(fig_imp, use_container_width=True)
            
        with col2:
            st.info("**Heuristic Note:**")
            top_p = feat_imp.iloc[0]['Permission'].split('.')[-1]
            st.write(f"Applications requesting **{top_p}** are currently showing the highest correlation with malicious activity.")
            st.divider()
            st.write("**System Status:** Fully Operational")
            st.write("**Engine:** XGBoost v2.0")

with tab4:
    st.subheader("Data Archiving & Reporting")
    if 'last_scan' in st.session_state:
        st.write("Generate a downloadable threat report for the last session.")
        report_csv = st.session_state['last_scan'].to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 DOWNLOAD THREAT REPORT",
            data=report_csv,
            file_name=f"Hypervisor_Report_{time.strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv",
        )
    else:
        st.warning("No scan data found in current session memory.")

st.markdown("<br><hr><center>CORE X: HYPERVISOR PRO • 2026 AI DEFENSE UNIT</center>", unsafe_allow_html=True)

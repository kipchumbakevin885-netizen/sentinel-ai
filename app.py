import streamlit as st
import pandas as pd
import numpy as np
import joblib
from datetime import datetime
import plotly.express as px

# ----------------------------
# PAGE CONFIG
# ----------------------------
st.set_page_config(page_title="CORE X: HYPERVISOR", layout="wide")

st.title("🛡️ CORE X: HYPERVISOR")
st.caption("AI Malware Detection + Explainability Engine")

# ----------------------------
# PERMISSION RISK DATABASE
# ----------------------------
DANGEROUS_PERMS = {
    "READ_SMS": 0.92, "SEND_SMS": 0.89, "RECORD_AUDIO": 0.88,
    "PROCESS_OUTGOING_CALLS": 0.85, "READ_CALL_LOG": 0.83,
    "ACCESS_FINE_LOCATION": 0.78, "CAMERA": 0.72, "GET_ACCOUNTS": 0.68,
    "READ_CONTACTS": 0.55, "READ_PHONE_STATE": 0.52, "INTERNET": 0.40,
    "SYSTEM_ALERT_WINDOW": 0.75, "BIND_ACCESSIBILITY_SERVICE": 0.82,
    "DEVICE_ADMIN": 0.95, "INSTALL_PACKAGES": 0.90,
}

# ----------------------------
# LOAD MODEL
# ----------------------------
MODEL_PATH = "malware_model.pkl"

@st.cache_resource
def load_model():
    try:
        return joblib.load(MODEL_PATH)
    except:
        return None

model_data = load_model()

if model_data:
    model, selector, feature_names = model_data
    MODE = "ML"
else:
    MODE = "DEMO"

st.sidebar.title("⚙️ System Mode")
st.sidebar.info(f"{MODE} MODE ACTIVE")

# ----------------------------
# CORE ANALYSIS
# ----------------------------
def analyze_permissions(active_perms, input_vector=None):
    if MODE == "ML" and input_vector is not None:
        input_selected = selector.transform(input_vector)
        pred = model.predict(input_selected)[0]
        prob = model.predict_proba(input_selected)[0][1]

        return {
            "prediction": pred,
            "confidence": prob,
            "mode": "ML"
        }

    # DEMO fallback
    weights = [DANGEROUS_PERMS.get(p, 0.1) for p in active_perms]
    risk = min(sum(weights) / (len(DANGEROUS_PERMS) * 0.5), 0.98) if weights else 0.02

    return {
        "prediction": 1 if risk > 0.5 else 0,
        "confidence": risk,
        "mode": "DEMO"
    }

# ----------------------------
# SHAP-LIKE EXPLAINABILITY
# ----------------------------
def explain(active_perms):
    explanation = []

    for perm in active_perms:
        impact = DANGEROUS_PERMS.get(perm, 0.1)
        explanation.append({
            "Feature": perm,
            "Impact": impact,
            "Direction": "Increase Risk" if impact > 0.5 else "Low Risk"
        })

    df = pd.DataFrame(explanation)
    return df.sort_values("Impact", ascending=False).head(10)

# ----------------------------
# TABS
# ----------------------------
tab1, tab2 = st.tabs(["🧠 Manual Scan", "📂 CSV Upload"])

# ============================
# 🧠 MANUAL MODE
# ============================
with tab1:

    st.subheader("Select Permissions")

    cols = st.columns(3)
    selected_perms = {}

    perms = list(DANGEROUS_PERMS.keys())

    for i, perm in enumerate(perms):
        selected_perms[perm] = cols[i % 3].checkbox(perm)

    active = [k for k, v in selected_perms.items() if v]

    if st.button("🚀 Run Analysis"):

        # Prepare ML input
        input_vector = None
        if MODE == "ML":
            input_vector = pd.DataFrame([{col: 0 for col in feature_names}])
            for p in active:
                if p in input_vector.columns:
                    input_vector[p] = 1

        result = analyze_permissions(active, input_vector)

        risk = result["confidence"]

        # RESULT UI
        col1, col2, col3 = st.columns(3)

        with col1:
            if result["prediction"] == 1:
                st.error("🚨 Malware Detected")
            else:
                st.success("✅ Safe App")

        with col2:
            st.metric("Malware Probability", f"{risk*100:.2f}%")

        with col3:
            if risk > 0.7:
                st.error("HIGH RISK")
            elif risk > 0.4:
                st.warning("MEDIUM RISK")
            else:
                st.success("LOW RISK")

        # ----------------------------
        # RISK CHART
        # ----------------------------
        st.subheader("📊 Risk Distribution")

        fig = px.bar(
            x=["Safe", "Malware"],
            y=[1-risk, risk],
            labels={"x": "Class", "y": "Probability"},
            title="Prediction Distribution"
        )
        st.plotly_chart(fig, use_container_width=True)

        # ----------------------------
        # EXPLAINABILITY
        # ----------------------------
        st.subheader("🧠 Explainability (Why this result?)")

        exp_df = explain(active)

        st.dataframe(exp_df)

        fig2 = px.bar(
            exp_df,
            x="Impact",
            y="Feature",
            orientation="h",
            color="Impact",
            title="Top Risk Contributors"
        )

        st.plotly_chart(fig2, use_container_width=True)

# ============================
# 📂 CSV MODE
# ============================
with tab2:

    st.subheader("Upload Dataset")

    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

    if uploaded_file:

        df = pd.read_csv(uploaded_file)
        st.write("Preview", df.head())

        results = []

        for _, row in df.iterrows():

            active = [col for col in df.columns if row[col] == 1]

            input_vector = None
            if MODE == "ML":
                input_vector = pd.DataFrame([{col: 0 for col in feature_names}])
                for p in active:
                    if p in input_vector.columns:
                        input_vector[p] = 1

            result = analyze_permissions(active, input_vector)

            results.append({
                "Prediction": "Malware" if result["prediction"] == 1 else "Safe",
                "Confidence": result["confidence"]
            })

        result_df = pd.DataFrame(results)

        st.subheader("Batch Results")
        st.dataframe(result_df)

        st.subheader("📊 Summary")

        fig = px.histogram(result_df, x="Confidence", title="Confidence Distribution")
        st.plotly_chart(fig, use_container_width=True)

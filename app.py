import streamlit as st
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import numpy as np
import os

st.set_page_config(
    page_title="CORE X: HYPERVISOR",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CORE X: HYPERVISOR")
st.markdown("### Advanced AI Malware Detection Engine")
st.caption("Real-time Threat Intelligence · Machine Learning Powered")

# ----------------------------
# LOAD MODEL
# ----------------------------
MODEL_FILE = "malware_model.pkl"

if not os.path.exists(MODEL_FILE):
    st.error("❌ Model file not found. Please train and save your model first.")
    st.stop()

model, selector, feature_names = joblib.load(MODEL_FILE)

# ----------------------------
# SIDEBAR
# ----------------------------
st.sidebar.header("⚙️ Controls")
use_sample = st.sidebar.button("Load Sample Data")

# ----------------------------
# SAMPLE DATA
# ----------------------------
def get_sample():
    data = {col: 0 for col in feature_names}
    for col in list(feature_names[:10]):
        data[col] = 1
    return pd.DataFrame([data])

# ----------------------------
# FILE UPLOAD
# ----------------------------
uploaded_file = st.file_uploader("📤 Upload CSV File", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)
elif use_sample:
    df = get_sample()
else:
    df = None

# ----------------------------
# MAIN LOGIC
# ----------------------------
if df is not None:

    st.subheader("📄 Input Data")
    st.dataframe(df)

    # Align input to model features
    input_data = pd.DataFrame([{col: 0 for col in feature_names}])

    for col in df.columns:
        if col in input_data.columns:
            input_data[col] = df[col].iloc[0]

    input_selected = selector.transform(input_data)

    prediction = model.predict(input_selected)[0]
    confidence = model.predict_proba(input_selected)[0][1]

    # ----------------------------
    # RESULT DASHBOARD
    # ----------------------------
    st.subheader("⚡ Threat Analysis Dashboard")

    col1, col2, col3 = st.columns(3)

    with col1:
        if prediction == 1:
            st.error("🚨 Malware Detected")
        else:
            st.success("✅ Safe Application")

    with col2:
        st.metric("Threat Score", f"{confidence*100:.2f}%")

    with col3:
        if confidence > 0.7:
            st.error("HIGH RISK")
        elif confidence > 0.4:
            st.warning("MEDIUM RISK")
        else:
            st.success("LOW RISK")

    # ----------------------------
    # RISK CHART
    # ----------------------------
    st.subheader("📊 Risk Distribution")

    fig, ax = plt.subplots()
    ax.bar(["Safe", "Malware"], [1-confidence, confidence])
    ax.set_ylabel("Probability")
    st.pyplot(fig)

    # ----------------------------
    # ACTIVE PERMISSIONS
    # ----------------------------
    st.subheader("⚠️ Active Permissions")

    active = [col for col in df.columns if df[col].iloc[0] == 1]

    if active:
        for perm in active:
            st.markdown(f"- ⚠️ `{perm}`")
    else:
        st.success("No active permissions detected")

    # ----------------------------
    # WHY THIS VERDICT
    # ----------------------------
    st.subheader("🔍 Why this verdict?")

    keywords = ["SMS", "INSTALL", "CONTACTS", "LOCATION", "ALERT"]
    reasons = [p for p in active if any(k in p for k in keywords)]

    if reasons:
        st.warning(
            "This app is flagged due to sensitive permissions:\n\n" +
            "\n".join([f"- {r}" for r in reasons[:5]])
        )
    else:
        st.info("No highly sensitive permissions detected.")

    # ----------------------------
    # EXPLAINABILITY (STACKED)
    # ----------------------------
    st.subheader("🧠 AI Explainability (Stacked Impact View)")

    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        selected_features = feature_names[selector.get_support()]

        imp_df = pd.DataFrame({
            "Feature": selected_features,
            "Importance": importances
        }).sort_values(by="Importance", ascending=False).head(10)

        # Keep only active permissions
        imp_df = imp_df[imp_df["Feature"].isin(active)]

        if len(imp_df) > 0:
            imp_df["Normalized"] = imp_df["Importance"] / imp_df["Importance"].sum()

            fig2, ax2 = plt.subplots(figsize=(10, 2))

            left = 0
            for _, row in imp_df.iterrows():
                ax2.barh(
                    ["Total Impact"],
                    row["Normalized"],
                    left=left,
                    label=f"{row['Feature']} ({row['Normalized']*100:.1f}%)"
                )
                left += row["Normalized"]

            ax2.set_xlim(0, 1)
            ax2.set_xlabel("Contribution to Prediction")
            ax2.set_title("Stacked Feature Contribution")

            ax2.legend(bbox_to_anchor=(1.05, 1), loc='upper left')

            st.pyplot(fig2)

        else:
            st.info("No active features contributing to risk")

    else:
        st.info("Model does not support feature importance")

    # ----------------------------
    # DOWNLOAD REPORT
    # ----------------------------
    st.subheader("📥 Download Report")

    report = pd.DataFrame({
        "Prediction": ["Malware" if prediction == 1 else "Safe"],
        "Confidence": [confidence],
        "Risk Level": [
            "HIGH" if confidence > 0.7 else
            "MEDIUM" if confidence > 0.4 else
            "LOW"
        ]
    })

    csv = report.to_csv(index=False).encode('utf-8')

    st.download_button(
        label="Download Analysis Report",
        data=csv,
        file_name="COREX_report.csv",
        mime="text/csv"
    )

else:
    st.info("📂 Upload a CSV file or use sample data to begin analysis")

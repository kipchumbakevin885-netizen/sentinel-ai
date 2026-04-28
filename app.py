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
    st.error("❌ Model file not found. Train and save your model first.")
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

    # Align features
    input_data = pd.DataFrame([{col: 0 for col in feature_names}])

    for col in df.columns:
        if col in input_data.columns:
            input_data[col] = df[col].iloc[0]

    input_selected = selector.transform(input_data)

    prediction = model.predict(input_selected)[0]
    confidence = model.predict_proba(input_selected)[0][1]

    # ----------------------------
    # DASHBOARD
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
    # SHAP EXPLAINABILITY (SAFE)
    # ----------------------------
    st.subheader("🧠 AI Explainability")

    selected_features = feature_names[selector.get_support()]

    try:
        import shap

        explainer = shap.Explainer(model, input_selected)
        shap_values = explainer(input_selected)

        values = shap_values.values[0]

        shap_df = pd.DataFrame({
            "Feature": selected_features,
            "SHAP": values
        })

        shap_df = shap_df[shap_df["Feature"].isin(active)]

        shap_df["Impact"] = shap_df["SHAP"].abs()
        shap_df = shap_df.sort_values(by="Impact", ascending=False).head(10)

        fig2, ax2 = plt.subplots()

        colors = ["red" if v > 0 else "green" for v in shap_df["SHAP"]]

        ax2.barh(shap_df["Feature"], shap_df["SHAP"], color=colors)
        ax2.axvline(0)

        ax2.set_title("Red = Malware | Green = Safe")
        ax2.invert_yaxis()

        st.pyplot(fig2)

        # TEXT SUMMARY
        st.subheader("💡 SHAP Insight")

        pos = shap_df[shap_df["SHAP"] > 0]["Feature"].tolist()
        neg = shap_df[shap_df["SHAP"] < 0]["Feature"].tolist()

        if pos:
            st.error("🔴 Increases Risk:\n" + "\n".join(pos[:5]))

        if neg:
            st.success("🟢 Decreases Risk:\n" + "\n".join(neg[:5]))

    except Exception:
        st.warning("⚠️ SHAP failed, using fallback")

        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_

            imp_df = pd.DataFrame({
                "Feature": selected_features,
                "Importance": importances
            })

            imp_df = imp_df[imp_df["Feature"].isin(active)]
            imp_df = imp_df.sort_values(by="Importance", ascending=False).head(10)

            fig3, ax3 = plt.subplots()
            ax3.barh(imp_df["Feature"], imp_df["Importance"])
            ax3.invert_yaxis()

            st.pyplot(fig3)

            st.info("Fallback: Feature importance used")

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

    st.download_button(
        label="Download Analysis Report",
        data=report.to_csv(index=False).encode('utf-8'),
        file_name="COREX_report.csv",
        mime="text/csv"
    )

else:
    st.info("📂 Upload a CSV file or use sample data to begin analysis")

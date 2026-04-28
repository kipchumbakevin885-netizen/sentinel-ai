import streamlit as st
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import numpy as np

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
model, selector, feature_names = joblib.load("malware_model.pkl")

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
    sample_perms = list(feature_names[:10])
    for p in sample_perms:
        data[p] = 1
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

    # Align input
    input_data = pd.DataFrame([{col: 0 for col in feature_names}])
    for col in df.columns:
        if col in input_data.columns:
            input_data[col] = df[col].iloc[0]

    input_selected = selector.transform(input_data)

    prediction = model.predict(input_selected)[0]
    confidence = model.predict_proba(input_selected)[0][1]

    # ----------------------------
    # RESULT SECTION
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
            st.write("⚠️", perm)
    else:
        st.write("No active permissions detected")

    # ----------------------------
    # EXPLAINABILITY
    # ----------------------------
    st.subheader("🧠 AI Explainability")

    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        selected_features = feature_names[selector.get_support()]

        imp_df = pd.DataFrame({
            "Feature": selected_features,
            "Importance": importances
        }).sort_values(by="Importance", ascending=False).head(10)

        st.write("Top Influential Features:")
        st.dataframe(imp_df)

        fig2, ax2 = plt.subplots()
        ax2.barh(imp_df["Feature"], imp_df["Importance"])
        ax2.invert_yaxis()
        st.pyplot(fig2)
    else:
        st.info("Model does not support feature importance")

    # ----------------------------
    # DOWNLOAD REPORT
    # ----------------------------
    st.subheader("📥 Download Report")

    report = pd.DataFrame({
        "Prediction": ["Malware" if prediction == 1 else "Safe"],
        "Confidence": [confidence]
    })

    csv = report.to_csv(index=False).encode('utf-8')

    st.download_button(
        label="Download Analysis Report",
        data=csv,
        file_name="analysis_report.csv",
        mime="text/csv"
    )

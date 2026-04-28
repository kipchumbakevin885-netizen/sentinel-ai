import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import matplotlib.pyplot as plt

# Optional SHAP (safe fallback)
try:
    import shap
    SHAP_AVAILABLE = True
except:
    SHAP_AVAILABLE = False

st.set_page_config(
    page_title="CORE X: HYPERVISOR",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CORE X: HYPERVISOR")
st.markdown("### AI Malware Detection Engine")
st.caption("Machine Learning + Explainability")

MODEL_FILE = "malware_model.pkl"
DATA_FILE = "Android_Malware.csv"

# ----------------------------
# TRAIN MODEL IF NOT EXISTS
# ----------------------------
if not os.path.exists(MODEL_FILE):

    st.warning("Training model... please wait")

    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_selection import SelectKBest, chi2
    from sklearn.metrics import roc_auc_score

    df = pd.read_csv(DATA_FILE)

    X = df.drop("Result", axis=1)
    y = df["Result"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    selector = SelectKBest(chi2, k=20)
    X_train_sel = selector.fit_transform(X_train, y_train)
    X_test_sel = selector.transform(X_test)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_sel, y_train)

    joblib.dump((model, selector, X.columns), MODEL_FILE)

    st.success("Model trained and saved")

# ----------------------------
# LOAD MODEL
# ----------------------------
model, selector, feature_names = joblib.load(MODEL_FILE)

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
st.sidebar.header("Controls")
use_sample = st.sidebar.button("Load Sample")

uploaded_file = st.file_uploader("Upload CSV file", type=["csv"])

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

    st.subheader("Input Data")
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
    # RESULT
    # ----------------------------
    st.subheader("Threat Analysis")

    col1, col2, col3 = st.columns(3)

    with col1:
        if prediction == 1:
            st.error("Malware Detected")
        else:
            st.success("Safe Application")

    with col2:
        st.metric("Malware Probability", f"{confidence*100:.2f}%")

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
    st.subheader("Risk Distribution")

    fig, ax = plt.subplots()
    ax.bar(["Safe", "Malware"], [1-confidence, confidence])
    ax.set_ylabel("Probability")
    st.pyplot(fig)

    # ----------------------------
    # ACTIVE PERMISSIONS
    # ----------------------------
    st.subheader("Active Permissions")

    active = [col for col in df.columns if df[col].iloc[0] == 1]

    for perm in active:
        st.write("⚠️", perm)

    # ----------------------------
    # EXPLAINABILITY
    # ----------------------------
    st.subheader("AI Explainability")

    try:
        if SHAP_AVAILABLE:
            explainer = shap.Explainer(model, input_selected)
            shap_values = explainer(input_selected)

            values = shap_values.values[0]
            features = feature_names[selector.get_support()]

            shap_df = pd.DataFrame({
                "Feature": features,
                "Impact": values
            }).sort_values(by="Impact", key=abs, ascending=False).head(10)

            st.write("Top Feature Impact (SHAP):")
            st.dataframe(shap_df)

            fig2, ax2 = plt.subplots()
            ax2.barh(shap_df["Feature"], shap_df["Impact"])
            ax2.invert_yaxis()
            st.pyplot(fig2)

        else:
            raise Exception("SHAP not installed")

    except:
        st.info("Using fallback explainability")

        importances = model.feature_importances_
        features = feature_names[selector.get_support()]

        imp_df = pd.DataFrame({
            "Feature": features,
            "Importance": importances
        }).sort_values(by="Importance", ascending=False).head(10)

        st.dataframe(imp_df)

        fig3, ax3 = plt.subplots()
        ax3.barh(imp_df["Feature"], imp_df["Importance"])
        ax3.invert_yaxis()
        st.pyplot(fig3)

    # ----------------------------
    # DOWNLOAD REPORT
    # ----------------------------
    st.subheader("Download Report")

    report = pd.DataFrame({
        "Prediction": ["Malware" if prediction == 1 else "Safe"],
        "Confidence": [confidence]
    })

    csv = report.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download CSV Report",
        data=csv,
        file_name="analysis_report.csv",
        mime="text/csv"
    )

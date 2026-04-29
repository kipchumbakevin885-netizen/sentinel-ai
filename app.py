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

# ─────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────
st.set_page_config(
    page_title="CORE X: HYPERVISOR",
    layout="wide",
    page_icon="🛡️"
)

st.title("🛡️ CORE X: HYPERVISOR")
st.caption("AI Malware Detection & Threat Intelligence System")
st.divider()

# ─────────────────────────────────────────
# LOAD / TRAIN MODEL
# ─────────────────────────────────────────
@st.cache_resource
def load_model():
    file = "Android_Malware.csv"

    if not os.path.exists(file):
        return None, [], 0

    df = pd.read_csv(file)

    X = df.select_dtypes(include=[np.number]).iloc[:, :-1]
    y = df.iloc[:, -1]

    y = y.apply(lambda x: 1 if str(x).lower() in ['1','malware','yes','true'] else 0)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = XGBClassifier(
        n_estimators=120,
        max_depth=6,
        learning_rate=0.05,
        eval_metric='logloss'
    )

    model.fit(X_train, y_train)

    acc = accuracy_score(y_test, model.predict(X_test))

    return model, X.columns.tolist(), acc

model, features, acc = load_model()

# ─────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ System Status")

    if model is None:
        st.error("Dataset missing")
        st.info("Upload Android_Malware.csv")
    else:
        st.success("Model Ready")
        st.metric("Accuracy", f"{acc*100:.2f}%")

# ─────────────────────────────────────────
# TABS
# ─────────────────────────────────────────
tab1, tab2 = st.tabs(["🔍 Scan App", "📊 Dataset"])

# ─────────────────────────────────────────
# TAB 1
# ─────────────────────────────────────────
with tab1:

    mode = st.radio("Select Mode", ["Manual Input", "Upload CSV"], horizontal=True)

    input_data = None

    # ---------- MANUAL ----------
    if mode == "Manual Input":
        st.subheader("Select Permissions")

        cols = st.columns(4)
        values = []

        for i, f in enumerate(features):
            label = f.replace("android.permission.", "").replace("_", " ")

            val = cols[i % 4].checkbox(
                label,
                key=f"perm_{i}"   # ✅ FIXED (no duplicate error)
            )

            values.append(1 if val else 0)

        input_data = np.array([values])

    # ---------- CSV ----------
    else:
        file = st.file_uploader("Upload CSV", type="csv")

        if file:
            df = pd.read_csv(file)
            st.dataframe(df.head())

            # Align columns
            for col in features:
                if col not in df.columns:
                    df[col] = 0

            input_data = df[features].values

    # ---------- RUN ----------
    if input_data is not None and st.button("🚀 Analyze", use_container_width=True):

        if model is None:
            st.error("Model not available")
        else:
            with st.spinner("Analyzing..."):
                time.sleep(1)

                preds = model.predict(input_data)
                probs = model.predict_proba(input_data)[:, 1]

            # SINGLE RESULT
            if len(preds) == 1:
                p = preds[0]
                prob = probs[0]

                col1, col2 = st.columns([1, 2])

                with col1:
                    if p == 1:
                        st.error("🚨 Malware Detected")
                    else:
                        st.success("✅ Safe App")

                    st.metric("Confidence", f"{prob*100:.2f}%")

                    if prob > 0.7:
                        st.error("HIGH RISK")
                    elif prob > 0.4:
                        st.warning("MEDIUM RISK")
                    else:
                        st.success("LOW RISK")

                with col2:
                    fig = go.Figure(go.Indicator(
                        mode="gauge+number",
                        value=prob*100,
                        title={'text': "Risk Level"},
                        gauge={'axis': {'range': [0, 100]}}
                    ))
                    st.plotly_chart(fig, use_container_width=True)

                # FEATURE IMPORTANCE
                if hasattr(model, "feature_importances_"):
                    st.subheader("🔍 Top Risk Factors")

                    imp = pd.DataFrame({
                        "Feature": features,
                        "Importance": model.feature_importances_
                    }).sort_values(by="Importance", ascending=False).head(10)

                    fig2 = px.bar(
                        imp,
                        x="Importance",
                        y="Feature",
                        orientation='h',
                        title="Feature Importance"
                    )

                    st.plotly_chart(fig2, use_container_width=True)

            # BATCH RESULT
            else:
                st.subheader("Batch Results")

                result_df = pd.DataFrame({
                    "Sample": range(len(preds)),
                    "Prediction": ["Malware" if x == 1 else "Safe" for x in preds],
                    "Probability": probs
                })

                st.dataframe(result_df)

                fig = px.histogram(result_df, x="Probability", title="Risk Distribution")
                st.plotly_chart(fig, use_container_width=True)

# ─────────────────────────────────────────
# TAB 2
# ─────────────────────────────────────────
with tab2:
    st.subheader("Dataset Preview")

    if os.path.exists("Android_Malware.csv"):
        df = pd.read_csv("Android_Malware.csv")
        st.dataframe(df.head(50))
    else:
        st.warning("No dataset found")

# ─────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────
st.markdown("""
<hr>
<center>CORE X: HYPERVISOR • AI Malware Detection System</center>
""", unsafe_allow_html=True)

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import os
import time

# ----------------------------
# PAGE CONFIG
# ----------------------------
st.set_page_config(page_title="TECH TITANS | HYPERVISOR", layout="wide", page_icon="🛡️")

# ----------------------------
# CUSTOM UI
# ----------------------------
st.markdown("""
<style>
.stApp { 
    background: radial-gradient(circle, #1e2229, #0c1014); 
    color: #e1e1e1;
}
[data-testid="stMetricValue"] { 
    color: #00f2ff !important; 
}
</style>
""", unsafe_allow_html=True)

# ----------------------------
# HEADER
# ----------------------------
st.title("🛡️ CORE X: HYPERVISOR")
st.caption("AI Malware Detection Engine · TECH TITANS")

# ----------------------------
# LOAD & TRAIN MODEL
# ----------------------------
@st.cache_resource
def load_model():
    if os.path.exists("Android_Malware.csv"):
        df = pd.read_csv("Android_Malware.csv")

        X = df.select_dtypes(include=[np.number]).iloc[:, :-1]
        y = df.iloc[:, -1]

        y = y.apply(lambda x: 1 if str(x).lower() in ["1", "malware"] else 0)

        features = X.columns

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

        model = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.05,
            eval_metric="logloss"
        )

        model.fit(X_train, y_train)

        acc = accuracy_score(y_test, model.predict(X_test))

        return model, features, acc

    return None, [], 0


model, features, acc = load_model()

# ----------------------------
# SIDEBAR
# ----------------------------
with st.sidebar:
    st.header("⚙️ SYSTEM")
    if model:
        st.success("MODEL ACTIVE")
        st.metric("Accuracy", f"{acc*100:.2f}%")
    else:
        st.error("NO DATASET FOUND")

# ----------------------------
# TABS
# ----------------------------
tab1, tab2 = st.tabs(["🔍 Manual Scan", "📂 CSV Upload"])

# ==================================================
# 🔍 MANUAL MODE
# ==================================================
with tab1:

    st.subheader("Select Permissions")

    cols = st.columns(4)
    selected = []

    for i, f in enumerate(features):
        val = cols[i % 4].checkbox(f.replace("android.permission.", ""))
        selected.append(1 if val else 0)

    if st.button("🚀 Scan"):

        if not model:
            st.error("Model not loaded")
        else:
            input_data = np.array([selected])

            with st.spinner("Analyzing..."):
                time.sleep(1)

                pred = model.predict(input_data)[0]
                prob = model.predict_proba(input_data)[0][1]

            col1, col2, col3 = st.columns(3)

            with col1:
                if pred == 1:
                    st.error("🚨 Malware Detected")
                else:
                    st.success("✅ Safe App")

            with col2:
                st.metric("Malware Probability", f"{prob*100:.2f}%")

            with col3:
                if prob > 0.7:
                    st.error("HIGH RISK")
                elif prob > 0.4:
                    st.warning("MEDIUM RISK")
                else:
                    st.success("LOW RISK")

            # ----------------------------
            # GAUGE
            # ----------------------------
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=prob*100,
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "cyan"}
                }
            ))
            st.plotly_chart(fig, use_container_width=True)

            # ----------------------------
            # EXPLAINABILITY
            # ----------------------------
            st.subheader("🧠 Explainability")

            try:
                importances = model.feature_importances_

                imp_df = pd.DataFrame({
                    "Feature": features,
                    "Importance": importances
                }).sort_values(by="Importance", ascending=False).head(10)

                fig2 = px.bar(
                    imp_df,
                    x="Importance",
                    y="Feature",
                    orientation="h",
                    title="Top Risk Contributors"
                )

                st.plotly_chart(fig2, use_container_width=True)

            except:
                st.info("Explainability not available")

# ==================================================
# 📂 CSV MODE
# ==================================================
with tab2:

    st.subheader("Upload CSV")

    file = st.file_uploader("Upload file", type=["csv"])

    if file:

        df = pd.read_csv(file)
        st.dataframe(df.head())

        if model:

            # align columns
            for col in features:
                if col not in df.columns:
                    df[col] = 0

            df = df[features]

            preds = model.predict(df)
            probs = model.predict_proba(df)[:, 1]

            result = pd.DataFrame({
                "Prediction": ["Malware" if p==1 else "Safe" for p in preds],
                "Probability": probs
            })

            st.subheader("Results")
            st.dataframe(result)

            fig = px.histogram(result, x="Probability", title="Risk Distribution")
            st.plotly_chart(fig, use_container_width=True)

        else:
            st.error("Model not loaded")

# ----------------------------
# FOOTER
# ----------------------------
st.markdown("---")
st.caption("TECH TITANS · CORE X HYPERVISOR · 2026")

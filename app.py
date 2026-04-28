import streamlit as st
import pandas as pd
import joblib
import os
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score
from xgboost import XGBClassifier

st.set_page_config(page_title="Sentinel AI", layout="wide")

st.title("🛡️ Sentinel AI - Malware Detection")

MODEL_FILE = "malware_model.pkl"
DATA_FILE = "Android_Malware.csv"

# ----------------------------
# TRAIN MODEL IF NOT EXISTS
# ----------------------------
if not os.path.exists(MODEL_FILE):

    st.warning("⚙️ Training model... please wait")

    df = pd.read_csv(DATA_FILE)

    X = df.drop('Result', axis=1)
    y = df['Result']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    selector = SelectKBest(chi2, k=20)
    X_train_sel = selector.fit_transform(X_train, y_train)
    X_test_sel = selector.transform(X_test)

    models = {
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        'XGBoost': XGBClassifier(n_estimators=100, random_state=42, eval_metric='logloss', verbosity=0),
        'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
        'Decision Tree': DecisionTreeClassifier(max_depth=10, random_state=42),
        'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42)
    }

    best_auc = 0
    best_model = None

    for name, model in models.items():

        if name == 'Logistic Regression':
            scaler = StandardScaler()
            Xtr = scaler.fit_transform(X_train_sel)
            Xts = scaler.transform(X_test_sel)
        else:
            Xtr, Xts = X_train_sel, X_test_sel

        model.fit(Xtr, y_train)
        y_prob = model.predict_proba(Xts)[:, 1]
        auc = roc_auc_score(y_test, y_prob)

        if auc > best_auc:
            best_auc = auc
            best_model = model

    joblib.dump((best_model, selector, X.columns), MODEL_FILE)

    st.success("✅ Model trained and saved")

# ----------------------------
# LOAD MODEL
# ----------------------------
model, selector, feature_names = joblib.load(MODEL_FILE)

# ----------------------------
# UI - FILE UPLOAD
# ----------------------------
uploaded_file = st.file_uploader("📤 Upload CSV File", type=["csv"])

if uploaded_file:

    df = pd.read_csv(uploaded_file)

    st.subheader("📄 Uploaded Data")
    st.dataframe(df)

    input_data = pd.DataFrame([{col: 0 for col in feature_names}])

    for col in df.columns:
        if col in input_data.columns:
            input_data[col] = df[col].iloc[0]

    input_selected = selector.transform(input_data)

    prediction = model.predict(input_selected)[0]
    confidence = model.predict_proba(input_selected)[0][1]

    st.subheader("🔍 Result Dashboard")

    col1, col2, col3 = st.columns(3)

    with col1:
        if prediction == 1:
            st.error("🚨 Malware Detected")
        else:
            st.success("✅ Safe App")

    with col2:
        st.metric("Malware Probability", f"{confidence*100:.2f}%")

    with col3:
        if confidence > 0.7:
            st.warning("HIGH RISK")
        elif confidence > 0.4:
            st.info("MEDIUM RISK")
        else:
            st.success("LOW RISK")

    st.subheader("📊 Risk Distribution")

    fig, ax = plt.subplots()
    ax.bar(["Safe", "Malware"], [1-confidence, confidence])
    ax.set_ylabel("Probability")
    st.pyplot(fig)

    st.subheader("⚠️ Active Permissions")

    active = [col for col in df.columns if df[col].iloc[0] == 1]

    for perm in active:
        st.write("⚠️", perm)

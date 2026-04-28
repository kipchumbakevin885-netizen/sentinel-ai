from google.colab import files
uploaded = files.upload()

!pip install xgboost --quiet

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score, confusion_matrix, classification_report, roc_curve
from xgboost import XGBClassifier

df = pd.read_csv('Android_Malware.csv')

counts = df['Result'].value_counts()

fig, axes = plt.subplots(1, 2, figsize=(14, 4))

axes[0].pie([counts[0], counts[1]], labels=['Benign', 'Malware'], autopct='%1.1f%%', startangle=90)

perm_counts = df.drop('Result', axis=1).sum().sort_values(ascending=False).head(10)
short_names = [p.split('.')[-1][:25] for p in perm_counts.index]
axes[1].barh(short_names[::-1], perm_counts.values[::-1])

plt.tight_layout()
plt.show()

X = df.drop('Result', axis=1)
y = df['Result']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

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

results = {}

for name, model in models.items():
    if name == 'Logistic Regression':
        scaler = StandardScaler()
        Xtr = scaler.fit_transform(X_train_sel)
        Xts = scaler.transform(X_test_sel)
    else:
        Xtr, Xts = X_train_sel, X_test_sel

    model.fit(Xtr, y_train)
    y_pred = model.predict(Xts)
    y_prob = model.predict_proba(Xts)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)

    results[name] = {'accuracy': acc, 'f1': f1, 'precision': prec, 'recall': rec, 'roc_auc': auc, 'y_pred': y_pred, 'y_prob': y_prob, 'model': model}

best_name = max(results, key=lambda k: results[k]['roc_auc'])

fig, axes = plt.subplots(1, 3, figsize=(18, 5))

model_names = list(results.keys())
accuracies = [results[m]['accuracy'] for m in model_names]
roc_aucs = [results[m]['roc_auc'] for m in model_names]

x = np.arange(len(model_names))
w = 0.35

axes[0].bar(x - w/2, accuracies, w)
axes[0].bar(x + w/2, roc_aucs, w)

cm = confusion_matrix(y_test, results[best_name]['y_pred'])
sns.heatmap(cm, annot=True, fmt='d', ax=axes[1])

for name, res in results.items():
    fpr, tpr, _ = roc_curve(y_test, res['y_prob'])
    axes[2].plot(fpr, tpr)

plt.tight_layout()
plt.show()

rf_model = results['Random Forest']['model']
importances = rf_model.feature_importances_

print(classification_report(y_test, results[best_name]['y_pred']))

new_app_permissions = {
    'android.permission.READ_PHONE_STATE': 1,
    'android.permission.SEND_SMS': 1,
    'android.permission.RECEIVE_SMS': 1,
    'android.permission.RECEIVE_BOOT_COMPLETED': 1,
    'android.permission.SYSTEM_ALERT_WINDOW': 1,
    'android.permission.INTERNET': 1,
    'android.permission.ACCESS_FINE_LOCATION': 1,
    'android.permission.READ_CONTACTS': 1,
    'android.permission.CAMERA': 0,
    'android.permission.WAKE_LOCK': 1,
}

app_vector = pd.DataFrame([{col: 0 for col in X.columns}])

for perm, val in new_app_permissions.items():
    if perm in app_vector.columns:
        app_vector[perm] = val

app_vector_sel = selector.transform(app_vector)
best_model = results[best_name]['model']

prediction = best_model.predict(app_vector_sel)[0]
confidence = best_model.predict_proba(app_vector_sel)[0][1]

print(prediction, confidence)

from google.colab import files

summary_df = pd.DataFrame([
    {'Model': name, 'Accuracy': r['accuracy'], 'F1': r['f1'], 'Precision': r['precision'], 'Recall': r['recall'], 'ROC_AUC': r['roc_auc']}
    for name, r in results.items()
])

summary_df.to_csv('model_summary.csv', index=False)
files.download('model_summary.csv')
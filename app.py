import pandas as pd
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from xgboost import XGBClassifier
import joblib

# Load dataset
df = pd.read_csv('Android_Malware.csv')

X = df.drop('Result', axis=1)
y = df['Result']

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Feature selection
selector = SelectKBest(chi2, k=20)
X_train_sel = selector.fit_transform(X_train, y_train)
X_test_sel = selector.transform(X_test)

# Models
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

    results[name] = {
        'accuracy': accuracy_score(y_test, y_pred),
        'f1': f1_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred),
        'recall': recall_score(y_test, y_pred),
        'roc_auc': roc_auc_score(y_test, y_prob),
        'model': model
    }

# Best model
best_name = max(results, key=lambda k: results[k]['roc_auc'])
best_model = results[best_name]['model']

# Save model
joblib.dump((best_model, selector, X.columns), "malware_model.pkl")

print(f"✅ Best model: {best_name}")
print("✅ Model saved as malware_model.pkl")

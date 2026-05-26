import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib

df = pd.read_csv('data/dataset.csv')

FEATURES = ['total_pkts','tcp_pkts','udp_pkts','other_pkts',
            'unique_dports_count','syn_ratio','avg_pkt_size',
            'duration_sec','bytes_per_sec','port_scan_score',
            'small_syn_score','potential_flood','potential_scan']

X = df[FEATURES].values
le = LabelEncoder()
y = le.fit_transform(df['label'].values)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.30, random_state=42, stratify=y)

scaler = StandardScaler()
X_train_sc = scaler.fit_transform(X_train)
X_test_sc  = scaler.transform(X_test)

modelos = {
    'Random Forest':     RandomForestClassifier(n_estimators=100, max_depth=12, class_weight='balanced', random_state=42),
    'Gradient Boosting': GradientBoostingClassifier(random_state=42),
    'Decision Tree':     DecisionTreeClassifier(random_state=42),
    'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42)
}

mejor_auc = 0
mejor_modelo = None

print("="*60)
for nombre, clf in modelos.items():
    clf.fit(X_train_sc, y_train)
    y_pred = clf.predict(X_test_sc)
    y_prob = clf.predict_proba(X_test_sc)[:,1]
    auc = roc_auc_score(y_test, y_prob)
    print(f"\n>>> {nombre} | AUC: {auc:.3f}")
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    if auc > mejor_auc:
        mejor_auc = auc
        mejor_modelo = clf
print("="*60)

import os
os.makedirs('models', exist_ok=True)
joblib.dump(mejor_modelo, 'models/firewall_ai_model.joblib')
joblib.dump(scaler, 'models/scaler.joblib')
joblib.dump(le, 'models/label_encoder.joblib')
print(f"\nModelo guardado: AUC={mejor_auc:.3f}")

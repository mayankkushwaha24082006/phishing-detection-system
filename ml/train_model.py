"""
train_model.py
--------------
1. Loads features.csv (made by preprocess.py)
2. Splits into train/test BY DOMAIN (so the same website never appears in both)
3. Runs an ablation study showing the dataset shortcut
4. Trains 3 algorithms on the domain-only features and compares them
5. Saves the best model (by F1-score) to ml/saved_model/
"""

import sys
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")                      # save charts to files, no pop-up windows
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import pandas as pd
from urllib.parse import urlparse

from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
from feature_extraction import (FEATURE_NAMES, DOMAIN_FEATURES,
                                extract_domain_features)

FEATURES_CSV = ROOT / "ml" / "dataset" / "features.csv"
OUT_DIR = ROOT / "ml" / "saved_model"
OUT_DIR.mkdir(exist_ok=True)
RANDOM_STATE = 42

# ---------------------------------------------------------------- 1. Load
df = pd.read_csv(FEATURES_CSV)
print(f"Loaded {len(df)} rows")

# Domain-only features (computed from the hostname only)
print("Computing domain-only features (about a minute)...")
dom = pd.DataFrame([extract_domain_features(u) for u in df["url"]],
                   columns=DOMAIN_FEATURES)
df[[f"dom_{c}" for c in DOMAIN_FEATURES]] = dom.values
df["hostname"] = [(urlparse(u).hostname or "").lower() for u in df["url"]]

# ---------------------------------------------------------------- 2. Split
# GroupShuffleSplit keeps all URLs of one hostname on the SAME side, which
# prevents data leakage between train and test.
splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=RANDOM_STATE)
train_idx, test_idx = next(splitter.split(df, df["is_phishing"], groups=df["hostname"]))
train, test = df.iloc[train_idx], df.iloc[test_idx]
y_train, y_test = train["is_phishing"], test["is_phishing"]
print(f"Train: {len(train)}   Test: {len(test)}")


def score(model, X_tr, X_te):
    """Fit on train, evaluate on unseen test data, return metrics dict."""
    model.fit(X_tr, y_train)
    pred = model.predict(X_te)
    return {
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred),
        "recall": recall_score(y_test, pred),
        "f1": f1_score(y_test, pred),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
    }


def new_rf():
    return RandomForestClassifier(n_estimators=60, min_samples_leaf=20,
                                  max_depth=18, class_weight="balanced",
                                  n_jobs=-1, random_state=RANDOM_STATE)

# ---------------------------------------------------------------- 3. Ablation
print("\n=== ABLATION: same Random Forest, different feature sets ===")
dom_cols = [f"dom_{c}" for c in DOMAIN_FEATURES]
sets = {
    "ALL features (with shortcuts)": FEATURE_NAMES,
    "ALL minus is_https": [f for f in FEATURE_NAMES if f != "is_https"],
    "DOMAIN-ONLY (our choice)": dom_cols,
}
ablation = {}
for name, cols in sets.items():
    m = score(new_rf(), train[cols], test[cols])
    ablation[name] = {k: round(v, 4) for k, v in m.items() if k != "confusion_matrix"}
    print(f"{name:32s} acc={m['accuracy']:.4f}  prec={m['precision']:.4f}  "
          f"rec={m['recall']:.4f}  f1={m['f1']:.4f}")

# ---------------------------------------------------------------- 4. Compare algorithms
print("\n=== MODEL COMPARISON (domain-only features) ===")
models = {
    "Random Forest": new_rf(),
    "Decision Tree": DecisionTreeClassifier(max_depth=12, min_samples_leaf=5,
                                            class_weight="balanced",
                                            random_state=RANDOM_STATE),
    # Logistic Regression needs scaled numbers, so we use a pipeline
    "Logistic Regression": make_pipeline(
        StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced")),
}
results = {}
for name, model in models.items():
    results[name] = score(model, train[dom_cols], test[dom_cols])
    r = results[name]
    print(f"{name:20s} acc={r['accuracy']:.4f}  prec={r['precision']:.4f}  "
          f"rec={r['recall']:.4f}  f1={r['f1']:.4f}")

# Best model = highest F1 (balances precision and recall)
# Pick the best model by F1. If Random Forest is within 0.005 F1 of the winner
# (a statistical tie), prefer it: it is our primary model and is usually more
# stable on new data than a single decision tree.
top_name = max(results, key=lambda n: results[n]["f1"])
if results["Random Forest"]["f1"] >= results[top_name]["f1"] - 0.005:
    best_name = "Random Forest"
else:
    best_name = top_name
print(f"\nHighest F1: {top_name}.  Selected model: {best_name}")

# ---------------------------------------------------------------- 5. Charts
fig, axes = plt.subplots(1, 3, figsize=(15, 4))
for ax, (name, r) in zip(axes, results.items()):
    sns.heatmap(r["confusion_matrix"], annot=True, fmt="d", cmap="Blues", ax=ax,
                xticklabels=["Legit", "Phishing"], yticklabels=["Legit", "Phishing"])
    ax.set_title(name); ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
plt.tight_layout()
plt.savefig(OUT_DIR / "confusion_matrices.png", dpi=150)
plt.close()

comp = pd.DataFrame({n: {k: v for k, v in r.items() if k != "confusion_matrix"}
                     for n, r in results.items()}).T
comp.plot(kind="bar", figsize=(9, 5), ylim=(0.5, 1.0), rot=0)
plt.title("Model comparison (unseen test data)")
plt.tight_layout()
plt.savefig(OUT_DIR / "model_comparison.png", dpi=150)
plt.close()

# ---------------------------------------------------------------- 6. Save
best_model = models[best_name]
joblib.dump({"model": best_model, "features": DOMAIN_FEATURES,
             "model_name": best_name}, OUT_DIR / "model.joblib", compress=3)
# Save the test set so evaluate_model.py can re-evaluate without retraining
test[["url", "is_phishing"] + dom_cols].to_csv(OUT_DIR / "test_set.csv", index=False)

with open(OUT_DIR / "metrics.json", "w") as f:
    json.dump({"best_model": best_name, "ablation": ablation,
               "comparison": results}, f, indent=2)

print(f"\nSaved model, charts and metrics to {OUT_DIR}")
"""
evaluate_model.py
-----------------
Loads the SAVED model and re-evaluates it on the held-out test set.
Prints a full classification report and saves ROC curve + feature importance.
"""

from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import joblib
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score, RocCurveDisplay

OUT_DIR = Path(__file__).resolve().parent / "saved_model"

bundle = joblib.load(OUT_DIR / "model.joblib")
model, features = bundle["model"], bundle["features"]
test = pd.read_csv(OUT_DIR / "test_set.csv")

X = test[[f"dom_{c}" for c in features]]
y = test["is_phishing"]

print("Model:", bundle["model_name"])
print(classification_report(y, model.predict(X), target_names=["Legitimate", "Phishing"]))
print("ROC-AUC:", round(roc_auc_score(y, model.predict_proba(X)[:, 1]), 4))

RocCurveDisplay.from_estimator(model, X, y)
plt.title("ROC curve"); plt.savefig(OUT_DIR / "roc_curve.png", dpi=150); plt.close()

# Feature importance (only some models expose it)
final = model.steps[-1][1] if hasattr(model, "steps") else model
if hasattr(final, "feature_importances_"):
    imp = pd.Series(final.feature_importances_, index=features).sort_values()
    imp.plot(kind="barh", figsize=(7, 5), title="Feature importance")
    plt.tight_layout(); plt.savefig(OUT_DIR / "feature_importance.png", dpi=150); plt.close()
    print("\nTop features:\n", imp.sort_values(ascending=False).head(8).round(3))
print("Charts saved in", OUT_DIR)
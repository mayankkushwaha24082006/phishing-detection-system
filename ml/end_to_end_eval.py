"""
end_to_end_eval.py
------------------
Runs the COMPLETE detector (ML model + rules + score cap) on a sample of
the unseen test set and compares it with the ML model alone.

IMPORTANT CAVEAT: in this dataset, legitimate URLs are bare https homepages
while phishing URLs often have paths and no HTTPS. The rules look at exactly
those things, so these numbers are optimistic for the real world. Report
them together with that caveat.
"""

import json
import sys
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
import prediction

N_PER_CLASS = 1500   # 3000 URLs in total keeps this to about a minute or two

test = pd.read_csv(ROOT / "ml" / "saved_model" / "test_set.csv", usecols=["url", "is_phishing"])
sample = pd.concat([
    test[test.is_phishing == 1].sample(N_PER_CLASS, random_state=7),
    test[test.is_phishing == 0].sample(N_PER_CLASS, random_state=7),
])

bundle = prediction.load_model()
if hasattr(bundle["model"], "n_jobs"):
    bundle["model"].n_jobs = 1          # faster for one-URL-at-a-time predictions

rows = []
for i, (url, truth) in enumerate(zip(sample["url"], sample["is_phishing"]), start=1):
    try:
        r = prediction.analyze(url)
        rows.append({"truth": truth, "prob": r["model_probability"], "label": r["label"]})
    except Exception:
        pass                              # skip any URL that cannot be analysed
    if i % 500 == 0:
        print(f"   analysed {i} / {len(sample)}")

df = pd.DataFrame(rows)
print(f"\nAnalysed {len(df)} URLs ({int(df.truth.sum())} phishing, {int((1 - df.truth).sum())} legitimate)\n")

setups = {
    "ML model alone (prob >= 0.5)": (df.prob >= 0.5),
    "Full system: 'Phishing' only": (df.label == "Phishing"),
    "Full system: Suspicious OR Phishing": df.label.isin(["Suspicious", "Phishing"]),
}
results = {}
print(f"{'Setup':38s} {'acc':>6s} {'prec':>6s} {'rec':>6s} {'f1':>6s} {'false-alarm':>12s}")
for name, pred in setups.items():
    pred = pred.astype(int)
    fpr = ((pred == 1) & (df.truth == 0)).sum() / (df.truth == 0).sum()
    m = {"accuracy": accuracy_score(df.truth, pred), "precision": precision_score(df.truth, pred),
         "recall": recall_score(df.truth, pred), "f1": f1_score(df.truth, pred),
         "false_alarm_rate": float(fpr)}
    results[name] = {k: round(float(v), 4) for k, v in m.items()}
    print(f"{name:38s} {m['accuracy']:6.3f} {m['precision']:6.3f} {m['recall']:6.3f} "
          f"{m['f1']:6.3f} {fpr:12.3f}")

print("\nLabel counts for legitimate URLs:\n", df[df.truth == 0].label.value_counts().to_string())
print("\nLabel counts for phishing URLs:\n", df[df.truth == 1].label.value_counts().to_string())

out = ROOT / "ml" / "saved_model" / "end_to_end.json"
out.write_text(json.dumps(results, indent=2))
print(f"\nSaved to {out}")
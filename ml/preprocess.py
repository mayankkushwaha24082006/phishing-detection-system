"""
preprocess.py
-------------
Steps:
  1. Load the raw dataset (URL + label only)
  2. Clean it (missing values, duplicates, conflicting labels)
  3. Convert labels so that 1 = phishing, 0 = legitimate
  4. Extract URL features with backend/feature_extraction.py
  5. Save the result to ml/dataset/features.csv
"""

import sys
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))   # so we can import feature_extraction
from feature_extraction import extract_features, FEATURE_NAMES

RAW_CSV = ROOT / "ml" / "dataset" / "phiusiil.csv"
OUT_CSV = ROOT / "ml" / "dataset" / "features.csv"

# In PhiUSIIL, label 0 = phishing and 1 = legitimate.
# If explore_dataset.py showed the opposite, change this number.
PHISHING_LABEL_VALUE = 0

# ---- 1. Load only the two columns we need ----
df = pd.read_csv(RAW_CSV, usecols=lambda c: c.strip().lower() in ("url", "label"))
df.columns = [c.strip().lower() for c in df.columns]
print(f"Loaded rows: {len(df)}")

# ---- 2. Clean ----
df = df.dropna(subset=["url", "label"])
df["url"] = df["url"].astype(str).str.strip()
df = df[df["url"] != ""]
print(f"After removing missing/empty: {len(df)}")

df = df.drop_duplicates(subset=["url", "label"])
print(f"After removing exact duplicates: {len(df)}")

# Same URL appearing with BOTH labels is confusing, so remove those URLs
conflict = df.groupby("url")["label"].nunique()
conflict_urls = conflict[conflict > 1].index
df = df[~df["url"].isin(conflict_urls)]
print(f"After removing conflicting URLs ({len(conflict_urls)}): {len(df)}")

# ---- 3. Make labels: 1 = phishing, 0 = legitimate ----
df["is_phishing"] = (df["label"] == PHISHING_LABEL_VALUE).astype(int)
df = df.drop(columns=["label"])

# ---- 4. Extract features ----
print("\nExtracting features (about a minute for ~235k URLs)...")
rows = []
for i, u in enumerate(df["url"], start=1):
    rows.append(extract_features(u))
    if i % 50000 == 0:
        print(f"   processed {i} URLs")

features_df = pd.DataFrame(rows, columns=FEATURE_NAMES)
features_df["url"] = df["url"].values
features_df["is_phishing"] = df["is_phishing"].values

# Safety check: no missing numbers
assert features_df[FEATURE_NAMES].isna().sum().sum() == 0, "Found NaN in features!"

# ---- 5. Save ----
features_df.to_csv(OUT_CSV, index=False)
print(f"\nSaved {len(features_df)} rows to {OUT_CSV}")

print("\n=== Class balance (1 = phishing) ===")
print(features_df["is_phishing"].value_counts())

print("\n=== Average feature value per class (look for big differences) ===")
pd.set_option("display.width", 200)
print(features_df.groupby("is_phishing")[FEATURE_NAMES].mean().T.round(3))
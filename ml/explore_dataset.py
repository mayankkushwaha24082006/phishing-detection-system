"""
explore_dataset.py
------------------
Loads the raw dataset and prints basic facts about it so we understand
the data BEFORE we train anything. Run it once and read the output.
"""

from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
RAW_CSV = ROOT / "ml" / "dataset" / "phiusiil.csv"

if not RAW_CSV.exists():
    raise SystemExit(f"Dataset not found at {RAW_CSV}\n"
                     "Download it from UCI and save it as ml/dataset/phiusiil.csv")

df = pd.read_csv(RAW_CSV)

print("=== SHAPE (rows, columns) ===")
print(df.shape)

print("\n=== FIRST 10 COLUMN NAMES ===")
print(list(df.columns)[:10], "...")

# Find the URL and label columns regardless of capital letters
cols = {c.strip().lower(): c for c in df.columns}
if "url" not in cols or "label" not in cols:
    raise SystemExit("Could not find 'URL' and 'label' columns. Tell me the column names you see above.")
url_col, label_col = cols["url"], cols["label"]

print("\n=== MISSING VALUES in URL / label ===")
print(df[[url_col, label_col]].isna().sum())

print("\n=== DUPLICATE URLs ===")
print(df[url_col].duplicated().sum())

print("\n=== LABEL COUNTS ===")
print(df[label_col].value_counts())

# Check what each label value means by LOOKING at real examples
for value in sorted(df[label_col].dropna().unique()):
    print(f"\n=== 8 random URLs where label == {value} ===")
    for u in df[df[label_col] == value][url_col].sample(8, random_state=1):
        print("  ", u)

print("\nNow decide: which label value contains the scammy-looking URLs?")
print("That value is the PHISHING label. (For PhiUSIIL it should be 0.)")
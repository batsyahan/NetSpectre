from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

IN = Path("data/processed/cicids2017.parquet")
OUT = Path("data/processed")

df = pd.read_parquet(IN)

feature_cols = [c for c in df.columns if c not in ("Label", "source_file")]
df = df.dropna(subset=feature_cols)

dedup_cols = [c for c in df.columns if c != "source_file"]
before = len(df)
df = df.drop_duplicates(subset=dedup_cols)
print(f"Dropped {before - len(df)} duplicate rows ({len(df)} remain)")

df["binary_label"] = (df["Label"] != "BENIGN").astype("int8")
print(df["binary_label"].value_counts())

train_df, test_df = train_test_split(
    df, test_size=0.2, random_state=42, stratify=df["binary_label"]
)

train_df.to_parquet(OUT / "train.parquet", index=False)
test_df.to_parquet(OUT / "test.parquet", index=False)

print("\nTrain rows:", len(train_df))
print("Test rows:", len(test_df))

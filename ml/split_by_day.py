from pathlib import Path
import pandas as pd

df = pd.read_parquet("data/processed/cicids2017.parquet")
feature_cols = [c for c in df.columns if c not in ("Label", "source_file")]
df = df.dropna(subset=feature_cols)
dedup_cols = [c for c in df.columns if c != "source_file"]
df = df.drop_duplicates(subset=dedup_cols)
df["binary_label"] = (df["Label"] != "BENIGN").astype("int8")

print(df["source_file"].unique())

# Hold out Wednesday entirely as the test set (has DoS + Heartbleed)
test_df = df[df["source_file"].str.startswith("Wednesday")]
train_df = df[~df["source_file"].str.startswith("Wednesday")]

train_df.to_parquet("data/processed/train_byday.parquet", index=False)
test_df.to_parquet("data/processed/test_byday.parquet", index=False)
print("Train:", len(train_df), "Test:", len(test_df))
print(test_df["binary_label"].value_counts())

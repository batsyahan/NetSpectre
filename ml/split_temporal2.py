from pathlib import Path
import pandas as pd

df = pd.read_parquet("data/processed/cicids2017.parquet")
feature_cols = [c for c in df.columns if c not in ("Label", "source_file")]
df = df.dropna(subset=feature_cols)
dedup_cols = [c for c in df.columns if c != "source_file"]
df = df.drop_duplicates(subset=dedup_cols)
df["binary_label"] = (df["Label"] != "BENIGN").astype("int8")

# Split within each (source_file, Label) group so every attack type
# appears in both train and test, but test rows still come later in time.
train_parts, test_parts = [], []
for (f, label), g in df.groupby(["source_file", "Label"]):
    cut = max(1, int(len(g) * 0.8)) if len(g) > 1 else len(g)
    train_parts.append(g.iloc[:cut])
    test_parts.append(g.iloc[cut:])

train_df = pd.concat(train_parts, ignore_index=True)
test_df = pd.concat(test_parts, ignore_index=True)

train_df.to_parquet("data/processed/train_temporal2.parquet", index=False)
test_df.to_parquet("data/processed/test_temporal2.parquet", index=False)

print("Train:", len(train_df), "Test:", len(test_df))
print("\nTrain labels:")
print(train_df["Label"].value_counts())
print("\nTest labels:")
print(test_df["Label"].value_counts())

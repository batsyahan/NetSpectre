from pathlib import Path
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

train_df = pd.read_parquet("data/processed/train_temporal2.parquet")
drop_cols = ["Label", "source_file", "binary_label"]
feature_cols = [c for c in train_df.columns if c not in drop_cols]

X = train_df[feature_cols].to_numpy(dtype="float32")
y = train_df["Label"].to_numpy()
print("Shape:", X.shape, "Classes:", len(set(y)))

clf = HistGradientBoostingClassifier(max_iter=10, max_bins=63, verbose=1)
clf.fit(X, y)
print("SUCCESS")

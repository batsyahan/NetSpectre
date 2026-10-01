from pathlib import Path
import gc
import time
import joblib
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import classification_report

DATA = Path("data/processed")
MODELS = Path("models")
MODELS.mkdir(exist_ok=True)

drop_cols = ["Label", "source_file", "binary_label"]

train_df = pd.read_parquet(DATA / "train_temporal2.parquet")
feature_cols = [c for c in train_df.columns if c not in drop_cols]

# Cap every class at 50,000 first (same as before) so SMOTE's neighbor
# search stays cheap, then oversample rare classes to 20,000 with SMOTE
# instead of RandomOverSampler for real synthetic variety.
CAP = 50_000
parts = []
for label, g in train_df.groupby("Label"):
    if len(g) > CAP:
        g = g.sample(CAP, random_state=42)
    parts.append(g)
train_df = pd.concat(parts, ignore_index=True)
del parts
gc.collect()

X_train = train_df[feature_cols].to_numpy(dtype="float32")
y_train = train_df["Label"].to_numpy()
del train_df
gc.collect()

counts = pd.Series(y_train).value_counts()
print("Before SMOTE (all classes capped at 50k):")
print(counts)

TARGET = 20000
sampling_strategy = {
    label: TARGET for label, n in counts.items()
    if label != "BENIGN" and n < TARGET
}
min_class = counts.min()
k = max(1, min(5, min_class - 1))
print(f"\nOversampling targets: {sampling_strategy}")
print(f"Using k_neighbors={k}")

start = time.time()
smote = SMOTE(random_state=42, k_neighbors=k, sampling_strategy=sampling_strategy)
X_train, y_train = smote.fit_resample(X_train, y_train)
X_train = X_train.astype("float32")
print(f"SMOTE took {time.time() - start:.1f}s")

print("\nAfter SMOTE:", X_train.shape, X_train.dtype)
print(pd.Series(y_train).value_counts())

start = time.time()
clf = HistGradientBoostingClassifier(
    max_iter=100, learning_rate=0.1, max_bins=127, random_state=42, verbose=1,
)
clf.fit(X_train, y_train)
del X_train, y_train
gc.collect()
print(f"\nTrained in {time.time() - start:.1f}s")

test_df = pd.read_parquet(DATA / "test_temporal2.parquet")
X_test = test_df[feature_cols].to_numpy(dtype="float32")
y_test = test_df["Label"].to_numpy()
del test_df
gc.collect()

y_pred = clf.predict(X_test)
print("\nClassification report (multi-class, SMOTE, temporal split):")
print(classification_report(y_test, y_pred))

joblib.dump({"model": clf, "feature_cols": feature_cols}, MODELS / "multiclass_hgb_smote.joblib")
print("\nSaved models/multiclass_hgb_smote.joblib")

from pathlib import Path
import gc
import time
import joblib
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix

DATA = Path("data/processed")
MODELS = Path("models")
MODELS.mkdir(exist_ok=True)

drop_cols = ["Label", "source_file", "binary_label"]

train_df = pd.read_parquet(DATA / "train_temporal2.parquet")
feature_cols = [c for c in train_df.columns if c not in drop_cols]
X_train = train_df[feature_cols].to_numpy()
y_train = train_df["binary_label"].to_numpy()
del train_df
gc.collect()

print("Before SMOTE:", X_train.shape)
print("Class counts:", pd.Series(y_train).value_counts().to_dict())

# k_neighbors must be less than the smallest class size; ATTACK class
# here is much bigger than BENIGN's minority partner, so we oversample
# using a modest k to stay safe with rare sub-patterns.
smote = SMOTE(random_state=42, k_neighbors=5)
X_train, y_train = smote.fit_resample(X_train, y_train)

print("After SMOTE:", X_train.shape)
print("Class counts:", pd.Series(y_train).value_counts().to_dict())

start = time.time()
clf = HistGradientBoostingClassifier(
    max_iter=100, learning_rate=0.1, max_bins=127, random_state=42, verbose=1,
)
clf.fit(X_train, y_train)
del X_train, y_train
gc.collect()
print(f"\nTrained in {time.time() - start:.1f}s")

test_df = pd.read_parquet(DATA / "test_temporal2.parquet")
X_test = test_df[feature_cols].to_numpy()
y_test = test_df["binary_label"].to_numpy()
labels_test = test_df["Label"].to_numpy()
del test_df
gc.collect()

y_pred = clf.predict(X_test)
print("\nClassification report (SMOTE, temporal split):")
print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))
print("Confusion matrix (rows=true, cols=pred):")
print(confusion_matrix(y_test, y_pred))

res = pd.DataFrame({"Label": labels_test, "pred": y_pred, "true": y_test})
print("\nRecall by attack type:")
for label, g in res[res["true"] == 1].groupby("Label"):
    recall = (g["pred"] == 1).mean()
    print(f"  {label:<32}{recall:.3f}  (n={len(g)})")

joblib.dump({"model": clf, "feature_cols": feature_cols}, MODELS / "binary_hgb_smote.joblib")
print("\nSaved models/binary_hgb_smote.joblib")

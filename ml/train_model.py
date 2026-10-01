from pathlib import Path
import gc
import time
import joblib
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix

DATA = Path("data/processed")
MODELS = Path("models")
MODELS.mkdir(exist_ok=True)

drop_cols = ["Label", "source_file", "binary_label"]

train_df = pd.read_parquet(DATA / "train.parquet")
feature_cols = [c for c in train_df.columns if c not in drop_cols]
X_train = train_df[feature_cols].to_numpy()
y_train = train_df["binary_label"].to_numpy()
del train_df
gc.collect()

print("Training on", X_train.shape)
start = time.time()

clf = HistGradientBoostingClassifier(
    max_iter=100,
    learning_rate=0.1,
    max_bins=127,
    random_state=42,
    verbose=1,
)
clf.fit(X_train, y_train)
del X_train, y_train
gc.collect()

print(f"\nTrained in {time.time() - start:.1f}s")

test_df = pd.read_parquet(DATA / "test.parquet")
X_test = test_df[feature_cols].to_numpy()
y_test = test_df["binary_label"].to_numpy()
del test_df
gc.collect()

y_pred = clf.predict(X_test)
print("\nClassification report:")
print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))
print("Confusion matrix (rows=true, cols=pred):")
print(confusion_matrix(y_test, y_pred))

joblib.dump({"model": clf, "feature_cols": feature_cols}, MODELS / "binary_hgb.joblib")
print("\nSaved models/binary_hgb.joblib")

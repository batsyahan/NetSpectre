from pathlib import Path
import gc, json, time
import joblib
import numpy as np
import pandas as pd
import onnxruntime as ort
from imblearn.over_sampling import RandomOverSampler
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier
from onnxmltools import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType

DATA = Path("data/processed")
MODELS = Path("models")
FEATURES = json.load(open(MODELS / "feature_cols_40.json"))
assert len(FEATURES) == 40

train_df = pd.read_parquet(DATA / "train_temporal2.parquet")
CAP = 50_000
parts = []
for label, g in train_df.groupby("Label"):
    if len(g) > CAP:
        g = g.sample(CAP, random_state=42)
    parts.append(g)
train_df = pd.concat(parts, ignore_index=True)
del parts; gc.collect()

X_train = train_df[FEATURES].to_numpy(dtype="float32")
y_raw = train_df["Label"].to_numpy()
del train_df; gc.collect()

counts = pd.Series(y_raw).value_counts()
TARGET = 20000
strategy = {l: TARGET for l, n in counts.items() if l != "BENIGN" and n < TARGET}
X_train, y_raw = RandomOverSampler(random_state=42, sampling_strategy=strategy).fit_resample(X_train, y_raw)
X_train = X_train.astype("float32")

le = LabelEncoder()
y_train = le.fit_transform(y_raw)
json.dump(list(le.classes_), open(MODELS / "classes.json", "w"), indent=2)
print("Training shape:", X_train.shape, "| classes:", len(le.classes_))

start = time.time()
clf = XGBClassifier(
    n_estimators=100, max_depth=6, learning_rate=0.2,
    tree_method="hist", n_jobs=8, random_state=42,
    objective="multi:softprob", eval_metric="mlogloss",
)
clf.fit(X_train, y_train)
print(f"Trained in {time.time() - start:.1f}s")
del X_train, y_train; gc.collect()

test_df = pd.read_parquet(DATA / "test_temporal2.parquet")
X_test = test_df[FEATURES].to_numpy(dtype="float32")
y_test = test_df["Label"].to_numpy()
del test_df; gc.collect()

y_pred = le.inverse_transform(clf.predict(X_test))
print(classification_report(y_test, y_pred))
rep = classification_report(y_test, y_pred, output_dict=True)
print(f"MACRO F1 (XGB, 40 features): {rep['macro avg']['f1-score']:.3f}   [RF 40: 0.796]")

clf.save_model(str(MODELS / "multiclass_xgb40.json"))

onx = convert_xgboost(clf, initial_types=[("input", FloatTensorType([None, 40]))])
open(MODELS / "multiclass_xgb40.onnx", "wb").write(onx.SerializeToString())

sess = ort.InferenceSession(str(MODELS / "multiclass_xgb40.onnx"))
idx = np.random.RandomState(1).choice(len(X_test), 20000, replace=False)
Xs = X_test[idx]
out = sess.run(None, {"input": Xs})
onnx_labels = np.array(out[0]).astype(int)
sk_labels = clf.predict(Xs).astype(int)
print("ONNX output names:", [o.name for o in sess.get_outputs()])
print("ONNX label match:", np.array_equal(onnx_labels, sk_labels))
print("Mismatches:", int((onnx_labels != sk_labels).sum()), "of", len(Xs))
print("ONNX size (MB):", round((MODELS / "multiclass_xgb40.onnx").stat().st_size / 1e6, 1))

from pathlib import Path
import gc, json, time
import joblib
import numpy as np
import pandas as pd
import onnxruntime as ort
from imblearn.over_sampling import RandomOverSampler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from skl2onnx import to_onnx

DATA = Path("data/processed")
MODELS = Path("models")

FEATURES = [
    "Destination Port", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Packet Length Mean", "Packet Length Std",
    "SYN Flag Count", "FIN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward",
]
assert len(FEATURES) == 40 and len(set(FEATURES)) == 40

train_df = pd.read_parquet(DATA / "train_temporal2.parquet")
missing = [c for c in FEATURES if c not in train_df.columns]
assert not missing, missing

CAP = 50_000
parts = []
for label, g in train_df.groupby("Label"):
    if len(g) > CAP:
        g = g.sample(CAP, random_state=42)
    parts.append(g)
train_df = pd.concat(parts, ignore_index=True)
del parts; gc.collect()

X_train = train_df[FEATURES].to_numpy(dtype="float32")
y_train = train_df["Label"].to_numpy()
del train_df; gc.collect()

counts = pd.Series(y_train).value_counts()
TARGET = 20000
strategy = {l: TARGET for l, n in counts.items() if l != "BENIGN" and n < TARGET}
X_train, y_train = RandomOverSampler(random_state=42, sampling_strategy=strategy).fit_resample(X_train, y_train)
X_train = X_train.astype("float32")
print("Training shape:", X_train.shape)

start = time.time()
clf = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)
clf.fit(X_train, y_train)
print(f"Trained in {time.time() - start:.1f}s")
del X_train, y_train; gc.collect()

test_df = pd.read_parquet(DATA / "test_temporal2.parquet")
X_test = test_df[FEATURES].to_numpy(dtype="float32")
y_test = test_df["Label"].to_numpy()
del test_df; gc.collect()

y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))
rep = classification_report(y_test, y_pred, output_dict=True)
print(f"MACRO F1 (40 features): {rep['macro avg']['f1-score']:.3f}   [78-feature baseline: 0.78]")

joblib.dump({"model": clf, "feature_cols": FEATURES}, MODELS / "multiclass_rf40.joblib")
json.dump(FEATURES, open(MODELS / "feature_cols_40.json", "w"), indent=2)

onx = to_onnx(clf, X=np.zeros((1, 40), dtype=np.float32), options={id(clf): {"zipmap": False}})
open(MODELS / "multiclass_rf40.onnx", "wb").write(onx.SerializeToString())
sess = ort.InferenceSession(str(MODELS / "multiclass_rf40.onnx"))
idx = np.random.RandomState(1).choice(len(X_test), 20000, replace=False)
o = sess.run(None, {sess.get_inputs()[0].name: X_test[idx]})[0].astype(str)
print("ONNX match:", np.array_equal(o, clf.predict(X_test[idx]).astype(str)))
print("ONNX size (MB):", round((MODELS / "multiclass_rf40.onnx").stat().st_size / 1e6, 1))

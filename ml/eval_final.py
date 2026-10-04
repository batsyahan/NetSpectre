"""Evaluate the deployed ONNX models on the held-out temporal test split. Run from ml/."""
import json
import numpy as np
import pandas as pd
import onnxruntime as ort
from sklearn.metrics import classification_report, accuracy_score, f1_score, confusion_matrix

F = json.load(open("models/feature_cols_35.json"))
classes = json.load(open("models/classes.json"))
te = pd.read_parquet("data/processed/test_temporal2.parquet")
X = te[F].to_numpy(dtype="float32")
y = te["Label"].to_numpy()
print(f"test flows: {len(te)} | features: {len(F)} | non-finite values: {int((~np.isfinite(X)).sum())}")
print("true class counts:", dict(pd.Series(y).value_counts()))

sx = ort.InferenceSession("models/multiclass_xgb35.onnx")
sc = ort.InferenceSession("models/multiclass_cat35.onnx")

def probs(sess, x):
    p = sess.run(None, {sess.get_inputs()[0].name: x})[1]
    if isinstance(p, list) and isinstance(p[0], dict):
        p = [[d[k] for k in sorted(d, key=int)] for d in p]
    return np.asarray(p, dtype=np.float64)

px, pc = [], []
for i in range(0, len(X), 50000):
    b = X[i:i + 50000]
    px.append(probs(sx, b)); pc.append(probs(sc, b))
px, pc = np.vstack(px), np.vstack(pc)
pe = (px + pc) / 2

meta = json.load(open("models/ae35_meta.json"))
mu, sd = np.array(meta["mu"], dtype=np.float32), np.array(meta["sd"], dtype=np.float32)
ae = ort.InferenceSession("models/ae35.onnx")
scores = []
for i in range(0, len(X), 50000):
    b = X[i:i + 50000]
    z = (((np.sign(b) * np.log1p(np.abs(b))).astype(np.float32) - mu) / sd).astype(np.float32)
    r = ae.run(None, {"x": z})[0]
    scores.append(((r - z) ** 2).mean(axis=1))
scores = np.concatenate(scores)

def report(name, p):
    pred = np.array(classes)[p.argmax(1)]
    print(f"\n===== {name} =====")
    print(f"accuracy {accuracy_score(y, pred):.4f} | macro F1 {f1_score(y, pred, average='macro'):.4f} | weighted F1 {f1_score(y, pred, average='weighted'):.4f}")
    ben = y == "BENIGN"
    print(f"benign false-positive rate (benign flagged as any attack): {(pred[ben] != 'BENIGN').mean():.4%}")
    print(classification_report(y, pred, labels=classes, digits=4, zero_division=0))
    return pred

report("XGBoost only", px)
report("CatBoost only", pc)
pred = report("ENSEMBLE (deployed)", pe)

print("\n===== most common confusions in the ensemble =====")
cm = confusion_matrix(y, pred, labels=classes)
pairs = [(cm[i, j], classes[i], classes[j]) for i in range(len(classes)) for j in range(len(classes)) if i != j and cm[i, j] > 0]
for n, a, b in sorted(pairs, reverse=True)[:12]:
    print(f"{n:8d}  true {a}  ->  predicted {b}")

for thr, tag in ((0.2369, "1%"), (0.1347, "3%"), (0.1040, "5%")):
    print(f"\n===== autoencoder: share of flows with anomaly score > {thr} (benign {tag} threshold) =====")
    for c in classes:
        m = y == c
        if m.any():
            print(f"{c:28s} {(scores[m] > thr).mean():7.2%}   (n={int(m.sum())})")

"""How does the deployed model treat a capture of normal traffic?

Run from ml/:  python check_capture.py [../baselines/benign_capture.csv] [model_name]
Every row in the capture should be BENIGN; anything else is a false positive.
"""
import json, sys
import numpy as np, pandas as pd, onnxruntime as ort

path = sys.argv[1] if len(sys.argv) > 1 else "../baselines/benign_capture.csv"
model = sys.argv[2] if len(sys.argv) > 2 else "multiclass_xgb35_v3"
F = json.load(open("models/feature_cols_35.json")); C = np.array(json.load(open("models/classes.json")))
d = pd.read_csv(path, header=None).apply(pd.to_numeric, errors="coerce").dropna()
d = d.iloc[:, :35]; d.columns = F
X = d.to_numpy("float32")

s = ort.InferenceSession(f"models/{model}.onnx")
p = s.run(None, {s.get_inputs()[0].name: X})[1]
if isinstance(p, list) and isinstance(p[0], dict):
    p = [[v[k] for k in sorted(v, key=int)] for v in p]
p = np.asarray(p); lab = C[p.argmax(1)]; conf = p.max(1)

m = json.load(open("models/ae35_meta.json"))
mu, sd = np.array(m["mu"], "float32"), np.array(m["sd"], "float32")
ae = ort.InferenceSession("models/ae35.onnx")
z = (((np.sign(X) * np.log1p(np.abs(X))) - mu) / sd).astype("float32")
err = ((ae.run(None, {"x": z})[0] - z) ** 2).mean(1)

n = len(X)
print(f"{path}: {n} flows, model {model}")
print("\nPredicted labels:")
print(pd.Series(lab).value_counts().to_string())
fp = lab != "BENIGN"
print(f"\nFalse positives (not BENIGN): {fp.sum()} / {n} = {100 * fp.mean():.2f}%")
print(f"  of those with confidence >= 0.8: {(fp & (conf >= 0.8)).sum()}")
for thr in (0.2369, 0.5):
    a = (~fp) & (err > thr)
    print(f"BENIGN flows the autoencoder flags at {thr}: {a.sum()} ({100 * a.mean():.2f}%)")
if fp.any():
    print("\nFalse positives by label and destination port (top 10):")
    print(pd.DataFrame({"label": lab[fp], "port": d["Destination Port"].to_numpy()[fp].astype(int)})
          .value_counts().head(10).to_string())

import json, numpy as np, pandas as pd, onnxruntime as ort
F = json.load(open("models/feature_cols_35.json"))
d = pd.read_csv("../baselines/scan_flows.csv", header=None).apply(pd.to_numeric, errors="coerce").dropna()
X = d.to_numpy("float32"); print(len(X), "flows,", X.shape[1], "columns")
def probs(s, x):
    p = s.run(None, {s.get_inputs()[0].name: x})[1]
    if isinstance(p, list) and isinstance(p[0], dict):
        p = [[v[k] for k in sorted(v, key=int)] for v in p]
    return np.asarray(p, dtype=np.float64)
for name, mf, cf in [("old v1", "multiclass_xgb35.onnx", "classes.json"), ("new v2", "multiclass_xgb35_v2.onnx", "classes_v2.json")]:
    s = ort.InferenceSession("models/" + mf); cl = json.load(open("models/" + cf))
    print(name, pd.Series(np.array(cl)[probs(s, X).argmax(1)]).value_counts().to_dict())
tr = pd.read_parquet("data/processed/train_temporal2.parquet", columns=F + ["Label"])
t = pd.DataFrame({"live_scan": np.median(X, axis=0),
                  "train_PortScan": tr[tr.Label == "PortScan"][F].median().to_numpy(),
                  "train_BENIGN": tr[tr.Label == "BENIGN"][F].median().to_numpy()}, index=F)
print(t.round(2).to_string())

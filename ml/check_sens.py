import json, numpy as np, pandas as pd, onnxruntime as ort
F = json.load(open("models/feature_cols_35.json")); ix = {f: i for i, f in enumerate(F)}
X0 = pd.read_csv("../baselines/scan_flows.csv", header=None).apply(pd.to_numeric, errors="coerce").dropna().to_numpy("float32")
def probs(s, x):
    p = s.run(None, {s.get_inputs()[0].name: x})[1]
    if isinstance(p, list) and isinstance(p[0], dict):
        p = [[v[k] for k in sorted(v, key=int)] for v in p]
    return np.asarray(p, dtype=np.float64)
TIME_UP = ["Flow Duration", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min"]
RATES = ["Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s"]
def variant(counter, timing):
    X = X0.copy()
    if counter: X[:, ix["act_data_pkt_fwd"]] = 0
    if timing:
        for f in TIME_UP: X[:, ix[f]] *= 12
        for f in RATES: X[:, ix[f]] /= 12
    return X
models = [("old v1", "multiclass_xgb35.onnx", "classes.json"), ("new v2", "multiclass_xgb35_v2.onnx", "classes_v2.json")]
for name, mf, cf in models:
    s = ort.InferenceSession("models/" + mf); cl = np.array(json.load(open("models/" + cf)))
    for label, c, t in [("as captured", 0, 0), ("counter fixed", 1, 0), ("timing x12 slower", 0, 1), ("both fixed", 1, 1)]:
        lab = cl[probs(s, variant(c, t)).argmax(1)]
        print(f"{name:7s} {label:20s} PortScan {int((lab == 'PortScan').sum())}/{len(lab)}")

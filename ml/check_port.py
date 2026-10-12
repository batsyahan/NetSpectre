import json, numpy as np, pandas as pd, onnxruntime as ort
from xgboost import XGBClassifier
F = json.load(open("models/feature_cols_35.json")); ix = {f: i for i, f in enumerate(F)}
X0 = pd.read_csv("../baselines/scan_flows.csv", header=None).apply(pd.to_numeric, errors="coerce").dropna().to_numpy("float32")
def probs(s, x):
    p = s.run(None, {s.get_inputs()[0].name: x})[1]
    if isinstance(p, list) and isinstance(p[0], dict):
        p = [[v[k] for k in sorted(v, key=int)] for v in p]
    return np.asarray(p, dtype=np.float64)
TIME_UP = ["Flow Duration", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min"]
RATES = ["Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s"]
def variant(highports, timing):
    X = X0.copy()
    if highports: X[:, ix["Destination Port"]] = np.random.default_rng(0).integers(1024, 65535, len(X))
    if timing:
        for f in TIME_UP: X[:, ix[f]] *= 12
        for f in RATES: X[:, ix[f]] /= 12
    return X
for name, mf, cf, js in [("old v1", "multiclass_xgb35.onnx", "classes.json", "multiclass_xgb35.json"), ("new v2", "multiclass_xgb35_v2.onnx", "classes_v2.json", "multiclass_xgb35_v2.json")]:
    s = ort.InferenceSession("models/" + mf); cl = np.array(json.load(open("models/" + cf)))
    for label, h, t in [("as captured", 0, 0), ("high ports", 1, 0), ("high ports + slower", 1, 1)]:
        lab = cl[probs(s, variant(h, t)).argmax(1)]
        print(f"{name:7s} {label:20s} PortScan {int((lab == 'PortScan').sum())}/{len(lab)}")
    clf = XGBClassifier(); clf.load_model("models/" + js)
    g = clf.get_booster().get_score(importance_type="total_gain"); tot = sum(g.values())
    top = sorted(((v / tot, F[int(k[1:])]) for k, v in g.items()), reverse=True)[:8]
    print("  top features:", ", ".join(f"{n} {p:.0%}" for p, n in top))

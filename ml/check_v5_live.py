"""Why does v5 call some normal home flows an attack? Compares v3 and v5 on own-network traffic.
Run from ml/:  python check_v5_live.py"""
import json, os
import numpy as np, pandas as pd, onnxruntime as ort

F = json.load(open("models/feature_cols_35.json")); C = np.array(json.load(open("models/classes.json")))
def load(p):
    d = pd.read_csv(p, header=None).apply(pd.to_numeric, errors="coerce").dropna().iloc[:, :35].reset_index(drop=True); d.columns = F; return d
def lab(s, x):
    p = s.run(None, {s.get_inputs()[0].name: x})[1]
    if isinstance(p, list) and isinstance(p[0], dict):
        p = [[v[k] for k in sorted(v, key=int)] for v in p]
    return C[np.asarray(p).argmax(1)]

live = load("../baselines/live_flows.csv")
sig = ((live["Init_Win_bytes_forward"] == 1024) & (live["Total Fwd Packets"] <= 2)).to_numpy()
b = np.where(~sig)[0]; b_ho = b[int(len(b) * 0.7):]
sets = {"live_flows benign holdout (100)": live.iloc[b_ho]}
if os.path.exists("../baselines/benign_capture.csv"):
    cap = load("../baselines/benign_capture.csv")
    probe = (cap["Total Fwd Packets"] <= 2) & (cap["Total Backward Packets"] <= 1)
    sets[f"benign_capture, all normal flows ({int((~probe).sum())})"] = cap[~probe]

m = {n: ort.InferenceSession(f"models/multiclass_xgb35_{n}.onnx") for n in ["v3", "v5"]}
for name, d in sets.items():
    X = d[F].to_numpy("float32")
    p3, p5 = lab(m["v3"], X), lab(m["v5"], X)
    print(f"\n== {name}")
    print(f"   false alarms: v3 {(p3 != 'BENIGN').sum()}  v5 {(p5 != 'BENIGN').sum()}")
    bad = p5 != "BENIGN"
    if bad.any():
        t = pd.DataFrame({"v5 label": p5[bad], "dst port": d["Destination Port"].to_numpy()[bad].astype(int),
                          "fwd pkts": d["Total Fwd Packets"].to_numpy()[bad].astype(int),
                          "init win": d["Init_Win_bytes_forward"].to_numpy()[bad].astype(int)})
        print(t.value_counts().head(15).to_string())

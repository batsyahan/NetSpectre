import json, numpy as np, pandas as pd, onnxruntime as ort
F = json.load(open("models/feature_cols_35.json")); ix = {f: i for i, f in enumerate(F)}
prep = lambda x: np.sign(x) * np.log1p(np.abs(x))
def load(p): return pd.read_csv(p, header=None).apply(pd.to_numeric, errors="coerce").dropna().to_numpy("float64")
m = json.load(open("models/ae35_meta.json")); mu, sd = np.array(m["mu"], "float32"), np.array(m["sd"], "float32")
s = ort.InferenceSession("models/ae35.onnx")
def err(raw):
    z = ((prep(raw).astype("float32") - mu) / sd).astype("float32"); r = s.run(None, {"x": z})[0]; return ((r - z) ** 2).mean(1)
live = load("../baselines/live_flows.csv")
sig = (live[:, ix["Init_Win_bytes_forward"]] == 1024) & (live[:, ix["Total Fwd Packets"]] <= 2)
te = pd.read_parquet("data/processed/test_temporal2.parquet", columns=F + ["Label"]); Xt = te[F].to_numpy("float64"); lab = te["Label"].to_numpy()
sets = [("2017 BENIGN", Xt[lab == "BENIGN"]), ("YOUR baseline (all 269)", load("../baselines/eth1_flows.csv")),
        ("YOUR nmap scans (live)", live[sig]), ("PortScan 2017", Xt[lab == "PortScan"]), ("DDoS", Xt[lab == "DDoS"]),
        ("DoS Slowhttptest", Xt[lab == "DoS Slowhttptest"]), ("DoS slowloris", Xt[lab == "DoS slowloris"]), ("DoS Hulk", Xt[lab == "DoS Hulk"])]
T = [0.2369, 0.35, 0.5, 0.7, 1.0, 1.5]
print(f"{'% of flows above threshold':<28}" + "".join(f"{t:>8}" for t in T))
for n, raw in sets:
    e = err(raw); print(f"{n:<28}" + "".join(f"{(e > t).mean():>8.1%}" for t in T))
e = err(load("../baselines/eth1_flows.csv")); print("\nyour baseline error percentiles 50/90/95/99/max:", np.round(np.percentile(e, [50, 90, 95, 99, 100]), 2))

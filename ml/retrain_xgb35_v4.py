"""v4 = v3 recipe + normal traffic captured on the user's own network (baselines/benign_capture.csv).

Run from ml/ inside the .venv:  python retrain_xgb35_v4.py
Writes models/multiclass_xgb35_v4.{json,onnx}; never overwrites v3.
Holdouts: the last 30% (in time order) of each live capture is kept out of training.
"""
import gc, json
import numpy as np, pandas as pd, onnxruntime as ort
from imblearn.over_sampling import RandomOverSampler
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import f1_score
from xgboost import XGBClassifier
from onnxmltools import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType

F = json.load(open("models/feature_cols_35.json")); classes = json.load(open("models/classes.json"))
def load(p):
    d = pd.read_csv(p, header=None).apply(pd.to_numeric, errors="coerce").dropna().iloc[:, :35].reset_index(drop=True)
    d.columns = F; return d
def split(idx, frac=0.7):
    c = int(len(idx) * frac); return idx[:c], idx[c:]

# --- live data used by v3 (scan probes + benign) ---
live = load("../baselines/live_flows.csv"); indep = load("../baselines/scan_flows.csv")
sig = ((live["Init_Win_bytes_forward"] == 1024) & (live["Total Fwd Packets"] <= 2)).to_numpy()
s_tr, s_ho = split(np.where(sig)[0]); b_tr, b_ho = split(np.where(~sig)[0])
Xl = live[F].to_numpy("float32")

# --- new: own-network normal traffic ---
cap = load("../baselines/benign_capture.csv")
n_raw = len(cap)
cap_sig = ((cap["Init_Win_bytes_forward"] == 1024) & (cap["Total Fwd Packets"] <= 2)).to_numpy()
cap = cap[~cap_sig].drop_duplicates().reset_index(drop=True)  # drop anything that looks like an nmap probe
c_tr, c_ho = split(np.arange(len(cap)))
Xc = cap[F].to_numpy("float32")
print(f"benign capture: {n_raw} rows, {int(cap_sig.sum())} scan-like dropped, {len(cap)} unique | train {len(c_tr)} holdout {len(c_ho)}")
print(f"v3 live data: train scan {len(s_tr)} benign {len(b_tr)} | holdout scan {len(s_ho)} benign {len(b_ho)}")

# --- CICIDS2017 training part, same caps/oversampling as v3 ---
tr = pd.read_parquet("data/processed/train_temporal2.parquet", columns=F + ["Label"])
lab_all = tr["Label"].astype(str).to_numpy(dtype=object)
Xall = tr[F].to_numpy(dtype="float32"); del tr; gc.collect()
rng = np.random.default_rng(42); keep = []
for l in np.unique(lab_all):
    idx = np.where(lab_all == l)[0]
    if len(idx) > 50000: idx = rng.choice(idx, 50000, replace=False)
    keep.append(idx)
keep = np.concatenate(keep)
X, y = Xall[keep], lab_all[keep]; del Xall; gc.collect()
cnt = pd.Series(y).value_counts()
strat = {l: 20000 for l, n in cnt.items() if l != "BENIGN" and n < 20000}
X, y = RandomOverSampler(random_state=42, sampling_strategy=strat).fit_resample(X, y)
n_base = len(X)
X = np.vstack([X, Xl[s_tr], Xl[b_tr], Xc[c_tr]])
y = np.concatenate([np.asarray(y, dtype=object),
                    np.array(["PortScan"] * len(s_tr) + ["BENIGN"] * (len(b_tr) + len(c_tr)), dtype=object)])
w = np.r_[np.ones(n_base), np.full(len(s_tr) + len(b_tr) + len(c_tr), 10.0)]
le = LabelEncoder(); yi = le.fit_transform(y)
assert list(le.classes_) == classes, "class order changed"
print("training rows:", len(X), flush=True)
clf = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.2, tree_method="hist", n_jobs=8, random_state=42, objective="multi:softprob")
clf.fit(X.astype("float32"), yi, sample_weight=w)
clf.save_model("models/multiclass_xgb35_v4.json")
onx = convert_xgboost(clf, initial_types=[("input", FloatTensorType([None, len(F)]))])
open("models/multiclass_xgb35_v4.onnx", "wb").write(onx.SerializeToString())

# --- compare v3 and v4 ---
def probs(s, x):
    p = s.run(None, {s.get_inputs()[0].name: x})[1]
    if isinstance(p, list) and isinstance(p[0], dict):
        p = [[v[k] for k in sorted(v, key=int)] for v in p]
    return np.asarray(p, dtype=np.float64)
def lab(s, x): return np.array(classes)[probs(s, x).argmax(1)]
te = pd.read_parquet("data/processed/test_temporal2.parquet"); Xt = te[F].to_numpy("float32"); yt = te["Label"].to_numpy()
labs = sorted(set(yt)); Xi = indep[F].to_numpy("float32")
f1 = lambda yp, ls: f1_score(yt, yp, labels=ls, average="macro", zero_division=0)
print()
for name in ("multiclass_xgb35_v3", "multiclass_xgb35_v4"):
    s = ort.InferenceSession(f"models/{name}.onnx"); pt = lab(s, Xt)
    fpr = 100 * np.mean(pt[yt == "BENIGN"] != "BENIGN")
    a = int((lab(s, Xl[s_ho]) == "PortScan").sum()); b = int((lab(s, Xl[b_ho]) == "BENIGN").sum())
    c = int((lab(s, Xi) == "PortScan").sum()); h = lab(s, Xc[c_ho]); hb = int((h == "BENIGN").sum())
    print(f"{name[-2:]}: test macro F1 {f1(pt, labs):.4f} | accuracy {np.mean(pt == yt):.4f} | benign FPR {fpr:.3f}%"
          f" | Bot F1 {f1(pt, ['Bot']):.3f} | PortScan F1 {f1(pt, ['PortScan']):.3f}")
    print(f"    live scans -> PortScan {a}/{len(s_ho)} | independent scans -> PortScan {c}/{len(Xi)}"
          f" | old live benign -> BENIGN {b}/{len(b_ho)} | NEW capture holdout -> BENIGN {hb}/{len(c_ho)}")
    if hb < len(c_ho):
        print("    capture-holdout false positives:", pd.Series(h[h != "BENIGN"]).value_counts().to_dict())

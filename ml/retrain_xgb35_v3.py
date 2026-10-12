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
    d = pd.read_csv(p, header=None).apply(pd.to_numeric, errors="coerce").dropna().reset_index(drop=True); d.columns = F; return d
live = load("../baselines/live_flows.csv"); indep = load("../baselines/scan_flows.csv")
sig = ((live["Init_Win_bytes_forward"] == 1024) & (live["Total Fwd Packets"] <= 2)).to_numpy()
def split(idx):
    c = int(len(idx) * 0.7); return idx[:c], idx[c:]
s_tr, s_ho = split(np.where(sig)[0]); b_tr, b_ho = split(np.where(~sig)[0])
Xl = live[F].to_numpy("float32")
print("live train: scan", len(s_tr), "benign", len(b_tr), "| holdout: scan", len(s_ho), "benign", len(b_ho))

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
print("base training rows:", len(X), flush=True)
cnt = pd.Series(y).value_counts()
strat = {l: 20000 for l, n in cnt.items() if l != "BENIGN" and n < 20000}
X, y = RandomOverSampler(random_state=42, sampling_strategy=strat).fit_resample(X, y)
n_base = len(X)
X = np.vstack([X, Xl[s_tr], Xl[b_tr]])
y = np.concatenate([np.asarray(y, dtype=object), np.array(["PortScan"] * len(s_tr) + ["BENIGN"] * len(b_tr), dtype=object)])
w = np.r_[np.ones(n_base), np.full(len(s_tr) + len(b_tr), 10.0)]
le = LabelEncoder(); yi = le.fit_transform(y)
assert list(le.classes_) == classes, "class order changed"
clf = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.2, tree_method="hist", n_jobs=8, random_state=42, objective="multi:softprob")
clf.fit(X.astype("float32"), yi, sample_weight=w)
clf.save_model("models/multiclass_xgb35_v3.json")
onx = convert_xgboost(clf, initial_types=[("input", FloatTensorType([None, len(F)]))])
open("models/multiclass_xgb35_v3.onnx", "wb").write(onx.SerializeToString())

def probs(s, x):
    p = s.run(None, {s.get_inputs()[0].name: x})[1]
    if isinstance(p, list) and isinstance(p[0], dict):
        p = [[v[k] for k in sorted(v, key=int)] for v in p]
    return np.asarray(p, dtype=np.float64)
def lab(s, x): return np.array(classes)[probs(s, x).argmax(1)]
te = pd.read_parquet("data/processed/test_temporal2.parquet"); Xt = te[F].to_numpy("float32"); yt = te["Label"].to_numpy()
labs = sorted(set(yt))
Xi = indep[F].to_numpy("float32")
print()
for name, path in [("old v1", "models/multiclass_xgb35.onnx"), ("new v3", "models/multiclass_xgb35_v3.onnx")]:
    s = ort.InferenceSession(path); pt = lab(s, Xt)
    a = int((lab(s, Xl[s_ho]) == "PortScan").sum()); b = int((lab(s, Xl[b_ho]) == "BENIGN").sum()); c = int((lab(s, Xi) == "PortScan").sum())
    print(f"{name}: test macro F1 {f1_score(yt, pt, labels=labs, average='macro', zero_division=0):.4f} | test PortScan F1 {f1_score(yt, pt, labels=['PortScan'], average='macro', zero_division=0):.3f}")
    print(f"        live holdout scans called PortScan {a}/{len(s_ho)} | live holdout benign called BENIGN {b}/{len(b_ho)} | independent scan flows called PortScan {c}/{len(Xi)}")

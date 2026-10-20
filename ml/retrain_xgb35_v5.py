"""v5 = v3 recipe + CSE-CIC-IDS2018 flows (trained on CICIDS2017 + 2018 together).

Run from ml/ inside the .venv:  python retrain_xgb35_v5.py
Writes models/multiclass_xgb35_v5.{json,onnx}; never overwrites v3. Report: ../docs/EVAL_V5.txt

Fair test on 2018: for every 2018 label the flows are sorted by time; the first 70% may be used for
training, the last 30% are held out and only used for testing (the model never sees later traffic).
2018 labels are mapped to the same 15 CICIDS2017 classes, so the server, alerts and severities do not change.
The CICIDS2017 test set and the live-capture holdouts from v3 are re-checked so nothing got worse there.
Memory: about 3 GB peak. Time: about 10-25 min on a 4-core laptop.
"""
import gc, json, os
import numpy as np, pandas as pd, onnxruntime as ort
from imblearn.over_sampling import RandomOverSampler
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import f1_score
from xgboost import XGBClassifier
from onnxmltools import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType
from cic2018 import FAMILY, load_2018

F = json.load(open("models/feature_cols_35.json")); classes = json.load(open("models/classes.json"))
CAP18 = int(os.environ.get("NS_CAP18", 60_000))        # max 2018 training rows per label
rng = np.random.default_rng(42)

# ---- live captures from the user's own network (same split as v3) ----
def load(p):
    d = pd.read_csv(p, header=None).apply(pd.to_numeric, errors="coerce").dropna().iloc[:, :35].reset_index(drop=True); d.columns = F; return d
live = load("../baselines/live_flows.csv"); indep = load("../baselines/scan_flows.csv")
sig = ((live["Init_Win_bytes_forward"] == 1024) & (live["Total Fwd Packets"] <= 2)).to_numpy()
def split(idx):
    c = int(len(idx) * 0.7); return idx[:c], idx[c:]
s_tr, s_ho = split(np.where(sig)[0]); b_tr, b_ho = split(np.where(~sig)[0])
Xl = live[F].to_numpy("float32")

# ---- CSE-CIC-IDS2018: time-ordered 70/30 split per label ----
X18, y18, ts18, total18, nf = load_2018(benign_frac=0.10, cap=10**9)
known = np.array([l in FAMILY for l in y18])
X18, y18, ts18 = X18[known], y18[known], ts18[known]
tr18, te18 = [], []
for l in np.unique(y18):
    idx = np.where(y18 == l)[0]
    idx = idx[np.argsort(ts18[idx], kind="stable")]
    a, b = split(idx)
    if len(a) > CAP18: a = rng.choice(a, CAP18, replace=False)
    if len(b) > 100_000: b = rng.choice(b, 100_000, replace=False)
    tr18.append(a); te18.append(b)
    print(f"2018 {l:<26} train {len(a):>7,}  test {len(b):>7,}", flush=True)
tr18, te18 = np.concatenate(tr18), np.concatenate(te18)
X18tr, y18tr = X18[tr18], np.array([FAMILY[l] for l in y18[tr18]], dtype=object)
X18te, y18te = X18[te18], y18[te18]
del X18, ts18; gc.collect()

# ---- CICIDS2017 base (same as v3) ----
tr = pd.read_parquet("data/processed/train_temporal2.parquet", columns=F + ["Label"])
lab_all = tr["Label"].astype(str).to_numpy(dtype=object)
Xall = tr[F].to_numpy(dtype="float32"); del tr; gc.collect()
keep = []
for l in np.unique(lab_all):
    idx = np.where(lab_all == l)[0]
    if len(idx) > 50000: idx = rng.choice(idx, 50000, replace=False)
    keep.append(idx)
keep = np.concatenate(keep)
X, y = Xall[keep], lab_all[keep]; del Xall; gc.collect()
cnt = pd.Series(y).value_counts()
strat = {l: 20000 for l, n in cnt.items() if l != "BENIGN" and n < 20000}
X, y = RandomOverSampler(random_state=42, sampling_strategy=strat).fit_resample(X, y)
n17 = len(X)
X = np.vstack([X, X18tr, Xl[s_tr], Xl[b_tr]])
y = np.concatenate([np.asarray(y, dtype=object), y18tr, np.array(["PortScan"] * len(s_tr) + ["BENIGN"] * len(b_tr), dtype=object)])
w = np.r_[np.ones(n17 + len(X18tr)), np.full(len(s_tr) + len(b_tr), 10.0)]
print(f"training rows: 2017 {n17:,} + 2018 {len(X18tr):,} + live {len(s_tr) + len(b_tr):,}", flush=True)
le = LabelEncoder(); yi = le.fit_transform(y)
assert list(le.classes_) == classes, "class order changed"
clf = XGBClassifier(n_estimators=150, max_depth=8, learning_rate=0.2, tree_method="hist", n_jobs=os.cpu_count(), random_state=42, objective="multi:softprob")
clf.fit(X.astype("float32"), yi, sample_weight=w)
del X; gc.collect()
clf.save_model("models/multiclass_xgb35_v5.json")
onx = convert_xgboost(clf, initial_types=[("input", FloatTensorType([None, len(F)]))])
open("models/multiclass_xgb35_v5.onnx", "wb").write(onx.SerializeToString())
print("saved models/multiclass_xgb35_v5.{json,onnx}", flush=True)

# ---- compare v3 and v5 on the same held-out data ----
def lab(s, x):
    out = []
    for i in range(0, len(x), 200_000):
        p = s.run(None, {s.get_inputs()[0].name: x[i:i + 200_000]})[1]
        if isinstance(p, list) and isinstance(p[0], dict):
            p = [[v[k] for k in sorted(v, key=int)] for v in p]
        out.append(np.array(classes)[np.asarray(p).argmax(1)])
    return np.concatenate(out)
te = pd.read_parquet("data/processed/test_temporal2.parquet", columns=F + ["Label"])
Xt = te[F].to_numpy("float32"); yt = te["Label"].astype(str).to_numpy(); del te; gc.collect()
labs = sorted(set(yt)); Xi = indep[F].to_numpy("float32")
order = ["Benign"] + sorted(set(y18te) - {"Benign"})
res = {}
for name in ["v3", "v5"]:
    s = ort.InferenceSession(f"models/multiclass_xgb35_{name}.onnx")
    pt, p18 = lab(s, Xt), lab(s, X18te)
    att17 = yt != "BENIGN"
    r = {"f1": f1_score(yt, pt, labels=labs, average="macro", zero_division=0),
         "fpr17": 100 * (pt[~att17] != "BENIGN").mean(), "det17": 100 * (pt[att17] != "BENIGN").mean(),
         "scan": int((lab(s, Xl[s_ho]) == "PortScan").sum()), "ben": int((lab(s, Xl[b_ho]) == "BENIGN").sum()),
         "indep": int((lab(s, Xi) == "PortScan").sum())}
    for l in order:
        m = y18te == l
        r[l] = (100 * (p18[m] != "BENIGN").mean(), 100 * (p18[m] == FAMILY[l]).mean())
    a18 = y18te != "Benign"
    r["all18"] = 100 * (p18[a18] != "BENIGN").mean(); r["right18"] = 100 * (p18[a18] == np.array([FAMILY[l] for l in y18te[a18]])).mean()
    res[name] = r

v3, v5 = res["v3"], res["v5"]
out = ["NetSpectre classifier v5: trained on CICIDS2017 + CSE-CIC-IDS2018 (v3 = CICIDS2017 only, deployed before)",
       f"2018 data: {nf} day files; per label, first 70% in time for training (max {CAP18:,} rows), last 30% held out for testing", "",
       "CSE-CIC-IDS2018 held-out flows (later in time than anything trained on)",
       f"{'2018 label':<26}{'test flows':>11}{'v3 flagged':>12}{'v5 flagged':>12}{'v3 right':>10}{'v5 right':>10}"]
for l in order:
    n = int((y18te == l).sum())
    out.append(f"{l:<26}{n:>11,}{v3[l][0]:>11.1f}%{v5[l][0]:>11.1f}%{v3[l][1]:>9.1f}%{v5[l][1]:>9.1f}%")
out += [f"{'ALL ATTACKS':<26}{int((y18te != 'Benign').sum()):>11,}{v3['all18']:>11.1f}%{v5['all18']:>11.1f}%{v3['right18']:>9.1f}%{v5['right18']:>9.1f}%",
        "Benign row = false alarms (lower is better); attack rows = detection. 'right' = correct attack family.", "",
        "CICIDS2017 test set (499,605 flows, unchanged)",
        f"  macro F1            v3 {v3['f1']:.4f}   v5 {v5['f1']:.4f}",
        f"  attack detection    v3 {v3['det17']:.2f}%  v5 {v5['det17']:.2f}%",
        f"  benign false alarms v3 {v3['fpr17']:.3f}%  v5 {v5['fpr17']:.3f}%", "",
        "Own-network live captures (held out)",
        f"  scans called PortScan        v3 {v3['scan']}/{len(s_ho)}   v5 {v5['scan']}/{len(s_ho)}",
        f"  normal flows called BENIGN   v3 {v3['ben']}/{len(b_ho)}   v5 {v5['ben']}/{len(b_ho)}",
        f"  independent scan flows       v3 {v3['indep']}/{len(Xi)}   v5 {v5['indep']}/{len(Xi)}"]
text = "\n".join(out); print("\n" + text)
open("../docs/EVAL_V5.txt", "w").write(text + "\n")
print("\nwritten ../docs/EVAL_V5.txt")

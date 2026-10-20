"""v8 = final v7: config A (picked on the validation split in v7) refit on train + validation data.

v7 held 15% of 2018 and 10% of 2017 out for choosing the config; after choosing, those rows go back into training,
so v8 learns from the first 70% (in time) of each 2018 label and the whole 2017 training file, like v6.
The test data is exactly the same as v5/v6/v7 (last 30% of each 2018 label, 2017 test file, own-network holdouts).
Run from ml/ inside the .venv:  python retrain_xgb35_v8.py      (about 25 min)  Report: ../docs/EVAL_V8.txt
Writes models/multiclass_xgb35_v8.{json,onnx}; never overwrites older models.
"""
import gc, json, os, time
import numpy as np, pandas as pd, onnxruntime as ort
from imblearn.over_sampling import RandomOverSampler
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import f1_score
from xgboost import XGBClassifier
from onnxmltools import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType
from cic2018 import FAMILY, load_2018

F = json.load(open("models/feature_cols_35.json")); classes = json.load(open("models/classes.json"))
CAP18, CAP18B = 60_000, 200_000
CONFIGS = {"A": dict(n_estimators=150, max_depth=8, learning_rate=0.2),      # = v6
           "B": dict(n_estimators=300, max_depth=8, learning_rate=0.1),
           "C": dict(n_estimators=400, max_depth=10, learning_rate=0.08)}
use = os.environ.get("NS_CONFIGS", "A,B,C").split(",")
rng = np.random.default_rng(42)
t0 = time.time()
def log(*a): print(f"[{(time.time() - t0) / 60:5.1f} min]", *a, flush=True)

# ---- own network ----
def load(p):
    d = pd.read_csv(p, header=None).apply(pd.to_numeric, errors="coerce").dropna().iloc[:, :35].reset_index(drop=True); d.columns = F; return d
def split(idx, f=0.7):
    c = int(len(idx) * f); return idx[:c], idx[c:]
live = load("../baselines/live_flows.csv"); indep = load("../baselines/scan_flows.csv")
sig = ((live["Init_Win_bytes_forward"] == 1024) & (live["Total Fwd Packets"] <= 2)).to_numpy()
s_tr, s_ho = split(np.where(sig)[0]); b_tr, b_ho = split(np.where(~sig)[0])
Xl = live[F].to_numpy("float32")
cap = load("../baselines/benign_capture.csv")
cap = cap[~((cap["Total Fwd Packets"] <= 2) & (cap["Total Backward Packets"] <= 1)).to_numpy()].drop_duplicates().reset_index(drop=True)
c_tr, c_ho = split(np.arange(len(cap))); Xc = cap[F].to_numpy("float32")

# ---- 2018: 70 / 30 in time per label ----
log("reading 2018 files (several minutes)")
X18, y18, ts18, total18, nf = load_2018(benign_frac=0.10, cap=500_000)
known = np.array([l in FAMILY for l in y18])
skipped = sorted(set(y18[~known]))
X18, y18, ts18 = X18[known], y18[known], ts18[known]
tr18, va18, te18 = [], [], []
for l in np.unique(y18):
    idx = np.where(y18 == l)[0]; idx = idx[np.argsort(ts18[idx], kind="stable")]
    n = len(idx); a, v, b = idx[:int(n * .70)], idx[:0], idx[int(n * .70):]
    lim = CAP18B if l == "Benign" else CAP18
    if len(a) > lim: a = rng.choice(a, lim, replace=False)
    if len(v) > 30_000: v = rng.choice(v, 30_000, replace=False)
    if len(b) > 100_000: b = rng.choice(b, 100_000, replace=False)
    tr18.append(a); va18.append(v); te18.append(b)
    log(f"2018 {l:<26} train {len(a):>7,}  val {len(v):>6,}  test {len(b):>7,}")
tr18, va18, te18 = map(np.concatenate, (tr18, va18, te18))
fam = lambda labs: np.array([FAMILY[l] for l in labs], dtype=object)
X18tr, y18tr = X18[tr18], fam(y18[tr18]); X18va, y18va = X18[va18], fam(y18[va18])
X18te, y18te = X18[te18], y18[te18]
del X18, ts18; gc.collect()

# ---- 2017: whole training file ----
tr = pd.read_parquet("data/processed/train_temporal2.parquet", columns=F + ["Label"])
lab_all = tr["Label"].astype(str).to_numpy(dtype=object); Xall = tr[F].to_numpy(dtype="float32"); del tr; gc.collect()
perm = rng.permutation(len(Xall)); nva = 0
va17, rest = perm[:nva], perm[nva:]
if len(va17) > 150_000: va17 = rng.choice(va17, 150_000, replace=False)
X17va, y17va = Xall[va17], lab_all[va17]
keep = []
for l in np.unique(lab_all[rest]):
    idx = rest[lab_all[rest] == l]
    if len(idx) > 50000: idx = rng.choice(idx, 50000, replace=False)
    keep.append(idx)
keep = np.concatenate(keep); X, y = Xall[keep], lab_all[keep]; del Xall; gc.collect()
cnt = pd.Series(y).value_counts()
X, y = RandomOverSampler(random_state=42, sampling_strategy={l: 20000 for l, n in cnt.items() if l != "BENIGN" and n < 20000}).fit_resample(X, y)
n17 = len(X)
X = np.vstack([X, X18tr, Xl[s_tr], Xl[b_tr], Xc[c_tr]]).astype("float32")
y = np.concatenate([np.asarray(y, dtype=object), y18tr, np.array(["PortScan"] * len(s_tr) + ["BENIGN"] * (len(b_tr) + len(c_tr)), dtype=object)])
w = np.r_[np.ones(n17 + len(X18tr)), np.full(len(s_tr) + len(b_tr) + len(c_tr), 10.0)]
le = LabelEncoder(); yi = le.fit_transform(y); assert list(le.classes_) == classes, "class order changed"
Xva = np.vstack([X17va, X18va]); yva = np.concatenate([y17va.astype(object), y18va])
log(f"training rows: 2017 {n17:,} + 2018 {len(X18tr):,} + own network {len(s_tr) + len(b_tr) + len(c_tr):,} | validation {len(Xva):,}")

def to_onnx(clf):
    return ort.InferenceSession(convert_xgboost(clf, initial_types=[("input", FloatTensorType([None, len(F)]))]).SerializeToString())
def lab(s, x):
    out = []
    for i in range(0, len(x), 200_000):
        p = s.run(None, {s.get_inputs()[0].name: x[i:i + 200_000]})[1]
        if isinstance(p, list) and isinstance(p[0], dict): p = [[v[k] for k in sorted(v, key=int)] for v in p]
        out.append(np.array(classes)[np.asarray(p).argmax(1)])
    return np.concatenate(out)
def one_flow_ms(s):
    x = Xl[:1]; name = s.get_inputs()[0].name
    for _ in range(20): s.run(None, {name: x})
    t = []
    for i in range(300):
        a = time.perf_counter(); s.run(None, {name: Xl[i:i + 1]}); t.append(time.perf_counter() - a)
    return 1000 * float(np.median(t))

best = "A"
log(f"training config A {CONFIGS['A']} on train + validation rows")
clf = XGBClassifier(**CONFIGS["A"], tree_method="hist", n_jobs=os.cpu_count(), random_state=42, objective="multi:softprob")
clf.fit(X, yi, sample_weight=w)
del X, y, w; gc.collect()
clf.save_model("models/multiclass_xgb35_v8.json")
onx = convert_xgboost(clf, initial_types=[("input", FloatTensorType([None, len(F)]))])
open("models/multiclass_xgb35_v8.onnx", "wb").write(onx.SerializeToString())
log("saved models/multiclass_xgb35_v8.{json,onnx}")

# ---- final test: v3 (deployed), v6, v7, v8 ----
te = pd.read_parquet("data/processed/test_temporal2.parquet", columns=F + ["Label"])
Xt = te[F].to_numpy("float32"); yt = te["Label"].astype(str).to_numpy(); del te; gc.collect()
labs = sorted(set(yt)); Xi = indep[F].to_numpy("float32"); order = ["Benign"] + sorted(set(y18te) - {"Benign"})
NAMES = ["v3", "v6", "v7", "v8"]; res = {}
for name in NAMES:
    s = ort.InferenceSession(f"models/multiclass_xgb35_{name}.onnx")
    pt, p18 = lab(s, Xt), lab(s, X18te); a17 = yt != "BENIGN"; a18 = y18te != "Benign"
    r = {"f1": f1_score(yt, pt, labels=labs, average="macro", zero_division=0),
         "cls": dict(zip(labs, f1_score(yt, pt, labels=labs, average=None, zero_division=0))),
         "fpr17": 100 * (pt[~a17] != "BENIGN").mean(), "det17": 100 * (pt[a17] != "BENIGN").mean(),
         "scan": int((lab(s, Xl[s_ho]) == "PortScan").sum()), "ben": int((lab(s, Xl[b_ho]) == "BENIGN").sum()),
         "cap": int((lab(s, Xc[c_ho]) == "BENIGN").sum()), "indep": int((lab(s, Xi) == "PortScan").sum()),
         "all18": 100 * (p18[a18] != "BENIGN").mean(), "right18": 100 * (p18[a18] == fam(y18te[a18])).mean(), "ms": one_flow_ms(s)}
    for l in order:
        m = y18te == l; r[l] = (100 * (p18[m] != "BENIGN").mean(), 100 * (p18[m] == FAMILY[l]).mean())
    res[name] = r
R = [res[n] for n in NAMES]
row = lambda key, fmt: "".join(fmt.format(r[key]) for r in R)
hdr = "".join(f"{n:>10}" for n in NAMES)
out = ["NetSpectre classifier v8: CICIDS2017 + CSE-CIC-IDS2018 (7 days) + own-network normal traffic; config A chosen on validation in v7, refit on train+validation",
       f"2018 data: {nf} day files; per label in time order first 70% train, last 30% test. v6 never saw 15-02, 21-02, 22-02, 23-02.", "",
       "CSE-CIC-IDS2018 test flows: % flagged as an attack (Benign row = false alarms)",
       f"{'2018 label':<26}{'test flows':>11}" + hdr]
for l in order:
    out.append(f"{l:<26}{int((y18te == l).sum()):>11,}" + "".join(f"{r[l][0]:>9.1f}%" for r in R))
out += [f"{'ALL ATTACKS':<26}{int((y18te != 'Benign').sum()):>11,}" + row("all18", "{:>9.1f}%"), "",
        "Same flows: % given the correct attack family",
        f"{'2018 label':<37}" + hdr]
for l in order[1:]:
    out.append(f"{l:<37}" + "".join(f"{r[l][1]:>9.1f}%" for r in R))
out += [f"{'ALL ATTACKS':<37}" + row("right18", "{:>9.1f}%"), "",
        f"CICIDS2017 test set (499,605 flows){'':<11}" + hdr,
        f"  {'macro F1':<44}" + row("f1", "{:>10.4f}"),
        f"  {'attack detection':<44}" + row("det17", "{:>9.2f}%"),
        f"  {'benign false alarms':<44}" + row("fpr17", "{:>9.3f}%"),
        "  F1 per class:"]
for c in labs:
    out.append(f"    {c:<42}" + "".join(f"{r['cls'][c]:>10.3f}" for r in R) + f"   ({int((yt == c).sum()):,} flows)")
out += ["", "Own network (held out)" + " " * 24 + hdr,
        f"  {'scans called PortScan (of %d)' % len(s_ho):<44}" + row("scan", "{:>10}"),
        f"  {'normal flows called BENIGN (of %d)' % len(b_ho):<44}" + row("ben", "{:>10}"),
        f"  {'normal capture called BENIGN (of %d)' % len(c_ho):<44}" + row("cap", "{:>10}"),
        f"  {'independent scan flows PortScan (of %d)' % len(Xi):<44}" + row("indep", "{:>10}"), "",
        f"  {'one flow, ms on this machine':<44}" + row("ms", "{:>10.3f}")]
v3, v6, v7, v8 = R
gate = [("no extra home false alarms vs v3", v8["ben"] >= v3["ben"] and v8["cap"] >= v3["cap"]),
        ("2017 macro F1 not lower than v6 by >0.005", v8["f1"] >= v6["f1"] - 0.005),
        ("2017 benign false alarms <= 0.15%", v8["fpr17"] <= 0.15),
        ("home scans called PortScan >= 99% (an alert needs 10 probes, so one missed probe changes nothing)", v8["scan"] >= 0.99 * len(s_ho)),
        ("one flow <= 3x v3 time", v8["ms"] <= 3 * v3["ms"])]
out += ["", "Deploy check for v8:"] + [f"  [{'PASS' if ok else 'FAIL'}] {t}" for t, ok in gate]
out.append("  => " + ("DEPLOY v8" if all(ok for _, ok in gate) else "do not deploy v8 as is (see FAIL lines)"))
text = "\n".join(out); print("\n" + text)
open("../docs/EVAL_V8.txt", "w").write(text + "\n")
print("\nwritten ../docs/EVAL_V8.txt")

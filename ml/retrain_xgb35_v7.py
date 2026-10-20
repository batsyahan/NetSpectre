"""v7 = v6 data (CICIDS2017 + CSE-CIC-IDS2018 + own-network normal traffic), all downloaded 2018 days,
and a small size/learning-rate search chosen on a VALIDATION split (the test data is never used to choose).

Splits, per 2018 label in time order: first 55% train, next 15% validation, last 30% test (same test rule as v5/v6).
CICIDS2017: 10% of the training file is held out for validation; the 2017 test file is only used at the end.
Choice rule: best validation macro F1; a smaller config wins if it is within 0.002 (it is faster on the Pi).
Run from ml/ inside the .venv:  python retrain_xgb35_v7.py
Optional: NS_CONFIGS=A,B to try fewer configs (faster).  Report: ../docs/EVAL_V7.txt
Writes models/multiclass_xgb35_v7.{json,onnx}; never overwrites v3/v6.
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

# ---- 2018: 55 / 15 / 30 in time per label ----
log("reading 2018 files (several minutes)")
X18, y18, ts18, total18, nf = load_2018(benign_frac=0.10, cap=500_000)
known = np.array([l in FAMILY for l in y18])
skipped = sorted(set(y18[~known]))
X18, y18, ts18 = X18[known], y18[known], ts18[known]
tr18, va18, te18 = [], [], []
for l in np.unique(y18):
    idx = np.where(y18 == l)[0]; idx = idx[np.argsort(ts18[idx], kind="stable")]
    n = len(idx); a, v, b = idx[:int(n * .55)], idx[int(n * .55):int(n * .70)], idx[int(n * .70):]
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

# ---- 2017: 90% train / 10% validation from the training file ----
tr = pd.read_parquet("data/processed/train_temporal2.parquet", columns=F + ["Label"])
lab_all = tr["Label"].astype(str).to_numpy(dtype=object); Xall = tr[F].to_numpy(dtype="float32"); del tr; gc.collect()
perm = rng.permutation(len(Xall)); nva = len(perm) // 10
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
    x = Xva[:1]; name = s.get_inputs()[0].name
    for _ in range(20): s.run(None, {name: x})
    t = []
    for i in range(300):
        a = time.perf_counter(); s.run(None, {name: Xva[i:i + 1]}); t.append(time.perf_counter() - a)
    return 1000 * float(np.median(t))

vlabs = sorted(set(yva)); sweep = {}
for k in use:
    log(f"training config {k} {CONFIGS[k]}")
    clf = XGBClassifier(**CONFIGS[k], tree_method="hist", n_jobs=os.cpu_count(), random_state=42, objective="multi:softprob")
    clf.fit(X, yi, sample_weight=w)
    s = to_onnx(clf)
    f1 = f1_score(yva, lab(s, Xva), labels=vlabs, average="macro", zero_division=0)
    sweep[k] = (f1, one_flow_ms(s), clf)
    log(f"config {k}: validation macro F1 {f1:.4f} | one flow {sweep[k][1]:.3f} ms on this machine")
best = max(sweep, key=lambda k: sweep[k][0])
for k in use:                                   # smaller config first: prefer it if nearly as good
    if sweep[k][0] >= sweep[best][0] - 0.002: best = k; break
clf = sweep[best][2]
del X, y, w; gc.collect()
clf.save_model("models/multiclass_xgb35_v7.json")
onx = convert_xgboost(clf, initial_types=[("input", FloatTensorType([None, len(F)]))])
open("models/multiclass_xgb35_v7.onnx", "wb").write(onx.SerializeToString())
log(f"chose config {best}; saved models/multiclass_xgb35_v7.{{json,onnx}}")

# ---- final test: v3 (deployed), v6, v7 ----
te = pd.read_parquet("data/processed/test_temporal2.parquet", columns=F + ["Label"])
Xt = te[F].to_numpy("float32"); yt = te["Label"].astype(str).to_numpy(); del te; gc.collect()
labs = sorted(set(yt)); Xi = indep[F].to_numpy("float32"); order = ["Benign"] + sorted(set(y18te) - {"Benign"})
res = {}
for name in ["v3", "v6", "v7"]:
    s = ort.InferenceSession(f"models/multiclass_xgb35_{name}.onnx")
    pt, p18 = lab(s, Xt), lab(s, X18te); a17 = yt != "BENIGN"; a18 = y18te != "Benign"
    r = {"f1": f1_score(yt, pt, labels=labs, average="macro", zero_division=0),
         "fpr17": 100 * (pt[~a17] != "BENIGN").mean(), "det17": 100 * (pt[a17] != "BENIGN").mean(),
         "scan": int((lab(s, Xl[s_ho]) == "PortScan").sum()), "ben": int((lab(s, Xl[b_ho]) == "BENIGN").sum()),
         "cap": int((lab(s, Xc[c_ho]) == "BENIGN").sum()), "indep": int((lab(s, Xi) == "PortScan").sum()),
         "all18": 100 * (p18[a18] != "BENIGN").mean(), "right18": 100 * (p18[a18] == fam(y18te[a18])).mean(), "ms": one_flow_ms(s)}
    for l in order:
        m = y18te == l; r[l] = (100 * (p18[m] != "BENIGN").mean(), 100 * (p18[m] == FAMILY[l]).mean())
    res[name] = r
R = [res[n] for n in ("v3", "v6", "v7")]
row = lambda key, fmt: "".join(fmt.format(r[key]) for r in R)
out = ["NetSpectre classifier v7: CICIDS2017 + CSE-CIC-IDS2018 + own-network normal traffic, tuned on a validation split",
       f"2018 data: {nf} day files; per label in time order 55% train / 15% validation / 30% test. Labels skipped (no 2017 class): {skipped or 'none'}",
       "Config search (validation macro F1, one-flow time on this machine):"]
out += [f"  {k} {CONFIGS[k]}: F1 {sweep[k][0]:.4f}, {sweep[k][1]:.3f} ms" + ("   <- chosen" if k == best else "") for k in use]
out += ["", "CSE-CIC-IDS2018 test flows (latest 30% in time of each label; v6 never saw the newly added days at all)",
        f"{'2018 label':<26}{'test flows':>11}{'v3 flag':>9}{'v6 flag':>9}{'v7 flag':>9}{'v3 right':>10}{'v6 right':>10}{'v7 right':>10}"]
for l in order:
    out.append(f"{l:<26}{int((y18te == l).sum()):>11,}" + "".join(f"{r[l][0]:>8.1f}%" for r in R) + "".join(f"{r[l][1]:>9.1f}%" for r in R))
out += [f"{'ALL ATTACKS':<26}{int((y18te != 'Benign').sum()):>11,}" + row("all18", "{:>8.1f}%") + "".join(f"{r['right18']:>9.1f}%" for r in R),
        "Benign row = false alarms (lower is better); attack rows = detection. 'right' = correct attack family.", "",
        "CICIDS2017 test set (499,605 flows)                  v3        v6        v7",
        "  macro F1                                   " + row("f1", "{:>10.4f}"),
        "  attack detection                           " + row("det17", "{:>9.2f}%"),
        "  benign false alarms                        " + row("fpr17", "{:>9.3f}%"), "",
        "Own network (held out)",
        f"  scans called PortScan (of {len(s_ho)})               " + row("scan", "{:>10}"),
        f"  normal flows called BENIGN (of {len(b_ho)})          " + row("ben", "{:>10}"),
        f"  normal capture called BENIGN (of {len(c_ho)})        " + row("cap", "{:>10}"),
        f"  independent scan flows PortScan (of {len(Xi)})     " + row("indep", "{:>10}"), "",
        "  one flow, ms on this machine               " + row("ms", "{:>10.3f}")]
v3, v6, v7 = R
gate = [("no extra home false alarms vs v3", v7["ben"] >= v3["ben"] and v7["cap"] >= v3["cap"]),
        ("2017 macro F1 not lower than v6 by >0.005", v7["f1"] >= v6["f1"] - 0.005),
        ("2017 benign false alarms <= 0.15%", v7["fpr17"] <= 0.15),
        ("all home scans still PortScan", v7["scan"] == len(s_ho)),
        ("one flow <= 3x v3 time", v7["ms"] <= 3 * v3["ms"])]
out += ["", "Deploy check for v7:"] + [f"  [{'PASS' if ok else 'FAIL'}] {t}" for t, ok in gate]
out.append("  => " + ("DEPLOY v7" if all(ok for _, ok in gate) else "keep v6/v3 (see FAIL lines)"))
text = "\n".join(out); print("\n" + text)
open("../docs/EVAL_V7.txt", "w").write(text + "\n")
print("\nwritten ../docs/EVAL_V7.txt")

"""Builds dashboard/public/model_report.json: every number on the dashboard's ML Advanced page comes from here.

Run from ml/ inside the .venv (about 5-10 minutes; trains the Random Forest once and caches it):
    python export_model_report.py
Compared on the same 499,605-flow CICIDS2017 test split and the same 35 features:
  Random Forest, CatBoost and XGBoost trained on the same CICIDS2017 training data (50k cap per class,
  small attack classes oversampled to 20k), the XGBoost+CatBoost ensemble, the previous XGBoost v3
  (that recipe plus live flows from the monitor) and the deployed model (NS_MODEL, default v7:
  CICIDS2017 + 7 days of CSE-CIC-IDS2018 + own-network normal traffic).
CSE-CIC-IDS2018 results are read from docs/EVAL_V8.txt (written by retrain_xgb35_v8.py).
"""
import gc, json, os, re, time
from datetime import datetime, timezone
import numpy as np, pandas as pd, onnxruntime as ort
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_recall_fscore_support

F = json.load(open("models/feature_cols_35.json")); classes = json.load(open("models/classes.json"))
DEPLOYED = os.environ.get("NS_MODEL", "multiclass_xgb35_v7"); AE = os.environ.get("NS_AE_MODEL", "ae35_v2")
OUT = "../dashboard/public/model_report.json"

# ---------- Random Forest on the same data and features (trained once, then cached) ----------
RF = "models/multiclass_rf35.onnx"
if not os.path.exists(RF):
    from imblearn.over_sampling import RandomOverSampler
    from sklearn.ensemble import RandomForestClassifier
    from skl2onnx import to_onnx
    tr = pd.read_parquet("data/processed/train_temporal2.parquet", columns=F + ["Label"])
    tr = pd.concat([g.sample(50_000, random_state=42) if len(g) > 50_000 else g for _, g in tr.groupby("Label")], ignore_index=True)
    X, y = tr[F].to_numpy("float32"), tr["Label"].to_numpy(); del tr; gc.collect()
    cnt = pd.Series(y).value_counts()
    X, y = RandomOverSampler(random_state=42, sampling_strategy={l: 20000 for l, n in cnt.items() if l != "BENIGN" and n < 20000}).fit_resample(X, y)
    t0 = time.time()
    rf = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42).fit(X.astype("float32"), y)
    print(f"Random Forest trained in {time.time() - t0:.0f}s", flush=True)
    assert list(rf.classes_) == classes, "class order differs"
    open(RF, "wb").write(to_onnx(rf, X=np.zeros((1, len(F)), "float32"), options={id(rf): {"zipmap": False}}).SerializeToString())
    del rf, X, y; gc.collect()

te = pd.read_parquet("data/processed/test_temporal2.parquet", columns=F + ["Label"])
Xt, yt = te[F].to_numpy("float32"), te["Label"].to_numpy(); del te
labs = np.array(classes)

def probs(sess, x):
    out = []
    for i in range(0, len(x), 50_000):
        p = sess.run(None, {sess.get_inputs()[0].name: x[i:i + 50_000]})[1]
        if isinstance(p, list) and isinstance(p[0], dict):
            p = [[d[k] for k in sorted(d, key=int)] for d in p]
        out.append(np.asarray(p, dtype=np.float64))
    return np.vstack(out)

def latency_ms(sess, n=1000):
    rng = np.random.default_rng(0); rows = Xt[rng.choice(len(Xt), n, replace=False)]
    name = sess.get_inputs()[0].name
    for r in rows[:50]: sess.run(None, {name: r[None]})
    t0 = time.perf_counter()
    for r in rows: sess.run(None, {name: r[None]})
    return (time.perf_counter() - t0) / n * 1000

def metrics(pred):
    p, r, f, s = precision_recall_fscore_support(yt, pred, labels=classes, zero_division=0)
    return {
        "accuracy": accuracy_score(yt, pred),
        "macro_precision": float(p.mean()), "macro_recall": float(r.mean()), "macro_f1": f1_score(yt, pred, labels=classes, average="macro", zero_division=0),
        "weighted_f1": f1_score(yt, pred, average="weighted", zero_division=0),
        "benign_fpr": float((pred[yt == "BENIGN"] != "BENIGN").mean()),
        "per_class": {c: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]), "support": int(s[i])} for i, c in enumerate(classes)},
        "confusion_matrix": confusion_matrix(yt, pred, labels=classes).tolist(),
    }

specs = [
    ("Random Forest", RF, "100 trees, max depth 20 (scikit-learn)", "CICIDS2017"),
    ("CatBoost", "models/multiclass_cat35.onnx", "200 iterations, depth 6, learning rate 0.2", "CICIDS2017"),
    ("XGBoost", "models/multiclass_xgb35.onnx", "100 trees per class, depth 6, learning rate 0.2", "CICIDS2017"),
]
models, P = [], {}
for name, path, params, data in specs:
    s = ort.InferenceSession(path); P[name] = probs(s, Xt)
    m = metrics(labs[P[name].argmax(1)])
    models.append({"name": name, "file": os.path.basename(path), "size_bytes": os.path.getsize(path), "params": params,
                   "trained_on": data, "latency_ms": latency_ms(s), "deployed": False, **m})
    print(f"{name}: macro F1 {m['macro_f1']:.4f}", flush=True)
ens = (P["XGBoost"] + P["CatBoost"]) / 2
models.append({"name": "XGBoost + CatBoost ensemble", "file": "average of the two", "size_bytes": models[1]["size_bytes"] + models[2]["size_bytes"],
               "params": "average of the two probability outputs (NS_ENSEMBLE=1)", "trained_on": "CICIDS2017",
               "latency_ms": models[1]["latency_ms"] + models[2]["latency_ms"], "deployed": False, **metrics(labs[ens.argmax(1)])})
# description of each XGBoost version that can be deployed
VERSIONS = {
    "multiclass_xgb35_v3": ("100 trees per class, depth 6, learning rate 0.2, plus 2,486 live flows from the monitor (weight 10)",
                            "CICIDS2017 + own live flows"),
    "multiclass_xgb35_v6": ("150 trees per class, depth 8, learning rate 0.2", "CICIDS2017 + CIC-IDS2018 (3 days) + own normal traffic"),
    "multiclass_xgb35_v7": ("150 trees per class, depth 8, learning rate 0.2 (chosen on a validation split)",
                            "CICIDS2017 + CIC-IDS2018 (7 days) + own normal traffic"),
}
VER = lambda f: f.rsplit("_", 1)[-1]                      # multiclass_xgb35_v7 -> v7
if DEPLOYED != "multiclass_xgb35_v3":
    s3 = ort.InferenceSession("models/multiclass_xgb35_v3.onnx")
    models.append({"name": "XGBoost v3 (previous)", "file": "multiclass_xgb35_v3.onnx", "size_bytes": os.path.getsize("models/multiclass_xgb35_v3.onnx"),
                   "params": VERSIONS["multiclass_xgb35_v3"][0], "trained_on": VERSIONS["multiclass_xgb35_v3"][1],
                   "latency_ms": latency_ms(s3), "deployed": False, **metrics(labs[probs(s3, Xt).argmax(1)])})
    del s3
sd = ort.InferenceSession(f"models/{DEPLOYED}.onnx"); pd_ = probs(sd, Xt); pred_dep = labs[pd_.argmax(1)]
params, data = VERSIONS.get(DEPLOYED, ("XGBoost", "see training script"))
models.append({"name": f"XGBoost {VER(DEPLOYED)} (deployed)", "file": f"{DEPLOYED}.onnx", "size_bytes": os.path.getsize(f"models/{DEPLOYED}.onnx"),
               "params": params, "trained_on": data, "latency_ms": latency_ms(sd), "deployed": True, **metrics(pred_dep)})
del P, ens; gc.collect()

# ---------- deployed model: confusion matrix and global feature importance (mean |TreeSHAP|) ----------
import xgboost as xgb
booster = xgb.Booster(); booster.load_model(f"models/{DEPLOYED}.json")
rng = np.random.default_rng(1); idx = rng.choice(len(Xt), 20_000, replace=False)
contrib = booster.predict(xgb.DMatrix(Xt[idx]), pred_contribs=True)          # (n, classes, features+1)
k = pd_[idx].argmax(1)
imp = np.abs(contrib[np.arange(len(idx)), k, :-1]).mean(0); imp = imp / imp.sum()
importance = sorted(({"feature": f, "share": float(v)} for f, v in zip(F, imp)), key=lambda d: -d["share"])

# ---------- autoencoder ----------
m = json.load(open(f"models/{AE}_meta.json")); thr = float(m["threshold"])
mu, sdv = np.array(m["mu"], "float32"), np.array(m["sd"], "float32"); ae = ort.InferenceSession(f"models/{AE}.onnx")
def ae_err(x):
    e = []
    for i in range(0, len(x), 100_000):
        z = (((np.sign(x[i:i + 100_000]) * np.log1p(np.abs(x[i:i + 100_000]))) - mu) / sdv).astype("float32")
        e.append(((ae.run(None, {"x": z})[0] - z) ** 2).mean(1))
    return np.concatenate(e)
err = ae_err(Xt)
cap_path = "../baselines/benign_capture.csv"
own = None
if os.path.exists(cap_path):
    c = pd.read_csv(cap_path, header=None).apply(pd.to_numeric, errors="coerce").dropna().iloc[:, :35].to_numpy("float32")
    own = {"flows": int(len(c)), "flagged": float((ae_err(c) > thr).mean())}
autoencoder = {"model": AE, "threshold": thr, "layers": "35-24-12-6-12-24-35",
               "cicids_benign_flagged": float((err[yt == "BENIGN"] > thr).mean()), "own_network": own,
               "attack_flagged": {c: float((err[yt == c] > thr).mean()) for c in classes if c != "BENIGN"}}

# ---------- leave-one-day-out summary (from docs/EVAL_LEAVE_DAY_OUT.txt) ----------
lodo = []
path = "../docs/EVAL_LEAVE_DAY_OUT.txt"
if os.path.exists(path):
    day = None
    for line in open(path):
        mt = re.match(r"=== held out: (\w+)", line)
        if mt: day = {"day": mt.group(1), "attacks": []}; lodo.append(day); continue
        if day is None or not line.strip() or line.startswith("class"): continue
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) >= 7:
            pc = [float(x.rstrip("%")) / 100 for x in parts[2:7]]
            row = {"label": parts[0], "flows": int(parts[1].replace(",", "")), "classifier": pc[0], "either_ae_0_5": pc[4]}
            if parts[0] == "BENIGN": day["benign_fpr"] = row
            elif parts[0].startswith("ALL ATTACKS"): day["all_attacks"] = row
            else: day["attacks"].append(row)

# ---------- CSE-CIC-IDS2018 (different network, one year later), from docs/EVAL_V8.txt ----------
cic18 = None
path = "../docs/EVAL_V8.txt"
if os.path.exists(path):
    cols, rows, section = [], {}, None
    for line in open(path):
        line = line.rstrip("\n")
        if line.startswith("CSE-CIC-IDS2018 test flows"): section = "caught"; continue
        if line.startswith("Same flows"): section = "right"; continue
        if line.startswith("Benign row") or line.startswith("CICIDS2017 test set"): section = None if line.startswith("CICIDS2017") else section; continue
        if section and line.startswith("2018 label"):
            cols = line.split()[4:] if section == "caught" else line.split()[2:]; continue
        if not section or not line.strip(): continue
        mt = re.match(r"^(.+?)\s{2,}(?:([\d,]+)\s+)?((?:[\d.]+%\s*)+)$", line)
        if not mt: continue
        label, n, vals = mt.group(1).strip(), mt.group(2), [float(v) / 100 for v in re.findall(r"([\d.]+)%", mt.group(3))]
        row = rows.setdefault(label, {"label": label})
        if n: row["flows"] = int(n.replace(",", ""))
        row[section] = dict(zip(cols, vals))
    order = [k for k in rows if k not in ("Benign", "ALL ATTACKS")]
    cic18 = {"models": cols, "benign": rows.get("Benign"), "all_attacks": rows.get("ALL ATTACKS"),
             "attacks": [rows[k] for k in order],
             "note": "CSE-CIC-IDS2018 (recorded a year later on a different network). For every label the latest 30% of flows in time are the test set; "
                     "v3 was trained on CICIDS2017 only, v6 never saw the days 15-02, 21-02, 22-02 and 23-02."}

report = {
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "test_set": {"flows": int(len(yt)), "source": "CICIDS2017",
                 "split": "first 80% of each capture day and attack type for training, last 20% for testing"},
    "features": F, "classes": classes, "deployed_model": DEPLOYED,
    "models": models, "feature_importance": importance,
    "feature_importance_method": "mean |TreeSHAP| contribution to the predicted class, deployed model, 20,000 random test flows",
    "autoencoder": autoencoder, "leave_one_day_out": lodo, "cicids2018": cic18,
    "leave_one_day_out_note": "From docs/EVAL_LEAVE_DAY_OUT.txt; classifier retrained per held-out day with the deployed recipe, autoencoder ae35 at 0.5 (the version deployed at that time).",
}
open(OUT, "w").write(json.dumps(report, indent=1))
print(f"\nwritten {OUT}")
for mo in models:
    print(f"{mo['name']:<30} acc {mo['accuracy']:.4f}  macro-F1 {mo['macro_f1']:.4f}  benign FPR {100 * mo['benign_fpr']:.3f}%  "
          f"{mo['size_bytes'] / 1e6:.1f} MB  {mo['latency_ms']:.2f} ms/flow")

"""Cross-dataset test: the deployed models (trained on CICIDS2017) on CSE-CIC-IDS2018.

CSE-CIC-IDS2018 was recorded a year later on a different, larger network (AWS) with CICFlowMeter-V3,
so its flow features use the same definitions under shorter column names. No retraining happens here.
Run from ml/ inside the .venv after the download finished:
    python eval_cicids2018.py            (reads data/raw/cicids2018/*.csv, writes ../docs/EVAL_CICIDS2018.txt)
Memory: files are read in chunks; benign flows are sampled (5%), attack flows kept up to 300,000 per label.
"""
import glob, json, os, sys
import numpy as np, pandas as pd, onnxruntime as ort

F = json.load(open("models/feature_cols_35.json")); C = np.array(json.load(open("models/classes.json")))
MODEL = os.environ.get("NS_MODEL", "multiclass_xgb35_v3"); AE = os.environ.get("NS_AE_MODEL", "ae35_v2")

from cic2018 import MAP, FAMILY, load_2018

CAP, BENIGN_FRAC = 300_000, 0.05
X, y, _, total, n_files = load_2018(BENIGN_FRAC, CAP)

s = ort.InferenceSession(f"models/{MODEL}.onnx")
pred = []
for i in range(0, len(X), 200_000):
    p = s.run(None, {s.get_inputs()[0].name: X[i:i + 200_000]})[1]
    if isinstance(p, list) and isinstance(p[0], dict):
        p = [[r[k] for k in sorted(r, key=int)] for r in p]
    pred.append(C[np.asarray(p).argmax(1)])
pred = np.concatenate(pred)
m = json.load(open(f"models/{AE}_meta.json")); thr = float(m["threshold"])
mu, sd = np.array(m["mu"], "float32"), np.array(m["sd"], "float32"); ae = ort.InferenceSession(f"models/{AE}.onnx")
err = np.empty(len(X), "float32")
for i in range(0, len(X), 200_000):
    x = X[i:i + 200_000]; z = (((np.sign(x) * np.log1p(np.abs(x))) - mu) / sd).astype("float32")
    err[i:i + 200_000] = ((ae.run(None, {"x": z})[0] - z) ** 2).mean(1)
flag_c = pred != "BENIGN"; flag_a = (~flag_c) & (err > thr)

out = [f"CSE-CIC-IDS2018 cross-dataset test: classifier {MODEL}, autoencoder {AE} @ {thr:.3f} (trained on CICIDS2017 only)",
       f"files: {n_files} | flows evaluated: {len(y):,} (benign sampled at {BENIGN_FRAC:.0%}, attacks capped at {CAP:,} per label)", "",
       f"{'2018 label':<26}{'total in data':>14}{'evaluated':>11}{'any attack':>12}{'right class':>13}{'AE only':>9}{'either':>9}"]
order = ["Benign"] + sorted(set(y) - {"Benign"})
for l in order:
    mk = y == l; fam = FAMILY.get(l)
    right = (pred[mk] == fam).mean() if fam else float("nan")
    out.append(f"{l:<26}{total.get(l, 0):>14,}{mk.sum():>11,}{100 * flag_c[mk].mean():>11.1f}%"
               f"{('%12.1f%%' % (100 * right)) if fam else '         n/a':>13}{100 * flag_a[mk].mean():>8.1f}%{100 * (flag_c | flag_a)[mk].mean():>8.1f}%")
att = y != "Benign"
out += [f"{'ALL ATTACKS':<26}{'':>14}{att.sum():>11,}{100 * flag_c[att].mean():>11.1f}%{'':>13}{100 * flag_a[att].mean():>8.1f}%{100 * (flag_c | flag_a)[att].mean():>8.1f}%", "",
        "Benign row: false-positive rates. Attack rows: detection rates. 'any attack' = classifier gave any attack label;",
        "'right class' = it gave the matching CICIDS2017 class; 'AE only' = classifier said BENIGN but the autoencoder flagged it;",
        "'either' = what NetSpectre would flag. Unknown labels (not in the mapping) are shown with n/a.", "",
        "Most frequent wrong labels for attack flows:"]
expect = np.array([FAMILY.get(l) for l in y[att]], dtype=object)
wrong = pd.DataFrame({"label": y[att], "pred": pred[att]})[expect != pred[att]]
for (l, p), n in wrong.value_counts().head(12).items():
    out.append(f"  {l:<26} -> {p:<26} {n:>9,}")
text = "\n".join(out); print("\n" + text)
open("../docs/EVAL_CICIDS2018.txt", "w").write(text + "\n")
print("\nwritten ../docs/EVAL_CICIDS2018.txt")

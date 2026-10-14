"""Leave-one-day-out test: can NetSpectre flag attacks it never saw during training?

In CICIDS2017 every attack type was recorded on one day only, so holding out a day removes its
attack types from training completely. For each held-out day we train the classifier on the other
days (same recipe as the deployed model: 50k cap per class, oversample small attack classes to 20k,
XGBoost 100 trees depth 6) and measure on the held-out day:
  - benign false-positive rate (normal flows called an attack),
  - per attack type, the share flagged by the classifier (any non-BENIGN label),
    by the autoencoder (score above threshold), and by either (what NetSpectre would flag).
Run from ml/ inside the .venv:  python eval_leave_day_out.py      (takes a few minutes)
Writes ../docs/EVAL_LEAVE_DAY_OUT.txt.
Caveat: the autoencoder (models/ae35.onnx) was trained on benign flows from all days, so its
benign false-positive rate on a held-out day is slightly optimistic; its attack scores are not affected.
"""
import gc, json, sys
import numpy as np, pandas as pd, onnxruntime as ort
from imblearn.over_sampling import RandomOverSampler
from xgboost import XGBClassifier

F = json.load(open("models/feature_cols_35.json"))
THR = [0.2369, 0.5]
out_lines = []
def say(s=""):
    print(s, flush=True); out_lines.append(s)

df = pd.read_parquet("data/processed/cicids2017.parquet", columns=F + ["Label", "source_file"])
df = df.dropna(subset=F).drop_duplicates(subset=F + ["Label"]).reset_index(drop=True)
df["day"] = df["source_file"].str.split("-").str[0]
say(f"flows after cleaning: {len(df):,}")
say("attack types per day: " + "; ".join(
    f"{d}: {', '.join(sorted(set(g['Label']) - {'BENIGN'})) or 'benign only'}" for d, g in df.groupby("day", sort=False)))

m = json.load(open("models/ae35_meta.json"))
mu, sd = np.array(m["mu"], "float32"), np.array(m["sd"], "float32")
ae = ort.InferenceSession("models/ae35.onnx")
def ae_score(X):
    out = np.empty(len(X), "float32")
    for i in range(0, len(X), 200_000):
        x = X[i:i + 200_000]
        z = (((np.sign(x) * np.log1p(np.abs(x))) - mu) / sd).astype("float32")
        out[i:i + 200_000] = ((ae.run(None, {"x": z})[0] - z) ** 2).mean(1)
    return out

rng = np.random.default_rng(42)
summary = []
for day in ["Tuesday", "Wednesday", "Thursday", "Friday"]:
    tr, te = df[df["day"] != day], df[df["day"] == day]
    y = tr["Label"].to_numpy(dtype=object)
    keep = np.concatenate([idx if len(idx) <= 50000 else rng.choice(idx, 50000, replace=False)
                           for idx in (np.where(y == l)[0] for l in np.unique(y))])
    X, y = tr[F].to_numpy("float32")[keep], y[keep]
    cnt = pd.Series(y).value_counts()
    X, y = RandomOverSampler(random_state=42, sampling_strategy={l: 20000 for l, n in cnt.items() if l != "BENIGN" and n < 20000}).fit_resample(X, y)
    classes = np.unique(y); yi = np.searchsorted(classes, y)
    clf = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.2, tree_method="hist", n_jobs=8,
                        random_state=42, objective="multi:softprob")
    clf.fit(X, yi); del X; gc.collect()

    Xt = te[F].to_numpy("float32"); yt = te["Label"].to_numpy()
    pred = classes[clf.predict(Xt)]; clf_flag = pred != "BENIGN"
    sc = ae_score(Xt)
    say(f"\n=== held out: {day} ({len(te):,} flows; trained on {', '.join(sorted(set(df['day']) - {day}))}) ===")
    say(f"{'class':<28}{'flows':>9}{'classifier':>12}" + "".join(f"{'AE>' + str(t):>11}{'either':>9}" for t in THR))
    for lab in ["BENIGN"] + sorted(set(yt) - {"BENIGN"}):
        mk = yt == lab
        row = f"{lab:<28}{mk.sum():>9,}{100 * clf_flag[mk].mean():>11.1f}%"
        for t in THR:
            a = sc[mk] > t
            row += f"{100 * a.mean():>10.1f}%{100 * (a | clf_flag[mk]).mean():>8.1f}%"
        say(row)
        if lab == "BENIGN":
            summary.append((day, "benign flagged (false positives)", 100 * clf_flag[mk].mean(),
                            100 * ((sc[mk] > 0.5) | clf_flag[mk]).mean()))
        else:
            summary.append((day, lab, 100 * clf_flag[mk].mean(), 100 * ((sc[mk] > 0.5) | clf_flag[mk]).mean()))
    att = yt != "BENIGN"
    say(f"{'ALL ATTACKS (unseen)':<28}{att.sum():>9,}{100 * clf_flag[att].mean():>11.1f}%" +
        "".join(f"{100 * (sc[att] > t).mean():>10.1f}%{100 * ((sc[att] > t) | clf_flag[att]).mean():>8.1f}%" for t in THR))
    del tr, te, Xt; gc.collect()

say("\nColumns: share of flows flagged. 'classifier' = any attack label; 'AE>t' = autoencoder score above t;")
say("'either' = flagged by classifier or autoencoder (NetSpectre uses 0.5 in docker-compose).")
say("For BENIGN rows the numbers are false-positive rates; for attack rows they are detection rates.")
open("../docs/EVAL_LEAVE_DAY_OUT.txt", "w").write("\n".join(out_lines) + "\n")
print("\nwritten ../docs/EVAL_LEAVE_DAY_OUT.txt")

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

# CICIDS2018 column name -> CICIDS2017 (model) column name
MAP = {
    "Dst Port": "Destination Port", "Flow Duration": "Flow Duration",
    "Tot Fwd Pkts": "Total Fwd Packets", "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets", "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max", "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean", "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max", "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean", "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s", "Flow Pkts/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean", "Flow IAT Std": "Flow IAT Std", "Flow IAT Max": "Flow IAT Max", "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Tot": "Fwd IAT Total", "Fwd IAT Mean": "Fwd IAT Mean", "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max", "Fwd IAT Min": "Fwd IAT Min",
    "Fwd Header Len": "Fwd Header Length", "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s", "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Mean": "Packet Length Mean", "Pkt Len Std": "Packet Length Std",
    "Init Fwd Win Byts": "Init_Win_bytes_forward", "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd", "Fwd Seg Size Min": "min_seg_size_forward",
}
assert sorted(MAP.values()) == sorted(F), "mapping does not cover the 35 model features"

# CICIDS2018 label -> the CICIDS2017 class the model should give (None: attack type the model never learned)
FAMILY = {
    "Benign": "BENIGN",
    "DoS attacks-Hulk": "DoS Hulk", "DoS attacks-GoldenEye": "DoS GoldenEye",
    "DoS attacks-Slowloris": "DoS slowloris", "DoS attacks-SlowHTTPTest": "DoS Slowhttptest",
    "DDoS attacks-LOIC-HTTP": "DDoS", "DDOS attack-HOIC": "DDoS", "DDOS attack-LOIC-UDP": "DDoS",
    "FTP-BruteForce": "FTP-Patator", "SSH-Bruteforce": "SSH-Patator",
    "Bot": "Bot", "Infilteration": "Infiltration",
    "Brute Force -Web": "Web Attack - Brute Force", "Brute Force -XSS": "Web Attack - XSS",
    "SQL Injection": "Web Attack - Sql Injection",
}

files = sorted(glob.glob("data/raw/cicids2018/*.csv"))
if not files:
    sys.exit("no CSV files in data/raw/cicids2018/")
rng = np.random.default_rng(42)
CAP, BENIGN_FRAC = 300_000, 0.05
kept, counts, total = [], {}, {}
for path in files:
    header = [c.strip() for c in pd.read_csv(path, nrows=0).columns]
    missing = [c for c in MAP if c not in header]
    if missing:
        sys.exit(f"{os.path.basename(path)}: columns not found {missing}\nheader: {header}")
    usecols = [c for c in pd.read_csv(path, nrows=0).columns if c.strip() in MAP or c.strip() == "Label"]
    for ch in pd.read_csv(path, usecols=usecols, chunksize=500_000, low_memory=False):
        ch.columns = [c.strip() for c in ch.columns]
        lab = ch["Label"].astype(str).str.strip()
        ch = ch.drop(columns="Label").apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
        ok = ch.notna().all(axis=1) & (lab != "Label")          # some files repeat the header inside
        ch, lab = ch[ok], lab[ok]
        for l, n in lab.value_counts().items():
            total[l] = total.get(l, 0) + int(n)
        keep = np.zeros(len(ch), bool)
        for l in lab.unique():
            idx = np.where(lab.to_numpy() == l)[0]
            if l == "Benign":
                idx = idx[rng.random(len(idx)) < BENIGN_FRAC]
            else:
                room = CAP - counts.get(l, 0)
                idx = idx[:max(room, 0)]
            counts[l] = counts.get(l, 0) + len(idx); keep[idx] = True
        part = ch[keep].rename(columns=MAP)[F].astype("float32"); part["Label"] = lab[keep].to_numpy()
        kept.append(part)
    print(f"read {os.path.basename(path)}", flush=True)
df = pd.concat(kept, ignore_index=True); del kept
X = df[F].to_numpy("float32"); y = df["Label"].to_numpy()

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
       f"files: {len(files)} | flows evaluated: {len(y):,} (benign sampled at {BENIGN_FRAC:.0%}, attacks capped at {CAP:,} per label)", "",
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

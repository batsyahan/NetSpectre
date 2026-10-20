"""CSE-CIC-IDS2018 helpers shared by eval_cicids2018.py and retrain_xgb35_v5.py.

MAP renames the 2018 (CICFlowMeter-V3) columns to the CICIDS2017 names the models use.
FAMILY maps each 2018 label to the CICIDS2017 class it belongs to.
load_2018() reads every CSV in data/raw/cicids2018/ in chunks and returns features, labels and timestamps.
"""
import glob, json, os, sys
import numpy as np, pandas as pd

F = json.load(open("models/feature_cols_35.json"))

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


def load_2018(benign_frac=0.05, cap=300_000, seed=42, folder="data/raw/cicids2018"):
    """Returns (X float32 [n,35], label array of 2018 names, timestamps, totals per label, file count).
    Benign rows are sampled at benign_frac; each attack label keeps at most cap rows (first ones in the file)."""
    files = sorted(glob.glob(f"{folder}/*.csv"))
    if not files:
        sys.exit(f"no CSV files in {folder}/")
    rng = np.random.default_rng(seed)
    kept, counts, total = [], {}, {}
    for path in files:
        raw = list(pd.read_csv(path, nrows=0).columns)
        header = [c.strip() for c in raw]
        missing = [c for c in MAP if c not in header]
        if missing:
            sys.exit(f"{os.path.basename(path)}: columns not found {missing}\nheader: {header}")
        usecols = [c for c in raw if c.strip() in MAP or c.strip() in ("Label", "Timestamp")]
        for ch in pd.read_csv(path, usecols=usecols, chunksize=500_000, low_memory=False):
            ch.columns = [c.strip() for c in ch.columns]
            lab = ch["Label"].astype(str).str.strip()
            ts = pd.to_datetime(ch["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
            ch = ch.drop(columns=["Label", "Timestamp"]).apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
            ok = ch.notna().all(axis=1) & (lab != "Label") & ts.notna()   # some files repeat the header inside
            ch, lab, ts = ch[ok], lab[ok], ts[ok]
            for l, n in lab.value_counts().items():
                total[l] = total.get(l, 0) + int(n)
            keep = np.zeros(len(ch), bool)
            labs = lab.to_numpy()
            for l in np.unique(labs):
                idx = np.where(labs == l)[0]
                if l == "Benign":
                    idx = idx[rng.random(len(idx)) < benign_frac]
                else:
                    idx = idx[:max(cap - counts.get(l, 0), 0)]
                counts[l] = counts.get(l, 0) + len(idx); keep[idx] = True
            part = ch[keep].rename(columns=MAP)[F].astype("float32")
            part["Label"] = labs[keep]; part["ts"] = ts[keep].to_numpy()
            kept.append(part)
        print(f"read {os.path.basename(path)}", flush=True)
    df = pd.concat(kept, ignore_index=True); del kept
    return df[F].to_numpy("float32"), df["Label"].to_numpy(), df["ts"].to_numpy(), total, len(files)

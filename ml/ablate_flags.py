import gc, json
import numpy as np
import pandas as pd
from imblearn.over_sampling import RandomOverSampler
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

ALL = json.load(open("models/feature_cols_40.json"))
DROP = ["SYN Flag Count", "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count"]
F = [c for c in ALL if c not in DROP]
print("features:", len(F))

tr = pd.read_parquet("data/processed/train_temporal2.parquet")
parts = [g.sample(50_000, random_state=42) if len(g) > 50_000 else g for _, g in tr.groupby("Label")]
tr = pd.concat(parts, ignore_index=True); del parts; gc.collect()
X, y = tr[F].to_numpy(dtype="float32"), tr["Label"].to_numpy()
del tr; gc.collect()
cnt = pd.Series(y).value_counts()
strat = {l: 20000 for l, n in cnt.items() if l != "BENIGN" and n < 20000}
X, y = RandomOverSampler(random_state=42, sampling_strategy=strat).fit_resample(X, y)
le = LabelEncoder(); yi = le.fit_transform(y)

clf = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.2, tree_method="hist",
                    n_jobs=8, random_state=42, objective="multi:softprob")
clf.fit(X.astype("float32"), yi)

te = pd.read_parquet("data/processed/test_temporal2.parquet")
Xt, yt = te[F].to_numpy(dtype="float32"), te["Label"].to_numpy()
pred = le.inverse_transform(clf.predict(Xt))
rep = classification_report(yt, pred, output_dict=True, zero_division=0)
print(f"MACRO F1 without flag counts: {rep['macro avg']['f1-score']:.3f}   [with flags: 0.851]")
for k in ["PortScan", "DDoS", "DoS Hulk", "SSH-Patator", "Bot"]:
    print(f"  {k:12s} precision {rep[k]['precision']:.2f}  recall {rep[k]['recall']:.2f}")

d = pd.read_csv("/tmp/flows.csv")
d["Fwd Header Length"] -= 20 * d["Total Fwd Packets"]
d["Bwd Header Length"] -= 20 * d["Total Backward Packets"]
d["Total Length of Bwd Packets"] = 6
for c in ["Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean"]:
    d[c] = 6
d["Packet Length Mean"], d["Packet Length Std"] = 3, 4.24
labels = le.inverse_transform(clf.predict(d[F].to_numpy(dtype="float32")))
print("\nOur real nmap scan flows (header/padding adjusted, true flags dropped):")
print(pd.Series(labels).value_counts().to_string())

import json
import numpy as np, pandas as pd, torch

F = json.load(open("models/feature_cols_35.json"))
meta = json.load(open("models/ae35_meta.json"))
mu, sd = np.array(meta["mu"], dtype="float32"), np.array(meta["sd"], dtype="float32")
d = len(F)
net = torch.nn.Sequential(
    torch.nn.Linear(d, 24), torch.nn.ReLU(), torch.nn.Linear(24, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 6), torch.nn.ReLU(), torch.nn.Linear(6, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 24), torch.nn.ReLU(), torch.nn.Linear(24, d))
net.load_state_dict(torch.load("models/ae35.pt")); net.eval()

te = pd.read_parquet("data/processed/test_temporal2.parquet", columns=F + ["Label"])
x = te[F].to_numpy(dtype="float64")
X = torch.tensor(((np.sign(x) * np.log1p(np.abs(x))).astype("float32") - mu) / sd)
with torch.no_grad():
    e = ((net(X) - X) ** 2).mean(1).numpy()
lab = te["Label"].to_numpy(); eb = e[lab == "BENIGN"]

big = ["DDoS", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest", "PortScan", "FTP-Patator", "SSH-Patator"]
print(f"{'benign FPR':<12}" + "".join(f"{c[:11]:>12}" for c in big))
for q in (99, 97, 95, 90):
    t = np.percentile(eb, q)
    print(f"{100 - q:>9}%  " + "".join(f"{(e[lab == c] > t).mean():>12.1%}" for c in big))

import json
import numpy as np, pandas as pd, torch
F = json.load(open("models/feature_cols_35.json"))
m = json.load(open("models/ae35_meta.json"))
mu, sd = np.array(m["mu"], dtype="float32"), np.array(m["sd"], dtype="float32")
d = len(F)
net = torch.nn.Sequential(
    torch.nn.Linear(d, 24), torch.nn.ReLU(), torch.nn.Linear(24, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 6), torch.nn.ReLU(), torch.nn.Linear(6, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 24), torch.nn.ReLU(), torch.nn.Linear(24, d))
net.load_state_dict(torch.load("models/ae35.pt")); net.eval()
te = pd.read_parquet("data/processed/test_temporal2.parquet", columns=F + ["Label"])
b = te[te["Label"] == "BENIGN"][F].to_numpy(dtype="float64")
X = torch.tensor(((np.sign(b) * np.log1p(np.abs(b))).astype("float32") - mu) / sd)
with torch.no_grad():
    e = ((net(X) - X) ** 2).mean(1).numpy()
for q in (99, 97, 95):
    print(f"{100 - q}% of benign flows above {np.percentile(e, q):.4f}")

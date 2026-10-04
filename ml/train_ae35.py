import json, time
import numpy as np, pandas as pd, torch
from sklearn.metrics import roc_auc_score

torch.manual_seed(42); np.random.seed(42); torch.set_num_threads(8)
F = json.load(open("models/feature_cols_35.json"))

def prep(x):
    return np.sign(x) * np.log1p(np.abs(x))

tr = pd.read_parquet("data/processed/train_temporal2.parquet", columns=F + ["Label"])
b = tr[tr["Label"] == "BENIGN"]
b = b.sample(min(len(b), 400_000), random_state=42)
Xb = prep(b[F].to_numpy(dtype="float64")).astype("float32")
del tr, b
mu, sd = Xb.mean(0), Xb.std(0) + 1e-6
Xb = (Xb - mu) / sd
idx = np.random.permutation(len(Xb)); cut = int(len(Xb) * 0.9)
Xtr, Xva = torch.tensor(Xb[idx[:cut]]), torch.tensor(Xb[idx[cut:]])
print(f"benign train {len(Xtr)}, benign validation {len(Xva)}")

d = len(F)
net = torch.nn.Sequential(
    torch.nn.Linear(d, 24), torch.nn.ReLU(),
    torch.nn.Linear(24, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 6), torch.nn.ReLU(),
    torch.nn.Linear(6, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 24), torch.nn.ReLU(),
    torch.nn.Linear(24, d),
)
opt = torch.optim.Adam(net.parameters(), lr=1e-3)
t0 = time.time()
for ep in range(20):
    perm = torch.randperm(len(Xtr)); tot = 0.0
    for i in range(0, len(Xtr), 512):
        xb = Xtr[perm[i:i + 512]]
        loss = torch.nn.functional.mse_loss(net(xb), xb)
        opt.zero_grad(); loss.backward(); opt.step()
        tot += loss.item() * len(xb)
    if ep % 5 == 4 or ep == 0:
        print(f"epoch {ep + 1}: train loss {tot / len(Xtr):.4f} ({time.time() - t0:.0f}s)")

def err(X):
    net.eval()
    with torch.no_grad():
        return ((net(X) - X) ** 2).mean(1).numpy()

thr = float(np.percentile(err(Xva), 99))
print(f"threshold (99th pct of benign validation error): {thr:.4f}")

te = pd.read_parquet("data/processed/test_temporal2.parquet", columns=F + ["Label"])
Xt = torch.tensor(((prep(te[F].to_numpy(dtype="float64")).astype("float32")) - mu) / sd)
e = err(Xt); lab = te["Label"].to_numpy()
eb = e[lab == "BENIGN"]
print(f"\nBENIGN test: false-positive rate {(eb > thr).mean():.3%} (n={len(eb)})")
print(f"{'class':<28}{'n':>8}{'flagged':>10}{'AUROC':>8}")
for c in sorted(set(lab) - {"BENIGN"}):
    ec = e[lab == c]
    y = np.r_[np.zeros(len(eb)), np.ones(len(ec))]
    auc = roc_auc_score(y, np.r_[eb, ec])
    print(f"{c:<28}{len(ec):>8}{(ec > thr).mean():>10.1%}{auc:>8.3f}")

torch.save(net.state_dict(), "models/ae35.pt")
json.dump({"mu": mu.tolist(), "sd": sd.tolist(), "threshold": thr}, open("models/ae35_meta.json", "w"))
print("saved models/ae35.pt and models/ae35_meta.json")

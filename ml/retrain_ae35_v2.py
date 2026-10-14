"""Autoencoder v2: learns normal traffic from CICIDS2017 AND the user's own network capture,
then picks its threshold from data instead of by hand.

Run from ml/ inside the .venv:  python retrain_ae35_v2.py
Writes models/ae35_v2.pt, models/ae35_v2.onnx, models/ae35_v2_meta.json (never touches ae35.*).
Threshold rule: the lowest value that keeps false alarms <= 0.5% on the held-out part of your own
capture AND <= 1% on CICIDS2017 benign test flows. Prints old-vs-new detection per attack type.
"""
import json, time
import numpy as np, pandas as pd, torch, onnxruntime as ort

torch.manual_seed(42); np.random.seed(42); torch.set_num_threads(8)
F = json.load(open("models/feature_cols_35.json")); d = len(F)
prep = lambda x: (np.sign(x) * np.log1p(np.abs(x))).astype("float32")

def load_capture(p):
    c = pd.read_csv(p, header=None).apply(pd.to_numeric, errors="coerce").dropna().iloc[:, :35]
    c.columns = F
    scan = (c["Init_Win_bytes_forward"] == 1024) & (c["Total Fwd Packets"] <= 2)   # nmap-like probes
    return c[~scan].drop_duplicates().to_numpy("float64")
cap = load_capture("../baselines/benign_capture.csv")
cut = int(len(cap) * 0.7); cap_tr, cap_ho = cap[:cut], cap[cut:]      # time order: last 30% held out
print(f"own capture: {len(cap)} unique benign flows | train {len(cap_tr)} | holdout {len(cap_ho)}")

tr = pd.read_parquet("data/processed/train_temporal2.parquet", columns=F + ["Label"])
b = tr[tr["Label"] == "BENIGN"].sample(400_000, random_state=42)[F].to_numpy("float64"); del tr
# own traffic is tiny next to 400k dataset flows, so repeat it to ~10% of the training set
rep = max(1, int(0.1 * len(b) / max(len(cap_tr), 1)))
Xraw = np.vstack([b, np.repeat(cap_tr, rep, axis=0)])
print(f"training flows: {len(b)} CICIDS benign + {len(cap_tr)} own x{rep}")
Xp = prep(Xraw); mu, sd = Xp.mean(0), Xp.std(0) + 1e-6
Xn = (Xp - mu) / sd
idx = np.random.permutation(len(Xn)); c9 = int(len(Xn) * 0.9)
Xtr = torch.tensor(Xn[idx[:c9]])

net = torch.nn.Sequential(
    torch.nn.Linear(d, 24), torch.nn.ReLU(), torch.nn.Linear(24, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 6), torch.nn.ReLU(), torch.nn.Linear(6, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 24), torch.nn.ReLU(), torch.nn.Linear(24, d))
opt = torch.optim.Adam(net.parameters(), lr=1e-3); t0 = time.time()
for ep in range(20):
    perm = torch.randperm(len(Xtr)); tot = 0.0
    for i in range(0, len(Xtr), 512):
        xb = Xtr[perm[i:i + 512]]; loss = torch.nn.functional.mse_loss(net(xb), xb)
        opt.zero_grad(); loss.backward(); opt.step(); tot += loss.item() * len(xb)
    if ep % 5 == 4 or ep == 0: print(f"epoch {ep + 1}: loss {tot / len(Xtr):.4f} ({time.time() - t0:.0f}s)", flush=True)
net.eval()

def score_new(x):
    with torch.no_grad():
        z = torch.tensor((prep(x) - mu) / sd); return ((net(z) - z) ** 2).mean(1).numpy()
m_old = json.load(open("models/ae35_meta.json")); ae_old = ort.InferenceSession("models/ae35.onnx")
def score_old(x):
    z = ((prep(x) - np.array(m_old["mu"], "float32")) / np.array(m_old["sd"], "float32")).astype("float32")
    return ((ae_old.run(None, {"x": z})[0] - z) ** 2).mean(1)

te = pd.read_parquet("data/processed/test_temporal2.parquet", columns=F + ["Label"])
Xt = te[F].to_numpy("float64"); lab = te["Label"].to_numpy(); ben = lab == "BENIGN"
e_new, e_old = score_new(Xt), score_old(Xt)
h_new, h_old = score_new(cap_ho), score_old(cap_ho)

thr = float(max(np.percentile(h_new, 99.5), np.percentile(e_new[ben], 99.0)))
print(f"\nchosen threshold for v2: {thr:.4f}  (old model runs at 0.5 in docker-compose)")
rows = [("old AE @ 0.5", e_old, h_old, 0.5), ("old AE @ 0.2369", e_old, h_old, 0.2369), (f"new AE @ {thr:.3f}", e_new, h_new, thr)]
big = ["DDoS", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest", "PortScan", "FTP-Patator", "SSH-Patator", "Bot"]
print(f"\n{'':<18}{'own FP':>8}{'CIC FP':>8}" + "".join(f"{c.replace('DoS ', '')[:10]:>11}" for c in big))
for name, e, h, t in rows:
    print(f"{name:<18}{100 * (h > t).mean():>7.2f}%{100 * (e[ben] > t).mean():>7.2f}%" +
          "".join(f"{100 * (e[lab == c] > t).mean():>10.1f}%" for c in big))
print("own FP = false alarms on your held-out normal traffic; CIC FP = on CICIDS2017 benign test flows;"
      " other columns = share of each attack's flows flagged")

torch.save(net.state_dict(), "models/ae35_v2.pt")
json.dump({"mu": mu.tolist(), "sd": sd.tolist(), "threshold": thr}, open("models/ae35_v2_meta.json", "w"))
x = torch.randn(64, d)
torch.onnx.export(net, x[:1], "models/ae35_v2.onnx", input_names=["x"], output_names=["recon"],
                  dynamic_axes={"x": {0: "batch"}, "recon": {0: "batch"}}, opset_version=17, dynamo=False)
diff = float(np.abs(ort.InferenceSession("models/ae35_v2.onnx").run(None, {"x": x.numpy()})[0] - net(x).detach().numpy()).max())
print(f"saved models/ae35_v2.{{pt,onnx}} + ae35_v2_meta.json (ONNX vs PyTorch max diff {diff:.2e})")
print(f"to deploy: NS_AE_MODEL=ae35_v2 for the ml service and NS_AE_THRESHOLD={thr:.4f} for the monitor")

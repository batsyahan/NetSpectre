import json, time
import numpy as np, pandas as pd, torch, onnxruntime as ort

torch.manual_seed(42); np.random.seed(42); torch.set_num_threads(8)
F = json.load(open("models/feature_cols_35.json")); ix = {f: i for i, f in enumerate(F)}
prep = lambda x: np.sign(x) * np.log1p(np.abs(x))
def load(p): return pd.read_csv(p, header=None).apply(pd.to_numeric, errors="coerce").dropna().to_numpy("float64")
base = load("../baselines/eth1_flows.csv"); live = load("../baselines/live_flows.csv")
sig = (live[:, ix["Init_Win_bytes_forward"]] == 1024) & (live[:, ix["Total Fwd Packets"]] <= 2)
live_scan, live_ben = live[sig], live[~sig]
c0 = int(len(base) * 0.7); base_tr, base_ho = base[:c0], base[c0:]
print(f"baseline: {len(base_tr)} train / {len(base_ho)} held-out | live scan {len(live_scan)} | live benign {len(live_ben)}")

tr = pd.read_parquet("data/processed/train_temporal2.parquet", columns=F + ["Label"])
b = tr[tr["Label"] == "BENIGN"]; b = b.sample(min(len(b), 400_000), random_state=42)
Xb = prep(b[F].to_numpy(dtype="float64")).astype("float32"); del tr, b
mu, sd = Xb.mean(0), Xb.std(0) + 1e-6
norm = lambda a: ((prep(a).astype("float32") - mu) / sd).astype("float32")
Xb = (Xb - mu) / sd
idx = np.random.permutation(len(Xb)); c1 = int(len(Xb) * 0.9)
Xtr, Xva = Xb[idx[:c1]], Xb[idx[c1:]]
aug = np.repeat(norm(base_tr), 200, axis=0)
aug = aug + np.random.normal(0, 0.1, aug.shape).astype("float32")
Xall = torch.tensor(np.vstack([Xtr, aug])); Xva_t = torch.tensor(Xva)
print(f"training rows: {len(Xall)} (2017 benign {len(Xtr)} + baseline copies {len(aug)})")

d = len(F)
net = torch.nn.Sequential(
    torch.nn.Linear(d, 24), torch.nn.ReLU(), torch.nn.Linear(24, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 6), torch.nn.ReLU(), torch.nn.Linear(6, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 24), torch.nn.ReLU(), torch.nn.Linear(24, d))
opt = torch.optim.Adam(net.parameters(), lr=1e-3); t0 = time.time()
for ep in range(20):
    perm = torch.randperm(len(Xall)); tot = 0.0
    for i in range(0, len(Xall), 512):
        xb = Xall[perm[i:i + 512]]
        loss = torch.nn.functional.mse_loss(net(xb), xb)
        opt.zero_grad(); loss.backward(); opt.step(); tot += loss.item() * len(xb)
    if ep % 5 == 4 or ep == 0: print(f"epoch {ep + 1}: loss {tot / len(Xall):.4f} ({time.time() - t0:.0f}s)", flush=True)
net.eval()
def new_err(raw):
    with torch.no_grad():
        z = torch.tensor(norm(raw)); return ((net(z) - z) ** 2).mean(1).numpy()
thr = float(np.percentile(new_err_va := ((net(Xva_t) - Xva_t) ** 2).mean(1).detach().numpy(), 99))

om = json.load(open("models/ae35_meta.json")); omu, osd = np.array(om["mu"], "float32"), np.array(om["sd"], "float32")
old = ort.InferenceSession("models/ae35.onnx")
def old_err(raw):
    z = ((prep(raw).astype("float32") - omu) / osd).astype("float32"); r = old.run(None, {"x": z})[0]; return ((r - z) ** 2).mean(1)

te = pd.read_parquet("data/processed/test_temporal2.parquet", columns=F + ["Label"])
Xt = te[F].to_numpy(dtype="float64"); lab = te["Label"].to_numpy()
print(f"\nthresholds: old {om['threshold']:.4f} | new {thr:.4f}\n")
print(f"{'FLAGGED AS ANOMALY':<36}{'n':>8}{'old':>9}{'new':>9}")
def row(name, raw): print(f"{name:<36}{len(raw):>8}{(old_err(raw) > om['threshold']).mean():>9.1%}{(new_err(raw) > thr).mean():>9.1%}")
print("-- normal traffic (want LOW) --")
row("2017 BENIGN test", Xt[lab == "BENIGN"]); row("YOUR baseline, held-out", base_ho)
row("YOUR baseline, train part", base_tr); row("docker curl benign (live)", live_ben)
print("-- attacks (want HIGH) --")
row("YOUR nmap scan flows (live)", live_scan)
for c in sorted(set(lab) - {"BENIGN"}): row(c, Xt[lab == c])

torch.save(net.state_dict(), "models/ae35_v2.pt")
json.dump({"mu": mu.tolist(), "sd": sd.tolist(), "threshold": thr}, open("models/ae35_v2_meta.json", "w"))
x = torch.randn(64, d)
torch.onnx.export(net, x[:1], "models/ae35_v2.onnx", input_names=["x"], output_names=["recon"],
                  dynamic_axes={"x": {0: "batch"}, "recon": {0: "batch"}}, opset_version=17, dynamo=False)
o = ort.InferenceSession("models/ae35_v2.onnx").run(None, {"x": x.numpy()})[0]
print("\nsaved ae35_v2.*  | ONNX max diff vs PyTorch:", float(np.abs(o - net(x).detach().numpy()).max()))

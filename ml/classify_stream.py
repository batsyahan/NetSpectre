import json, sys, time
from collections import defaultdict
import numpy as np
import onnxruntime as ort

WINDOW, COOLDOWN = 10, 30  # seconds
verbose = "-v" in sys.argv

classes = json.load(open("models/classes.json"))
sess = ort.InferenceSession("models/multiclass_xgb35.onnx")
n_feat = len(json.load(open("models/feature_cols_35.json")))
hist = defaultdict(list)   # (src_ip, label) -> [(t, dst_port, conf)]
last_alert = {}
print("classifier ready, waiting for flows...", flush=True)

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    flow, *vals = line.split(",")
    if len(vals) != n_feat:
        continue
    src, dst = flow.split(">")
    src_ip, dst_port = src.rsplit(":", 1)[0], dst.rsplit(":", 1)[1]
    p = sess.run(None, {"input": np.array([vals], dtype=np.float32)})[1][0]
    p = [p[k] for k in sorted(p)] if isinstance(p, dict) else list(p)
    i = int(np.argmax(p))
    label, conf = classes[i], p[i]

    if label == "BENIGN":
        if verbose:
            print(f"ok    {flow:48s} BENIGN ({conf:.2f})", flush=True)
        continue

    key, now = (src_ip, label), time.time()
    h = [x for x in hist[key] if now - x[0] <= WINDOW] + [(now, dst_port, conf)]
    hist[key] = h
    if label == "PortScan":
        count, unit, need = len({x[1] for x in h}), "ports", 10
    else:
        count, unit, need = len(h), "flows", 3
    if count >= need and now - last_alert.get(key, 0) > COOLDOWN:
        last_alert[key] = now
        avg = sum(x[2] for x in h) / len(h)
        print(f"ALERT {src_ip} -> {label}: {count} {unit} in {WINDOW}s (avg confidence {avg:.2f})", flush=True)

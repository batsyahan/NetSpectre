import json, sys
import numpy as np
import onnxruntime as ort

classes = json.load(open("models/classes.json"))
sess = ort.InferenceSession("models/multiclass_xgb35.onnx")
n_feat = len(json.load(open("models/feature_cols_35.json")))
print("classifier ready, waiting for flows...", flush=True)
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    flow, *vals = line.split(",")
    if len(vals) != n_feat:
        continue
    p = sess.run(None, {"input": np.array([vals], dtype=np.float32)})[1][0]
    p = [p[k] for k in sorted(p)] if isinstance(p, dict) else list(p)
    i = int(np.argmax(p))
    tag = "ok   " if classes[i] == "BENIGN" else "ALERT"
    print(f"{tag} {flow:48s} {classes[i]} ({p[i]:.2f})", flush=True)

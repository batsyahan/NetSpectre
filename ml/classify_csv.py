import json, sys
from collections import Counter
import numpy as np
import pandas as pd
import onnxruntime as ort

cols = json.load(open("models/feature_cols_35.json"))
classes = json.load(open("models/classes.json"))
df = pd.read_csv(sys.argv[1] if len(sys.argv) > 1 else "/tmp/flows.csv")
assert list(df.columns) == cols, "column order mismatch!"
sess = ort.InferenceSession("models/multiclass_xgb35.onnx")
probs = sess.run(None, {"input": df.to_numpy(dtype=np.float32)})[1]
probs = np.array([[p[k] for k in sorted(p)] for p in probs]) if isinstance(probs[0], dict) else np.array(probs)
pred = [classes[i] for i in probs.argmax(axis=1)]
print(f"{len(pred)} flows classified:")
for label, n in Counter(pred).most_common():
    print(f"  {label}: {n}")

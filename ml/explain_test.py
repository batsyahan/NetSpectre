import json, time
import numpy as np
import pandas as pd
import xgboost as xgb

F = json.load(open("models/feature_cols_35.json"))
classes = json.load(open("models/classes.json"))
clf = xgb.XGBClassifier()
clf.load_model("models/multiclass_xgb35.json")
booster = clf.get_booster()

te = pd.read_parquet("data/processed/test_temporal2.parquet")
for label in ["PortScan", "DDoS", "DoS Hulk", "SSH-Patator"]:
    row = te[te["Label"] == label].sample(1, random_state=3)
    x = row[F].to_numpy(dtype="float32")
    probs = clf.predict_proba(x)[0]
    k = int(probs.argmax())
    t = time.perf_counter()
    c = booster.predict(xgb.DMatrix(x), pred_contribs=True)
    ms = (time.perf_counter() - t) * 1000
    assert c.shape == (1, len(classes), len(F) + 1), c.shape
    contrib = c[0][k][:-1]
    print(f"\nTrue: {label} | predicted: {classes[k]} ({probs[k]:.2f}) | SHAP time {ms:.1f} ms")
    for i in np.argsort(-np.abs(contrib))[:3]:
        print(f"   {F[i]:28s} value={x[0][i]:>12.1f}  contribution={contrib[i]:+.2f}")

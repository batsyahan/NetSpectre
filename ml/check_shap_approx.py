"""Exact TreeSHAP vs fast approximate contributions: speed and how often the top-3 reasons agree.
Run from ml/:  python check_shap_approx.py   (uses NS_MODEL, default multiclass_xgb35_v7)"""
import json, os, time
import numpy as np, pandas as pd, xgboost as xgb
from explain import explain

MODEL = os.environ.get("NS_MODEL", "multiclass_xgb35_v7")
F = json.load(open("models/feature_cols_35.json")); C = json.load(open("models/classes.json"))
b = xgb.Booster(); b.load_model(f"models/{MODEL}.json")
te = pd.read_parquet("data/processed/test_temporal2.parquet", columns=F + ["Label"])
att = te[te["Label"] != "BENIGN"]
att = pd.concat([d.sample(min(len(d), 40), random_state=1) for _, d in att.groupby("Label")])
X = att[F].to_numpy("float32")
k = b.predict(xgb.DMatrix(X)).argmax(1)
same3 = same1 = 0; t = {True: [], False: []}
for i in range(len(X)):
    x = X[i:i + 1]; r = {}
    for ap in (False, True):
        a = time.perf_counter(); r[ap] = [n for n, _, _ in explain(b, x, int(k[i]), F, approx=ap)]; t[ap].append(time.perf_counter() - a)
    same3 += set(r[False]) == set(r[True]); same1 += r[False][:1] == r[True][:1]
n = len(X)
print(f"{MODEL}: {n} attack flows from {att['Label'].nunique()} classes")
print(f"exact  SHAP: mean {1000 * np.mean(t[False]):.2f} ms per flow")
print(f"approx SHAP: mean {1000 * np.mean(t[True]):.2f} ms per flow")
print(f"same main reason: {100 * same1 / n:.1f}% | same top-3 set: {100 * same3 / n:.1f}%")

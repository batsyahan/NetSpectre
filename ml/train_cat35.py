import gc, json, time
import numpy as np
import pandas as pd
import onnxruntime as ort
from catboost import CatBoostClassifier
from imblearn.over_sampling import RandomOverSampler
from sklearn.metrics import classification_report, f1_score
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

F = json.load(open("models/feature_cols_35.json"))
classes = json.load(open("models/classes.json"))

tr = pd.read_parquet("data/processed/train_temporal2.parquet")
parts = [g.sample(50_000, random_state=42) if len(g) > 50_000 else g for _, g in tr.groupby("Label")]
tr = pd.concat(parts, ignore_index=True); del parts; gc.collect()
X, y = tr[F].to_numpy(dtype="float32"), tr["Label"].to_numpy()
del tr; gc.collect()
cnt = pd.Series(y).value_counts()
strat = {l: 20000 for l, n in cnt.items() if l != "BENIGN" and n < 20000}
X, y = RandomOverSampler(random_state=42, sampling_strategy=strat).fit_resample(X, y)
le = LabelEncoder(); yi = le.fit_transform(y)
assert list(le.classes_) == classes, "class order changed"

start = time.time()
cat = CatBoostClassifier(iterations=200, depth=6, learning_rate=0.2, loss_function="MultiClass",
                         thread_count=8, random_seed=42, verbose=50)
cat.fit(X.astype("float32"), yi)
print(f"CatBoost trained in {time.time() - start:.1f}s")
cat.save_model("models/multiclass_cat35.onnx", format="onnx")
cat.save_model("models/multiclass_cat35.cbm")

te = pd.read_parquet("data/processed/test_temporal2.parquet")
Xt = te[F].to_numpy(dtype="float32")
yt = le.transform(te["Label"].to_numpy())

xgb = XGBClassifier(); xgb.load_model("models/multiclass_xgb35.json")
p_xgb = xgb.predict_proba(Xt)
p_cat = cat.predict_proba(Xt)
p_ens = (p_xgb + p_cat) / 2

def macro(p):
    return f1_score(yt, p.argmax(axis=1), average="macro")

print(f"\nMACRO F1  XGBoost: {macro(p_xgb):.3f} | CatBoost: {macro(p_cat):.3f} | Ensemble (avg): {macro(p_ens):.3f}")
print("\nEnsemble report:")
print(classification_report(yt, p_ens.argmax(axis=1), target_names=classes, zero_division=0))

sess = ort.InferenceSession("models/multiclass_cat35.onnx")
sub = Xt[:20000]
out = sess.run(None, {sess.get_inputs()[0].name: sub})
print("ONNX outputs:", [o.name for o in sess.get_outputs()])
onnx_labels = np.array(out[0]).astype(int).ravel()
print("ONNX label match:", np.array_equal(onnx_labels, cat.predict(sub).astype(int).ravel()))
import os
print("ONNX size (MB):", round(os.path.getsize("models/multiclass_cat35.onnx") / 1e6, 1))

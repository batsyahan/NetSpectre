import gc, json
import numpy as np
import pandas as pd
import onnxruntime as ort
from imblearn.over_sampling import RandomOverSampler
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, f1_score
from xgboost import XGBClassifier
from onnxmltools import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType

F = json.load(open("models/feature_cols_35.json"))

def merge(a):
    a = np.asarray(a, dtype=object)
    return np.where(pd.Series(a).str.startswith("Web Attack").to_numpy(), "Web Attack", a)

tr = pd.read_parquet("data/processed/train_temporal2.parquet")
parts = [g.sample(50_000, random_state=42) if len(g) > 50_000 else g for _, g in tr.groupby("Label")]
tr = pd.concat(parts, ignore_index=True); del parts; gc.collect()
X, y = tr[F].to_numpy(dtype="float32"), merge(tr["Label"].to_numpy())
del tr; gc.collect()
cnt = pd.Series(y).value_counts()
print("train class counts (merged):\n", cnt.to_string())
strat = {l: 20000 for l, n in cnt.items() if l != "BENIGN" and n < 20000}
X, y = RandomOverSampler(random_state=42, sampling_strategy=strat).fit_resample(X, y)
le = LabelEncoder(); yi = le.fit_transform(y)
json.dump(list(le.classes_), open("models/classes_v2.json", "w"))
print("classes:", list(le.classes_))

clf = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.2, tree_method="hist",
                    n_jobs=8, random_state=42, objective="multi:softprob")
clf.fit(X.astype("float32"), yi)
clf.save_model("models/multiclass_xgb35_v2.json")
onx = convert_xgboost(clf, initial_types=[("input", FloatTensorType([None, len(F)]))])
open("models/multiclass_xgb35_v2.onnx", "wb").write(onx.SerializeToString())

te = pd.read_parquet("data/processed/test_temporal2.parquet")
Xt = te[F].to_numpy(dtype="float32"); yt = merge(te["Label"].to_numpy())
pred = le.inverse_transform(clf.predict(Xt).astype(int))
print("\nmacro F1 (v2, web attacks merged):", round(f1_score(yt, pred, average="macro", zero_division=0), 4))
print("(old XGBoost with predictions relabelled: 0.9209)\n")
print(classification_report(yt, pred, digits=3, zero_division=0))

sess = ort.InferenceSession("models/multiclass_xgb35_v2.onnx")
o = np.array(sess.run(None, {"input": Xt[:20000]})[0]).astype(int)
print("ONNX matches xgboost:", np.array_equal(o, clf.predict(Xt[:20000]).astype(int)))

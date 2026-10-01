import gc, json
import numpy as np
import pandas as pd
import onnxruntime as ort
from imblearn.over_sampling import RandomOverSampler
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier
from onnxmltools import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType

ALL = json.load(open("models/feature_cols_40.json"))
DROP = ["SYN Flag Count", "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count"]
F = [c for c in ALL if c not in DROP]
json.dump(F, open("models/feature_cols_35.json", "w"), indent=2)

tr = pd.read_parquet("data/processed/train_temporal2.parquet")
parts = [g.sample(50_000, random_state=42) if len(g) > 50_000 else g for _, g in tr.groupby("Label")]
tr = pd.concat(parts, ignore_index=True); del parts; gc.collect()
X, y = tr[F].to_numpy(dtype="float32"), tr["Label"].to_numpy()
del tr; gc.collect()
cnt = pd.Series(y).value_counts()
strat = {l: 20000 for l, n in cnt.items() if l != "BENIGN" and n < 20000}
X, y = RandomOverSampler(random_state=42, sampling_strategy=strat).fit_resample(X, y)
le = LabelEncoder(); yi = le.fit_transform(y)
assert list(le.classes_) == json.load(open("models/classes.json")), "class order changed"

clf = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.2, tree_method="hist",
                    n_jobs=8, random_state=42, objective="multi:softprob")
clf.fit(X.astype("float32"), yi)
clf.save_model("models/multiclass_xgb35.json")

onx = convert_xgboost(clf, initial_types=[("input", FloatTensorType([None, len(F)]))])
open("models/multiclass_xgb35.onnx", "wb").write(onx.SerializeToString())
sess = ort.InferenceSession("models/multiclass_xgb35.onnx")

te = pd.read_parquet("data/processed/test_temporal2.parquet")
Xt = te[F].to_numpy(dtype="float32")[:20000]
o = np.array(sess.run(None, {"input": Xt})[0]).astype(int)
print("ONNX match:", np.array_equal(o, clf.predict(Xt).astype(int)), "| features:", len(F))

d = pd.read_csv("/tmp/flows.csv")
d["Fwd Header Length"] -= 20 * d["Total Fwd Packets"]
d["Bwd Header Length"] -= 20 * d["Total Backward Packets"]

def predict(df):
    p = sess.run(None, {"input": df[F].to_numpy(dtype=np.float32)})[0]
    return pd.Series(le.inverse_transform(np.array(p).astype(int))).value_counts().to_string()

print("\nScan flows, header fix only (no padding hack):")
print(predict(d))

d["Total Length of Bwd Packets"] = 6
for c in ["Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean"]:
    d[c] = 6
d["Packet Length Mean"], d["Packet Length Std"] = 3, 4.24
print("\nScan flows, header fix + padding:")
print(predict(d))

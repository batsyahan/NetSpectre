import joblib
import numpy as np
from skl2onnx import to_onnx

bundle = joblib.load("models/multiclass_hgb_capped.joblib")
clf, feature_cols = bundle["model"], bundle["feature_cols"]

print("Model classes:", clf.classes_)
print("Num features:", len(feature_cols))

onx = to_onnx(clf, X=np.zeros((1, len(feature_cols)), dtype=np.float32))
with open("models/multiclass_hgb.onnx", "wb") as f:
    f.write(onx.SerializeToString())

print("Saved models/multiclass_hgb.onnx")

# Verify: compare sklearn vs ONNX predictions on a few real test rows
import pandas as pd
import onnxruntime as ort

test_df = pd.read_parquet("data/processed/test_temporal2.parquet").sample(10, random_state=1)
X_sample = test_df[feature_cols].to_numpy(dtype=np.float32)

sk_pred = clf.predict(X_sample)

sess = ort.InferenceSession("models/multiclass_hgb.onnx")
input_name = sess.get_inputs()[0].name
onnx_pred = sess.run(None, {input_name: X_sample})[0]

print("\nsklearn predictions:", sk_pred)
print("onnx predictions:   ", onnx_pred)
print("Match:", (sk_pred == onnx_pred).all())

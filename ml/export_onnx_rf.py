import joblib
import numpy as np
import onnxruntime as ort
from skl2onnx import to_onnx

bundle = joblib.load("models/multiclass_rf_capped.joblib")
clf = bundle["model"]
feature_cols = bundle["feature_cols"]
print("Model classes:", clf.classes_)
print("Num features:", len(feature_cols))

X0 = np.zeros((1, len(feature_cols)), dtype=np.float32)
onx = to_onnx(clf, X=X0, options={id(clf): {"zipmap": False}})
with open("models/multiclass_rf.onnx", "wb") as f:
    f.write(onx.SerializeToString())
print("Saved models/multiclass_rf.onnx")

# sanity check: ONNX vs sklearn on random inputs
Xr = np.random.rand(200, len(feature_cols)).astype(np.float32) * 1000
sess = ort.InferenceSession("models/multiclass_rf.onnx")
onnx_pred = sess.run(None, {sess.get_inputs()[0].name: Xr})[0]
print("Match:", np.array_equal(clf.classes_[onnx_pred], clf.predict(Xr)))

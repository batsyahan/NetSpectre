import json
from concurrent import futures

import grpc
import numpy as np
import onnxruntime as ort

from gen import netspectre_pb2 as pb
from gen import netspectre_pb2_grpc as pbg

classes = json.load(open("models/classes.json"))
n_feat = len(json.load(open("models/feature_cols_35.json")))
import os
ENSEMBLE = os.environ.get("NS_ENSEMBLE", "1") == "1"
sess_x = ort.InferenceSession("models/multiclass_xgb35.onnx")
sess_c = ort.InferenceSession("models/multiclass_cat35.onnx")
import xgboost as xgb
from explain import explain
FEATURES = json.load(open("models/feature_cols_35.json"))
_xgb = xgb.XGBClassifier()
_xgb.load_model("models/multiclass_xgb35.json")
booster = _xgb.get_booster()
booster.predict(xgb.DMatrix(np.zeros((1, len(FEATURES)), dtype=np.float32)), pred_contribs=True)  # warm-up

import torch
torch.set_num_threads(1)
_meta = json.load(open("models/ae35_meta.json"))
_mu = np.array(_meta["mu"], dtype=np.float32)
_sd = np.array(_meta["sd"], dtype=np.float32)
_ae = torch.nn.Sequential(
    torch.nn.Linear(n_feat, 24), torch.nn.ReLU(), torch.nn.Linear(24, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 6), torch.nn.ReLU(), torch.nn.Linear(6, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 24), torch.nn.ReLU(), torch.nn.Linear(24, n_feat))
_ae.load_state_dict(torch.load("models/ae35.pt"))
_ae.eval()


def anomaly(x):
    z = ((np.sign(x) * np.log1p(np.abs(x))).astype(np.float32) - _mu) / _sd
    t = torch.from_numpy(z)
    with torch.no_grad():
        return float(((_ae(t) - t) ** 2).mean())


anomaly(np.zeros((1, n_feat), dtype=np.float32))  # warm-up


def probs(sess, x):
    p = sess.run(None, {sess.get_inputs()[0].name: x})[1][0]
    if isinstance(p, dict):
        p = [p[k] for k in sorted(p, key=int)]
    return np.asarray(p, dtype=np.float64)


def classify(features):
    if len(features) != n_feat:
        raise ValueError(f"expected {n_feat} features, got {len(features)}")
    x = np.array([features], dtype=np.float32)
    p = probs(sess_x, x)
    if ENSEMBLE:
        p = (p + probs(sess_c, x)) / 2
    i = int(np.argmax(p))
    out = pb.Classification(label=classes[i], confidence=float(p[i]), anomaly_score=anomaly(x))
    if classes[i] != "BENIGN":
        for name, text, w in explain(booster, x, i, FEATURES):
            out.reasons.append(pb.Reason(feature=name, text=text, weight=w))
    return out


class Inference(pbg.InferenceServicer):
    def Classify(self, request, context):
        try:
            return classify(list(request.features))
        except ValueError as e:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(e))

    def ClassifyStream(self, request_iterator, context):
        for req in request_iterator:
            try:
                yield classify(list(req.features))
            except ValueError as e:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(e))


if __name__ == "__main__":
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    pbg.add_InferenceServicer_to_server(Inference(), server)
    server.add_insecure_port("127.0.0.1:50051")
    server.start()
    print("inference server listening on 127.0.0.1:50051 | ensemble:", ENSEMBLE, flush=True)
    server.wait_for_termination()

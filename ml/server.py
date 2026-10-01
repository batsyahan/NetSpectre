import json
from concurrent import futures

import grpc
import numpy as np
import onnxruntime as ort

from gen import netspectre_pb2 as pb
from gen import netspectre_pb2_grpc as pbg

classes = json.load(open("models/classes.json"))
n_feat = len(json.load(open("models/feature_cols_35.json")))
sess = ort.InferenceSession("models/multiclass_xgb35.onnx")


def classify(features):
    if len(features) != n_feat:
        raise ValueError(f"expected {n_feat} features, got {len(features)}")
    p = sess.run(None, {"input": np.array([features], dtype=np.float32)})[1][0]
    p = [p[k] for k in sorted(p)] if isinstance(p, dict) else list(p)
    i = int(np.argmax(p))
    return pb.Classification(label=classes[i], confidence=float(p[i]))


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
    print("inference server listening on 127.0.0.1:50051", flush=True)
    server.wait_for_termination()

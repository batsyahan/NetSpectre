import json, time
import grpc, numpy as np, pandas as pd
from gen import netspectre_pb2 as pb, netspectre_pb2_grpc as pbg

F = json.load(open("models/feature_cols_35.json"))
te = pd.read_parquet("data/processed/test_temporal2.parquet", columns=F + ["Label"])
stub = pbg.InferenceStub(grpc.insecure_channel("127.0.0.1:50051"))
thr = json.load(open("models/ae35_meta.json"))["threshold"]

for lab in ("BENIGN", "DDoS"):
    rows = te[te["Label"] == lab].sample(200, random_state=1)[F].to_numpy(dtype="float32")
    scores, t0 = [], time.time()
    for r in rows:
        resp = stub.Classify(pb.FlowFeatures(features=r.tolist()))
        scores.append(resp.anomaly_score)
    ms = (time.time() - t0) / len(rows) * 1000
    s = np.array(scores)
    print(f"{lab:<7} median score {np.median(s):.3f} | above 99% threshold ({thr:.3f}): {(s > thr).mean():.0%} | {ms:.1f} ms per call")

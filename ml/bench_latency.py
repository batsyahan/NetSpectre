import os
import json, time
import grpc, numpy as np, pandas as pd
from gen import netspectre_pb2 as pb, netspectre_pb2_grpc as pbg

F = json.load(open("models/feature_cols_35.json"))
te = pd.read_parquet("data/processed/test_temporal2.parquet", columns=F + ["Label"])
stub = pbg.InferenceStub(grpc.insecure_channel(os.environ.get("NS_ML_ADDR", "127.0.0.1:50051")))

def run(name, df, warm=50):
    rows = df[F].to_numpy(dtype="float32")
    for r in rows[:warm]:
        stub.Classify(pb.FlowFeatures(features=r.tolist()))
    ms = []
    for r in rows[warm:]:
        t = time.perf_counter()
        stub.Classify(pb.FlowFeatures(features=r.tolist()))
        ms.append((time.perf_counter() - t) * 1000)
    a = np.array(ms)
    print(f"{name:<8} n={len(a)}  mean {a.mean():.1f} | p50 {np.percentile(a,50):.1f} | p95 {np.percentile(a,95):.1f} | p99 {np.percentile(a,99):.1f} | max {a.max():.1f} ms")

run("BENIGN", te[te["Label"] == "BENIGN"].sample(550, random_state=2))
run("ATTACK", te[te["Label"] != "BENIGN"].sample(550, random_state=2))

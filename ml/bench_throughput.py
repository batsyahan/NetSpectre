import json, time
import numpy as np, pandas as pd, grpc
from concurrent.futures import ThreadPoolExecutor
from gen import netspectre_pb2 as pb, netspectre_pb2_grpc as pbg
X = pd.read_csv("../baselines/drop_test.csv", header=None).apply(pd.to_numeric, errors="coerce").dropna().to_numpy("float32")[:800]
stub = pbg.InferenceStub(grpc.insecure_channel("127.0.0.1:50051"))
def one(r): return stub.Classify(pb.FlowFeatures(features=r.tolist()))
for r in X[:30]: one(r)
t = time.perf_counter(); res = [one(r) for r in X]; dt = time.perf_counter() - t
print(f"sequential : {len(X)/dt:5.0f} flows/s ({dt/len(X)*1000:.1f} ms each)  labels: {pd.Series([r.label for r in res]).value_counts().to_dict()}")
for w in (4, 8):
    with ThreadPoolExecutor(w) as ex:
        t = time.perf_counter(); list(ex.map(one, X)); dt = time.perf_counter() - t
    print(f"{w} in flight  : {len(X)/dt:5.0f} flows/s")

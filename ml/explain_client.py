import time
import grpc
import pandas as pd
from gen import netspectre_pb2 as pb
from gen import netspectre_pb2_grpc as pbg

F = pd.read_json("models/feature_cols_35.json", typ="series").tolist()
te = pd.read_parquet("data/processed/test_temporal2.parquet")
stub = pbg.InferenceStub(grpc.insecure_channel("127.0.0.1:50051"))
for label in ["PortScan", "DDoS", "SSH-Patator", "BENIGN"]:
    row = te[te["Label"] == label].sample(1, random_state=5)[F].iloc[0].tolist()
    t = time.perf_counter()
    r = stub.Classify(pb.FlowFeatures(features=row))
    ms = (time.perf_counter() - t) * 1000
    print(f"\nTrue: {label} -> {r.label} ({r.confidence:.2f}) in {ms:.0f} ms")
    for x in r.reasons:
        print(f"   {x.weight:3.0f}%  {x.text}")
    if not r.reasons:
        print("   (no reasons for normal traffic)")

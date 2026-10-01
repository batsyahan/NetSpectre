import time

import grpc
import pandas as pd

from gen import netspectre_pb2 as pb
from gen import netspectre_pb2_grpc as pbg

df = pd.read_csv("/tmp/flows.csv")
print("sending", len(df), "flows from /tmp/flows.csv (", df.shape[1], "features each )")
stub = pbg.InferenceStub(grpc.insecure_channel("127.0.0.1:50051"))
stub.Classify(pb.FlowFeatures(features=df.iloc[0].tolist()))  # warm-up

times = []
for i, row in df.head(20).iterrows():
    t = time.perf_counter()
    r = stub.Classify(pb.FlowFeatures(src_ip="test", features=row.tolist()))
    times.append((time.perf_counter() - t) * 1000)
    if i < 3:
        print(f"flow{i + 1}: {r.label} ({r.confidence:.2f})")
print(f"unary round trip: mean {sum(times) / len(times):.1f} ms, max {max(times):.1f} ms over {len(times)} calls")

reqs = (pb.FlowFeatures(features=r.tolist()) for _, r in df.head(5).iterrows())
labels = [r.label for r in stub.ClassifyStream(reqs)]
print("stream results:", labels)
try:
    stub.Classify(pb.FlowFeatures(features=[1.0, 2.0]))
except grpc.RpcError as e:
    print("bad input rejected with:", e.code().name)

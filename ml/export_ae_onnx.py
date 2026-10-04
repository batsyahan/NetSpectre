import json
import numpy as np, torch
import onnxruntime as ort

d = len(json.load(open("models/feature_cols_35.json")))
net = torch.nn.Sequential(
    torch.nn.Linear(d, 24), torch.nn.ReLU(), torch.nn.Linear(24, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 6), torch.nn.ReLU(), torch.nn.Linear(6, 12), torch.nn.ReLU(),
    torch.nn.Linear(12, 24), torch.nn.ReLU(), torch.nn.Linear(24, d))
net.load_state_dict(torch.load("models/ae35.pt")); net.eval()
x = torch.randn(64, d)
torch.onnx.export(net, x[:1], "models/ae35.onnx", input_names=["x"], output_names=["recon"],
                  dynamic_axes={"x": {0: "batch"}, "recon": {0: "batch"}}, opset_version=17, dynamo=False)
out = ort.InferenceSession("models/ae35.onnx").run(None, {"x": x.numpy()})[0]
with torch.no_grad():
    ref = net(x).numpy()
print("max abs difference vs PyTorch:", float(np.abs(out - ref).max()))

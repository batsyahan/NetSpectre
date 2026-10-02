import numpy as np
import xgboost as xgb

TEXT = {
    "Destination Port": "destination port {v:.0f}",
    "Flow Duration": "flow lasted {v:.0f} µs",
    "Total Fwd Packets": "{v:.0f} packets sent by the initiator",
    "Total Backward Packets": "{v:.0f} reply packets",
    "Total Length of Fwd Packets": "{v:.0f} bytes sent",
    "Total Length of Bwd Packets": "{v:.0f} bytes received in reply",
    "Fwd Packet Length Max": "largest outgoing payload of {v:.0f} bytes",
    "Fwd Packet Length Min": "smallest outgoing payload of {v:.0f} bytes",
    "Fwd Packet Length Mean": "average outgoing payload of {v:.0f} bytes",
    "Fwd Packet Length Std": "outgoing packet size variation of {v:.0f}",
    "Bwd Packet Length Max": "largest reply payload of {v:.0f} bytes",
    "Bwd Packet Length Min": "smallest reply payload of {v:.0f} bytes",
    "Bwd Packet Length Mean": "average reply payload of {v:.0f} bytes",
    "Bwd Packet Length Std": "reply packet size variation of {v:.0f}",
    "Flow Bytes/s": "data rate of {v:.0f} bytes/s",
    "Flow Packets/s": "packet rate of {v:.0f} packets/s",
    "Flow IAT Mean": "average gap between packets of {v:.0f} µs",
    "Flow IAT Std": "gap between packets varies by {v:.0f} µs",
    "Flow IAT Max": "longest gap between packets of {v:.0f} µs",
    "Flow IAT Min": "shortest gap between packets of {v:.0f} µs",
    "Fwd IAT Total": "outgoing packets spread over {v:.0f} µs",
    "Fwd IAT Mean": "average gap between outgoing packets of {v:.0f} µs",
    "Fwd IAT Std": "outgoing gap variation of {v:.0f} µs",
    "Fwd IAT Max": "longest gap between outgoing packets of {v:.0f} µs",
    "Fwd IAT Min": "shortest gap between outgoing packets of {v:.0f} µs",
    "Fwd Header Length": "outgoing header bytes of {v:.0f}",
    "Bwd Header Length": "reply header bytes of {v:.0f}",
    "Fwd Packets/s": "outgoing rate of {v:.0f} packets/s",
    "Bwd Packets/s": "reply rate of {v:.0f} packets/s",
    "Packet Length Mean": "average packet size of {v:.0f} bytes",
    "Packet Length Std": "packet size variation of {v:.0f}",
    "Init_Win_bytes_forward": "sender's initial TCP window of {v:.0f} bytes",
    "Init_Win_bytes_backward": "receiver's initial TCP window of {v:.0f} bytes",
    "act_data_pkt_fwd": "{v:.0f} outgoing packets carrying data",
    "min_seg_size_forward": "minimum TCP header size of {v:.0f} bytes",
}


def explain(booster, x, k, features, top=3):
    """Top contributing features for class k, as (feature, plain text, share in %)."""
    c = booster.predict(xgb.DMatrix(x), pred_contribs=True)[0][k][:-1]
    order = [i for i in np.argsort(-c) if c[i] > 0][:top]
    total = float(sum(c[i] for i in order)) or 1.0
    out = []
    for i in order:
        name, v = features[i], float(x[0][i])
        out.append((name, TEXT.get(name, name + " = {v:.0f}").format(v=v), 100.0 * float(c[i]) / total))
    return out

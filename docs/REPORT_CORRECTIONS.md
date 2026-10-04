# Report corrections and new findings

All figures come from `docs/EVAL_TEST_SET.txt` (script `ml/eval_final.py`, deployed ONNX models, temporal test split of 499,605 flows) and `docs/RESULTS.md`.

## 1. Replace the Monte Carlo paragraph (end of the methodology/results chapter, page 21)

> The deployed ensemble (XGBoost and CatBoost soft voting over 35 flow-level features) was evaluated on a held-out temporal split of CICIDS2017: the model is trained on earlier capture days and tested on later ones, which avoids the optimistic results of random splits. On the 499,605 test flows it reached 99.45% accuracy, a weighted F1 of 99.48% and a macro F1 of 84.64%. Only 0.17% of benign flows were flagged as an attack. Performance is uneven across classes: large classes (DDoS, PortScan, DoS variants, FTP and SSH brute force) score F1 above 0.90, while Web Attack XSS (F1 0.37) and Web Attack Brute Force (F1 0.62) are weak, and Bot is detected with full recall but 44% precision.

Delete: "Monte Carlo ... 100 independent repetitions", "top 100 most predictive features", "95.4%" and "96% recall for DDoS, Botnet and Infiltration".
Reason: the evaluation was a single temporal split, the feature set has 35 features, and the Infiltration test set has only 8 flows, so no meaningful recall can be claimed for it.

## 2. Feature selection (replace "top 100 features by Information Gain Ratio")

> The flow extractor computes 35 CICFlowMeter-compatible features: the original 40 minus five TCP flag-count features (SYN, FIN, RST, PSH, ACK counts). An ablation on the temporal test split shows the removal costs no accuracy: macro F1 is 0.851 with the flag counts and 0.852 without them (same XGBoost settings; ml/ablate_flags.py and ml/eval_final.py). The flag counts were removed because [CONFIRM AND FILL IN: the reason you observed with live capture, e.g. flows captured by our own extractor did not reproduce the dataset's flag-count values, so a model relying on them did not transfer to live traffic].

## 3. Replace Table 6.1 (attack catalogue)

CICIDS2017 has 15 labels: BENIGN plus 14 attack classes. The report's catalogue listed classes that are not in the dataset (Generic Brute Force, Zero-Day Anomaly as a class, Malware Distribution, HTTPS Brute Force, DNS Spoofing, Packet Fragmentation); remove them and use the table below. Unknown attacks are handled by the autoencoder, not by a trained class.

| # | Class | Test flows | Precision | Recall | F1 |
|---|---|---|---|---|---|
| 1 | DDoS | 25,603 | 0.9985 | 0.9987 | 0.9986 |
| 2 | DoS Hulk | 34,570 | 0.9979 | 0.9544 | 0.9757 |
| 3 | DoS GoldenEye | 2,057 | 0.9323 | 0.9976 | 0.9638 |
| 4 | DoS slowloris | 1,075 | 0.9349 | 0.8819 | 0.9076 |
| 5 | DoS Slowhttptest | 1,046 | 0.8528 | 0.9914 | 0.9169 |
| 6 | PortScan | 18,139 | 0.9661 | 0.9961 | 0.9809 |
| 7 | FTP-Patator | 1,187 | 0.9983 | 0.9924 | 0.9954 |
| 8 | SSH-Patator | 644 | 0.9539 | 0.9969 | 0.9749 |
| 9 | Bot | 390 | 0.4412 | 1.0000 | 0.6122 |
| 10 | Web Attack - Brute Force | 294 | 0.6026 | 0.6293 | 0.6156 |
| 11 | Web Attack - XSS | 131 | 0.2857 | 0.5191 | 0.3686 |
| 12 | Web Attack - Sql Injection | 5 | 0.4545 | 1.0000 | 0.6250 |
| 13 | Infiltration | 8 | 0.6154 | 1.0000 | 0.7619 |
| 14 | Heartbleed | 3 | 1.0000 | 1.0000 | 1.0000 |
| - | BENIGN | 414,453 | 0.9982 | 0.9983 | 0.9982 |

Note under the table: Infiltration (8 flows), Web Attack SQL Injection (5) and Heartbleed (3) have too few test flows for their scores to be statistically meaningful.

## 4. Technology statements to correct

| Report says | Replace with |
|---|---|
| Random Forest, XGBoost, CatBoost and LSTM autoencoder ensemble | XGBoost and CatBoost soft-voting ensemble, plus a dense autoencoder (35-24-12-6-12-24-35) for anomaly scoring. Random Forest was tried during development but is not deployed. A windowed LSTM autoencoder is future work |
| libpcap and pnet | libpcap through the Rust `pcap` crate |
| WebSocket push to dashboard within 1 s | REST API, clients poll every 3 s |
| Mobile push notifications (FCM/APNs) within 10 s | Mobile app shows live alerts by polling and supports acknowledge, dismiss and reopen. Push notifications are future work |
| PostgreSQL, InfluxDB, Redis | SQLite |
| scikit-learn and PyTorch at inference | ONNX Runtime, XGBoost and CatBoost exported to ONNX at inference. PyTorch only trains the autoencoder |
| Explanations | TreeSHAP (XGBoost pred_contribs): the top 3 contributing features, shown as a share of the explanation and as plain text |

## 5. Performance targets table (Table 6.2): measured versus not measured

| Metric | Target | Status |
|---|---|---|
| ML inference round trip (gRPC) | < 50 ms | Met on laptop: benign 2.0 ms mean, p99 4.5 ms; attack including explanation 8.2 ms mean, p99 19.5 ms. ARM64 image under QEMU emulation: 12.8 / 174.6 ms mean. Not yet timed on a real Raspberry Pi 4 |
| Detection accuracy (weighted F1) | >= 95% | Met: 99.48% (accuracy 99.45%) |
| False positive rate | < 5% | Met: 0.17% of benign flows on the test set |
| Attack categories detected | 15 types | 14 attack classes plus benign; three web-attack classes are weak (see Table 6.1) |
| Alert delivery to dashboard | < 1 s | Not met as written: the dashboard polls every 3 s |
| Push notification delivery | < 10 s | Not implemented |
| Per-packet capture latency, throughput (1 Gbps / 100 Mbps), CPU <= 15%, RAM <= 2 GB, deploy < 5 min | as listed | Not measured. Needs real Raspberry Pi 4 hardware |
| Zero-day detection (F1 >= 0.80, held-out unseen categories) | F1 >= 0.80 | Not evaluated as defined. See the anomaly detection results in section 6 |

## 6. New findings to add (results and discussion chapter)

**Ensemble versus single model.** XGBoost alone: accuracy 99.40%, macro F1 0.852, benign false-positive rate 0.14%. CatBoost alone: 98.90%, macro F1 0.753, 0.51%. Ensemble: 99.45%, macro F1 0.846, 0.17%. Voting improves accuracy and weighted F1 slightly, but macro F1 and the false-positive rate are marginally worse than XGBoost alone. The ensemble mainly adds stability on the large classes.

**Main confusions (ensemble).** 665 DoS Hulk flows predicted as BENIGN and 616 as PortScan (1.9% and 1.8% of Hulk); 494 benign flows predicted as Bot, which explains Bot's 44% precision; Web Attack Brute Force and XSS are confused with each other (109 and 60 flows), consistent with both being HTTP login/form traffic with similar flow statistics.

**Autoencoder as a second line of defence.** Trained only on benign traffic, it flags a flow when reconstruction error exceeds a threshold taken from the benign test distribution. Share of flows flagged per true class:

| Class | 1% benign threshold (0.2369) | 3% threshold (0.1347) |
|---|---|---|
| BENIGN (the false-alarm rate) | 1.00% | 3.00% |
| DDoS | 73.8% | 98.7% |
| DoS Slowhttptest | 85.9% | 99.4% |
| DoS slowloris | 23.9% | 98.1% |
| FTP-Patator | 2.5% | 98.4% |
| DoS Hulk | 5.7% | 39.0% |
| DoS GoldenEye | 8.7% | 17.3% |
| PortScan | 1.1% | 6.2% |
| SSH-Patator | 0.2% | 4.7% |
| Bot | 0.0% | 0.3% |
| Web attacks (3 classes) | 0.0% | 2.3-20% |
| Heartbleed (3 flows) | 0.0% | 100% |
| Infiltration (8 flows) | 0.0% | 12.5% |

The autoencoder and the classifier are complementary: it catches volumetric and slow DoS and FTP brute force that fall in a single known class anyway, but it misses the web attacks, scans and bot traffic. Raising the threshold's false-alarm rate buys detection but costs benign alerts (a 5% threshold flags 5% of normal traffic). In the live system the default is the 1% threshold. These thresholds are calibrated on the CICIDS2017 benign distribution and need recalibration for each home network.

**Dataset shift observed on live traffic.** Benign DNS traffic from the WSL resolver (10.255.255.254) was flagged as anomalous because it is unlike CICIDS2017 benign traffic. The monitor therefore has a trusted-source list (NS_ANOMALY_IGNORE). This is evidence that a model trained on a 2017 lab capture does not transfer cleanly to a different network.

**Deployment finding.** Packet capture needs a vantage point that sees the traffic. Under WSL2 (mirrored networking) the Wi-Fi interface carried no packets and loopback scans bypassed `lo`; a host on ordinary Wi-Fi sees only its own traffic. A deployment must sit at the gateway, on an access point, or on a mirror port. An end-to-end test used a container scanning the host over the Docker bridge: the PortScan was detected at 97% confidence with an explanation. A scan between identical source and destination addresses was not classified as PortScan, so self-scans are not valid evidence.

**Raspberry Pi.** The ML service builds and serves on ARM64 (verified under QEMU emulation). Real Pi latency, CPU, RAM and throughput are still to be measured.

**Testing.** 10 Rust unit tests (packet parser, flow features, statistics, token check), 10 Python tests (feature-order contract between the Rust extractor and the model, classification output, explanations, anomaly score) and a 6-check end-to-end smoke test.

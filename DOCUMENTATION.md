# NetSpectre documentation

NetSpectre is an ML-based network intrusion detection system (IDS) for home networks. It detects and reports suspicious traffic; it does not block it.

| Part | Where | What it does |
|---|---|---|
| Monitor | `core/` (Rust) | Captures packets with libpcap, builds bidirectional flows, computes 35 CICFlowMeter-style features, groups classified flows into alerts, stores them in SQLite, serves the REST API and live event stream, deletes data older than 30 days. |
| ML service | `ml/` (Python) | gRPC service: XGBoost classifier (15 CICIDS2017 classes, ONNX), autoencoder anomaly score (ONNX), TreeSHAP reasons. Training and evaluation scripts live here too. |
| Contract | `shared/netspectre.proto` | Messages and the `Inference` service shared by Rust and Python. |
| Dashboard | `dashboard/` (React + TypeScript) | Alerts, devices, attack types, IP lookup, reports, attack guide, settings, privacy and terms. |
| Mobile app | `mobile/` (Expo) | Alert list with acknowledge/dismiss and the full dashboard in a second tab. |
| Deployment | `docker-compose.yml` | ML service, monitor and dashboard containers. |

Where to read more:

- `README.md`: quick start, configuration, API, demo script, tests.
- `docs/RESULTS.md`: measured latency, live detection checks and deployment findings.
- `docs/EVAL_TEST_SET.txt`: per-class results on the 499,605-flow test set.
- `docs/EVAL_LEAVE_DAY_OUT.txt`: detection of attack types never seen in training.
- `docs/REPORT_CORRECTIONS.md`: corrected figures and wording for the project report.

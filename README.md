# NetSpectre

**ML-based intrusion detection for home networks.** NetSpectre captures live traffic, turns each network flow into 35 features, classifies it with an XGBoost + CatBoost ensemble trained on CICIDS2017, flags traffic that matches no known attack with an autoencoder, and shows plain-language reasons for every alert on a web dashboard and an Android/iOS app.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/batsyahan/NetSpectre/actions/workflows/ci.yml/badge.svg)](https://github.com/batsyahan/NetSpectre/actions/workflows/ci.yml)

## Architecture

```
 packets ──▶ Rust monitor (core/) ──gRPC──▶ Python ML service (ml/)
 (libpcap)   flows → 35 features            XGBoost+CatBoost classifier (ONNX)
                 │                          autoencoder anomaly score (ONNX)
                 │                          TreeSHAP "why" reasons
                 ▼
          SQLite alerts + devices
                 │
          REST API (Axum, :8080, token for non-local clients)
             │                    │
   Web dashboard (:5173)    Mobile app (Expo)
```

| Directory | Technology | Purpose |
|---|---|---|
| `core/` | Rust (pcap, tokio, tonic, axum, rusqlite) | Packet capture, flow features, alert grouping, REST API |
| `ml/` | Python (onnxruntime, xgboost, grpcio) | Inference server, explanations, anomaly score, training scripts |
| `dashboard/` | React + TypeScript | Alerts, triage, device list, CSV export |
| `mobile/` | React Native (Expo) | Live alerts on a phone, acknowledge / dismiss |
| `shared/` | Protobuf | gRPC contract between monitor and ML service |
| `scripts/` | Bash | End-to-end smoke test |
| `docs/` | Markdown | Measured results and limitations (`RESULTS.md`) |

## Quick start (Docker)

```bash
git clone https://github.com/batsyahan/NetSpectre.git && cd NetSpectre
echo "NS_API_TOKEN=$(openssl rand -hex 16)" > .env     # token for API clients on other devices
docker compose up -d --build
```

- Dashboard: http://localhost:5173
- API: http://localhost:8080/api/health
- The monitor captures on `lo` by default. To watch a real interface: `NS_IFACE=eth0 docker compose up -d monitor`.
- Trusted sources that should not raise anomaly alerts: `NS_ANOMALY_IGNORE` in `docker-compose.yml`.

### Configuration

Settings are environment variables. Put secrets in the git-ignored `.env`; `docker-compose.yml` passes them to the monitor.

| Variable | Default | Purpose |
|---|---|---|
| `NS_IFACE` | `lo` | Network interface the monitor captures on. |
| `NS_API_TOKEN` | empty | Token (`x-api-token` header) required from non-loopback API clients, such as the phone app. |
| `NS_ANOMALY_IGNORE` | see compose file | Trusted source IPs that never raise "Anomaly (unknown)" alerts. |
| `NS_AE_THRESHOLD` | 0.2369 | Autoencoder reconstruction-error threshold (calibrated for ~1% false alarms on benign traffic). |
| `NS_RARE_MIN_CONF` | 0.8 | Minimum model confidence before Heartbleed or Infiltration flows may count toward an alert. These classes have very few training flows, so weak detections are ignored. |
| `NS_NTFY_TOPIC` | empty (off) | Enables phone notifications through [ntfy](https://ntfy.sh). Use a long random topic name and treat it like a password. |
| `NS_NTFY_MIN_SEVERITY` | `medium` | Lowest severity that sends a phone notification: `low`, `medium`, `high` or `critical`. |
| `NS_NTFY_SERVER` | `https://ntfy.sh` | ntfy server; point this at your own server to keep alerts off third-party infrastructure. |

Phone notifications send only the attack type, severity, source IP, flow count and confidence. The ntfy server operator can see that text, so self-host ntfy if that matters for your network.

### REST API

The monitor serves a JSON API on port 8080 (token required except from loopback).

| Endpoint | Description |
|---|---|
| `GET /api/health` | Liveness check. |
| `GET /api/alerts?limit=N&src_ip=IP` | Newest alerts first; `src_ip` limits the result to one device (default limit 50, maximum 500). |
| `POST /api/alerts/status` | Acknowledge, dismiss or reopen an alert. |
| `GET /api/devices` | Device inventory with flow and alert counts. |
| `GET /api/alerts/export` | All alerts as CSV. |
| `GET /api/stream` | Server-sent events; emits an `alert` event whenever a new alert is stored, so the dashboard updates instantly. |

### Mobile app

```bash
cd mobile && npm install
# mobile/.env.local (git-ignored):
#   EXPO_PUBLIC_API_URL=http://<laptop-lan-ip>:8080
#   EXPO_PUBLIC_API_TOKEN=<the NS_API_TOKEN from .env>
npx expo start
```

Open the QR code in Expo Go on a phone on the same Wi-Fi.

## Demo script (about 5 minutes)

1. `docker compose up -d` and open the dashboard.
2. Run `bash scripts/smoke_test.sh`. It launches a port scan from a throwaway container and checks the result.
3. Watch a **PortScan** alert appear, with its "Why:" line showing the top contributing features.
4. Open the phone app and show the same alert. Acknowledge one alert and dismiss another, then confirm the status changes on the dashboard.
5. Click **Export CSV** to show the audit trail, and open the **Devices** panel.
6. Point out the anomaly alerts ("Anomaly (unknown)"), which come from the autoencoder and not from the classifier.

## Tests

GitHub Actions runs the Rust, dashboard and ML test suites on every push (see the CI badge above).

```bash
cd core && cargo test                 # 10 Rust unit tests (parser, flow features, statistics, token check)
cd ml && python -m unittest -v test_ml    # 10 Python tests (feature contract, classify, explanations, anomaly)
bash scripts/smoke_test.sh            # end-to-end against the running stack
```

## Results and limitations

Measured numbers (latency, detection checks, deployment findings) are in [docs/RESULTS.md](docs/RESULTS.md). Key points:

- ML call latency on a laptop: 2.0 ms mean for benign flows, 8.2 ms mean for attacks including explanations. The ARM64 image builds and serves under emulation; it has not yet been timed on real Raspberry Pi hardware.
- Anomaly thresholds are demo-grade and need calibration per network.
- Capture needs a vantage point that actually sees the traffic (a gateway, access point or mirror port). A host on ordinary Wi-Fi, and WSL2, see only their own traffic.
- TCP flag-count features were removed from the model because they are a dataset artifact in CICIDS2017.

## License

MIT, see [LICENSE](LICENSE).

## Acknowledgments

- [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) (Canadian Institute for Cybersecurity) for training data
- XGBoost, CatBoost, ONNX Runtime and SHAP for the models and explanations

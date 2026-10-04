# NetSpectre: measured results and known limitations

## Test coverage
- Rust unit tests (`cd core && cargo test`): 10 tests. Packet parser, flow features (hand-built 3-packet handshake), running statistics, token comparison.
- Python unit tests (`cd ml && python -m unittest test_ml`): 10 tests. Feature contract (Rust extractor order == model training order, 35 features), classify output, explanations, anomaly score.
- End-to-end smoke test (`bash scripts/smoke_test.sh`): 6 checks. Health, alert raised by a real port scan, PortScan label, explanation present, device inventory, CSV export.

## Inference latency (gRPC call, loopback, 500 requests per row)
| Path | Native x86 laptop (mean / p99) | ARM64 under QEMU emulation (mean / p99) |
|---|---|---|
| BENIGN | 2.0 / 4.5 ms | 12.8 / 21.1 ms |
| ATTACK incl. SHAP | 8.2 / 19.5 ms | 174.6 / 342.7 ms |

Target: 50 ms. The ARM64 figures come from an emulator, not from a Raspberry Pi 4, so they are a functional check plus a pessimistic bound, not Pi performance. The ARM64 image builds and serves correctly. The real Pi has not been measured.

## Detection observations
- Port scan between two distinct addresses (container on docker0 -> host): labelled PortScan, 97% confidence, with an explanation.
- The same scan from the laptop to its own address (same source and destination IP) was NOT labelled PortScan (autoencoder raised "Anomaly (unknown)" instead). Self-scans are not valid test traffic.

## Deployment findings
- WSL2 in mirrored networking mode cannot sniff the LAN: the Wi-Fi interface (eth1) carried 0 packets in 10 s, and scans to 127.0.0.1 no longer pass through `lo`. Live home-network monitoring requires a host placed where it sees the traffic (a Pi acting as gateway or access point, or a switch mirror port). A passive Pi on Wi-Fi sees only its own traffic.
- API access from other devices requires a token (`x-api-token`); loopback clients are exempt. Verified: no token -> 401, token -> OK.

## Known limitations
- Anomaly thresholds (0.2369 at 1%, 0.1347 at 3%, 0.1040 at 5% of benign test flows) are demo-grade and need per-network calibration.
- Dataset shift: DNS traffic from the WSL resolver (10.255.255.254) is flagged as anomalous, so it is on a trusted-source list.
- TCP flag-count features were dropped from the model (dataset artifact in CICIDS2017).

## Real-traffic false-alert check (small sanity test)
- Setup: 300 ordinary HTTP GET requests (0.2 s apart) from a container to the dashboard over the Docker bridge, captured by the live monitor and classified by the deployed models.
- Result: 300/300 requests completed, 0 alerts raised.
- Caveat: one traffic type, one server, one client. This is a sanity check, not a false-alarm rate. The dataset figure (0.17% of benign test flows misclassified) remains the quantitative estimate; a realistic home-traffic mix (streaming, DNS, calls, IoT) has not been tested.

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

## Mixed-traffic false-alert check (2 minutes, 8 parallel clients)
- Setup: 8 threads from a container sent random requests to the dashboard server over the Docker bridge (small API calls up to the CSV export, random 0.05-1.0 s pauses). 1,784 requests, 0 errors, about 6.4 MB.
- Result: 0 alerts from the classifier (no attack class), 3 "Anomaly (unknown)" alerts from the autoencoder (5-6 flows each, confidence about 0.5, i.e. just above the 0.2369 threshold).
- Reading: the classifier did not confuse this traffic with any known attack. The autoencoder flagged at least 16 of 1,784 flows (about 1% or more), consistent with its 1% design threshold but clustered, so alerts form. Under dense synthetic load this is roughly 1-2 low-confidence anomaly alerts per minute.
- Implication: the anomaly threshold needs per-network calibration (or a higher default / minimum confidence) before unattended use. Traffic is synthetic and from one client type; this is not a household false-alarm rate.

### Which request type triggers the anomaly alerts? (one 20 s trial each, 4 clients)
| Request | Requests | New anomaly alerts |
|---|---|---|
| /api/health (tiny) | 284 | 0 |
| / (dashboard page) | 291 | 0 |
| /api/alerts?limit=50 (medium JSON) | 282 | 1 (5 flows) |
| /api/alerts/export (CSV) | 280 | 0 |
Single short trial per path: suggestive only (a medium-sized response may look unlike the 2017 benign data), not confirmed. Does not change the conclusion that the anomaly threshold needs per-network calibration.

## Observed during development (9-10 Oct 2026)

### Critical false positive: Heartbleed on a package download
- What happened: while a Docker image build downloaded npm packages from a container on the `docker0` bridge, the monitor raised a critical "Heartbleed" alert (3 flows, average confidence 0.50). The explanation was dominated by "largest reply payload of 44208 bytes" (97%).
- Likely cause (not confirmed): a large encrypted download resembles the Heartbleed class, which has very few training flows in CICIDS2017, so the classifier is unreliable at low confidence for it.
- Mitigation: flows labelled Heartbleed or Infiltration only count toward an alert when model confidence is at least 0.8 (`NS_RARE_MIN_CONF`). The rule is unit-tested (3 tests). A later rebuild with the same download produced no Heartbleed alert, but that is a single run, not proof.
- Trade-off: a genuine but weakly scored Heartbleed or Infiltration attack would now be missed. Only one false alert of this kind was observed, so the 0.8 value is a judgement, not a tuned figure.

### Anomaly alerts on package downloads
- During builds and package downloads from the same container, the autoencoder raised 5 "Anomaly (unknown)" alerts over about half an hour (confidence 0.66 to 0.80, 5 flows each). Large software downloads look unusual compared with the 2017 benign traffic.
- Because they are rated medium, they also trigger phone notifications at the default `NS_NTFY_MIN_SEVERITY=medium`. Raising it to `high` silences them (and also PortScan, which is rated medium).

### Device inventory includes remote servers
- The device list shows external addresses (for example CDN servers such as 104.16.x.x and 151.101.158.137) as "devices" because every flow source is recorded. There is no local-network filter yet, so on a busy network the list will grow with internet hosts.

### End-to-end checks
- Live alert push: the `/api/stream` endpoint emitted an `alert` event for each alert raised by the smoke-test scan, with keep-alive comments every 15 s; the dashboard updates without waiting for its 10 s fallback poll.
- Phone alerts: after the smoke-test port scan, two ntfy notifications reached an Android phone (PortScan, 10 ports, 86% confidence; "Anomaly (unknown)", 5 flows, 100%). Delivery latency was not measured.
- Automated tests: 35 tests (17 Rust, 8 dashboard, 10 ML service) run on GitHub Actions for every push; all passed on a clean GitHub-hosted runner.

## Own-network baseline and model updates (14 Oct 2026)

Normal traffic was recorded on the developer laptop for about 80 minutes (`scripts/gen_benign.sh` browsing, downloads, DNS, API calls over IPv4; monitor on `eth1`, flows logged by the ML service). 2,031 flows were kept in `baselines/benign_capture.csv`; the last 30% (in time order) is used only for testing. Checker: `ml/check_capture.py`.

**Autoencoder.** The deployed autoencoder (`ae35`, threshold 0.5) flagged 20% of this normal traffic (12.9% of the held-out part), which explains the false "Anomaly (unknown)" alerts seen live. A new autoencoder (`ml/retrain_ae35_v2.py`, `ae35_v2`) was trained on 400k CICIDS2017 benign flows plus the own-network flows, with the threshold chosen from data (<= 0.5% false alarms on held-out own traffic and <= 1% on CICIDS benign):

| Model | False alarms, own traffic | False alarms, CICIDS benign | DDoS flagged | Slowloris | Slowhttptest |
|---|---|---|---|---|---|
| ae35 @ 0.5 (previous) | 12.88% | 0.21% | 0.0% | 12.5% | 2.1% |
| ae35 @ 0.2369 | 25.77% | 1.00% | 73.8% | 23.9% | 85.9% |
| ae35_v2 @ 0.645 (deployed) | 0.61% | 0.14% | 0.0% | 6.5% | 1.8% |

Finding: the old autoencoder's DDoS "detection" at 0.2369 came with a quarter of real browsing flagged. CICIDS2017 DDoS is an HTTP flood, and at the level of single flows it resembles ordinary web traffic, so a per-flow autoencoder cannot separate the two on a real network. The autoencoder is kept as a detector of clearly unusual traffic, not as a reliable zero-day detector.

**Classifier.** A retrain with the own-network flows (`ml/retrain_xgb35_v4.py`, v4) was tested and **not deployed**. The first attempt taught refused connections (one SYN out, one reset back, logged while the API was restarting) as BENIGN; these are identical to single port-scan probes, and v4 then missed the smoke-test scan (0 alerts; v3 raised `PortScan: 10 ports in 10s`). With such one-packet-each-way flows excluded, v4 matched v3 on live data (own held-out traffic 380/380 vs 379/380 BENIGN; smoke-test connect() probes 1224/1266 PortScan for both) but scored lower on the CICIDS2017 test set (macro F1 0.840 vs 0.850, benign FPR 0.143% vs 0.131%), so v3 stays.

Deployed after these tests: classifier `multiclass_xgb35_v3`, autoencoder `ae35_v2` at 0.645 (`docker-compose.yml`); `scripts/smoke_test.sh` passes 6/6.

Limitations found: the monitor only analysed IPv4 TCP/UDP, so browser traffic over IPv6/QUIC was invisible (IPv6 support was added afterwards, see below); on WSL2 the monitor sees little of the Windows host's traffic.

### IPv6 support (14 Oct 2026)

The monitor now parses TCP and UDP over IPv6 as well as IPv4. A first version passed its unit tests but raised no alert for a port scan over IPv6: the models learned the CICIDS2017 convention that Ethernet padding of short frames counts as payload, and IPv6 frames are never padded. Replaying the 1,266 real connect() scan probes from `baselines/connect_scan_flows.csv` with IPv6 sizes turned 1,224 PortScan verdicts into 24. The monitor therefore measures each IPv6 packet as the same packet would be over IPv4 (20 header bytes fewer, then the 60-byte minimum). Live check after the fix: 15 refused IPv6 connections to `::1` raised `ALERT ::1 -> PortScan: 10 ports in 10s (avg confidence 1.00)`. The models have not been evaluated on other IPv6 attack traffic.

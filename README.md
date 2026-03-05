# 🛡️ NetSpectre

[![Rust CI](https://github.com/batsyahan/NetSpectre/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/batsyahan/NetSpectre/actions/workflows/rust-ci.yml)
[![Python CI](https://github.com/batsyahan/NetSpectre/actions/workflows/python-ci.yml/badge.svg)](https://github.com/batsyahan/NetSpectre/actions/workflows/python-ci.yml)
[![React CI](https://github.com/batsyahan/NetSpectre/actions/workflows/react-ci.yml/badge.svg)](https://github.com/batsyahan/NetSpectre/actions/workflows/react-ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**ML-Based Network Intrusion Detection System for Home Networks**

NetSpectre is an intelligent, real-time network intrusion detection system designed specifically for home networks. It combines the raw performance of Rust for packet capture and analysis with Python-based machine learning for anomaly detection, presented through a beautiful React dashboard and React Native mobile app.

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Network     │────▶│  Rust Core   │────▶│  Python ML      │
│  Traffic     │     │  Engine      │     │  Pipeline       │
│  (pcap)      │     │  (capture/   │     │  (inference/    │
│              │     │   analyze)   │     │   training)     │
└─────────────┘     └──────┬───────┘     └────────┬────────┘
                           │                       │
                           ▼                       ▼
                    ┌──────────────┐     ┌─────────────────┐
                    │  REST/gRPC   │────▶│  React          │
                    │  API Layer   │     │  Dashboard      │
                    │              │     │  + React Native │
                    └──────────────┘     │  Mobile App     │
                                        └─────────────────┘
```

## 📦 Project Structure

| Directory | Technology | Purpose |
|-----------|-----------|---------|
| `core/` | 🦀 Rust | Packet capture, traffic analysis, protocol parsing, API server |
| `ml/` | 🐍 Python | ML models, training pipelines, real-time inference |
| `dashboard/` | ⚛️ React + TypeScript | Web-based monitoring dashboard |
| `mobile/` | 📱 React Native | Mobile monitoring & push alerts |
| `shared/` | 🔗 Protobuf + OpenAPI | API contracts & shared type definitions |
| `infra/` | 🐳 Docker + K8s | Containerization & deployment |
| `docs/` | 📚 Markdown | Architecture docs, setup guides, API reference |

## 🚀 Quick Start

### Prerequisites

- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Python 3.11+ with pip
- Node.js 20+ with npm
- Docker & Docker Compose
- libpcap (`sudo apt install libpcap-dev` / `brew install libpcap`)

### Development Setup

```bash
# Clone the repository
git clone https://github.com/batsyahan/NetSpectre.git
cd NetSpectre

# Start all services with Docker Compose
docker compose -f infra/docker-compose.yml up --build

# Or run individual components:

# Rust core engine
cd core && cargo build && cargo run

# Python ML pipeline
cd ml && pip install -e ".[dev]" && python -m netspectre_ml

# React dashboard
cd dashboard && npm install && npm run dev

# React Native mobile app
cd mobile && npm install && npx expo start
```

## 🧪 Running Tests

```bash
# Rust tests
cd core && cargo test

# Python tests
cd ml && pytest

# Dashboard tests
cd dashboard && npm test

# Mobile tests
cd mobile && npm test
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) for ML training data
- [libpnet](https://github.com/libpnet/libpnet) for Rust packet capture
- [scikit-learn](https://scikit-learn.org/) & [PyTorch](https://pytorch.org/) for ML models

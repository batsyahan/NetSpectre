#!/usr/bin/env bash
# Downloads 4 more CSE-CIC-IDS2018 days (about 1.5 GB) into data/raw/cicids2018/. Run from ml/.
# 15-02: DoS GoldenEye + Slowloris | 21-02: DDoS HOIC + LOIC-UDP | 22-02 and 23-02: web brute force, XSS, SQL injection
# Skipped: 20-02 (4 GB file), 28-02 and 01-03 (Infiltration labels are known to be unreliable).
set -e
mkdir -p data/raw/cicids2018
BASE="https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms"
for d in Thursday-15-02-2018 Wednesday-21-02-2018 Thursday-22-02-2018 Friday-23-02-2018; do
  out="data/raw/cicids2018/$d.csv"
  [ -s "$out" ] && { echo "have $d"; continue; }
  echo "downloading $d"
  for try in 1 2 3; do
    curl -fL --retry 3 -C - -o "$out.part" "$BASE/${d}_TrafficForML_CICFlowMeter.csv" && break
    echo "retry $try"; sleep 5
  done
  mv "$out.part" "$out"
done
ls -lh data/raw/cicids2018/; df -h ~ | tail -1

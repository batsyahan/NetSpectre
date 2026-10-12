#!/usr/bin/env bash
# Harmless, ordinary web traffic from WSL for the autoencoder baseline.
# Usage: scripts/gen_baseline_traffic.sh [seconds]   (default 900)
SITES="https://www.wikipedia.org https://github.com https://www.python.org https://www.rust-lang.org https://docs.docker.com https://www.google.com https://www.bing.com https://duckduckgo.com https://www.cloudflare.com https://www.npmjs.com https://pypi.org https://news.ycombinator.com https://www.bbc.com https://stackoverflow.com https://www.mozilla.org https://www.apache.org https://www.gnu.org https://www.kernel.org https://archive.org https://www.nginx.org"
END=$(( $(date +%s) + ${1:-900} ))
while [ "$(date +%s)" -lt "$END" ]; do
  for s in $SITES; do
    curl -s -o /dev/null --max-time 8 "$s" &
    sleep 0.3
  done
  wait
  sleep 2
done
echo done

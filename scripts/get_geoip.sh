#!/usr/bin/env bash
# Downloads the free DB-IP "IP to Country Lite" database (CC BY 4.0, https://db-ip.com) into ./geo/.
# The monitor reads it locally for the Attack Map; no IP address is ever sent to DB-IP.
# Re-run monthly to refresh. Usage: bash scripts/get_geoip.sh
set -e
cd "$(dirname "$0")/.." && mkdir -p geo
for m in "$(date +%Y-%m)" "$(date -d "$(date +%Y-%m-15) -1 month" +%Y-%m)"; do
  url="https://download.db-ip.com/free/dbip-country-lite-$m.mmdb.gz"
  echo "trying $url"
  if curl -fL --retry 3 -o geo/dbip-country-lite.mmdb.gz "$url"; then
    gunzip -f geo/dbip-country-lite.mmdb.gz
    ls -la geo/dbip-country-lite.mmdb
    echo "done. Restart the monitor: docker compose up -d monitor"
    exit 0
  fi
done
echo "download failed; check https://db-ip.com/db/download/ip-to-country-lite"; exit 1

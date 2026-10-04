#!/usr/bin/env bash
# End-to-end smoke test for a running NetSpectre stack (docker compose up -d).
# The scan comes from a throwaway container on docker0 (different src/dst addresses).
# Note: leaves the monitor capturing on docker0; restart it with NS_IFACE=<iface> for other use.
cd "$(dirname "$0")/.." || exit 1
API=http://127.0.0.1:8080
pass=0; fail=0
check() { if [ "$2" = "ok" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  ($3)"; fail=$((fail+1)); fi; }

# scanner container on the default bridge (brings docker0 up)
docker inspect -f '{{.State.Running}}' nsscan 2>/dev/null | grep -q true || {
  docker rm -f nsscan >/dev/null 2>&1
  docker run -d --name nsscan --entrypoint sleep netspectre-ml 86400 >/dev/null
}
SCANNER=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' nsscan)
HOSTIP=$(ip -4 -br addr show docker0 | awk '{print $3}' | cut -d/ -f1)

# make sure the monitor is capturing on docker0
if ! docker compose logs --tail 200 monitor 2>/dev/null | grep "monitoring" | tail -1 | grep -q docker0; then
  NS_IFACE=docker0 docker compose up -d monitor >/dev/null 2>&1
  sleep 8
fi

health=$(curl -s $API/api/health)
[[ "$health" == *'"ok"'* ]] && check "API health" ok || check "API health" no "$health"

before=$(curl -s "$API/api/alerts?limit=1" | python3 -c "import json,sys; a=json.load(sys.stdin); print(a[0]['id'] if a else 0)")
docker exec nsscan python -c "
import socket
for p in range(1,401):
    s=socket.socket(); s.settimeout(0.3)
    try: s.connect(('$HOSTIP',p))
    except Exception: pass
    s.close()
" >/dev/null 2>&1
sleep 12
new=$(curl -s "$API/api/alerts?limit=20" | python3 -c "
import json, sys
rows = [a for a in json.load(sys.stdin) if a['id'] > $before]
for a in rows: print('   new alert', a['id'], a['src_ip'], a['label'], a['flow_count'])
ps = [a for a in rows if a['label'] == 'PortScan']
print('RESULT', 'ok' if rows else 'no', 'ok' if ps else 'no', 'ok' if ps and ps[0]['explanation'] else 'no')
")
echo "$new" | grep -v '^RESULT'
read -r _ r1 r2 r3 <<< "$(echo "$new" | grep '^RESULT')"
check "scan raised at least one new alert" "$r1"
check "a PortScan alert was raised" "$r2"
check "the PortScan alert has an explanation" "$r3"

dev=$(curl -s $API/api/devices)
[[ -n "$SCANNER" && "$dev" == *"$SCANNER"* ]] && check "device inventory lists $SCANNER" ok || check "device inventory" no
hdr=$(curl -s $API/api/alerts/export | head -1)
[[ "$hdr" == id,time_utc* ]] && check "CSV export header" ok || check "CSV export header" no "$hdr"

echo; echo "passed $pass, failed $fail"
[ $fail -eq 0 ]

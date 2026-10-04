#!/usr/bin/env bash
# End-to-end smoke test for a running NetSpectre stack (docker compose up -d).
API=http://127.0.0.1:8080
pass=0; fail=0
check() { if [ "$2" = "ok" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1  ($3)"; fail=$((fail+1)); fi; }

health=$(curl -s $API/api/health)
[[ "$health" == *'"ok"'* ]] && check "API health" ok || check "API health" no "$health"

before=$(curl -s "$API/api/alerts?limit=1" | python3 -c "import json,sys; a=json.load(sys.stdin); print(a[0]['id'] if a else 0)")
sudo nmap -sS -p 1-400 127.0.0.1 > /dev/null 2>&1
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
[[ "$dev" == *127.0.0.1* ]] && check "device inventory lists 127.0.0.1" ok || check "device inventory" no
hdr=$(curl -s $API/api/alerts/export | head -1)
[[ "$hdr" == id,time_utc* ]] && check "CSV export header" ok || check "CSV export header" no "$hdr"

echo; echo "passed $pass, failed $fail"
[ $fail -eq 0 ]

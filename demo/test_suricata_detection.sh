#!/bin/bash

echo "=================================================="
echo "Suricata Detection Verification Script"
echo "=================================================="

echo -e "\n[1] Checking if custom.rules exists in container..."
docker exec suricata_ids ls -lh /etc/suricata/rules/custom.rules

echo -e "\n[2] Viewing custom.rules content..."
docker exec suricata_ids cat /etc/suricata/rules/custom.rules

echo -e "\n[3] Checking Suricata startup logs for rule loading..."
docker exec suricata_ids cat /var/log/suricata-stdout.log 2>/dev/null | grep -i "rule" | head -10

echo -e "\n[4] Checking Suricata main log..."
cat shared/logs/suricata.log | grep -E "rule.*loaded|custom.rules" | head -10

echo -e "\n[5] Checking current alert count in eve.json..."
ALERT_COUNT=$(cat shared/logs/eve.json | grep '"event_type":"alert"' | wc -l)
echo "Current alerts in eve.json: $ALERT_COUNT"

echo -e "\n[6] Testing SQL Injection (should trigger sid:1000022)..."
echo "Sending: UNION SELECT attack..."
curl -s "http://localhost:8081/dvwa/vulnerabilities/sqli/?id=1'+UNION+SELECT+null,user()+--+&Submit=Submit" > /dev/null
sleep 2

echo -e "\n[7] Checking for NEW alerts..."
NEW_ALERT_COUNT=$(cat shared/logs/eve.json | grep '"event_type":"alert"' | wc -l)
echo "Alerts after SQL injection: $NEW_ALERT_COUNT"

if [ $NEW_ALERT_COUNT -gt $ALERT_COUNT ]; then
    echo "✓ NEW ALERT DETECTED!"
    echo -e "\n[8] Latest alert details:"
    cat shared/logs/eve.json | grep '"event_type":"alert"' | tail -1 | jq '.'
else
    echo "✗ NO NEW ALERT - Rules may not be working"
    echo -e "\n[8] Checking for suppressed alerts in stats..."
    cat shared/logs/stats.log | grep -i "suppress" | tail -5
fi

echo -e "\n[9] Checking Suricata rule counters..."
docker exec suricata_ids cat /var/log/suricata/stats.log 2>/dev/null | grep -E "detect\." | tail -10

echo -e "\n[10] Verifying Suricata is monitoring eth0..."
docker exec suricata_ids ps aux | grep suricata

echo "=================================================="
echo "Verification Complete"
echo "=================================================="

#!/bin/bash

echo "========================================"
echo "DVWA Initialization Debug Script"
echo "========================================"

cd ~/netsec-project

# Check container status
echo -e "\n[1/8] Checking container status..."
SURICATA_STATUS=$(docker inspect -f '{{.State.Running}}' suricata_ids 2>/dev/null)
MLIDS_STATUS=$(docker inspect -f '{{.State.Running}}' ml_ids 2>/dev/null)

echo "Suricata container running: $SURICATA_STATUS"
echo "ML-IDS container running: $MLIDS_STATUS"

if [ "$SURICATA_STATUS" != "true" ] || [ "$MLIDS_STATUS" != "true" ]; then
    echo "ERROR: Containers not running!"
    echo "Starting containers..."
    docker-compose up -d
    sleep 30
fi

# Get IPs
echo -e "\n[2/8] Getting container IPs..."
SURICATA_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' suricata_ids 2>/dev/null)
ML_IDS_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ml_ids 2>/dev/null)

echo "Suricata IP: ${SURICATA_IP:-NOT FOUND}"
echo "ML-IDS IP: ${ML_IDS_IP:-NOT FOUND}"

# Check services inside containers
echo -e "\n[3/8] Checking Apache service..."
docker exec suricata_ids pgrep apache2 > /dev/null && echo "  ✓ Suricata Apache running" || echo "  ✗ Suricata Apache NOT running"
docker exec ml_ids pgrep apache2 > /dev/null && echo "  ✓ ML-IDS Apache running" || echo "  ✗ ML-IDS Apache NOT running"

echo -e "\n[4/8] Checking MySQL service..."
docker exec suricata_ids pgrep mysql > /dev/null && echo "  ✓ Suricata MySQL running" || echo "  ✗ Suricata MySQL NOT running"
docker exec ml_ids pgrep mysql > /dev/null && echo "  ✓ ML-IDS MySQL running" || echo "  ✗ ML-IDS MySQL NOT running"

# Restart services if needed
echo -e "\n[5/8] Ensuring services are running..."
docker exec suricata_ids service apache2 status > /dev/null 2>&1 || docker exec suricata_ids service apache2 start
docker exec suricata_ids service mysql status > /dev/null 2>&1 || docker exec suricata_ids service mysql start
docker exec ml_ids service apache2 status > /dev/null 2>&1 || docker exec ml_ids service apache2 start
docker exec ml_ids service mysql status > /dev/null 2>&1 || docker exec ml_ids service mysql start

sleep 5

# Create databases manually
echo -e "\n[6/8] Creating DVWA databases..."

echo "  Creating Suricata DVWA database..."
docker exec suricata_ids mysql -u root -e "DROP DATABASE IF EXISTS dvwa; CREATE DATABASE dvwa; CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'password'; GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost'; FLUSH PRIVILEGES;" 2>/dev/null && echo "    ✓ Success" || echo "    ✗ Failed"

echo "  Creating ML-IDS DVWA database..."
docker exec ml_ids mysql -u root -e "DROP DATABASE IF EXISTS dvwa; CREATE DATABASE dvwa; CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'password'; GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost'; FLUSH PRIVILEGES;" 2>/dev/null && echo "    ✓ Success" || echo "    ✗ Failed"

# Test web access
echo -e "\n[7/8] Testing web access..."

# Test Suricata DVWA
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8081/dvwa/ | grep -q "200"; then
    echo "  ✓ Suricata DVWA accessible (HTTP 200)"
else
    echo "  ✗ Suricata DVWA not accessible"
    echo "    Checking Apache error log:"
    docker exec suricata_ids tail -10 /var/log/apache2/error.log 2>/dev/null || echo "    Cannot read log"
fi

# Test ML-IDS DVWA
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8082/dvwa/ | grep -q "200"; then
    echo "  ✓ ML-IDS DVWA accessible (HTTP 200)"
else
    echo "  ✗ ML-IDS DVWA not accessible"
    echo "    Checking Apache error log:"
    docker exec ml_ids tail -10 /var/log/apache2/error.log 2>/dev/null || echo "    Cannot read log"
fi

# Initialize via web interface
echo -e "\n[8/8] Initializing via web interface..."

echo "  Initializing Suricata DVWA..."
curl -s "http://localhost:8081/dvwa/setup.php" > /dev/null
sleep 2
curl -s -X POST "http://localhost:8081/dvwa/setup.php" -d "create_db=Create / Reset Database" > /dev/null
sleep 2

echo "  Initializing ML-IDS DVWA..."
curl -s "http://localhost:8082/dvwa/setup.php" > /dev/null
sleep 2
curl -s -X POST "http://localhost:8082/dvwa/setup.php" -d "create_db=Create / Reset Database" > /dev/null
sleep 3

# Final verification
echo -e "\n========================================"
echo "Final Verification:"
echo "========================================"

if curl -s "http://localhost:8081/dvwa/" | grep -qi "login"; then
    echo "✓ Suricata DVWA: WORKING"
else
    echo "✗ Suricata DVWA: FAILED"
    echo "  Try manually: http://localhost:8081/dvwa/setup.php"
fi

if curl -s "http://localhost:8082/dvwa/" | grep -qi "login"; then
    echo "✓ ML-IDS DVWA: WORKING"
else
    echo "✗ ML-IDS DVWA: FAILED"
    echo "  Try manually: http://localhost:8082/dvwa/setup.php"
fi

echo -e "\n========================================"
echo "Access Information:"
echo "========================================"
echo "Suricata DVWA:  http://localhost:8081/dvwa"
echo "ML-IDS DVWA:    http://localhost:8082/dvwa"
echo "Dashboard:      http://localhost:8080"
echo ""
echo "Credentials: admin / password"
echo "========================================"

echo -e "\nIf issues persist, run:"
echo "  docker-compose logs suricata-ids"
echo "  docker-compose logs ml-ids"

#!/bin/bash

echo "=========================================="
echo "IDS System Health Check"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
PASSED=0
FAILED=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}: $2"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: $2"
        ((FAILED++))
    fi
}

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. CONTAINER STATUS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if containers are running
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "suricata_ids|ml_ids|ids_dashboard"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. SERVICE HEALTH (SURICATA-IDS)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check Suricata services
docker exec suricata_ids supervisorctl status 2>/dev/null
SURICATA_SUPERVISOR=$?
test_result $SURICATA_SUPERVISOR "Suricata supervisor running"

docker exec suricata_ids pgrep apache2 > /dev/null 2>&1
test_result $? "Suricata Apache2 process"

docker exec suricata_ids pgrep mysql > /dev/null 2>&1
test_result $? "Suricata MySQL process"

docker exec suricata_ids pgrep suricata > /dev/null 2>&1
test_result $? "Suricata IDS process"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. SERVICE HEALTH (ML-IDS)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check ML-IDS services
docker exec ml_ids supervisorctl status 2>/dev/null
ML_SUPERVISOR=$?
test_result $ML_SUPERVISOR "ML-IDS supervisor running"

docker exec ml_ids pgrep apache2 > /dev/null 2>&1
test_result $? "ML-IDS Apache2 process"

docker exec ml_ids pgrep mysql > /dev/null 2>&1
test_result $? "ML-IDS MySQL process"

docker exec ml_ids pgrep python3 > /dev/null 2>&1
test_result $? "ML-IDS Python process"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. DATABASE CONNECTIVITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test MySQL connections
docker exec suricata_ids mysql -u dvwa -ppassword -e "SELECT 1;" dvwa > /dev/null 2>&1
test_result $? "Suricata DVWA database access"

docker exec ml_ids mysql -u dvwa -ppassword -e "SELECT 1;" dvwa > /dev/null 2>&1
test_result $? "ML-IDS DVWA database access"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. WEB APPLICATION ACCESSIBILITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test web access
SURICATA_HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8081/dvwa/)
if [ "$SURICATA_HTTP" = "200" ] || [ "$SURICATA_HTTP" = "302" ]; then
    test_result 0 "Suricata DVWA (HTTP $SURICATA_HTTP)"
else
    test_result 1 "Suricata DVWA (HTTP $SURICATA_HTTP)"
fi

ML_HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8082/dvwa/)
if [ "$ML_HTTP" = "200" ] || [ "$ML_HTTP" = "302" ]; then
    test_result 0 "ML-IDS DVWA (HTTP $ML_HTTP)"
else
    test_result 1 "ML-IDS DVWA (HTTP $ML_HTTP)"
fi

DASHBOARD_HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/)
if [ "$DASHBOARD_HTTP" = "200" ]; then
    test_result 0 "Dashboard (HTTP $DASHBOARD_HTTP)"
else
    test_result 1 "Dashboard (HTTP $DASHBOARD_HTTP)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. LOG FILES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if log directories exist
if [ -d "./shared/logs" ]; then
    test_result 0 "Shared logs directory exists"
    ls -lh ./shared/logs/ 2>/dev/null | tail -n +2
else
    test_result 1 "Shared logs directory missing"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "7. MODEL FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "./shared/models/model.pkl" ]; then
    MODEL_SIZE=$(ls -lh ./shared/models/model.pkl | awk '{print $5}')
    test_result 0 "XGBoost model exists ($MODEL_SIZE)"
else
    test_result 1 "XGBoost model missing (ML-IDS will use pattern detection only)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "8. NETWORK CONNECTIVITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Get container IPs
SURICATA_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' suricata_ids 2>/dev/null)
ML_IDS_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ml_ids 2>/dev/null)
DASHBOARD_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids_dashboard 2>/dev/null)

echo "Suricata IP:  $SURICATA_IP"
echo "ML-IDS IP:    $ML_IDS_IP"
echo "Dashboard IP: $DASHBOARD_IP"

# Test inter-container connectivity
docker exec ids_dashboard ping -c 1 $SURICATA_IP > /dev/null 2>&1
test_result $? "Dashboard can reach Suricata"

docker exec ids_dashboard ping -c 1 $ML_IDS_IP > /dev/null 2>&1
test_result $? "Dashboard can reach ML-IDS"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}Tests Passed: $PASSED${NC}"
echo -e "${RED}Tests Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓ ALL SYSTEMS OPERATIONAL${NC}"
else
    echo -e "\n${YELLOW}⚠ SOME ISSUES DETECTED${NC}"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ACCESS URLS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Suricata DVWA:  http://localhost:8081/dvwa"
echo "ML-IDS DVWA:    http://localhost:8082/dvwa"
echo "Dashboard:      http://localhost:8080"
echo ""
echo "Default Login:  admin / password"
echo "Security Level: Set to 'Low' in both DVWA instances"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "NEXT STEPS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Open browser and visit the DVWA URLs above"
echo "2. Login with admin/password"
echo "3. Run attack suite:"
echo "   docker exec ml_ids python3 /demo/attacks/attack_suite.py $ML_IDS_IP"
echo "4. Monitor dashboard at http://localhost:8080"
echo "5. Check logs in ./shared/logs/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

#!/bin/bash

echo "========================================"
echo "Quick ML-IDS Diagnostics"
echo "========================================"

echo -e "\n[1] Container Status:"
docker ps | grep ml_ids

echo -e "\n[2] Recent Container Logs (last 30 lines):"
docker logs ml_ids --tail 30

echo -e "\n[3] Running Processes:"
docker exec ml_ids ps aux 2>/dev/null || echo "Cannot execute ps - container might be restarting"

echo -e "\n[4] Check if startup script is hung:"
docker exec ml_ids ps aux | grep -E 'start\.sh|mysql|bash' 2>/dev/null || echo "Cannot check processes"

echo -e "\n[5] Check supervisor:"
docker exec ml_ids ls -la /var/run/supervisor* 2>/dev/null || echo "No supervisor socket found"
docker exec ml_ids cat /var/log/supervisor/supervisord.log 2>/dev/null || echo "No supervisor log yet"

echo -e "\n[6] Check if MySQL is actually responding:"
docker exec ml_ids mysqladmin ping 2>/dev/null && echo "MySQL: OK" || echo "MySQL: Not responding"

echo -e "\n[7] Check startup script status:"
docker exec ml_ids pgrep -f start.sh && echo "Startup script STILL RUNNING (BAD!)" || echo "Startup script finished (GOOD)"

echo -e "\n[8] Check for supervisor process:"
docker exec ml_ids pgrep supervisord && echo "Supervisor IS running" || echo "Supervisor NOT running"

echo "========================================"

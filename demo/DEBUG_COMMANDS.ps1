# Debug Commands for IDS System Issues
# Run these commands in PowerShell to diagnose problems

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "IDS System Debug Commands" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n1. Check ML-IDS container logs:" -ForegroundColor Yellow
Write-Host "   docker logs ml_ids --tail 50" -ForegroundColor White
Write-Host "   docker logs ml_ids -f  (follow logs in real-time)" -ForegroundColor White

Write-Host "`n2. Check Suricata container logs:" -ForegroundColor Yellow
Write-Host "   docker logs suricata_ids --tail 50" -ForegroundColor White

Write-Host "`n3. Check if startup script is still running:" -ForegroundColor Yellow
Write-Host "   docker exec ml_ids ps aux | grep start.sh" -ForegroundColor White
Write-Host "   docker exec suricata_ids ps aux | grep start.sh" -ForegroundColor White

Write-Host "`n4. Check supervisor status (if running):" -ForegroundColor Yellow
Write-Host "   docker exec ml_ids supervisorctl status" -ForegroundColor White
Write-Host "   docker exec suricata_ids supervisorctl status" -ForegroundColor White

Write-Host "`n5. Check what processes are running:" -ForegroundColor Yellow
Write-Host "   docker exec ml_ids ps aux" -ForegroundColor White
Write-Host "   docker exec suricata_ids ps aux" -ForegroundColor White

Write-Host "`n6. Check supervisor logs (if exists):" -ForegroundColor Yellow
Write-Host "   docker exec ml_ids cat /var/log/supervisor/supervisord.log" -ForegroundColor White
Write-Host "   docker exec ml_ids cat /var/log/ml-ids-stdout.log" -ForegroundColor White
Write-Host "   docker exec ml_ids cat /var/log/ml-ids-stderr.log" -ForegroundColor White

Write-Host "`n7. Check Apache logs:" -ForegroundColor Yellow
Write-Host "   docker exec ml_ids cat /var/log/apache2/error.log" -ForegroundColor White
Write-Host "   docker exec suricata_ids cat /var/log/apache2/error.log" -ForegroundColor White

Write-Host "`n8. Check MySQL status:" -ForegroundColor Yellow
Write-Host "   docker exec ml_ids mysqladmin ping" -ForegroundColor White
Write-Host "   docker exec ml_ids ps aux | grep mysql" -ForegroundColor White

Write-Host "`n9. Manually restart supervisor (if needed):" -ForegroundColor Yellow
Write-Host "   docker exec ml_ids /usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf &" -ForegroundColor White

Write-Host "`n10. Check if startup completed:" -ForegroundColor Yellow
Write-Host "   docker exec ml_ids cat /tmp/startup_complete 2>/dev/null || echo 'Not complete'" -ForegroundColor White

Write-Host "`n11. Interactive shell to investigate:" -ForegroundColor Yellow
Write-Host "   docker exec -it ml_ids /bin/bash" -ForegroundColor White
Write-Host "   docker exec -it suricata_ids /bin/bash" -ForegroundColor White

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Quick diagnostic - run this first:" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host @"
docker logs ml_ids --tail 30
docker exec ml_ids ps aux | grep -E 'supervisord|apache2|mysql|python3'
"@ -ForegroundColor White

Write-Host "`n========================================" -ForegroundColor Cyan

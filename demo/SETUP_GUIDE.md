# IDS System Setup and Testing Guide

## Issues Fixed

### Both Containers
1. **Supervisor not starting** - Fixed startup script to properly use `exec supervisord -n` (nodaemon mode)
2. **MySQL initialization** - Using `--skip-networking` and socket connection for initial setup
3. **Process cleanup** - Properly shutting down temporary MySQL before supervisor takes over
4. **Suricata version check** - Fixed `--version` flag to `-V`

### ML-IDS Container  
- Added better error messages
- Model file warning is expected until setup_model.sh is run

### Suricata-IDS Container
- Fixed Suricata configuration test in startup
- Added proper version display

## Setup Steps

### 1. Copy the trained model to shared folder

```bash
cd C:\Users\amos\Documents\50.020-Network-Security-Project\demo

# On Windows PowerShell:
mkdir -p shared/models
copy ..\model\xg_30_model.pkl shared\models\model.pkl
copy ..\model\scaler.pkl shared\models\
copy ..\model\feature_list.pkl shared\models\

# Or use the bash script in Git Bash/WSL:
# bash setup_model.sh
```

### 2. Rebuild the containers with fixes

```bash
docker compose down
docker compose build --no-cache
```

### 3. Start the containers

```bash
docker compose up -d

# Wait 30-60 seconds for initialization
```

### 4. Run the health check

```bash
# In Git Bash/WSL:
bash test_system.sh

# Or manually check:
docker ps
docker logs ml_ids --tail 20
docker logs suricata_ids --tail 20
```

### 5. Verify all services are running

Expected output from test_system.sh:
- ✓ All containers running
- ✓ Supervisor running in both containers
- ✓ Apache2, MySQL, Suricata/ML-IDS processes running
- ✓ Databases accessible
- ✓ Web applications accessible (HTTP 200/302)
- ✓ Model file exists
- ✓ Network connectivity between containers

### 6. Access the applications

- **Suricata DVWA**: http://localhost:8081/dvwa
- **ML-IDS DVWA**: http://localhost:8082/dvwa  
- **Dashboard**: http://localhost:8080

Login: `admin` / `password`

### 7. Run the attack suite

```bash
# Get ML-IDS container IP
ML_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ml_ids)

# Run attacks from within ml_ids container
docker exec -it ml_ids python3 /opt/attacks/attack_suite.py $ML_IP

# Or copy attack suite into container first
docker cp ./attacks ml_ids:/opt/
docker exec -it ml_ids python3 /opt/attacks/attack_suite.py 172.21.0.3
```

### 8. Monitor the dashboard

Open http://localhost:8080 in your browser to see:
- XGBoost ML-IDS detections vs Suricata IDS detections
- Real-time alerts
- Detection statistics
- Performance comparison

## Troubleshooting

### If services still not running after rebuild:

```bash
# Check supervisor status
docker exec ml_ids supervisorctl status
docker exec suricata_ids supervisorctl status

# Check logs
docker exec ml_ids tail -f /var/log/supervisor/supervisord.log
docker exec ml_ids tail -f /var/log/ml-ids-stdout.log
docker exec suricata_ids tail -f /var/log/suricata-stdout.log

# Restart specific service
docker exec ml_ids supervisorctl restart apache2
docker exec ml_ids supervisorctl restart ml-ids
```

### If Apache not starting:

```bash
# Check Apache config
docker exec ml_ids apache2ctl configtest

# Check Apache logs
docker exec ml_ids tail /var/log/apache2/error.log
```

### If MySQL connection fails:

```bash
# Test MySQL
docker exec ml_ids mysql -u dvwa -ppassword -e "SELECT 1;" dvwa

# Check MySQL logs  
docker exec ml_ids tail /var/log/mysql-stderr.log
```

### If model not loading:

```bash
# Verify model file exists
docker exec ml_ids ls -lh /app/models/

# Check ML-IDS logs
docker exec ml_ids tail -f /var/log/ml-ids-stdout.log
```

## Key Changes Made

### Startup Script Improvements:
1. Use `mysqld --skip-networking` instead of `mysqld_safe` for initial setup
2. Connect via socket (`--socket=/var/run/mysqld/mysqld.sock`) instead of network
3. Properly shutdown MySQL with `mysqladmin shutdown` before supervisor
4. Use `exec supervisord -n` to run supervisor in foreground as PID 1
5. Added better logging and error messages

### Supervisor Configuration:
- Already correct with `nodaemon=true`
- Services set to autostart
- Proper log file locations

## Expected Test Results

After fixes, `bash test_system.sh` should show:
- **Tests Passed**: 15-17
- **Tests Failed**: 0-2 (model file and maybe ping due to network policies)

All critical services should be operational.

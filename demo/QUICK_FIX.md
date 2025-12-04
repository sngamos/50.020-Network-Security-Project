# Quick Diagnostic and Fix Guide

## Run These Commands Now

### 1. Check what's actually happening in ML-IDS:

```powershell
# See the last 30 lines of logs
docker logs ml_ids --tail 30

# Check if processes are running
docker exec ml_ids ps aux

# Look for hanging processes
docker exec ml_ids ps aux | findstr /i "start mysql bash"
```

### 2. Check Suricata similarly:

```powershell
docker logs suricata_ids --tail 30
docker exec suricata_ids ps aux
```

## Common Issues and Quick Fixes

### Issue 1: Startup script still running (hung on MySQL)
**Symptom**: MySQL process exists but nothing else

**Fix**:
```powershell
# Restart the container
docker restart ml_ids
docker restart suricata_ids

# Wait 30 seconds
timeout /t 30

# Test again
bash test_system.sh
```

### Issue 2: Supervisor not starting
**Symptom**: "unix:///var/run/supervisor.sock no such file"

**Quick Fix - Manually start supervisor**:
```powershell
# Enter the container
docker exec -it ml_ids /bin/bash

# Inside container, check if supervisor config exists
ls -la /etc/supervisor/conf.d/supervisord.conf

# Manually start supervisor
/usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf
```

### Issue 3: Model file missing
**Fix**:
```powershell
# Run the setup script
.\setup_model.ps1

# Verify it copied
dir .\shared\models\
```

## Full Rebuild (If Above Doesn't Work)

The Dockerfiles have been updated with better error handling. Rebuild:

```powershell
# 1. Stop everything
docker compose down

# 2. Copy model file
.\setup_model.ps1

# 3. Rebuild with no cache
docker compose build --no-cache

# 4. Start services
docker compose up -d

# 5. Wait for initialization (60 seconds)
Write-Host "Waiting 60 seconds for containers to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 60

# 6. Check logs
docker logs ml_ids
docker logs suricata_ids

# 7. Run health check
bash test_system.sh
```

## What Was Fixed in Dockerfiles

1. **Better MySQL shutdown**: 
   - Wait loop to confirm MySQL stopped
   - Force kill if needed
   - Clean up socket files

2. **Supervisor config validation**:
   - Check if config file exists before starting
   - Better error messages

3. **Process cleanup**:
   - Properly terminate MySQL before supervisor starts
   - Remove stale socket files

## Debug Commands Cheat Sheet

```powershell
# View logs live
docker logs ml_ids -f

# Check specific service logs
docker exec ml_ids cat /var/log/supervisor/supervisord.log
docker exec ml_ids cat /var/log/ml-ids-stdout.log
docker exec ml_ids cat /var/log/apache2/error.log

# Check supervisor status (if running)
docker exec ml_ids supervisorctl status

# Manually restart a service
docker exec ml_ids supervisorctl restart apache2
docker exec ml_ids supervisorctl restart ml-ids

# Check MySQL
docker exec ml_ids mysql -u dvwa -ppassword -e "SELECT 1;" dvwa

# Interactive shell
docker exec -it ml_ids /bin/bash
```

## Expected Behavior After Fix

When you run `docker logs ml_ids`, you should see:
```
========================================
Starting ML-IDS Container
========================================
WARNING: Model file not found... (or "Model file found...")
Initializing MySQL data directory...
Starting MySQL for initial setup...
Waiting for MySQL...
MySQL is ready
Setting up DVWA database...
Database setup complete
Stopping temporary MySQL...
MySQL stopped successfully
Starting all services via supervisor...
========================================
```

Then supervisor should start Apache, MySQL, and ML-IDS.

## If Still Failing

Run the diagnostic script:
```bash
bash diagnose_mlids.sh
```

This will tell you exactly where it's stuck.

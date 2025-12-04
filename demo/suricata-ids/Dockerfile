FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies and add Suricata PPA for version 8.0
RUN apt-get update && apt-get install -y \
    software-properties-common \
    && add-apt-repository ppa:oisf/suricata-stable \
    && apt-get update && apt-get install -y \
    suricata \
    apache2 \
    php \
    php-mysqli \
    php-gd \
    libapache2-mod-php \
    mariadb-server \
    git \
    curl \
    net-tools \
    iputils-ping \
    tcpdump \
    vim \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Verify Suricata version (should be 8.0+)
RUN suricata -V

# Clone DVWA
WORKDIR /var/www/html
RUN git clone https://github.com/digininja/DVWA.git dvwa

# Configure DVWA
WORKDIR /var/www/html/dvwa
RUN cp config/config.inc.php.dist config/config.inc.php && \
    sed -i "s/p@ssw0rd/password/g" config/config.inc.php && \
    sed -i "s/'impossible'/'low'/g" config/config.inc.php && \
    chmod -R 777 /var/www/html/dvwa/hackable/uploads/

# Create PHPIDS directory if it doesn't exist and set permissions
RUN mkdir -p /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp && \
    touch /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt && \
    chmod -R 777 /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp/ || true

# Configure Apache
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf && \
    sed -i 's/AllowOverride None/AllowOverride All/g' /etc/apache2/apache2.conf

# Create required directories for logs and services
RUN mkdir -p /var/log/suricata /etc/suricata/rules /var/log/supervisor /var/run/mysqld /var/log/apache2 && \
    chown mysql:mysql /var/run/mysqld && \
    chown www-data:www-data /var/log/apache2

# Fix git ownership issues for DVWA
RUN git config --global --add safe.directory /var/www/html/dvwa && \
    chown -R www-data:www-data /var/www/html/dvwa

# Copy your custom rules file
COPY suricata-config/custom.rules /etc/suricata/rules/custom.rules

# Copy your Suricata 8.0 configuration
COPY suricata-config/suricata.yaml /etc/suricata/suricata.yaml

# Set proper permissions
RUN chmod 644 /etc/suricata/rules/custom.rules && \
    chmod 644 /etc/suricata/suricata.yaml

# Verify Suricata configuration
RUN suricata -T -c /etc/suricata/suricata.yaml || \
    (echo "Suricata configuration test failed!" && cat /var/log/suricata/suricata.log && exit 1)

# Create supervisor config
RUN echo '[supervisord]\n\
nodaemon=true\n\
logfile=/var/log/supervisor/supervisord.log\n\
pidfile=/var/run/supervisord.pid\n\
\n\
[program:mysql]\n\
command=/usr/bin/mysqld_safe\n\
autostart=true\n\
autorestart=true\n\
stdout_logfile=/var/log/mysql-stdout.log\n\
stderr_logfile=/var/log/mysql-stderr.log\n\
\n\
[program:apache2]\n\
command=/bin/bash -c "source /etc/apache2/envvars && exec /usr/sbin/apache2 -DFOREGROUND"\n\
autostart=true\n\
autorestart=true\n\
stdout_logfile=/var/log/apache2-stdout.log\n\
stderr_logfile=/var/log/apache2-stderr.log\n\
\n\
[program:suricata]\n\
command=/usr/bin/suricata -c /etc/suricata/suricata.yaml -i eth0 -v\n\
autostart=true\n\
autorestart=true\n\
stdout_logfile=/var/log/suricata-stdout.log\n\
stderr_logfile=/var/log/suricata-stderr.log\n\
' > /etc/supervisor/conf.d/supervisord.conf

# Create startup script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
echo "========================================"\n\
echo "Starting Suricata IDS Container"\n\
echo "Suricata version: $(suricata -V 2>&1 | head -1)"\n\
echo "========================================"\n\
\n\
# Initialize MySQL data directory if needed\n\
if [ ! -d "/var/lib/mysql/mysql" ]; then\n\
    echo "Initializing MySQL data directory..."\n\
    mysql_install_db --user=mysql --datadir=/var/lib/mysql\n\
fi\n\
\n\
# Start MySQL temporarily to create database\n\
echo "Starting MySQL for initial setup..."\n\
mysqld --user=mysql --skip-networking &\n\
MYSQL_PID=$!\n\
\n\
# Wait for MySQL to be ready\n\
echo "Waiting for MySQL..."\n\
for i in {1..30}; do\n\
    if mysqladmin ping --socket=/var/run/mysqld/mysqld.sock 2>/dev/null; then\n\
        echo "MySQL is ready"\n\
        break\n\
    fi\n\
    sleep 1\n\
done\n\
\n\
# Setup DVWA database\n\
echo "Setting up DVWA database..."\n\
mysql --socket=/var/run/mysqld/mysqld.sock -u root <<EOF\n\
CREATE DATABASE IF NOT EXISTS dvwa;\n\
CREATE USER IF NOT EXISTS '"'"'dvwa'"'"'@'"'"'localhost'"'"' IDENTIFIED BY '"'"'password'"'"';\n\
GRANT ALL PRIVILEGES ON dvwa.* TO '"'"'dvwa'"'"'@'"'"'localhost'"'"';\n\
FLUSH PRIVILEGES;\n\
EOF\n\
\n\
echo "Database setup complete"\n\
\n\
# Shutdown temporary MySQL\n\
echo "Stopping temporary MySQL..."\n\
mysqladmin --socket=/var/run/mysqld/mysqld.sock shutdown 2>/dev/null || kill -TERM $MYSQL_PID\n\
sleep 2\n\
\n\
# Wait for MySQL to fully stop\n\
for i in {1..10}; do\n\
    if ! ps -p $MYSQL_PID > /dev/null 2>&1; then\n\
        echo "MySQL stopped successfully"\n\
        break\n\
    fi\n\
    sleep 1\n\
done\n\
\n\
# Force kill if still running\n\
kill -9 $MYSQL_PID 2>/dev/null || true\n\
sleep 1\n\
\n\
# Clean up MySQL socket\n\
rm -f /var/run/mysqld/mysqld.sock /var/run/mysqld/mysqld.pid\n\
\n\
# Test Suricata configuration\n\
echo "Testing Suricata configuration..."\n\
suricata -T -c /etc/suricata/suricata.yaml\n\
if [ $? -ne 0 ]; then\n\
    echo "ERROR: Suricata configuration test failed!"\n\
    exit 1\n\
fi\n\
echo "Suricata configuration OK"\n\
\n\
# Create required directories for supervisor and Apache\n\
mkdir -p /var/log/supervisor /var/run /var/run/apache2 /var/lock/apache2\n\
\n\
# Verify supervisor config exists\n\
if [ ! -f /etc/supervisor/conf.d/supervisord.conf ]; then\n\
    echo \"ERROR: Supervisor config not found!\"\n\
    ls -la /etc/supervisor/conf.d/\n\
    exit 1\n\
fi\n\
\n\
echo \"Supervisor config found, directories created\"\n\
\n\
# Start all services with supervisor\n\
echo \"Starting all services via supervisor...\"\n\
echo \"========================================\"\n\
exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/supervisord.conf\n\
' > /start.sh && chmod +x /start.sh

EXPOSE 80

CMD ["/start.sh"]
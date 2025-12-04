FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    software-properties-common \
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

# Create Suricata directories
RUN mkdir -p /var/log/suricata /etc/suricata/rules

# Copy custom rules file
COPY suricata-config/custom.rules /etc/suricata/rules/custom.rules

# Copy Suricata configuration
COPY suricata-config/suricata.yaml /etc/suricata/suricata.yaml

# Set proper permissions
RUN chmod 644 /etc/suricata/rules/custom.rules && \
    chmod 644 /etc/suricata/suricata.yaml

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
# Start MySQL and wait for it to be ready\n\
service mysql start\n\
sleep 10\n\
\n\
# Setup DVWA database\n\
mysql -u root << EOF\n\
CREATE DATABASE IF NOT EXISTS dvwa;\n\
CREATE USER IF NOT EXISTS "dvwa"@"localhost" IDENTIFIED BY "password";\n\
GRANT ALL PRIVILEGES ON dvwa.* TO "dvwa"@"localhost";\n\
FLUSH PRIVILEGES;\n\
EOF\n\
\n\
# Stop MySQL (supervisor will restart it)\n\
service mysql stop\n\
sleep 2\n\
\n\
# Test Suricata configuration\n\
echo "Testing Suricata configuration..."\n\
suricata -T -c /etc/suricata/suricata.yaml\n\
if [ $? -ne 0 ]; then\n\
    echo "ERROR: Suricata configuration test failed!"\n\
    cat /var/log/suricata/suricata.log\n\
    exit 1\n\
fi\n\
echo "Suricata configuration OK"\n\
\n\
# Start supervisor\n\
/usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf\n\
' > /start.sh && chmod +x /start.sh

EXPOSE 80

CMD ["/start.sh"]

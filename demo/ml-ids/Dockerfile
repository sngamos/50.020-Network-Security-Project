FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
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

# Install Python packages
RUN pip3 install --no-cache-dir scapy pandas numpy scikit-learn

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

# Copy ML-IDS scripts
COPY ml_ids.py /opt/ml_ids.py

# Create app directory for model (will be mounted via volume)
RUN mkdir -p /app/models

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
[program:ml-ids]\n\
command=python3 /opt/ml_ids.py /app/models/model.pkl eth0\n\
autostart=true\n\
autorestart=true\n\
stdout_logfile=/var/log/ml-ids-stdout.log\n\
stderr_logfile=/var/log/ml-ids-stderr.log\n\
' > /etc/supervisor/conf.d/supervisord.conf

# Create startup script
RUN echo '#!/bin/bash\n\
# Check if model file exists\n\
if [ ! -f /app/models/model.pkl ]; then\n\
    echo "WARNING: Model file not found at /app/models/model.pkl"\n\
    echo "ML-IDS will run in pattern-detection-only mode"\n\
else\n\
    echo "Model file found at /app/models/model.pkl"\n\
fi\n\
\n\
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
# Start supervisor\n\
/usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf\n\
' > /start.sh && chmod +x /start.sh

EXPOSE 80

CMD ["/start.sh"]

# snort-ids/Dockerfile
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install minimal dependencies
RUN apt-get update && apt-get install -y \
    snort \
    net-tools \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /etc/snort/rules /var/log/snort /etc/snort/preproc_rules

# Copy configuration files
COPY snort.conf /etc/snort/
COPY rules/* /etc/snort/rules/

# Set permissions
RUN chmod -R 755 /etc/snort /var/log/snort

# Default command
CMD ["snort", "-i", "eth0", "-c", "/etc/snort/snort.conf", "-A", "fast", "-l", "/var/log/snort", "-K", "ascii"]
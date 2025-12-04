FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY dashboard.py .
COPY config/ ./config/

# Create directory for logs
RUN mkdir -p /shared/logs

# Expose port
EXPOSE 8080

# Run the dashboard
CMD ["python", "dashboard.py"]

# Use small official Python image
FROM python:3.11-slim

# Create app dir
WORKDIR /app

# Copy script and sites file
COPY Scripts/check_ssl.py /app/check_ssl.py
COPY Scripts/sites.txt /app/sites.txt

# Install required dependency (cryptography)
RUN pip install --no-cache-dir cryptography

# Make script executable
RUN chmod +x /app/check_ssl.py

# Default envs (can be overridden at runtime)
ENV SITES_FILE=/app/sites.txt \
    WARN_DAYS=30 \
    CRIT_DAYS=7 \
    PARALLEL_WORKERS=16 \
    CONNECT_TIMEOUT=6.0

ENTRYPOINT ["bash", "-c", "python3 /app/check_ssl.py || true"]
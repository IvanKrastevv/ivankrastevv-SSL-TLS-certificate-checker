# Use small official Python image
FROM python:3.11-slim

# Create app dir
WORKDIR /app

# Copy script and example sites
COPY check_ssl.py /app/check_ssl.py
COPY sites.txt /app/sites.txt

# Make script executable
RUN chmod +x /app/check_ssl.py

# Default envs (can be overridden at runtime)
ENV SITES_FILE=/app/sites.txt \
    WARN_DAYS=30 \
    CRIT_DAYS=7 \
    PARALLEL_WORKERS=16 \
    CONNECT_TIMEOUT=6.0

# No extra dependencies required - using stdlib only
ENTRYPOINT ["python3", "/app/check_ssl.py"]

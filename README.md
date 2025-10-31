This project provides a Python-based script to automatically check and display SSL/TLS certificate expiration dates for a list of websites.

It can run:
Locally, as a standalone script or Docker container.
In Kubernetes (e.g., Minikube) as a CronJob that runs periodically or a standard k8s deployment.


Features:
Reads a list of target websites from a config file (sites.txt).
Retrieves SSL/TLS certificates and extracts expiration dates.
Displays expiry info and remaining days in a clear, human-readable format.
Supports thresholds for warnings and critical alerts.
Optional Slack/Teams webhook integration for notifications.
Handles network/certificate errors gracefully.
Lightweight and threaded for efficiency.
Deployable as a Docker container and Kubernetes CronJob/Deployment.


Prerequisites:
You’ll need one or more of the following:
Python 3.9+ (for local script run)
Docker (for containerized run)
kubectl and Minikube (for Kubernetes deployment)


How It Works
The script reads domain names from sites.txt.
For each site:
It connects via TLS (port 443 by default).
Retrieves the SSL certificate.
Parses the notAfter field to determine expiration date.
Displays each site’s expiration info, days left, and status:
✅ OK — more than WARN_DAYS left
⚠️ WARNING — less than WARN_DAYS
🔴 CRITICAL / EXPIRED — less than CRIT_DAYS or expired
Optionally sends a summary message to Slack/Teams via SLACK_WEBHOOK/TEAMS_WEBHOOK.


Running Locally (Without Docker)
Install Python 3.9+
Create or edit your sites.txt
Run the script:
python3 check_ssl.py
(Optional) Adjust thresholds:
WARN_DAYS=14 CRIT_DAYS=3 python3 check_ssl.py


Running in Docker
Build the image
docker build -t ssl-checker:latest .
Run the container
docker run --rm ssl-checker:latest
Or override thresholds and site file:
docker run --rm \
  -v $(pwd)/sites.txt:/config/sites.txt \
  -e SITES_FILE=/config/sites.txt \
  -e WARN_DAYS=15 \
  -e CRIT_DAYS=5 \
  ssl-checker:latest


Running in Kubernetes / Minikube
1. Start Minikube
minikube start

2. Build image inside Minikube
eval $(minikube -p minikube docker-env)
docker build -t ssl-checker:latest .

(Or load it manually:)
minikube image load ssl-checker:latest

3. Create ConfigMap for your sites list
kubectl create configmap ssl-check-sites \
  --from-file=sites.txt=./sites.txt \
  --dry-run=client -o yaml | kubectl apply -f -

4. Deploy CronJob
kubectl apply -f k8s/cronjob-ssl-check.yaml

This runs the job daily at 06:00 by default.

5. View results
kubectl get cronjob
kubectl get jobs --watch
kubectl logs job/<job-name>

To trigger it immediately:

kubectl create job --from=cronjob/ssl-expiry-check ssl-expiry-manual-<name>
kubectl logs -f job/ssl-expiry-manual-<name>


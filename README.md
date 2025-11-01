This project provides a Python-based script to automatically check and display SSL/TLS certificate expiration dates for a list of websites.

Repo provides possibilities for this to be ran bith:
Locally, as a standalone script or Docker container.
In Kubernetes (e.g., Minikube) as a CronJob that runs periodically or a standard k8s deployment.


Features:
- Reads a list of target websites from a config file locally - (sites.txt) or in Minikube (configmap).
- Retrieves SSL/TLS certificates and extracts expiration dates.
- Displays expiry info and remaining days in a clear, human-readable format.
- Supports thresholds for warnings and critical alerts.
- Optional Slack/Teams webhook integration for notifications.
- Handles network/certificate errors gracefully.
- Lightweight and threaded for efficiency.
- Deployable as a Docker container and Kubernetes CronJob/Deployment.


Prerequisites:
You’ll need one or more of the following:
- Python 3.9+ (for local script run)
- Docker (for containerized run)
- kubectl and Minikube (for Kubernetes deployment)


How It Works
The script reads domain names from sites.txt - (locally) or for K8s it uses the configmap setup.
For each site:
- It connects via TLS based on provided port (port 443 by default).
- Retrieves the SSL certificate.
- Parses the notAfter field to determine expiration date - if cert structure contains 'notAfter' or using the cryptography package we decode the raw DER-encoded certificate and extract the not_valid_after field.
Displays each site’s expiration info, days left, and status:
- ✅ OK — more than WARN_DAYS left
- ⚠️ WARNING — less than WARN_DAYS
- 🔴 CRITICAL / EXPIRED — less than CRIT_DAYS or expired
Optionally sends a summary message to Slack via SLACK_WEBHOOK.
- if K8s is being used all these can be overwritten in the configmap - easy way for testing - real production ready approach should have a bit more flexibility.


Instructions on how to run this:

Local run - no Docker 

- Install Python 3.9+
- Create or edit your sites.txt
Run the script:
- python3 check_ssl.py
(Optional) Adjust thresholds:
SITES_FILE=Scripts/sites.txt WARN_DAYS=14 CRIT_DAYS=3 python check_ssl.py



Running in Docker

Build the image
From the root project foler:
- docker build -f Infrastructure/checker.Dockerfile -t ssl-checker:latest .
If your file is already named just Dockerfile, then the simple version is fine:
- docker build -t ssl-checker:latest .

Run the container
- docker run --rm ssl-checker:latest

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

or use the already existing one in the repo and just do changes when needed.
- kubectl apply -f Infrastructure/k8s/configmap-sites.yaml
4. Deploy CronJob
kubectl apply -f k8s/cronjob-ssl-check.yaml

This runs the job daily at 06:00 by default.

5. View results
- kubectl get cronjob
- kubectl get jobs --watch
- kubectl logs job/<job-name>
- kubectl logs <job-pod-name>
For debug if needed
- kubectl exec -it ssl-expiry-run-26nwt -- cat /app/sites.txt
- kubectl get events (-n namespace) - provide namespace if not working in the 'default' namespace

To trigger it immediately:

- kubectl create job --from=cronjob/ssl-expiry-check ssl-expiry-manual-<name>
- kubectl logs -f job/ssl-expiry-manual-<name>


Important - if you do any changes to the Dockerfile, configmap, cronjob file, deployment file and you are running on a local minikube. 

If Dockerfile is changed - it needs to be rebuild, load it manually if needed and make sure the cronjob cronjob and job use the new file.
- docker build -t ssl-checker:latest -f Infrastructure/checker.Dockerfile . - then test the job again - you can run <docker images> to check the new image is created based on the age
If configmap is edited when doing this in minukube you need to apply the file.
- kubectl apply -f Infrastructure/k8s/configmap-sites.yaml - then the cronjob will use the new configmap.
If you change the deploy or the cronjob file the same should be done.
- kubectl apply -f Infrastructure/k8s/cronjob-ssl-check.yaml

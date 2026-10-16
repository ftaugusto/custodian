# c7n_ibmcloud — IBM Cloud Deployment Guide

This guide covers every operational pattern for running Cloud Custodian on IBM Cloud:
packaging and deploying to Code Engine, scheduled sweeps, near-real-time enforcement
via Activity Tracker → Event Notifications → Code Engine, webhook integration with
Security and Compliance Center Workload Protection (SCC WP), and event streaming via
IBM Event Streams (Kafka).

---

## Table of contents

1. [Prerequisites](#1-prerequisites)
2. [Container image](#2-container-image)
3. [Secrets and configuration](#3-secrets-and-configuration)
4. [Scheduled sweep — Code Engine job](#4-scheduled-sweep--code-engine-job)
5. [Near-real-time enforcement — event-triggered pipeline](#5-near-real-time-enforcement--event-triggered-pipeline)
   - 5.1 [Architecture overview](#51-architecture-overview)
   - 5.2 [Activity Tracker routing rule](#52-activity-tracker-routing-rule)
   - 5.3 [Event Notifications subscription](#53-event-notifications-subscription)
   - 5.4 [Code Engine application — webhook receiver](#54-code-engine-application--webhook-receiver)
   - 5.5 [Mapping activity events to policy files](#55-mapping-activity-events-to-policy-files)
6. [Event Streams (Kafka) integration](#6-event-streams-kafka-integration)
7. [SCC Workload Protection webhook](#7-scc-workload-protection-webhook)
8. [IAM service-to-service authorisations](#8-iam-service-to-service-authorisations)
9. [Outputs and findings](#9-outputs-and-findings)
10. [Operational runbook](#10-operational-runbook)

---

## 1. Prerequisites

| Tool | Min version | Install |
|---|---|---|
| IBM Cloud CLI | latest | `curl -fsSL https://clis.cloud.ibm.com/install/linux \| sh` |
| `container-registry` plugin | latest | `ibmcloud plugin install container-registry` |
| `code-engine` plugin | latest | `ibmcloud plugin install code-engine` |
| Docker / Podman | any | system package |
| Python | 3.11+ | system package |

**IBM Cloud services required** (all must exist in the same account):

- IBM Cloud Container Registry (ICR) — stores the custodian image
- IBM Code Engine — runs the job and the webhook application
- IBM Secrets Manager — stores the API key and other secrets
- IBM Activity Tracker (Event Routing) — routes audit events
- IBM Event Notifications — fan-out to Code Engine webhook
- IBM Event Streams *(optional)* — Kafka bus for audit event fan-out
- IBM Security and Compliance Center Workload Protection *(optional)*

---

## 2. Container image

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install c7n and the IBM Cloud provider
COPY tools/c7n_ibmcloud /app/c7n_ibmcloud
RUN pip install --no-cache-dir c7n && \
    pip install --no-cache-dir -e /app/c7n_ibmcloud

# Copy policy files
COPY tools/c7n_ibmcloud/policies /app/policies

# Entrypoint: pass CMD as custodian arguments
ENTRYPOINT ["custodian"]
CMD ["run", "--help"]
```

### Build and push to IBM Container Registry

```bash
# Authenticate
ibmcloud login --apikey "$IBMCLOUD_API_KEY" -r us-south
ibmcloud cr login
ibmcloud cr region-set us-south

# Create a namespace if needed
ibmcloud cr namespace-add custodian

# Build and push
docker build -t us.icr.io/custodian/c7n-ibmcloud:latest .
docker push us.icr.io/custodian/c7n-ibmcloud:latest
```

---

## 3. Secrets and configuration

Store sensitive values in **IBM Secrets Manager** rather than Code Engine environment
variables so rotation does not require redeployment.

### Create secrets

```bash
# Using the IBM Cloud CLI sm plugin
ibmcloud sm arbitrary-secret-create \
  --name custodian-api-key \
  --secret-data "$IBMCLOUD_API_KEY" \
  --instance-id "$SM_INSTANCE_ID"

ibmcloud sm arbitrary-secret-create \
  --name custodian-account-id \
  --secret-data "$IBMCLOUD_ACCOUNT_ID" \
  --instance-id "$SM_INSTANCE_ID"
```

### Code Engine secret reference

When creating the Code Engine job or application (sections 4 and 5.4), reference
secrets by their Secrets Manager CRN. Code Engine will inject them as environment
variables at runtime:

| Env var | Secrets Manager secret | Required |
|---|---|---|
| `IBMCLOUD_API_KEY` | `custodian-api-key` | Always |
| `IBMCLOUD_ACCOUNT_ID` | `custodian-account-id` | Always |
| `IBMCLOUD_REGION` | literal value in job spec | Always |
| `IBMCLOUD_COS_RESOURCE_INSTANCE_ID` | `custodian-cos-instance-id` | COS policies only |
| `IBMCLOUD_POWERVS_WORKSPACE_ID` | `custodian-powervs-ws-id` | PowerVS policies only |

---

## 4. Scheduled sweep — Code Engine job

A scheduled job runs all policies on a fixed cadence. It acts as a safety net that
catches anything the event-triggered pipeline may have missed.

### Create the job

```bash
# Target your Code Engine project
ibmcloud ce project select --name custodian-prod

# Create the job definition
ibmcloud ce job create \
  --name custodian-sweep \
  --image us.icr.io/custodian/c7n-ibmcloud:latest \
  --argument run \
  --argument "--configs=/app/policies/" \
  --argument "--output-dir=/tmp/c7n-out" \
  --argument "--cache-period=300" \
  --env-from-secret custodian-secrets \
  --env IBMCLOUD_REGION=us-south \
  --cpu 1 \
  --memory 2G \
  --maxexecutiontime 1800
```

### Schedule it (every 15 minutes)

```bash
ibmcloud ce jobrun schedule create \
  --name custodian-sweep-schedule \
  --job custodian-sweep \
  --schedule "*/15 * * * *"
```

### Scoped sweeps (per service, faster)

For large accounts, run separate scheduled jobs per policy file so each completes
faster and failures are isolated:

```bash
for POLICY_FILE in vpc-networking vpc-compute vpc-storage cos iam kms kubernetes powervs dbaas cross-cutting; do
  ibmcloud ce job create \
    --name "custodian-sweep-${POLICY_FILE}" \
    --image us.icr.io/custodian/c7n-ibmcloud:latest \
    --argument run \
    --argument "--configs=/app/policies/${POLICY_FILE}.yaml" \
    --argument "--output-dir=/tmp/c7n-out" \
    --argument "--cache-period=300" \
    --env-from-secret custodian-secrets \
    --env IBMCLOUD_REGION=us-south

  ibmcloud ce jobrun schedule create \
    --name "custodian-sweep-${POLICY_FILE}-schedule" \
    --job "custodian-sweep-${POLICY_FILE}" \
    --schedule "*/15 * * * *"
done
```

---

## 5. Near-real-time enforcement — event-triggered pipeline

End-to-end latency: **~60–90 seconds** from the API call that creates or modifies
a resource to the policy check completing.

### 5.1 Architecture overview

```
IBM Cloud API call
       │
       ▼
Activity Tracker (Event Routing)
  routing rule: action starts with "cloud-object-storage" / "is." / "power-iaas" …
       │
       ▼
Event Notifications
  topic → subscription → webhook
       │
       ▼
Code Engine application  (custodian-webhook)
  • parses the AT event payload
  • maps action → policy file
  • runs: custodian run --configs /app/policies/<file>.yaml --cache-period 0
       │
       ▼
IBM Cloud APIs  (query + remediate)
       │
       ▼
Outputs: /tmp/c7n-out/  +  SCC WP findings  +  Event Streams topic
```

### 5.2 Activity Tracker routing rule

Route all control-plane events to an Event Notifications target.

```bash
# Create an Event Notifications target in Activity Tracker Event Routing
ibmcloud atracker target create \
  --name custodian-en-target \
  --type event-notifications \
  --event-notifications-crn "$EN_INSTANCE_CRN" \
  --target-crn "$EN_INSTANCE_CRN"

# Create a routing rule — send all account events (or narrow by action prefix)
ibmcloud atracker route create \
  --name custodian-route \
  --rules '[{
    "target_ids": ["<target-id-from-above>"],
    "locations": ["*"]
  }]'
```

To narrow the rule to only the services custodian governs, replace `"locations": ["*"]`
with an action-prefix filter. IBM Activity Tracker event routing supports
`action` as a filter key:

```json
{
  "target_ids": ["<target-id>"],
  "locations": ["*"],
  "actions": [
    "cloud-object-storage.",
    "is.instance.",
    "is.volume.",
    "is.security-group.",
    "is.network-acl.",
    "is.floating-ip.",
    "is.subnet.",
    "is.vpc.",
    "is.load-balancer.",
    "is.vpn-gateway.",
    "power-iaas.",
    "kms.",
    "containers-kubernetes.",
    "databases-for-",
    "iam-identity.",
    "iam-groups.",
    "iam-am."
  ]
}
```

### 5.3 Event Notifications subscription

```bash
# Create a topic in your Event Notifications instance
ibmcloud en topic-create \
  --instance-id "$EN_INSTANCE_ID" \
  --name custodian-at-events \
  --source "$AT_SOURCE_ID"

# Create a webhook destination pointing at the Code Engine application URL
# (deploy the application first per section 5.4, then come back and set the URL)
ibmcloud en subscription-create \
  --instance-id "$EN_INSTANCE_ID" \
  --name custodian-webhook-sub \
  --destination-id "$WEBHOOK_DEST_ID" \
  --topic-id "$TOPIC_ID"
```

### 5.4 Code Engine application — webhook receiver

The webhook application is a small HTTP server that receives Event Notifications
payloads, maps the `action` field to the right policy file, and runs custodian.

#### `webhook/app.py`

```python
#!/usr/bin/env python3
"""
Minimal webhook receiver for IBM Event Notifications → custodian.

Runs as a Code Engine application (HTTP on port 8080).
Receives Activity Tracker event payloads from Event Notifications,
maps the action field to a policy file, and runs custodian inline.
"""

import json
import logging
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("custodian-webhook")

# Map AT action prefixes to policy files
ACTION_TO_POLICY = {
    "cloud-object-storage":    "cos.yaml",
    "is.instance":             "vpc-compute.yaml",
    "is.bare-metal-server":    "vpc-compute.yaml",
    "is.dedicated-host":       "vpc-compute.yaml",
    "is.volume":               "vpc-storage.yaml",
    "is.snapshot":             "vpc-storage.yaml",
    "is.backup-policy":        "vpc-storage.yaml",
    "is.share":                "vpc-storage.yaml",
    "is.security-group":       "vpc-networking.yaml",
    "is.network-acl":          "vpc-networking.yaml",
    "is.floating-ip":          "vpc-networking.yaml",
    "is.subnet":               "vpc-networking.yaml",
    "is.vpc":                  "vpc-networking.yaml",
    "is.load-balancer":        "vpc-networking.yaml",
    "is.vpn-gateway":          "vpc-networking.yaml",
    "is.public-gateway":       "vpc-networking.yaml",
    "is.transit-gateway":      "vpc-networking.yaml",
    "power-iaas":              "powervs.yaml",
    "kms":                     "kms.yaml",
    "containers-kubernetes":   "kubernetes.yaml",
    "databases-for-":          "dbaas.yaml",
    "iam-identity":            "iam.yaml",
    "iam-groups":              "iam.yaml",
    "iam-am":                  "iam.yaml",
}

POLICY_DIR = os.environ.get("POLICY_DIR", "/app/policies")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/tmp/c7n-out")


def _policy_file_for_action(action: str) -> str | None:
    for prefix, fname in ACTION_TO_POLICY.items():
        if action.startswith(prefix):
            return fname
    return None


def _run_custodian(policy_file: str, action: str) -> None:
    policy_path = os.path.join(POLICY_DIR, policy_file)
    cmd = [
        "custodian", "run",
        f"--configs={policy_path}",
        f"--output-dir={OUTPUT_DIR}",
        "--cache-period=0",
    ]
    log.info("Running custodian for action=%r policy=%r: %s", action, policy_file, " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            log.error("custodian exited %d: %s", result.returncode, result.stderr[-2000:])
        else:
            log.info("custodian completed OK: %s", result.stdout[-1000:])
    except subprocess.TimeoutExpired:
        log.error("custodian timed out for policy %s", policy_file)
    except Exception as exc:
        log.exception("custodian run failed: %s", exc)


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.send_response(200)
        self.end_headers()

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            log.warning("Non-JSON payload received, ignoring")
            return

        # Event Notifications wraps the AT event under "data"
        at_event = payload.get("data", payload)
        action = at_event.get("action", "")
        if not action:
            log.debug("No action field in payload, ignoring")
            return

        policy_file = _policy_file_for_action(action)
        if not policy_file:
            log.debug("No policy mapping for action=%r, ignoring", action)
            return

        # Run custodian in a background thread so the HTTP response is immediate
        threading.Thread(
            target=_run_custodian,
            args=(policy_file, action),
            daemon=True,
        ).start()

    def log_message(self, fmt, *args):  # suppress default access log noise
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    log.info("Starting custodian webhook receiver on port %d", port)
    HTTPServer(("", port), WebhookHandler).serve_forever()
```

#### Deploy the webhook application

```bash
ibmcloud ce application create \
  --name custodian-webhook \
  --image us.icr.io/custodian/c7n-ibmcloud:latest \
  --command python3 \
  --argument /app/webhook/app.py \
  --env-from-secret custodian-secrets \
  --env IBMCLOUD_REGION=us-south \
  --env POLICY_DIR=/app/policies \
  --env OUTPUT_DIR=/tmp/c7n-out \
  --min-scale 1 \
  --max-scale 5 \
  --cpu 1 \
  --memory 2G \
  --port 8080

# Get the public URL
ibmcloud ce application get --name custodian-webhook --output json \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['status']['url'])"
```

Use that URL when creating the Event Notifications webhook destination.

### 5.5 Mapping activity events to policy files

| AT action prefix | Custodian resource types | Policy file |
|---|---|---|
| `cloud-object-storage.*` | `ibm.cos-bucket` | `cos.yaml` |
| `is.instance.*` | `ibm.vpc-instance` | `vpc-compute.yaml` |
| `is.bare-metal-server.*` | `ibm.vpc-bare-metal` | `vpc-compute.yaml` |
| `is.volume.*` | `ibm.vpc-volume` | `vpc-storage.yaml` |
| `is.snapshot.*` | `ibm.vpc-snapshot` | `vpc-storage.yaml` |
| `is.security-group.*` | `ibm.vpc-security-group` | `vpc-networking.yaml` |
| `is.network-acl.*` | `ibm.vpc-network-acl` | `vpc-networking.yaml` |
| `is.floating-ip.*` | `ibm.vpc-floating-ip` | `vpc-networking.yaml` |
| `is.load-balancer.*` | `ibm.vpc-load-balancer` | `vpc-networking.yaml` |
| `is.transit-gateway.*` | `ibm.vpc-transit-gateway` | `vpc-networking.yaml` |
| `power-iaas.*` | `ibm.powervs-instance`, `ibm.powervs-volume` | `powervs.yaml` |
| `kms.*` | `ibm.kms-key`, `ibm.kms-key-ring` | `kms.yaml` |
| `containers-kubernetes.*` | `ibm.iks-cluster`, `ibm.roks-cluster` | `kubernetes.yaml` |
| `databases-for-*` | `ibm.dbaas-*` | `dbaas.yaml` |
| `iam-identity.*`, `iam-groups.*` | `ibm.iam-*` | `iam.yaml` |

---

## 6. Event Streams (Kafka) integration

Use IBM Event Streams when you need audit-event fan-out to multiple consumers
(SIEM, data lake, custodian) from a single Activity Tracker route, or when you
need replay and retention beyond what Event Notifications provides.

### Architecture

```
Activity Tracker (Event Routing)
       │ target: Event Streams
       ▼
Event Streams topic  "at-audit-events"
       │
       ├─► SIEM / Splunk / QRadar consumer
       ├─► Data lake / COS archive consumer
       └─► custodian-kafka-consumer  (Code Engine job)
               │
               ▼
           custodian run --cache-period 0
```

### Create an Event Streams target in Activity Tracker

```bash
ibmcloud atracker target create \
  --name custodian-kafka-target \
  --type event-streams \
  --brokers "$KAFKA_BROKERS" \
  --topic at-audit-events \
  --api-key "$KAFKA_API_KEY"
```

### Kafka consumer job (`kafka_consumer.py`)

```python
#!/usr/bin/env python3
"""
Consume Activity Tracker events from IBM Event Streams (Kafka)
and trigger custodian runs for relevant actions.

Requires: kafka-python  (pip install kafka-python)
"""

import json
import logging
import os
import subprocess
from kafka import KafkaConsumer

log = logging.getLogger("custodian-kafka")
logging.basicConfig(level=logging.INFO)

BROKERS      = os.environ["KAFKA_BROKERS"].split(",")
TOPIC        = os.environ.get("KAFKA_TOPIC", "at-audit-events")
API_KEY      = os.environ["KAFKA_API_KEY"]
GROUP_ID     = os.environ.get("KAFKA_GROUP_ID", "custodian-consumer")
POLICY_DIR   = os.environ.get("POLICY_DIR", "/app/policies")
OUTPUT_DIR   = os.environ.get("OUTPUT_DIR", "/tmp/c7n-out")

# Same mapping as the webhook receiver
ACTION_TO_POLICY = {
    "cloud-object-storage": "cos.yaml",
    "is.instance":          "vpc-compute.yaml",
    "is.volume":            "vpc-storage.yaml",
    "is.security-group":    "vpc-networking.yaml",
    "is.network-acl":       "vpc-networking.yaml",
    "is.floating-ip":       "vpc-networking.yaml",
    "power-iaas":           "powervs.yaml",
    "kms":                  "kms.yaml",
    "containers-kubernetes":"kubernetes.yaml",
    "databases-for-":       "dbaas.yaml",
    "iam-identity":         "iam.yaml",
    "iam-groups":           "iam.yaml",
}

consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers=BROKERS,
    security_protocol="SASL_SSL",
    sasl_mechanism="PLAIN",
    sasl_plain_username="token",
    sasl_plain_password=API_KEY,
    group_id=GROUP_ID,
    auto_offset_reset="latest",
    value_deserializer=lambda b: json.loads(b.decode("utf-8")),
)

seen_policies: set[str] = set()

for msg in consumer:
    action = msg.value.get("action", "")
    policy_file = next(
        (f for p, f in ACTION_TO_POLICY.items() if action.startswith(p)), None
    )
    if not policy_file or policy_file in seen_policies:
        continue

    seen_policies.add(policy_file)
    log.info("Triggering custodian for action=%s → %s", action, policy_file)
    subprocess.run([
        "custodian", "run",
        f"--configs={POLICY_DIR}/{policy_file}",
        f"--output-dir={OUTPUT_DIR}",
        "--cache-period=0",
    ], check=False)
    seen_policies.discard(policy_file)  # allow re-run after completion
```

---

## 7. SCC Workload Protection webhook

IBM Security and Compliance Center Workload Protection can trigger custodian
runs via a webhook when it raises a finding — for example, a misconfigured
security group or a COS bucket that fails a compliance check.

### How it works

SCC WP → **Notification channel** (webhook type) → custodian webhook receiver
(same Code Engine application from section 5.4) → custodian run scoped to the
affected resource type.

### Configure the SCC WP notification channel

1. In the SCC WP console, go to **Settings → Notification channels**.
2. Click **Add channel**, choose **Webhook**.
3. Set the URL to your Code Engine application URL (`custodian-webhook` from
   section 5.4) — append `/sccwp` to use a dedicated path.
4. Choose the finding types that should trigger remediation:
   - `STORAGE` — triggers `cos.yaml`
   - `NETWORK` — triggers `vpc-networking.yaml`
   - `IAM` — triggers `iam.yaml`
   - `RUNTIME` — triggers `vpc-compute.yaml`

### Extend the webhook receiver to handle SCC WP payloads

Add this handler to `webhook/app.py`:

```python
# SCC WP finding type → policy file
SCCWP_TO_POLICY = {
    "STORAGE":   "cos.yaml",
    "NETWORK":   "vpc-networking.yaml",
    "IAM":       "iam.yaml",
    "RUNTIME":   "vpc-compute.yaml",
    "KMS":       "kms.yaml",
    "CONTAINER": "kubernetes.yaml",
}

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        path = self.path.rstrip("/")
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.send_response(200)
        self.end_headers()

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return

        if path == "/sccwp":
            # SCC WP finding payload
            finding_type = payload.get("finding", {}).get("kind", "")
            policy_file = SCCWP_TO_POLICY.get(finding_type.upper())
            if policy_file:
                threading.Thread(
                    target=_run_custodian,
                    args=(policy_file, f"sccwp:{finding_type}"),
                    daemon=True,
                ).start()
        else:
            # Activity Tracker event via Event Notifications (existing logic)
            at_event = payload.get("data", payload)
            action = at_event.get("action", "")
            policy_file = _policy_file_for_action(action)
            if policy_file:
                threading.Thread(
                    target=_run_custodian,
                    args=(policy_file, action),
                    daemon=True,
                ).start()
```

### SCC WP → custodian → SCC WP findings loop

Custodian can also **write findings back** to SCC WP by posting to the SCC
Findings API after a policy run. Add a post-run step to `_run_custodian`:

```python
import glob
import requests

SCC_API_KEY      = os.environ.get("IBMCLOUD_API_KEY", "")
SCC_ACCOUNT_ID   = os.environ.get("IBMCLOUD_ACCOUNT_ID", "")
SCC_FINDINGS_URL = (
    f"https://us-south.secadvisor.cloud.ibm.com/findings/v1/"
    f"{SCC_ACCOUNT_ID}/providers/custodian/notes"
)

def _post_findings_to_scc(output_dir: str, policy_file: str) -> None:
    """Read custodian resources.json outputs and post findings to SCC."""
    iam_token = _get_iam_token(SCC_API_KEY)
    for resources_file in glob.glob(f"{output_dir}/**/resources.json", recursive=True):
        with open(resources_file) as fh:
            resources = json.load(fh)
        for r in resources:
            rid = r.get("id") or r.get("crn") or r.get("name", "unknown")
            requests.post(
                SCC_FINDINGS_URL,
                headers={"Authorization": f"Bearer {iam_token}"},
                json={
                    "kind": "FINDING",
                    "provider_id": "custodian",
                    "id": f"custodian-{rid}",
                    "short_description": f"Custodian policy violation: {policy_file}",
                    "finding": {"severity": "HIGH"},
                    "context": {"resource_name": rid},
                },
                timeout=10,
            )


def _get_iam_token(api_key: str) -> str:
    r = requests.post(
        "https://iam.cloud.ibm.com/identity/token",
        data={"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": api_key},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    return r.json()["access_token"]
```

---

## 8. IAM service-to-service authorisations

The Code Engine job and application need these IAM permissions. Create a
**service ID** (`custodian-runner`) and assign these policies:

```bash
# Create the service ID
ibmcloud iam service-id-create custodian-runner \
  --description "Cloud Custodian policy runner"

# Platform Viewer + Service Writer on each governed service
for SERVICE in cloud-object-storage is kms containers-kubernetes \
               databases-for-postgresql databases-for-mysql \
               databases-for-mongodb databases-for-redis \
               databases-for-elasticsearch databases-for-rabbitmq \
               power-iaas; do
  ibmcloud iam service-policy-create custodian-runner \
    --roles Viewer,Writer \
    --service-name "$SERVICE"
done

# GlobalSearch Viewer (tag reads)
ibmcloud iam service-policy-create custodian-runner \
  --roles Viewer \
  --service-name global-search-tagging

# GlobalTagging Writer (tag actions)
ibmcloud iam service-policy-create custodian-runner \
  --roles Writer \
  --service-name global-tagging

# IAM access — to read users, service IDs, access groups, policies
ibmcloud iam service-policy-create custodian-runner \
  --roles Viewer \
  --service-name iam-identity
ibmcloud iam service-policy-create custodian-runner \
  --roles Viewer \
  --service-name iam-groups
ibmcloud iam service-policy-create custodian-runner \
  --roles Viewer \
  --service-name iam-access-management

# Secrets Manager — read-only access to custodian secrets
ibmcloud iam service-policy-create custodian-runner \
  --roles SecretsReader \
  --service-name secrets-manager \
  --service-instance "$SM_INSTANCE_ID"

# Create an API key for the service ID and store it in Secrets Manager
ibmcloud iam service-api-key-create custodian-runner-key custodian-runner \
  --description "Custodian runner API key"
```

---

## 9. Outputs and findings

By default custodian writes JSON output to `--output-dir`. Each policy that
matched resources creates:

```
/tmp/c7n-out/
└── <policy-name>/
    ├── resources.json     — full resource objects that matched
    ├── actions.json       — actions taken and their results
    └── metadata.json      — run metadata (timestamp, count, duration)
```

### Persist outputs to COS

Mount a COS bucket as the output directory or copy after each run:

```bash
# After custodian run, sync outputs to COS
ibmcloud cos upload-dir \
  --bucket custodian-outputs \
  --key-prefix "$(date +%Y/%m/%d/%H%M%S)/" \
  --dir /tmp/c7n-out
```

### Push metrics to IBM Cloud Monitoring

```bash
# Use the custodian report command to emit metrics
custodian report \
  --configs /app/policies/ \
  --output-dir /tmp/c7n-out \
  --format json | python3 /app/scripts/push_metrics.py
```

---

## 10. Operational runbook

### Test a single policy without taking action (dry run)

```bash
custodian run \
  --configs tools/c7n_ibmcloud/policies/cos.yaml \
  --output-dir /tmp/c7n-dry \
  --cache-period 0 \
  --dryrun
```

### Check what resources matched last run

```bash
cat /tmp/c7n-out/cos-bucket-public-access/resources.json | python3 -m json.tool
```

### Re-run only failing policies

```bash
# List policies that matched resources (non-zero count)
grep -r '"count": [^0]' /tmp/c7n-out/*/metadata.json
```

### Force cache bypass (always use for event-triggered runs)

```bash
custodian run --configs ... --output-dir ... --cache-period 0
```

### Clear stale output directory before a fresh run

```bash
rm -rf /tmp/c7n-out && custodian run ...
```

### View logs in Code Engine

```bash
# Job run logs
ibmcloud ce jobrun logs --name <jobrun-name>

# Application logs (webhook)
ibmcloud ce application logs --name custodian-webhook --follow
```

### Scaling the webhook application under load

```bash
ibmcloud ce application update \
  --name custodian-webhook \
  --min-scale 2 \
  --max-scale 10 \
  --concurrency 20
```

The `--concurrency 20` setting means up to 20 simultaneous webhook requests
per replica. Each custodian run takes 10–30 seconds so keep concurrency at
or below the number of runs that can execute in parallel without exhausting
IBM Cloud API rate limits (~100 req/s per API key).

### API key rotation

1. Create a new API key for the `custodian-runner` service ID.
2. Update the `custodian-api-key` secret in Secrets Manager.
3. Redeploy the Code Engine job and application (they pull secrets at startup).
4. Delete the old API key.

---

*For filter and action reference, see [`README.md`](../README.md).  
For the interactive policy builder, open [`policy-builder.html`](../policy-builder.html) in a browser.*

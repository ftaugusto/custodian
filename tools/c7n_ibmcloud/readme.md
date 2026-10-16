# c7n_ibmcloud — IBM Cloud Provider for Cloud Custodian

Cloud Custodian policy engine extended for IBM Cloud. Enumerate, filter, and
act on IBM Cloud resources using a declarative YAML policy syntax — the same
way you would govern AWS, Azure, or GCP with Custodian.

---

## At a glance

| Metric | Count |
|---|---|
| **Services covered** | 7 |
| **Resource types** | 43 |
| **Ready-to-use policies** | 193 |
| **Filter types** | 20 |
| **Action types** | 19 |
| **Unit tests** | 439 |

---

## Services and resource types

### IAM — 7 resource types

| Resource type | What it governs |
|---|---|
| `ibm.iam-user` | Account users — MFA, state, email domain |
| `ibm.iam-service-id` | Service IDs — age, description, owner tag |
| `ibm.iam-api-key` | API keys — rotation age, lock state, description |
| `ibm.iam-access-group` | Access groups — empty groups, missing description |
| `ibm.iam-policy` | IAM policies — wildcard resources, missing conditions |
| `ibm.iam-trusted-profile` | Trusted profiles — age, description |
| `ibm.iam-custom-role` | Custom IAM roles — missing description |

### VPC — 19 resource types

| Resource type | What it governs |
|---|---|
| `ibm.vpc-instance` | Virtual server instances — state, tags, zone, size |
| `ibm.vpc-network` | VPCs — empty, tags, resource group |
| `ibm.vpc-subnet` | Subnets — state, IP exhaustion, tags |
| `ibm.vpc-security-group` | Security groups — open SSH/RDP/0.0.0.0 rules, orphans |
| `ibm.vpc-network-acl` | Network ACLs — open inbound rules, missing deny-all |
| `ibm.vpc-floating-ip` | Floating IPs — unattached (wasted cost) |
| `ibm.vpc-vpn-gateway` | VPN gateways — state, weak IKE/IPsec, tags |
| `ibm.vpc-load-balancer` | Load balancers — no HTTPS listener, state |
| `ibm.vpc-public-gateway` | Public gateways — unattached, tags |
| `ibm.vpc-transit-gateway` | Transit gateways — state, empty connections, age |
| `ibm.vpc-bare-metal` | Bare metal servers — state, secure boot, age |
| `ibm.vpc-dedicated-host` | Dedicated hosts — state, provisionable, utilisation |
| `ibm.vpc-instance-group` | Instance groups — empty, lifecycle state |
| `ibm.vpc-instance-template` | Instance templates — age, orphaned |
| `ibm.vpc-volume` | Block volumes — unattached, encryption, capacity |
| `ibm.vpc-snapshot` | Block snapshots — orphaned, age, encryption |
| `ibm.vpc-file-share` | File shares — no mount targets, encryption, size |
| `ibm.vpc-backup-policy` | Backup policies — no plans, unmatched tags |
| `ibm.vpc-ssh-key` | SSH keys (VPC) — age, tags |

### Cloud Object Storage — 1 resource type

| Resource type | What it governs |
|---|---|
| `ibm.cos-bucket` | COS buckets — public access, CMK encryption, versioning, lifecycle |

### Key Protect / KMS — 2 resource types

| Resource type | What it governs |
|---|---|
| `ibm.kms-key` | Keys — rotation policy, state, age |
| `ibm.kms-key-ring` | Key rings — empty rings |

### Kubernetes (IKS / ROKS) — 3 resource types

| Resource type | What it governs |
|---|---|
| `ibm.iks-cluster` | IKS clusters — EOL version, KMS, public endpoint, resource group |
| `ibm.roks-cluster` | ROKS clusters — EOL version, KMS, public endpoint, resource group |
| `ibm.iks-worker-pool` | Worker pools — empty pools, underpopulated pools |

### Power Systems Virtual Server (PowerVS) — 5 resource types

| Resource type | What it governs |
|---|---|
| `ibm.powervs-instance` | PVM instances — state, public network interface, CPU/memory sizing |
| `ibm.powervs-volume` | PowerVS volumes — unattached, shareable, tier-1 idle |
| `ibm.powervs-network` | PowerVS networks — public type (pub-vlan) |
| `ibm.powervs-image` | PowerVS OS images — age, state |
| `ibm.powervs-ssh-key` | PowerVS SSH keys — age, description |

### Databases as a Service (DBaaS) — 6 resource types

All 6 engines share the same filter and action set.

| Resource type | Engine |
|---|---|
| `ibm.dbaas-postgresql` | PostgreSQL |
| `ibm.dbaas-mysql` | MySQL |
| `ibm.dbaas-mongodb` | MongoDB |
| `ibm.dbaas-redis` | Redis |
| `ibm.dbaas-elasticsearch` | Elasticsearch |
| `ibm.dbaas-rabbitmq` | RabbitMQ |

Checks: EOL version, non-running state, public endpoint, non-standard plan,
missing tags, under-provisioned memory, wrong resource group.

---

## Policies

193 ready-to-use policies are organised into 10 YAML files under `policies/`.

| File | Policies | Focus |
|---|---|---|
| `cross-cutting.yaml` | 53 | Mandatory tags (owner, environment, cost-centre), resource group, mark-for-op, stale+untagged across all services |
| `vpc-networking.yaml` | 28 | VPCs, subnets, security groups, ACLs, gateways, VPN, load balancers, floating IPs, SSH keys |
| `vpc-compute.yaml` | 21 | Instances, bare metal, dedicated hosts, instance groups and templates |
| `powervs.yaml` | 18 | PowerVS instances (incl. public network detection), volumes, networks, images, SSH keys |
| `vpc-storage.yaml` | 15 | Block volumes, snapshots, backup policies, file shares |
| `kubernetes.yaml` | 15 | IKS + ROKS clusters (version, KMS, public endpoint, resource group), worker pools |
| `iam.yaml` | 18 | MFA, API key rotation, service IDs, access groups, trusted profiles, custom roles, IAM policies |
| `dbaas.yaml` | 12 | EOL version, state, plan, tags for all 6 database engines |
| `kms.yaml` | 7 | Key rotation, state lifecycle, key ring hygiene |
| `cos.yaml` | 6 | Public access, CMK encryption, versioning, lifecycle, tags |

### Example policy

```yaml
policies:
  - name: powervs-instance-public-network-tag
    description: |
      MUST — PowerVS instances with a public network interface (pub-vlan or
      external IP). Tags the instance workspace for operator review.
    resource: ibm.powervs-instance
    filters:
      - type: public-network-interface
    actions:
      - type: tag
        tags:
          custodian-review: "public-network-interface"
```

---

## Filters

19 filter types available across all resource types.

| Filter | Description |
|---|---|
| `value` | JMESPath field comparison (eq, ne, gt, lt, contains, absent, present, …) |
| `tag` | Match on IBM Cloud user tag (key:value pairs or bare keys) |
| `age` | Resource creation date comparison in days |
| `resource-group` | Filter by resource group name or ID — handles both nested dict (VPC/COS SDK) and flat string (Container API) shapes |
| `marked-for-op` | Match resources previously scheduled for an operation |
| `version` | Semantic version comparison (clusters, databases) |
| `plan` | DBaaS service plan (standard, enterprise, …) |
| `state` | KMS key state (active, deactivated, destroyed, pre-activation, …) |
| `mfa-disabled` | IAM users without MFA enrolled |
| `kms-enabled` | IKS/ROKS clusters without Key Protect / KMS configured |
| `public-network-interface` | PowerVS instances with a routable external IP or pub-vlan network |
| `public-access` | COS buckets with public access enabled — detects S3 ACL `AllUsers`/`AuthenticatedUsers` grants and IBM IAM policies on the built-in "Public Access" access group (`AccessGroupId-PublicAccess`) |
| `lifecycle-configured` | COS buckets with/without a lifecycle configuration |
| `versioning-enabled` | COS buckets with/without versioning |
| `customer-managed-key` | COS buckets with/without a Key Protect CMK |
| `rotation-policy` | KMS keys with/without an automatic rotation policy |
| `rule-match` | VPC security group rules matching port/direction/CIDR |
| `acl-rule-match` | VPC Network ACL rules matching port/direction/action/CIDR |
| `orphaned` | VPC snapshots whose source volume has been deleted |
| `unused` | VPC backup policies with no plans configured |

---

## Actions

19 action types available across all resource types.

| Action | Risk | Description |
|---|---|---|
| `tag` | Safe | Attach IBM Cloud user tags via GlobalTaggingV1 |
| `remove-tag` | Safe | Detach user tags via GlobalTaggingV1 |
| `mark-for-op` | Safe | Attach a dated `custodian_status_<op>:<date>` tag for future action |
| `start` | Safe | Start a stopped instance (VPC, PowerVS) |
| `stop` | Safe | Stop a running instance (VPC, PowerVS) |
| `reboot` | Safe | Reboot a running VPC instance |
| `set-versioning` | Safe | Enable or disable versioning on a COS bucket |
| `set-encryption` | Safe | Flag-only: log non-compliant COS bucket (no per-bucket SSE API) |
| `set-lifecycle` | Safe | Apply an expiry lifecycle rule to a COS bucket |
| `scale` | Safe | Resize a DBaaS instance (memory, disk, CPU) |
| `enable` | Safe | Re-enable a disabled KMS key |
| `append-description` | Safe | Append a custodian notice to an IAM/PowerVS resource description |
| `add-to-review-group` | Safe | Add an IAM user to a review access group |
| `lock` | Warn | Lock an IAM API key (disables it without deleting) |
| `unlock` | Warn | Unlock a previously locked IAM API key |
| `disable` | Warn | Disable a KMS key |
| `rotate` | Warn | Trigger an immediate KMS key rotation |
| `release` | Danger | Release an unattached VPC floating IP (irreversible) |
| `delete` | Danger | Delete a resource (irreversible) |

---

## Installation

```bash
pip install c7n
pip install -e tools/c7n_ibmcloud
```

**Required environment variables:**

```bash
export IBMCLOUD_API_KEY="<your-api-key>"
export IBMCLOUD_REGION="us-south"
export IBMCLOUD_ACCOUNT_ID="<your-account-id>"
```

**Run a policy file:**

```bash
custodian run \
  --configs tools/c7n_ibmcloud/policies/vpc-networking.yaml \
  --output-dir /tmp/c7n-out \
  --cache-period 0
```

**Run all policies:**

```bash
custodian run \
  --configs tools/c7n_ibmcloud/policies/ \
  --output-dir /tmp/c7n-out \
  --cache-period 300
```

---

## Testing

```bash
cd cloud-custodian
python3 -m pytest tools/c7n_ibmcloud/tests/ -v
```

439 unit tests covering all resource types, filters, and actions. No live IBM
Cloud credentials are required — all tests use in-process stubs and mocks.

---

## Tools

| Tool | Location | Description |
|---|---|---|
| Policy Builder | `tools/c7n_ibmcloud/policy-builder.html` | Interactive browser-based YAML policy generator with resource reference table |
| Governance Reference | `tools/c7n_ibmcloud/docs/governance-checks-reference.html` | Complete catalogue of all checks — filter keys, severity levels, recommended actions |
| Overview | `tools/c7n_ibmcloud/docs/overview.html` | Project one-pager: resource types, filters, actions, policies |
| Test Resources Guide | `tools/c7n_ibmcloud/docs/test-resources-guide.html` | IBM CLI commands to create compliant/non-compliant resources for every policy |
| **Deployment Guide (HTML)** | `tools/c7n_ibmcloud/docs/deployment-guide.html` | Rendered HTML version of the deployment guide |
| **Deployment Guide (MD)** | `tools/c7n_ibmcloud/docs/deployment-guide.md` | End-to-end IBM Cloud deployment: Code Engine, scheduled sweeps, Activity Tracker, Event Notifications, Event Streams, SCC WP |

---

## Deployment

See **[`docs/deployment-guide.md`](docs/deployment-guide.md)** for full instructions covering:

- Container image build and push to IBM Container Registry
- Secrets Manager configuration
- Code Engine scheduled job (sweep every 15 minutes)
- Near-real-time enforcement: Activity Tracker → Event Notifications → Code Engine webhook
- IBM Event Streams (Kafka) fan-out integration
- SCC Workload Protection webhook and findings write-back
- IAM service-to-service authorisations
- Operational runbook (dry run, log inspection, API key rotation)

---

## Project structure

```
tools/c7n_ibmcloud/
├── c7n_ibmcloud/
│   ├── resources/
│   │   ├── iam.py          — IAM users, service IDs, API keys, groups, policies
│   │   ├── vpc.py          — VPC compute, networking, storage (19 types)
│   │   ├── cos.py          — Cloud Object Storage buckets
│   │   ├── kms.py          — Key Protect keys and key rings
│   │   ├── kubernetes.py   — IKS / ROKS clusters and worker pools
│   │   ├── powervs.py      — Power Systems Virtual Server (5 types)
│   │   └── dbaas.py        — IBM Cloud Databases (6 engines)
│   ├── filters/
│   │   └── base.py         — Shared filters (tag, age, resource-group, …)
│   ├── actions/
│   │   └── base.py         — Shared actions (tag, delete, mark-for-op, …)
│   └── session.py          — IBM Cloud SDK session and PowerVS client
├── policies/
│   ├── cross-cutting.yaml  — Tag and resource-group checks across all services
│   ├── iam.yaml
│   ├── vpc-compute.yaml
│   ├── vpc-networking.yaml
│   ├── vpc-storage.yaml
│   ├── cos.yaml
│   ├── kms.yaml
│   ├── kubernetes.yaml
│   ├── powervs.yaml
│   └── dbaas.yaml
├── tests/                  — 439 unit tests (no live credentials required)
├── policy-builder.html     — Interactive policy builder (open in browser)
└── README.md               — This file
```

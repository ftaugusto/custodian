#!/usr/bin/env bash
# =============================================================================
# IBM Cloud Custodian — Test Resources Creation Script
# Creates both non-compliant and compliant resources for 6 governance
# policy files: iam, vpc-compute, vpc-networking, vpc-storage, kms,
# cross-cutting.
#
# Usage:
#   ibmcloud login --sso
#   ibmcloud target -r us-south -g Default
#   bash create-test-resources.sh
#
# NOTE: Some policies are time-dependent (age > N days) and cannot be
#       simulated immediately. Those are marked with a comment.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

echo "==> [PREREQ] Targeting us-south / Default"
ibmcloud target -r us-south -g Default

echo "==> [PREREQ] Creating resource groups"
ibmcloud resource group-create governance-tests        || true
ibmcloud resource group-create approved-resource-group || true

# IMPORTANT: Switch to governance-tests for all IS resource lookups.
# ibmcloud is vpcs only returns resources in the currently-targeted resource group.
ibmcloud target -g governance-tests

echo "==> [PREREQ] Creating base VPC infrastructure"
ibmcloud is vpc-create test-vpc --resource-group-name governance-tests || true

# Poll until the VPC reaches 'available' state (max 90s) before creating subnets
echo "    Waiting for test-vpc to become available..."
for i in $(seq 1 18); do
  VPC_STATUS=$(ibmcloud is vpcs --output json 2>/dev/null | jq -r '.[] | select(.name=="test-vpc") | .status' 2>/dev/null || true)
  [ "$VPC_STATUS" = "available" ] && break
  echo "    ...VPC status: ${VPC_STATUS:-not found} (attempt $i/18)"
  sleep 5
done

VPC_ID=$(ibmcloud is vpcs --output json | jq -r '.[] | select(.name=="test-vpc") | .id')
VPC_CRN=$(ibmcloud is vpcs --output json | jq -r '.[] | select(.name=="test-vpc") | .crn')
echo "    VPC_ID=$VPC_ID"

# subnet-create: use --ipv4-address-count + --zone so IBM assigns a CIDR from the
# VPC's auto-created address prefixes (hardcoded CIDRs fail with subnet_not_in_address_prefix)
[ -n "$VPC_ID" ] && ibmcloud is subnet-create test-subnet test-vpc \
  --ipv4-address-count 256 --zone us-south-1 \
  --resource-group-name governance-tests || true

# Poll until subnet is available (max 90s)
echo "    Waiting for test-subnet to become available..."
for i in $(seq 1 18); do
  SUBNET_STATUS=$(ibmcloud is subnets --output json 2>/dev/null | jq -r '.[] | select(.name=="test-subnet") | .status' 2>/dev/null || true)
  [ "$SUBNET_STATUS" = "available" ] && break
  echo "    ...subnet status: ${SUBNET_STATUS:-not found} (attempt $i/18)"
  sleep 5
done

SUBNET_ID=$(ibmcloud is subnets --output json | jq -r '.[] | select(.name=="test-subnet") | .id')
SUBNET_CRN=$(ibmcloud is subnets --output json | jq -r '.[] | select(.name=="test-subnet") | .crn')
echo "    SUBNET_ID=$SUBNET_ID"

echo "==> [PREREQ] Creating SSH key for instance tests"
ibmcloud is key-create test-key \
  "$(cat ~/.ssh/id_rsa.pub 2>/dev/null || (ssh-keygen -t rsa -N '' -f /tmp/testkey -q && cat /tmp/testkey.pub))" \
  || true
# Look up key ID regardless of whether create succeeded (key may already exist)
KEY_ID=$(ibmcloud is keys --output json | jq -r '.[] | select(.name=="test-key") | .id')
echo "    KEY_ID=$KEY_ID"

echo "==> [PREREQ] Installing plugins"
ibmcloud plugin install tg -f || true

export REGION=us-south

# ---------------------------------------------------------------------------
# 1. IAM — iam.yaml
# ---------------------------------------------------------------------------
echo ""
echo "=== [1/6] IAM ==="

# iam-user-mfa-disabled (non-compliant)
echo "--> iam-user-mfa-disabled: inviting non-compliant user"
ibmcloud account user-invite noncompliant-user@external.com || true

# iam-user-suspended: ibmcloud account user-status-set does not exist in this CLI version — skip
echo "--> iam-user-suspended: (skipped — no CLI command to set SUSPENDED state)"

# iam-user-external-domain (non-compliant)
echo "--> iam-user-external-domain: inviting external-domain user"
ibmcloud account user-invite outsider@external.com || true

# iam-user-external-domain (compliant)
echo "--> iam-user-external-domain: inviting compliant internal user"
ibmcloud account user-invite insider@yourcompany.com || true

# iam-api-key-rotation-overdue
# NOTE: Time-dependent — policy fires after 180 days. Cannot be simulated immediately.
# api-key-create description flag is -d, not --description
echo "--> iam-api-key-rotation-overdue: creating test key (fires after 180 days)"
ibmcloud iam api-key-create old-test-key -d "Old key for custodian test" || true

echo "--> iam-api-key-rotation-overdue: creating fresh compliant key"
ibmcloud iam api-key-create fresh-test-key -d "Fresh key for custodian test" || true

# iam-api-key-unlocked-past-rotation-age (non-compliant)
echo "--> iam-api-key-unlocked-past-rotation-age: creating unlocked key"
ibmcloud iam api-key-create unlocked-old-key -d "Unlocked old key" || true

# iam-api-key-unlocked-past-rotation-age (compliant — locked)
echo "--> iam-api-key-unlocked-past-rotation-age: creating and locking compliant key"
ibmcloud iam api-key-create locked-key -d "Locked for compliance" || true
KEY_LOCK_ID=$(ibmcloud iam api-keys --output json | jq -r '.[] | select(.name=="locked-key") | .id')
[ -n "$KEY_LOCK_ID" ] && ibmcloud iam api-key-lock "$KEY_LOCK_ID" || true

# iam-api-key-root-account-owner (non-compliant)
echo "--> iam-api-key-root-account-owner: creating root owner key"
ibmcloud iam api-key-create root-owner-key -d "Root key test" || true

# iam-api-key-root-account-owner (compliant — service ID key)
echo "--> iam-api-key-root-account-owner: creating service ID key"
ibmcloud iam service-id-create svc-non-root -d "Non-root service" || true
# service-id --output json returns an array; use .[0].id
SVC_ID=$(ibmcloud iam service-id svc-non-root --output json | jq -r '.[0].id') || true
[ -n "$SVC_ID" ] && ibmcloud iam service-api-key-create svc-non-root-key "$SVC_ID" -d "ServiceID key" || true

# iam-api-key-no-description (non-compliant)
echo "--> iam-api-key-no-description: creating key without description"
ibmcloud iam api-key-create no-desc-key || true

# iam-api-key-no-description (compliant)
echo "--> iam-api-key-no-description: creating key with description"
ibmcloud iam api-key-create described-key -d "Owner: team-alpha; purpose: CI/CD" || true

# iam-service-id-stale
# NOTE: Time-dependent — policy fires after 365 days.
echo "--> iam-service-id-stale: listing existing old service IDs (time-dependent)"
ibmcloud iam service-ids --output json | jq '.[] | select(.created_at) | {name:.name, created:.created_at}' || true

echo "--> iam-service-id-stale: creating fresh service ID"
ibmcloud iam service-id-create fresh-svc-id -d "Fresh service ID for custodian test" || true

# iam-service-id-no-description (non-compliant)
echo "--> iam-service-id-no-description: creating service ID without description"
ibmcloud iam service-id-create no-desc-svc-id || true

# iam-service-id-no-description (compliant)
echo "--> iam-service-id-no-description: creating service ID with description"
ibmcloud iam service-id-create described-svc-id -d "Owned by team-beta" || true

# iam-service-id-missing-owner-tag (non-compliant)
echo "--> iam-service-id-missing-owner-tag: creating service ID without owner tag"
ibmcloud iam service-id-create no-owner-svc-id -d "Missing owner tag test" || true

# iam-service-id-missing-owner-tag (compliant)
# service-id --output json returns an array; use .[0].crn
echo "--> iam-service-id-missing-owner-tag: attaching owner tag to described-svc-id"
SVC_CRN=$(ibmcloud iam service-id described-svc-id --output json | jq -r '.[0].crn') || true
[ -n "$SVC_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-beta" --resource-id "$SVC_CRN" || true

# iam-service-id-marked-for-op (non-compliant)
echo "--> iam-service-id-marked-for-op: applying expired custodian_status tag"
SVC_CRN2=$(ibmcloud iam service-id no-desc-svc-id --output json | jq -r '.[0].crn') || true
[ -n "$SVC_CRN2" ] && ibmcloud resource tag-attach --tag-names "custodian_status:delete_2000-01-01" --resource-id "$SVC_CRN2" || true

# iam-service-id-marked-for-op (compliant)
echo "--> iam-service-id-marked-for-op: creating non-marked service ID"
ibmcloud iam service-id-create not-marked-svc-id -d "Not marked for deletion" || true

# iam-access-group-empty (non-compliant)
echo "--> iam-access-group-empty: creating empty access group"
ibmcloud iam access-group-create empty-test-group -d "Empty group for custodian test" || true

# iam-access-group-empty (compliant)
# NOTE: Replace user@yourcompany.com with an actual account user
echo "--> iam-access-group-empty: creating non-empty access group"
ibmcloud iam access-group-create nonempty-test-group -d "Non-empty group" || true
# ibmcloud iam access-group-user-add nonempty-test-group <real-user@yourcompany.com>

# iam-trusted-profile-stale (compliant)
# NOTE: Time-dependent — policy fires after 180 days.
echo "--> iam-trusted-profile-stale: creating fresh trusted profile"
ibmcloud iam trusted-profile-create fresh-trusted-profile -d "Fresh profile" || true

# iam-policy-wildcard-resource (non-compliant)
# NOTE: Replace user@example.com with an actual account user before running
echo "--> iam-policy-wildcard-resource: (requires a real account user — edit script to set USER_EMAIL)"
# ibmcloud iam user-policy-create "$USER_EMAIL" --roles Viewer --service-name cloud-object-storage || true

# iam-policy-no-conditions (compliant — policy with time condition via JSON file)
echo "--> iam-policy-no-conditions: creating policy with time condition"
cat > /tmp/policy-with-condition.json <<'EOF'
{
  "type": "access",
  "subjects": [{"attributes":[{"name":"iam_id","value":"IBMid-XXXXXX"}]}],
  "roles": [{"role_id":"crn:v1:bluemix:public:iam::::role:Viewer"}],
  "resources": [{"attributes":[{"name":"serviceName","value":"is"}]}],
  "rule": {"operator":"and","conditions":[{"key":"{{environment.attributes.current_time}}","operator":"timeLessThanOrEquals","value":"17:00:00+00:00"}]}
}
EOF
# ibmcloud iam user-policy-create --file /tmp/policy-with-condition.json || true

# ---------------------------------------------------------------------------
# 2. VPC Compute — vpc-compute.yaml
# ---------------------------------------------------------------------------
echo ""
echo "=== [2/6] VPC Compute ==="

# instance-create: subnet must be passed as --subnet flag (positional arg removed in newer CLI)
# vpc-instance-zombie-stopped (non-compliant — stop; must wait 30 days)
echo "--> vpc-instance-zombie-stopped: creating and stopping zombie instance"
ibmcloud is instance-create zombie-instance test-vpc us-south-1 bx2-2x8 \
  --subnet "$SUBNET_ID" \
  --image ibm-ubuntu-22-04-minimal-amd64-1 --keys "$KEY_ID" \
  --resource-group-name governance-tests || true
ZOMBIE_ID=$(ibmcloud is instances --output json | jq -r '.[] | select(.name=="zombie-instance") | .id')
[ -n "$ZOMBIE_ID" ] && ibmcloud is instance-stop "$ZOMBIE_ID" --force || true

# vpc-instance-zombie-stopped (compliant)
echo "--> vpc-instance-zombie-stopped: creating running instance"
ibmcloud is instance-create running-instance test-vpc us-south-1 bx2-2x8 \
  --subnet "$SUBNET_ID" \
  --image ibm-ubuntu-22-04-minimal-amd64-1 --keys "$KEY_ID" \
  --resource-group-name governance-tests || true

# vpc-instance-missing-owner-tag (non-compliant)
echo "--> vpc-instance-missing-owner-tag: creating instance without owner tag"
ibmcloud is instance-create no-owner-instance test-vpc us-south-1 bx2-2x8 \
  --subnet "$SUBNET_ID" \
  --image ibm-ubuntu-22-04-minimal-amd64-1 --keys "$KEY_ID" \
  --resource-group-name governance-tests || true

# tag-attach for IS resources: use .crn, not .id
# vpc-instance-missing-owner-tag (compliant)
echo "--> vpc-instance-missing-owner-tag: attaching owner tag to running-instance"
INST_CRN=$(ibmcloud is instances --output json | jq -r '.[] | select(.name=="running-instance") | .crn')
[ -n "$INST_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-alpha" --resource-id "$INST_CRN" || true

# vpc-instance-missing-environment-tag (compliant)
echo "--> vpc-instance-missing-environment-tag: attaching environment tag to running-instance"
[ -n "$INST_CRN" ] && ibmcloud resource tag-attach --tag-names "environment:production" --resource-id "$INST_CRN" || true

# vpc-instance-non-approved-zone (non-compliant — us-south-2)
echo "--> vpc-instance-non-approved-zone: creating subnet and instance in us-south-2"
ibmcloud is subnet-create test-subnet-2 test-vpc \
  --ipv4-address-count 256 --zone us-south-2 \
  --resource-group-name governance-tests || true
SUBNET2_ID=$(ibmcloud is subnets --output json | jq -r '.[] | select(.name=="test-subnet-2") | .id')
[ -n "$SUBNET2_ID" ] && ibmcloud is instance-create wrong-zone-instance test-vpc us-south-2 bx2-2x8 \
  --subnet "$SUBNET2_ID" \
  --image ibm-ubuntu-22-04-minimal-amd64-1 --keys "$KEY_ID" \
  --resource-group-name governance-tests || true

# vpc-instance-non-approved-zone (compliant)
echo "--> vpc-instance-non-approved-zone: creating instance in approved zone us-south-1"
ibmcloud is instance-create approved-zone-instance test-vpc us-south-1 bx2-2x8 \
  --subnet "$SUBNET_ID" \
  --image ibm-ubuntu-22-04-minimal-amd64-1 --keys "$KEY_ID" \
  --resource-group-name governance-tests || true

# vpc-instance-oversized (non-compliant — 32 vCPUs)
echo "--> vpc-instance-oversized: creating oversized instance (32 vCPUs)"
ibmcloud is instance-create oversized-instance test-vpc us-south-1 bx2-32x128 \
  --subnet "$SUBNET_ID" \
  --image ibm-ubuntu-22-04-minimal-amd64-1 --keys "$KEY_ID" \
  --resource-group-name governance-tests || true

# vpc-instance-oversized (compliant — 8 vCPUs)
echo "--> vpc-instance-oversized: creating small instance (8 vCPUs)"
ibmcloud is instance-create small-instance test-vpc us-south-1 bx2-8x32 \
  --subnet "$SUBNET_ID" \
  --image ibm-ubuntu-22-04-minimal-amd64-1 --keys "$KEY_ID" \
  --resource-group-name governance-tests || true

# vpc-instance-marked-for-op (non-compliant — expired mark tag)
echo "--> vpc-instance-marked-for-op: applying expired tag to zombie-instance"
ZOMBIE_CRN=$(ibmcloud is instances --output json | jq -r '.[] | select(.name=="zombie-instance") | .crn')
[ -n "$ZOMBIE_CRN" ] && ibmcloud resource tag-attach --tag-names "custodian_status:delete_2000-01-01" \
  --resource-id "$ZOMBIE_CRN" || true

# vpc-instance-wrong-resource-group (non-compliant)
echo "--> vpc-instance-wrong-resource-group: creating instance in governance-tests"
ibmcloud is instance-create wrong-rg-instance test-vpc us-south-1 bx2-2x8 \
  --subnet "$SUBNET_ID" \
  --image ibm-ubuntu-22-04-minimal-amd64-1 --keys "$KEY_ID" \
  --resource-group-name governance-tests || true

# vpc-instance-wrong-resource-group (compliant — approved-resource-group)
echo "--> vpc-instance-wrong-resource-group: creating instance in approved-resource-group"
ibmcloud is instance-create approved-rg-instance test-vpc us-south-1 bx2-2x8 \
  --subnet "$SUBNET_ID" \
  --image ibm-ubuntu-22-04-minimal-amd64-1 --keys "$KEY_ID" \
  --resource-group-name approved-resource-group || true

# vpc-instance-group — instance-group-create requires --instance-template and --subnets flags
echo "--> vpc-instance-group: creating instance template and empty instance group"
ibmcloud is instance-template-create tmpl-test test-vpc us-south-1 bx2-2x8 \
  --subnet "$SUBNET_ID" \
  --image ibm-ubuntu-22-04-minimal-amd64-1 --keys "$KEY_ID" \
  --resource-group-name governance-tests || true
TMPL_ID=$(ibmcloud is instance-templates --output json | jq -r '.[] | select(.name=="tmpl-test") | .id')

[ -n "$TMPL_ID" ] && ibmcloud is instance-group-create empty-ig \
  --instance-template "$TMPL_ID" \
  --subnets "$SUBNET_ID" \
  --membership-count 0 \
  --resource-group-name governance-tests || true

echo "--> vpc-instance-group: creating non-empty tagged instance group"
[ -n "$TMPL_ID" ] && ibmcloud is instance-group-create nonempty-ig \
  --instance-template "$TMPL_ID" \
  --subnets "$SUBNET_ID" \
  --membership-count 1 \
  --resource-group-name governance-tests || true
IG_CRN=$(ibmcloud is instance-groups --output json | jq -r '.[] | select(.name=="nonempty-ig") | .crn')
[ -n "$IG_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-alpha" --resource-id "$IG_CRN" || true

echo "--> vpc-instance-template: creating owned instance template"
ibmcloud is instance-template-create tmpl-owned test-vpc us-south-1 bx2-2x8 \
  --subnet "$SUBNET_ID" \
  --image ibm-ubuntu-22-04-minimal-amd64-1 --keys "$KEY_ID" \
  --resource-group-name approved-resource-group || true
TMPL2_CRN=$(ibmcloud is instance-templates --output json | jq -r '.[] | select(.name=="tmpl-owned") | .crn')
[ -n "$TMPL2_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-alpha" --resource-id "$TMPL2_CRN" || true

# ---------------------------------------------------------------------------
# 3. VPC Networking — vpc-networking.yaml
# ---------------------------------------------------------------------------
echo ""
echo "=== [3/6] VPC Networking ==="

echo "--> vpc-network-empty: creating empty VPC"
ibmcloud is vpc-create empty-vpc --resource-group-name governance-tests || true

echo "--> vpc-network-missing-owner-tag: tagging test-vpc"
# Refresh VPC_ID and VPC_CRN — re-target governance-tests so IS list commands return its resources
ibmcloud target -g governance-tests
VPC_ID=$(ibmcloud is vpcs --output json | jq -r '.[] | select(.name=="test-vpc") | .id')
VPC_CRN=$(ibmcloud is vpcs --output json | jq -r '.[] | select(.name=="test-vpc") | .crn')
SUBNET_ID=$(ibmcloud is subnets --output json | jq -r '.[] | select(.name=="test-subnet") | .id')
echo "    [Section 3 re-read] VPC_ID=$VPC_ID  SUBNET_ID=$SUBNET_ID"
[ -n "$VPC_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-alpha" --resource-id "$VPC_CRN" || true

echo "--> vpc-network-wrong-resource-group: creating VPC in approved-resource-group"
ibmcloud is vpc-create approved-vpc --resource-group-name approved-resource-group || true

echo "--> vpc-subnet-exhausted: creating /29 subnet (8 addresses, 3 usable)"
# Use --ipv4-address-count 8 (minimum, power of 2) to stay within VPC address prefixes
ibmcloud is subnet-create tiny-subnet test-vpc \
  --ipv4-address-count 8 --zone us-south-1 \
  --resource-group-name governance-tests || true

echo "--> vpc-subnet-missing-owner-tag: tagging test-subnet"
SUBNET_CRN=$(ibmcloud is subnets --output json | jq -r '.[] | select(.name=="test-subnet") | .crn')
[ -n "$SUBNET_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-alpha" --resource-id "$SUBNET_CRN" || true

# security-group-create: --vpc flag required (positional VPC arg removed)
echo "--> vpc-security-group-open-ssh: creating SG with SSH open to 0.0.0.0/0"
ibmcloud is security-group-create sg-open-ssh \
  --vpc "$VPC_ID" --resource-group-name governance-tests || true
SG_ID=$(ibmcloud is security-groups --output json | jq -r '.[] | select(.name=="sg-open-ssh") | .id')
[ -n "$SG_ID" ] && ibmcloud is security-group-rule-add "$SG_ID" inbound tcp \
  --port-min 22 --port-max 22 --remote 0.0.0.0/0 || true

echo "--> vpc-security-group-open-ssh: creating SG with SSH restricted to 10.0.0.0/8"
ibmcloud is security-group-create sg-restricted-ssh \
  --vpc "$VPC_ID" --resource-group-name governance-tests || true
SG2_ID=$(ibmcloud is security-groups --output json | jq -r '.[] | select(.name=="sg-restricted-ssh") | .id')
SG2_CRN=$(ibmcloud is security-groups --output json | jq -r '.[] | select(.name=="sg-restricted-ssh") | .crn')
[ -n "$SG2_ID" ] && ibmcloud is security-group-rule-add "$SG2_ID" inbound tcp \
  --port-min 22 --port-max 22 --remote 10.0.0.0/8 || true

echo "--> vpc-security-group-open-rdp: creating SG with RDP open to 0.0.0.0/0"
ibmcloud is security-group-create sg-open-rdp \
  --vpc "$VPC_ID" --resource-group-name governance-tests || true
SG_RDP=$(ibmcloud is security-groups --output json | jq -r '.[] | select(.name=="sg-open-rdp") | .id')
[ -n "$SG_RDP" ] && ibmcloud is security-group-rule-add "$SG_RDP" inbound tcp \
  --port-min 3389 --port-max 3389 --remote 0.0.0.0/0 || true

echo "--> vpc-security-group-open-rdp: creating SG with RDP restricted to 192.168.1.0/24"
ibmcloud is security-group-create sg-restricted-rdp \
  --vpc "$VPC_ID" --resource-group-name governance-tests || true
SG_RDP2=$(ibmcloud is security-groups --output json | jq -r '.[] | select(.name=="sg-restricted-rdp") | .id')
[ -n "$SG_RDP2" ] && ibmcloud is security-group-rule-add "$SG_RDP2" inbound tcp \
  --port-min 3389 --port-max 3389 --remote 192.168.1.0/24 || true

echo "--> vpc-security-group-wide-open-inbound: creating SG with all ports open"
ibmcloud is security-group-create sg-wide-open \
  --vpc "$VPC_ID" --resource-group-name governance-tests || true
SG_WIDE=$(ibmcloud is security-groups --output json | jq -r '.[] | select(.name=="sg-wide-open") | .id')
[ -n "$SG_WIDE" ] && ibmcloud is security-group-rule-add "$SG_WIDE" inbound tcp \
  --port-min 1 --port-max 65535 --remote 0.0.0.0/0 || true

# vpc-security-group-missing-owner-tag (compliant)
echo "--> vpc-security-group-missing-owner-tag: tagging sg-restricted-ssh"
[ -n "$SG2_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-alpha" --resource-id "$SG2_CRN" || true

# network-acl-create: requires --vpc flag
echo "--> vpc-network-acl-open-ssh: creating ACL allowing SSH from 0.0.0.0/0"
ibmcloud is network-acl-create acl-open-ssh \
  --vpc "$VPC_ID" --resource-group-name governance-tests || true
ACL_ID=$(ibmcloud is network-acls --output json | jq -r '.[] | select(.name=="acl-open-ssh") | .id')
[ -n "$ACL_ID" ] && ibmcloud is network-acl-rule-add "$ACL_ID" allow inbound tcp 0.0.0.0/0 0.0.0.0/0 \
  --destination-port-min 22 --destination-port-max 22 || true

echo "--> vpc-network-acl-open-ssh: creating restricted ACL with deny-all"
ibmcloud is network-acl-create acl-restricted \
  --vpc "$VPC_ID" --resource-group-name governance-tests || true
ACL2_ID=$(ibmcloud is network-acls --output json | jq -r '.[] | select(.name=="acl-restricted") | .id')
[ -n "$ACL2_ID" ] && ibmcloud is network-acl-rule-add "$ACL2_ID" allow inbound tcp 10.0.0.0/8 0.0.0.0/0 \
  --destination-port-min 22 --destination-port-max 22 || true
# --before-rule-name does not exist; use --before-rule with the rule ID, or just append deny-all
[ -n "$ACL2_ID" ] && ibmcloud is network-acl-rule-add "$ACL2_ID" deny inbound all 0.0.0.0/0 0.0.0.0/0 || true

echo "--> vpc-network-acl-open-rdp: creating ACL allowing RDP from 0.0.0.0/0"
ibmcloud is network-acl-create acl-open-rdp \
  --vpc "$VPC_ID" --resource-group-name governance-tests || true
ACL_RDP=$(ibmcloud is network-acls --output json | jq -r '.[] | select(.name=="acl-open-rdp") | .id')
[ -n "$ACL_RDP" ] && ibmcloud is network-acl-rule-add "$ACL_RDP" allow inbound tcp 0.0.0.0/0 0.0.0.0/0 \
  --destination-port-min 3389 --destination-port-max 3389 || true

# public-gateway-create: VPC and ZONE are positional args (NAME VPC ZONE)
echo "--> vpc-public-gateway-missing-owner-tag: creating public gateway"
ibmcloud is public-gateway-create pgw-test "$VPC_ID" us-south-1 \
  --resource-group-name governance-tests || true
PGW_CRN=$(ibmcloud is public-gateways --output json | jq -r '.[] | select(.name=="pgw-test") | .crn')
[ -n "$PGW_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-alpha" --resource-id "$PGW_CRN" || true

# tg gateway-create: --name is a required named flag
# --resource-group-id needs the group's GUID; get it via list (returns array)
echo "--> vpc-transit-gateway: creating transit gateway with no connections"
RG_ID=$(ibmcloud resource groups --output json | jq -r '.[] | select(.name=="governance-tests") | .id')
ibmcloud tg gateway-create --name tgw-test --location us-south --routing local \
  --resource-group-id "$RG_ID" || true
TGW_ID=$(ibmcloud tg gateways --output json | jq -r '.[] | select(.name=="tgw-test") | .id')

echo "--> vpc-transit-gateway: adding VPC connection and owner tag"
# tg connection-create --network-id requires the VPC CRN, not the plain ID
[ -n "$TGW_ID" ] && [ -n "$VPC_CRN" ] && ibmcloud tg connection-create "$TGW_ID" --name conn-test \
  --network-type vpc --network-id "$VPC_CRN" || true
TGW_CRN=$(ibmcloud tg gateways --output json | jq -r '.[] | select(.name=="tgw-test") | .crn') || true
[ -n "$TGW_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-alpha" --resource-id "$TGW_CRN" || true

# vpn-gateway-create: subnet is a positional arg (NAME SUBNET)
echo "--> vpc-vpn-gateway: creating VPN gateway"
ibmcloud is vpn-gateway-create vpngw-test "$SUBNET_ID" \
  --resource-group-name governance-tests || true
VPNGW_CRN=$(ibmcloud is vpn-gateways --output json | jq -r '.[] | select(.name=="vpngw-test") | .crn')
[ -n "$VPNGW_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-alpha" --resource-id "$VPNGW_CRN" || true

# load-balancer-create: --subnets does not exist; use --subnet (repeatable)
# load-balancer-listener-create: LB must be 'active' before adding a listener; poll up to 5min
echo "--> vpc-load-balancer: creating LB with HTTP only"
ibmcloud is load-balancer-create lb-no-https public \
  --subnet "$SUBNET_ID" \
  --resource-group-name governance-tests || true
LB_ID=$(ibmcloud is load-balancers --output json | jq -r '.[] | select(.name=="lb-no-https") | .id')
if [ -n "$LB_ID" ]; then
  echo "    Waiting for lb-no-https to become active..."
  for i in $(seq 1 30); do
    LB_STATUS=$(ibmcloud is load-balancer "$LB_ID" --output json 2>/dev/null | jq -r '.provisioning_status' 2>/dev/null || true)
    [ "$LB_STATUS" = "active" ] && break
    echo "    ...LB status: ${LB_STATUS:-unknown} (attempt $i/30)"
    sleep 10
  done
  ibmcloud is load-balancer-listener-create "$LB_ID" --port 80 --protocol http || true
fi

echo "--> vpc-load-balancer: creating tagged HTTPS-ready LB"
ibmcloud is load-balancer-create lb-https public \
  --subnet "$SUBNET_ID" \
  --resource-group-name approved-resource-group || true
LB2_CRN=$(ibmcloud is load-balancers --output json | jq -r '.[] | select(.name=="lb-https") | .crn')
[ -n "$LB2_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-alpha" --resource-id "$LB2_CRN" || true

echo "--> vpc-floating-ip-unattached: reserving unattached floating IP"
ibmcloud is floating-ip-reserve fip-unattached --zone us-south-1 \
  --resource-group-name governance-tests || true

echo "--> vpc-floating-ip-unattached: reserving attached floating IP"
INST_ID=$(ibmcloud is instances --output json | jq -r '.[] | select(.name=="running-instance") | .id')
NIC_ID=$(ibmcloud is instance-network-interfaces running-instance --output json 2>/dev/null | jq -r '.[0].id // empty')
[ -n "$NIC_ID" ] && ibmcloud is floating-ip-reserve fip-attached \
  --nic "$NIC_ID" --in running-instance \
  --resource-group-name governance-tests || true
FIP_CRN=$(ibmcloud is floating-ips --output json | jq -r '.[] | select(.name=="fip-attached") | .crn')
[ -n "$FIP_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-alpha" --resource-id "$FIP_CRN" || true

echo "--> vpc-ssh-key-missing-owner-tag: tagging test-key"
KEY_CRN=$(ibmcloud is keys --output json | jq -r '.[] | select(.name=="test-key") | .crn')
[ -n "$KEY_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-alpha" --resource-id "$KEY_CRN" || true

# ---------------------------------------------------------------------------
# 4. VPC Storage — vpc-storage.yaml
# ---------------------------------------------------------------------------
echo ""
echo "=== [4/6] VPC Storage ==="

# volume-create positional args: NAME PROFILE ZONE (profile was missing)
echo "--> vpc-volume-unattached: creating unattached volume (fires after 30 days)"
ibmcloud is volume-create vol-unattached general-purpose us-south-1 --capacity 100 \
  --resource-group-name governance-tests || true

echo "--> vpc-volume-unattached: creating and attaching volume"
INST_ID=$(ibmcloud is instances --output json | jq -r '.[] | select(.name=="running-instance") | .id')
ibmcloud is volume-create vol-attached general-purpose us-south-1 --capacity 100 \
  --resource-group-name governance-tests || true
VOL_ID=$(ibmcloud is volumes --output json | jq -r '.[] | select(.name=="vol-attached") | .id')
[ -n "$INST_ID" ] && [ -n "$VOL_ID" ] && \
  ibmcloud is instance-volume-attachment-add running-instance-attachment "$INST_ID" "$VOL_ID" || true

echo "--> vpc-volume-no-customer-managed-key: creating volume with provider encryption"
ibmcloud is volume-create vol-provider-enc general-purpose us-south-1 --capacity 100 \
  --resource-group-name governance-tests || true

echo "--> vpc-volume-oversized: creating oversized volume (2001 GiB)"
ibmcloud is volume-create vol-oversized general-purpose us-south-1 --capacity 2001 \
  --resource-group-name governance-tests || true

echo "--> vpc-volume-oversized: creating normal-sized volume"
ibmcloud is volume-create vol-normal general-purpose us-south-1 --capacity 100 \
  --resource-group-name governance-tests || true

echo "--> vpc-snapshot-orphaned: creating orphaned snapshot"
# Snapshots require the source volume to be attached to a running VSI.
# Attach vol-attached (already attached to running-instance) and snapshot it, then detach as orphan simulation.
VOL_ATTACHED_ID=$(ibmcloud is volumes --output json | jq -r '.[] | select(.name=="vol-attached") | .id')
[ -n "$VOL_ATTACHED_ID" ] && ibmcloud is snapshot-create snap-orphan --volume "$VOL_ATTACHED_ID" \
  --resource-group-name governance-tests || true

echo "--> vpc-snapshot-orphaned: creating snapshot from running vol-normal (attach first)"
VOL_NORM=$(ibmcloud is volumes --output json | jq -r '.[] | select(.name=="vol-normal") | .id')
INST_ID_RUN=$(ibmcloud is instances --output json | jq -r '.[] | select(.name=="running-instance") | .id')
if [ -n "$VOL_NORM" ] && [ -n "$INST_ID_RUN" ]; then
  ibmcloud is instance-volume-attachment-add snap-vol-attach "$INST_ID_RUN" "$VOL_NORM" || true
  sleep 10
  ibmcloud is snapshot-create snap-active --volume "$VOL_NORM" \
    --resource-group-name governance-tests || true
fi

# backup-policy-create: --match-tags is required; flag renamed from --match-user-tags
echo "--> vpc-backup-policy: creating unused backup policy (no plan)"
ibmcloud is backup-policy-create --name bp-unused \
  --match-tags "bp-unused-sentinel" \
  --resource-group-name governance-tests || true

echo "--> vpc-backup-policy: creating active backup policy with plan"
ibmcloud is backup-policy-create --name bp-active \
  --match-tags "backup:daily" \
  --plan-name daily-plan --plan-cron-spec "0 2 * * *" --plan-active \
  --resource-group-name governance-tests || true

# share-create: --name must be explicit (otherwise CLI auto-generates a name and lookups fail)
echo "--> vpc-file-share: creating non-compliant file share (oversized, no mount target)"
ibmcloud is share-create --name fs-no-mount --zone us-south-1 --size 10001 \
  --profile dp2 --resource-group-name governance-tests || true

echo "--> vpc-file-share: creating compliant file share with mount target"
ibmcloud is share-create --name fs-mounted --zone us-south-1 --size 100 \
  --profile dp2 --resource-group-name governance-tests || true
FS_ID=$(ibmcloud is shares --output json | jq -r '.[] | select(.name=="fs-mounted") | .id')
FS_CRN=$(ibmcloud is shares --output json | jq -r '.[] | select(.name=="fs-mounted") | .crn')
# share-mount-target-create: add --vpc to disambiguate subnet by name
[ -n "$FS_ID" ] && ibmcloud is share-mount-target-create "$FS_ID" \
  --name mt-test --subnet "$SUBNET_ID" --vpc "$VPC_ID" || true
[ -n "$FS_CRN" ] && ibmcloud resource tag-attach --tag-names "owner:team-alpha" --resource-id "$FS_CRN" || true

# ---------------------------------------------------------------------------
# 5. Key Management Service — kms.yaml
# ---------------------------------------------------------------------------
echo ""
echo "=== [5/6] KMS ==="

echo "--> kms: creating KMS instance"
ibmcloud resource service-instance-create kms-test kms tiered-pricing us-south \
  -g governance-tests || true
KMS_GUID=$(ibmcloud resource service-instance kms-test -g governance-tests --output json 2>/dev/null | jq -r '.[0].guid // .guid // empty') || true
[ -z "$KMS_GUID" ] && KMS_GUID=$(ibmcloud resource service-instances --output json 2>/dev/null | jq -r '.[] | select(.name=="kms-test") | .guid' 2>/dev/null | head -n1) || true
echo "    KMS_GUID=$KMS_GUID"

echo "--> kms-key-no-rotation-policy: creating key without rotation policy"
ibmcloud kp key create key-no-rotation -i "$KMS_GUID" || true
KP_KEY_ID=$(ibmcloud kp keys -i "$KMS_GUID" --output json | jq -r '.[] | select(.name=="key-no-rotation") | .id') || true

echo "--> kms-key-no-rotation-policy: creating key with 90-day rotation policy"
ibmcloud kp key create key-with-rotation -i "$KMS_GUID" || true
KEY2_ID=$(ibmcloud kp keys -i "$KMS_GUID" --output json | jq -r '.[] | select(.name=="key-with-rotation") | .id') || true
[ -n "$KEY2_ID" ] && ibmcloud kp key rotation-policy-set "$KEY2_ID" -i "$KMS_GUID" --rotation-interval 3 || true

echo "--> kms-key-deactivated: creating and retiring a key"
ibmcloud kp key create key-to-deactivate -i "$KMS_GUID" || true
DEACT_ID=$(ibmcloud kp keys -i "$KMS_GUID" --output json | jq -r '.[] | select(.name=="key-to-deactivate") | .id') || true
[ -n "$DEACT_ID" ] && ibmcloud kp key retire "$DEACT_ID" -i "$KMS_GUID" || true

echo "--> kms-key-pre-activation: creating extractable key via API (pre-activation state)"
BEARER=$(ibmcloud iam oauth-tokens --output json | jq -r '.iam_token') || true
[ -n "$KMS_GUID" ] && curl -s -X POST "https://us-south.kms.cloud.ibm.com/api/v2/keys" \
  -H "Authorization: $BEARER" \
  -H "bluemix-instance: $KMS_GUID" \
  -H "Content-Type: application/vnd.ibm.kms.key+json" \
  -d '{"metadata":{"collectionType":"application/vnd.ibm.kms.key+json","collectionTotal":1},"resources":[{"type":"application/vnd.ibm.kms.key+json","name":"key-pre-activation","extractable":true,"payload":"dGVzdC1wYXlsb2FkMTIzNDU2Nzg="}]}' || true

echo "--> kms-key-ring: creating empty non-standard key ring"
ibmcloud kp key-ring create nonstandard-ring -i "$KMS_GUID" || true

# ---------------------------------------------------------------------------
# 6. Cross-Cutting — cross-cutting.yaml
# ---------------------------------------------------------------------------
echo ""
echo "=== [6/6] Cross-Cutting ==="

echo "--> cross-*-missing-owner: creating instance without owner tag"
ibmcloud is instance-create no-owner-cross-test test-vpc us-south-1 bx2-2x8 \
  --subnet "$SUBNET_ID" \
  --image ibm-ubuntu-22-04-minimal-amd64-1 --keys "$KEY_ID" \
  --resource-group-name governance-tests || true

echo "--> cross-*-missing-environment: creating instance without environment tag"
ibmcloud is instance-create no-env-cross-test test-vpc us-south-1 bx2-2x8 \
  --subnet "$SUBNET_ID" \
  --image ibm-ubuntu-22-04-minimal-amd64-1 --keys "$KEY_ID" \
  --resource-group-name governance-tests || true

echo "--> cross-*-marked-for-op: applying expired custodian_status tag"
CROSS_CRN=$(ibmcloud is instances --output json | jq -r '.[] | select(.name=="no-owner-cross-test") | .crn') || true
[ -n "$CROSS_CRN" ] && ibmcloud resource tag-attach --tag-names "custodian_status:delete_2000-01-01" \
  --resource-id "$CROSS_CRN" || true

echo "--> cross-*-wrong-resource-group: listing instances in governance-tests (non-compliant)"
ibmcloud is instances --output json | jq '.[] | select(.resource_group.name=="governance-tests") | .name' || true

echo ""
echo "============================================================"
echo "  All resource creation commands have been executed."
echo "  Review output above for any errors or time-dependent notes."
echo "  Run cleanup when done: see the cleanup section in the HTML guide."
echo "============================================================"

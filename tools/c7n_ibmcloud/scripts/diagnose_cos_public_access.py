#!/usr/bin/env python3
# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
Diagnostic script: dump every public-access signal for a COS bucket.

Usage:
    python3 scripts/diagnose_cos_public_access.py <bucket-name>

Required environment variables:
    IBMCLOUD_API_KEY
    IBMCLOUD_ACCOUNT_ID
    IBMCLOUD_REGION           (default: us-south)
    IBMCLOUD_COS_RESOURCE_INSTANCE_ID   (optional; speeds up COS client init)

The script prints the raw ACL grants, the full RC config block, and all IAM
policies whose subject is PUBLIC that reference this bucket — exactly what
the augment() method uses to determine c7n:public_access.
"""

import json
import os
import sys

# Resolve paths relative to this script's location so it works regardless of
# the current working directory.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR  = os.path.join(_SCRIPT_DIR, "..")          # tools/c7n_ibmcloud/
_C7N_DIR    = os.path.join(_TOOLS_DIR,  "..", "..")     # cloud-custodian/ (contains c7n/)

for _p in (_TOOLS_DIR, _C7N_DIR):
    _p = os.path.normpath(_p)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from c7n_ibmcloud.session import SessionFactory

_COS_STORAGE_CLASS_SUFFIXES = frozenset(["standard", "vault", "cold", "flex", "smart"])


def _cos_endpoint_for_location(location):
    """Return the IBM COS S3 endpoint URL for a bucket location constraint."""
    if not location:
        return None
    parts = location.rsplit("-", 1)
    if len(parts) == 2 and parts[1] in _COS_STORAGE_CLASS_SUFFIXES:
        region = parts[0]
    else:
        region = location
    return "https://s3.{}.cloud-object-storage.appdomain.cloud".format(region)


def _sep(label):
    print("\n" + "=" * 60)
    print(" " + label)
    print("=" * 60)


def main():
    if len(sys.argv) < 2:
        print("Usage: diagnose_cos_public_access.py <bucket-name>")
        sys.exit(1)

    bucket_name = sys.argv[1]
    api_key = os.environ.get("IBMCLOUD_API_KEY", "")
    account_id = os.environ.get("IBMCLOUD_ACCOUNT_ID", "")
    region = os.environ.get("IBMCLOUD_REGION", "us-south")

    if not api_key:
        print("ERROR: IBMCLOUD_API_KEY is not set")
        sys.exit(1)
    if not account_id:
        print("ERROR: IBMCLOUD_ACCOUNT_ID is not set")
        sys.exit(1)

    factory = SessionFactory(api_key=api_key, region=region, account_id=account_id)
    session = factory()

    # ------------------------------------------------------------------
    # 1. Discover bucket location via GetBucketLocation
    # ------------------------------------------------------------------
    _sep("1. Bucket location")
    cos_default = session.cos_client()
    try:
        loc_resp = cos_default.get_bucket_location(Bucket=bucket_name)
        location = loc_resp.get("LocationConstraint", "") or ""
        print(f"  LocationConstraint: {location!r}")
    except Exception as exc:
        location = ""
        print(f"  GetBucketLocation FAILED: {exc}")

    # Build a regional COS client
    endpoint = _cos_endpoint_for_location(location)
    print(f"  Resolved endpoint:  {endpoint}")
    cos = session.cos_client(endpoint_url=endpoint)

    # ------------------------------------------------------------------
    # 2. S3 ACL grants
    # ------------------------------------------------------------------
    _sep("2. S3 ACL grants (Signal 1)")
    try:
        acl = cos.get_bucket_acl(Bucket=bucket_name)
        grants = acl.get("Grants", [])
        print(f"  Total grants: {len(grants)}")
        for g in grants:
            grantee = g.get("Grantee", {})
            uri = grantee.get("URI", "")
            display = grantee.get("DisplayName", "")
            gtype = grantee.get("Type", "")
            perm = g.get("Permission", "")
            print(f"    type={gtype!r:20s} permission={perm!r:10s} URI={uri!r} display={display!r}")
            if uri.endswith("AllUsers") or uri.endswith("AuthenticatedUsers"):
                print("    ^^^ PUBLIC GRANT DETECTED ^^^")
    except Exception as exc:
        print(f"  get_bucket_acl FAILED: {exc}")

    # ------------------------------------------------------------------
    # 3. RC Config (full dump — public_access_block, firewall, activity_tracking, …)
    # ------------------------------------------------------------------
    _sep("3. RC Config (full response)")
    bucket_crn = ""
    try:
        rc_cfg = session.cos_resource_config_client()
        rc_result = rc_cfg.get_bucket_config(bucket=bucket_name).get_result()
        bucket_crn = rc_result.get("crn", "")
        print(f"  bucket CRN:           {bucket_crn!r}")
        print(f"  service_instance_crn: {rc_result.get('service_instance_crn', '')!r}")
        # Print every top-level field so we don't miss any public-access signal
        print("\n  Full RC config response:")
        for k, v in sorted(rc_result.items()):
            print(f"    {k}: {json.dumps(v, default=str)}")
    except Exception as exc:
        print(f"  RC Config FAILED: {exc}")

    # ------------------------------------------------------------------
    # 3b. IAM Access Groups — find the "Public Access" built-in group
    # ------------------------------------------------------------------
    _sep("3b. IAM Access Groups — Public Access group policies")
    try:
        ag_client = session.client("iam-groups")
        # List all access groups; the built-in "Public Access" group has
        # is_federated_allowed=True and a well-known name.
        ag_resp = ag_client.list_access_groups(
            account_id=account_id,
        ).get_result()
        groups = ag_resp.get("groups", [])
        print(f"  Total access groups: {len(groups)}")
        public_group_ids = []
        for g in groups:
            name = g.get("name", "")
            gid  = g.get("id", "")
            is_public = (
                name.lower() == "public access"
                or g.get("is_federated_allowed") is True
                or name.lower().startswith("public")
            )
            marker = " <<< PUBLIC ACCESS GROUP" if is_public else ""
            print(f"  group id={gid!r:40s} name={name!r}{marker}")
            if is_public:
                public_group_ids.append(gid)
    except Exception as exc:
        print(f"  list_access_groups FAILED: {exc}")
        public_group_ids = []

    # Now list IAM policies for each public access group ID
    for gid in public_group_ids:
        print(f"\n  Policies for Public Access group {gid!r}:")
        try:
            iam = session.client("iam-policy")
            pg_resp = iam.list_policies(
                account_id=account_id,
                access_group_id=gid,
            ).get_result()
            pg_policies = pg_resp.get("policies", [])
            print(f"    Total policies: {len(pg_policies)}")
            for i, p in enumerate(pg_policies):
                print(f"    policy[{i}] id={p.get('id','')}")
                print(f"      resources: {json.dumps(p.get('resources', []))}")
                for res in p.get("resources", []):
                    attrs = {a.get("name"): a.get("value", "") for a in res.get("attributes", [])}
                    resource_val  = attrs.get("resource", "")
                    resource_type = attrs.get("resourceType", "")
                    service_name  = attrs.get("serviceName", "")
                    if resource_val == bucket_name or (bucket_crn and resource_val == bucket_crn):
                        print(f"      ^^^ MATCHES bucket {bucket_name!r} by name/CRN ^^^")
                    elif resource_type == "bucket" and not resource_val:
                        print(f"      ^^^ MATCHES all buckets (instance-wide) ^^^")
                    elif service_name == "cloud-object-storage" and not resource_type:
                        print(f"      ^^^ MATCHES all COS resources (service-wide) ^^^")
                    elif not service_name and not resource_type and not resource_val:
                        print(f"      ^^^ MATCHES all resources (account-wide) ^^^")
        except Exception as exc:
            print(f"    list_policies for group {gid} FAILED: {exc}")

    # ------------------------------------------------------------------
    # 4. IAM PUBLIC policies (full account scan)
    # ------------------------------------------------------------------
    _sep("4. IAM PUBLIC policies (Signal 2)")
    try:
        iam = session.client("iam-policy")
        resp = iam.list_policies(
            account_id=account_id,
            iam_id="PUBLIC",
            format="include_last_permit",
        ).get_result()
        raw_policies = resp.get("policies", [])
        print(f"  Total PUBLIC policies in account: {len(raw_policies)}")
        for i, p in enumerate(raw_policies):
            print(f"\n  Policy [{i}]:")
            print(f"    id:       {p.get('id', '')}")
            print(f"    subjects: {json.dumps(p.get('subjects', []), indent=6)}")
            print(f"    resources:{json.dumps(p.get('resources', []), indent=6)}")
            # Check if this policy targets our bucket
            for res in p.get("resources", []):
                for attr in res.get("attributes", []):
                    v = attr.get("value", "")
                    if v == bucket_name or (bucket_crn and v == bucket_crn):
                        print(f"    ^^^ MATCHES BUCKET {bucket_name!r} ^^^")
    except Exception as exc:
        print(f"  IAM list_policies FAILED: {exc}")

    _sep("Summary")
    print(f"  Bucket: {bucket_name}")
    print(f"  Run with --verbose to see full SDK debug output.")


if __name__ == "__main__":
    main()

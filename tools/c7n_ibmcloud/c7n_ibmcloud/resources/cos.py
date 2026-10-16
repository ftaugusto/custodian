# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Cloud Object Storage resources.

COS is S3-compatible and uses ibm-cos-sdk (a boto3 fork) for API access.
Authentication supports both HMAC keys and IAM token-based auth.

Bucket enumeration strategy
----------------------------
``list_buckets_extended()`` (IBM COS extension) returns buckets with their
location constraint but **requires HMAC credentials** — it rejects IAM OAuth
tokens with ``InvalidArgument``.

When HMAC credentials are not available we fall back to two approaches in order:

1. ``list_buckets(IBMServiceInstanceId=<guid>)`` — works with IAM OAuth when a
   specific COS service instance GUID is supplied.  The GUID is taken from
   ``IBMCLOUD_COS_RESOURCE_INSTANCE_ID`` if set, or discovered by enumerating
   all COS service instances via ResourceControllerV2.

2. If neither HMAC nor a COS instance GUID is available, the source returns an
   empty list and logs a warning rather than raising an unhandled exception.

Encryption model
----------------
All IBM COS buckets are **always encrypted at rest** using IBM-managed keys.
There is no unencrypted bucket. The meaningful compliance check is whether a
bucket uses **customer-managed keys** (CMK) via IBM Key Protect — the
``customer-managed-key`` filter detects this.

CMK status is read from the ``HEAD /bucket`` response headers that the
ibm-cos-sdk surfaces as ``IBMSSEKPEnabled`` (bool) and ``IBMSSEKPCrkId``
(string CRN of the root key). These are stored as ``c7n:kp_enabled`` and
``c7n:kp_key_crn`` on every augmented bucket resource.

- ibm.cos-bucket  — COS buckets, augmented with ACL, versioning, Key Protect
                    encryption status, lifecycle, and public-access metadata.
"""

import logging
import os

from c7n.utils import local_session, type_schema

from c7n_ibmcloud.actions.base import IBMBaseAction, _ensure_access_tags
from c7n_ibmcloud.filters.base import TagFilter, AgeFilter, PublicAccessFilter
from c7n_ibmcloud.provider import resources
from c7n_ibmcloud.query import QueryResourceManager, TypeInfo, DescribeSource, sources

log = logging.getLogger("custodian.ibm.cos")

# The IBM Cloud built-in "Public Access" IAM access group has this fixed ID
# across all accounts. The Console "public access" bucket toggle creates an
# IAM policy attached to this group (not a raw iam_id="PUBLIC" subject policy).
_PUBLIC_ACCESS_GROUP_ID = "AccessGroupId-PublicAccess"

# CRN service-name segment that identifies a Cloud Object Storage instance.
# Used to filter RC results client-side — avoids depending on the opaque
# global-catalog UUID ("dff97f5c-bc5e-4455-b470-411c3edbe49c") that the
# resource_id query parameter would require.
COS_CRN_SERVICE_NAME = "cloud-object-storage"

# IBM COS location constraints look like "us-south-standard", "eu-de-flex",
# "us-east-vault", "us-geo-standard", "ams03-standard", etc.
# The region prefix is everything before the last hyphen-separated storage-class
# suffix (standard, vault, cold, flex).  We strip it to get the region token
# that maps to the regional S3 endpoint.
_COS_STORAGE_CLASS_SUFFIXES = frozenset(["standard", "vault", "cold", "flex", "smart"])


def _cos_endpoint_for_location(location):
    """Return the IBM COS S3 endpoint URL for a bucket location constraint.

    >>> _cos_endpoint_for_location("us-south-standard")
    'https://s3.us-south.cloud-object-storage.appdomain.cloud'
    >>> _cos_endpoint_for_location("eu-de-flex")
    'https://s3.eu-de.cloud-object-storage.appdomain.cloud'
    >>> _cos_endpoint_for_location("")
    None
    """
    if not location:
        return None
    parts = location.rsplit("-", 1)
    if len(parts) == 2 and parts[1] in _COS_STORAGE_CLASS_SUFFIXES:
        region = parts[0]
    else:
        region = location  # already a bare region token; use as-is
    return "https://s3.{}.cloud-object-storage.appdomain.cloud".format(region)


def _list_cos_instances(session):
    """Return all COS service instance details in the account via ResourceControllerV2.

    Fetches all service instances (type=service_instance) and filters
    client-side on the CRN service-name segment so we do not rely on the
    opaque global-catalog UUID that the ``resource_id`` query parameter needs.

    Returns a list of ``(guid, name, instance_crn)`` triples.
    """
    try:
        rc = session.client("resource-ctrl")
        instances = []
        start = None
        while True:
            kw = {"type": "service_instance", "limit": 50}
            if start:
                kw["start"] = start
            resp = rc.list_resource_instances(**kw).get_result()
            for inst in resp.get("resources", []):
                crn = inst.get("crn", "")
                if COS_CRN_SERVICE_NAME not in crn:
                    continue
                instances.append((
                    inst.get("guid", inst.get("id")),
                    inst.get("name", ""),
                    crn,
                ))
            next_url = resp.get("next_url")
            if not next_url:
                break
            for part in next_url.split("?", 1)[-1].split("&"):
                if part.startswith("start="):
                    start = part[len("start="):]
                    break
            else:
                break
        return instances
    except Exception as exc:
        log.warning(
            "Could not enumerate COS instances via ResourceController: %s. "
            "Set IBMCLOUD_COS_RESOURCE_INSTANCE_ID to bypass auto-discovery.",
            exc,
        )
        return []


def _lookup_instance_crn(session, guid):
    """Return the CRN for a COS service instance GUID via ResourceControllerV2.

    Used when the instance GUID is supplied via ``IBMCLOUD_COS_RESOURCE_INSTANCE_ID``
    so we can still obtain the taggable CRN for the tag action.  Returns an empty
    string if the lookup fails (tag action will warn and skip gracefully).
    """
    try:
        rc = session.client("resource-ctrl")
        resp = rc.get_resource_instance(id=guid).get_result()
        return resp.get("crn", "")
    except Exception as exc:
        log.warning(
            "Could not look up CRN for COS instance %s: %s. "
            "Tag action will be skipped for buckets in this instance.",
            guid, exc,
        )
        return ""


# ---------------------------------------------------------------------------
# Custom describe source for COS (uses ibm-cos-sdk, not IBM platform SDK)
# ---------------------------------------------------------------------------

@sources.register("describe-cos")
class COSDescribeSource(DescribeSource):
    """Source for COS buckets using ibm-cos-sdk (S3-compatible).

    Bucket enumeration uses one of three paths (tried in order):

    1. ``list_buckets_extended()`` — fast path, requires HMAC credentials.
    2. ``list_buckets(IBMServiceInstanceId=guid)`` per COS instance — works
       with IAM OAuth; iterates all COS service instances discovered via RC.
    3. Returns ``[]`` with a warning if neither path succeeds.
    """

    def get_resources(self, query):
        session = local_session(self.manager.session_factory)
        cos = session.cos_client()

        # --- Fast path: HMAC credentials → list_buckets_extended() -----------
        hmac_key = os.environ.get("IBMCLOUD_COS_HMAC_ACCESS_KEY_ID")
        if hmac_key:
            try:
                response = cos.list_buckets_extended()
                return self._normalise(response.get("Buckets", []))
            except Exception as exc:
                log.warning(
                    "list_buckets_extended failed even with HMAC credentials: %s. "
                    "Falling back to per-instance list_buckets.",
                    exc,
                )

        # --- IAM path: per-instance list_buckets(IBMServiceInstanceId=) ------
        # Gather COS instance GUIDs: env var takes priority, then RC discovery.
        env_guid = os.environ.get("IBMCLOUD_COS_RESOURCE_INSTANCE_ID", "").strip()
        if env_guid:
            env_crn = _lookup_instance_crn(session, env_guid)
            instance_guids = [(env_guid, "", env_crn)]
        else:
            instance_guids = _list_cos_instances(session)

        if not instance_guids:
            log.warning(
                "No COS service instance GUID available. "
                "Set IBMCLOUD_COS_RESOURCE_INSTANCE_ID or ensure the account "
                "has at least one Cloud Object Storage instance. "
                "Returning empty bucket list."
            )
            return []

        all_buckets = []
        for guid, inst_name, inst_crn in instance_guids:
            try:
                inst_cos = session.cos_client(cos_instance_id=guid)
                resp = inst_cos.list_buckets(IBMServiceInstanceId=guid)
                buckets = resp.get("Buckets", [])
                for b in buckets:
                    b["_cos_instance_id"] = guid
                    b["_cos_instance_name"] = inst_name
                    b["_cos_instance_crn"] = inst_crn
                all_buckets.extend(buckets)
            except Exception as exc:
                log.warning(
                    "list_buckets failed for COS instance %s (%s): %s",
                    guid, inst_name, exc,
                )

        return self._normalise(all_buckets)

    @staticmethod
    def _normalise(buckets):
        """Convert raw S3 bucket dicts to IBM-SDK-style lowercase-key dicts."""
        result = []
        for b in buckets:
            result.append({
                "name": b.get("Name", ""),
                "id": b.get("Name", ""),
                "created_at": str(b.get("CreationDate", "")),
                "location": b.get("LocationConstraint", ""),
                "c7n:instance_id": b.get("_cos_instance_id", ""),
                "c7n:instance_name": b.get("_cos_instance_name", ""),
                "c7n:instance_crn": b.get("_cos_instance_crn", ""),
            })
        return result

    def augment(self, resources):
        """Enrich each bucket with versioning, KP encryption status, ACL, and lifecycle.

        Key Protect (customer-managed key) status is read from the HEAD bucket
        response.  The ibm-cos-sdk maps the ``ibm-sse-kp-enabled`` and
        ``ibm-sse-kp-crk-id`` response headers to ``IBMSSEKPEnabled`` (bool)
        and ``IBMSSEKPCrkId`` (string) in the returned dict.
        """
        session = local_session(self.manager.session_factory)
        enriched = []
        for r in resources:
            name = r["name"]
            r = dict(r)
            location = r.get("location", "")
            # list_buckets() (IAM / non-HMAC path) does not return LocationConstraint,
            # so location may be empty.  Discover it via GetBucketLocation using the
            # default-region client, then switch to the correct regional endpoint.
            if not location:
                try:
                    probe = session.cos_client()
                    loc_resp = probe.get_bucket_location(Bucket=name)
                    location = loc_resp.get("LocationConstraint", "") or ""
                    r["location"] = location
                    log.debug("Discovered location %r for bucket %s", location, name)
                except Exception as exc:
                    log.debug("Could not determine location for bucket %s: %s", name, exc)
            endpoint = _cos_endpoint_for_location(location)
            cos = session.cos_client(endpoint_url=endpoint)
            # Versioning
            try:
                v = cos.get_bucket_versioning(Bucket=name)
                r["c7n:versioning"] = v.get("Status", "Disabled")
            except Exception:
                r["c7n:versioning"] = "unknown"
            # Key Protect (customer-managed key) encryption status.
            # IBMSSEKPEnabled is True when the bucket uses a Key Protect CRK.
            # IBMSSEKPCrkId is the CRN of the root key (empty string if none).
            # All IBM COS buckets are always encrypted; this specifically checks
            # for customer-managed keys vs IBM-managed keys.
            try:
                head = cos.head_bucket(Bucket=name)
                r["c7n:kp_enabled"] = bool(head.get("IBMSSEKPEnabled", False))
                r["c7n:kp_key_crn"] = head.get("IBMSSEKPCrkId", "")
            except Exception:
                r["c7n:kp_enabled"] = False
                r["c7n:kp_key_crn"] = ""
            # Public access check — two independent signals, any one is enough:
            # 1. S3 ACL grants: AllUsers or AuthenticatedUsers grantee URI.
            # 2. IAM Public Access policy: an IAM policy on this bucket whose subject
            #    carries iam_id="PUBLIC" (the built-in Public Access group). This is
            #    what the IBM Cloud Console "Public access" toggle creates.
            # NOTE: The RC Config firewall field is NOT used for public-access detection.
            #    A missing firewall key is the default state for all buckets — it does
            #    not mean the bucket is public. Only an explicitly empty allowed_ip list
            #    would indicate that, but that config is rarely used in practice and
            #    would produce false positives for normal private buckets.
            public = False
            # Signal 1 — S3 ACL: AllUsers or AuthenticatedUsers grantee URI
            try:
                acl = cos.get_bucket_acl(Bucket=name)
                grants = acl.get("Grants", [])
                public = any(
                    g.get("Grantee", {}).get("URI", "").endswith("AllUsers")
                    or g.get("Grantee", {}).get("URI", "").endswith("AuthenticatedUsers")
                    for g in grants
                )
            except Exception as exc:
                log.debug("Bucket %s ACL check failed (skipped): %s", name, exc)
            # RC Config fetch — used only for CRN and service_instance_crn (tagging),
            # not for public-access detection.
            rc_cfg_result = None
            try:
                rc_cfg = session.cos_resource_config_client()
                rc_cfg_result = rc_cfg.get_bucket_config(bucket=name).get_result()
            except Exception as exc:
                log.debug("Bucket %s RC config fetch failed (skipped): %s", name, exc)
            # Signal 2 — IAM Public Access group policy.
            #
            # The IBM Cloud Console "Public Access" toggle creates an IAM policy
            # attached to the built-in access group "Public Access", whose ID is
            # always "AccessGroupId-PublicAccess" across all IBM Cloud accounts.
            # list_policies(iam_id="PUBLIC") queries a different, unrelated subject
            # and returns 0 results — the correct call is access_group_id=.
            #
            # IBM IAM policy resource attributes for COS use this shape:
            #   accountId=<id>, serviceName=cloud-object-storage,
            #   serviceInstance=<guid>, resourceType=bucket, resource=<bucket-name>
            #
            # A policy grants public access to this bucket when:
            #   (a) resource=<bucket-name> or resource=<bucket-crn>   — bucket-scoped
            #   (b) resourceType=bucket but no resource attr           — instance-wide
            #   (c) serviceName=cloud-object-storage but no resourceType — service-wide
            #   (d) only accountId present                             — account-wide
            # Cases (b)–(d) mean all COS buckets (in scope) are public.
            if not public:
                try:
                    iam = session.client("iam-policy")
                    policies_resp = iam.list_policies(
                        account_id=session.account_id,
                        access_group_id=_PUBLIC_ACCESS_GROUP_ID,
                    ).get_result()
                    bucket_crn = r.get("crn") or (rc_cfg_result.get("crn") if rc_cfg_result else "")
                    instance_id = r.get("c7n:instance_id", "")
                    raw_policies = policies_resp.get("policies", [])
                    for iam_policy in raw_policies:
                        # Use a local variable so we don't shadow the outer `resources` param.
                        policy_resources = iam_policy.get("resources", [])
                        for res in policy_resources:
                            attrs = {a.get("name"): a.get("value", "") for a in res.get("attributes", [])}
                            resource_val  = attrs.get("resource", "")
                            resource_type = attrs.get("resourceType", "")
                            service_name  = attrs.get("serviceName", "")
                            svc_instance  = attrs.get("serviceInstance", "")

                            # (a) Bucket-scoped: resource matches by name or CRN
                            if resource_val and (
                                resource_val == name
                                or (bucket_crn and resource_val == bucket_crn)
                            ):
                                public = True
                            # (b) Instance-wide: resourceType=bucket, no specific resource
                            elif resource_type == "bucket" and not resource_val:
                                if not svc_instance or svc_instance == instance_id:
                                    public = True
                            # (c) Service-wide: serviceName=cos, no resourceType
                            elif service_name == "cloud-object-storage" and not resource_type:
                                public = True
                            # (d) Account-wide: only accountId constrained
                            elif not service_name and not resource_type and not resource_val:
                                public = True
                except Exception as exc:
                    log.debug("Bucket %s IAM public-access check failed (skipped): %s", name, exc)
            r["c7n:public_access"] = public
            # Bucket CRN from RC config; fall back to service_instance_crn for tagging.
            if not r.get("crn") and rc_cfg_result is not None:
                r["crn"] = rc_cfg_result.get("crn", "")
            # Backfill instance CRN from RC config response if enumeration path
            # didn't supply it (e.g. HMAC path or env-var GUID with no RC lookup).
            if not r.get("c7n:instance_crn") and rc_cfg_result is not None:
                r["c7n:instance_crn"] = rc_cfg_result.get("service_instance_crn", "")
            # Lifecycle
            try:
                lc = cos.get_bucket_lifecycle_configuration(Bucket=name)
                r["c7n:lifecycle"] = lc.get("Rules", [])
            except Exception:
                r["c7n:lifecycle"] = []
            enriched.append(r)
        return enriched


# ---------------------------------------------------------------------------
# ibm.cos-bucket
# ---------------------------------------------------------------------------

@resources.register("cos-bucket")
class COSBucket(QueryResourceManager):
    """IBM Cloud Object Storage buckets.

    All IBM COS buckets are always encrypted at rest with IBM-managed keys.
    Use the ``customer-managed-key`` filter to detect buckets that do not use a
    customer-managed Key Protect root key (``IBMSSEKPEnabled=False``).

    :example:

    Find COS buckets with public ACL access:

    .. code-block:: yaml

        policies:
          - name: ibm-cos-public-buckets
            resource: ibm.cos-bucket
            filters:
              - type: public-access
                value: true

    Find buckets using only IBM-managed encryption (no customer Key Protect key):

    .. code-block:: yaml

        policies:
          - name: ibm-cos-no-customer-managed-key
            resource: ibm.cos-bucket
            filters:
              - type: customer-managed-key
                value: false
            actions:
              - type: tag
                tags:
                  compliance: no-customer-managed-key
    """

    source_mapping = {"describe-cos": COSDescribeSource}

    class resource_type(TypeInfo):
        service = "cos"
        global_service = True
        enum_spec = ("list_buckets_extended", "Buckets", None)
        pagination = None
        id = "name"
        name = "name"
        default_report_fields = ("name", "location", "created_at")
        permissions = ("cloud-object-storage.bucket.list",)
        scope = "account"

    @property
    def source_type(self):
        return self.data.get("source", "describe-cos")

    def _fetch_resources(self, query):
        # COSDescribeSource.augment() enriches each bucket with versioning,
        # KP status, ACL, lifecycle, RC config, and IAM public-access metadata.
        # The base class _fetch_resources calls self.augment() (a no-op here);
        # we must explicitly call self.source.augment() instead.
        return self.source.augment(self.source.get_resources(query) or [])


@COSBucket.filter_registry.register("public-access")
class COSBucketPublicAccessFilter(PublicAccessFilter):
    pass


@COSBucket.filter_registry.register("age")
class COSBucketAgeFilter(AgeFilter):
    date_attribute = "created_at"


@COSBucket.filter_registry.register("tag")
class COSBucketTagFilter(TagFilter):
    pass


@COSBucket.filter_registry.register("versioning-enabled")
class COSBucketVersioningFilter(IBMBaseAction):
    """Match buckets based on whether versioning is enabled.

    .. code-block:: yaml

        policies:
          - name: ibm-cos-unversioned
            resource: ibm.cos-bucket
            filters:
              - type: versioning-enabled
                value: false
    """

    # This is a filter, not an action — inheriting IBMBaseAction for schema only
    # Implemented as a proper Filter below.
    pass


from c7n.filters import Filter  # noqa


@COSBucket.filter_registry.register("versioning-enabled")
class COSBucketVersioningFilter(Filter):
    type = "versioning-enabled"
    schema = type_schema("versioning-enabled", value={"type": "boolean"})

    def process(self, resources, event=None):
        want = self.data.get("value", True)
        return [
            r for r in resources
            if (r.get("c7n:versioning", "Disabled") == "Enabled") == want
        ]


@COSBucket.filter_registry.register("lifecycle-configured")
class COSBucketLifecycleFilter(Filter):
    """Match buckets based on whether a lifecycle configuration exists.

    IBM COS lifecycle rules are fetched during augmentation and stored as
    ``c7n:lifecycle`` (a list of rule dicts, possibly empty).

    ``value: true``  — buckets that have at least one lifecycle rule
    ``value: false`` — buckets with no lifecycle rules at all

    Cannot be expressed as a plain ``type: value`` filter because JMESPath
    rejects keys that contain a colon (``c7n:lifecycle``).

    .. code-block:: yaml

        policies:
          - name: cos-bucket-no-lifecycle
            resource: ibm.cos-bucket
            filters:
              - type: lifecycle-configured
                value: false
    """

    type = "lifecycle-configured"
    schema = type_schema("lifecycle-configured", value={"type": "boolean"})

    def process(self, resources, event=None):
        want = self.data.get("value", True)
        return [
            r for r in resources
            if bool(r.get("c7n:lifecycle")) == want
        ]


@COSBucket.filter_registry.register("customer-managed-key")
class COSBucketCustomerManagedKeyFilter(Filter):
    """Match buckets based on whether they use a customer-managed Key Protect key.

    IBM COS always encrypts data at rest using IBM-managed keys.  The meaningful
    compliance check is whether a bucket also uses a **customer-managed root key**
    (CMK) stored in IBM Key Protect, which gives the account owner full control
    over key lifecycle including revocation.

    ``value: true``  — buckets that already use a CMK (``IBMSSEKPEnabled=True``)
    ``value: false`` — buckets that use only IBM-managed keys (the default)

    .. code-block:: yaml

        policies:
          - name: ibm-cos-no-customer-managed-key
            resource: ibm.cos-bucket
            filters:
              - type: customer-managed-key
                value: false
            actions:
              - type: tag
                tags:
                  compliance: no-customer-managed-key
    """

    type = "customer-managed-key"
    schema = type_schema("customer-managed-key", value={"type": "boolean"})

    def process(self, resources, event=None):
        want = self.data.get("value", True)
        return [r for r in resources if r.get("c7n:kp_enabled", False) == want]


@COSBucket.action_registry.register("tag")
class COSBucketTagAction(IBMBaseAction):
    """Tag the COS **service instance** that owns a bucket.

    IBM COS buckets are not directly taggable via GlobalTaggingV1 — only the
    parent service instance (a Resource Controller resource) has a CRN that
    the tagging API accepts.

    This action attaches each tag to the **instance CRN** and encodes the
    offending bucket name into the tag value so operators know which bucket
    triggered the policy:

    .. code-block:: text

        custodian-review:public-access/bucket-name

    The tag value format is ``<policy-value>/<bucket-name>``.

    .. code-block:: yaml

        policies:
          - name: cos-bucket-public-access
            resource: ibm.cos-bucket
            filters:
              - type: public-access
                value: true
            actions:
              - type: tag
                tags:
                  custodian-review: "public-access"
    """

    type = "tag"
    schema = type_schema(
        "tag",
        tags={"type": "object", "additionalProperties": {"type": "string"}},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        instance_crn = resource.get("c7n:instance_crn", "")
        if not instance_crn:
            log.warning(
                "Bucket %s has no service instance CRN; skipping tag action. "
                "Ensure IBMCLOUD_COS_RESOURCE_INSTANCE_ID is set or the account "
                "API key has ResourceController list access.",
                resource.get("name", resource.get("id")),
            )
            return

        bucket_name = resource.get("name", resource.get("id", "unknown"))
        tags = self.data.get("tags", {})
        # Encode bucket name into the tag value so operators know which bucket
        # triggered the policy: e.g. "custodian-review:public-access--my-bucket-name"
        # IBM Cloud user tags cannot contain "/" — use "--" as the separator.
        tag_list = ["%s:%s--%s" % (k, v, bucket_name) for k, v in tags.items()]
        tag_type = getattr(self.manager.resource_type, "tag_type", "user")

        session = local_session(self.manager.session_factory)
        client = session.client("global-tagging")

        from ibm_platform_services.global_tagging_v1 import Resource

        if tag_type == "access":
            _ensure_access_tags(client, tag_list)

        client.attach_tag(
            resources=[Resource(resource_id=instance_crn)],
            tag_names=tag_list,
            tag_type=tag_type,
        )
        log.debug(
            "Tagged COS instance %s with %s on behalf of bucket %s (tag_type=%s)",
            instance_crn, tag_list, bucket_name, tag_type,
        )


@COSBucket.action_registry.register("remove-tag")
class COSBucketRemoveTagAction(IBMBaseAction):
    """Remove tags from the COS **service instance** that owns a bucket.

    Mirrors :class:`COSBucketTagAction` — operates on the instance CRN, not
    the bucket itself.

    .. code-block:: yaml

        policies:
          - name: cos-clear-review-tags
            resource: ibm.cos-bucket
            actions:
              - type: remove-tag
                tags:
                  - custodian-review
    """

    type = "remove-tag"
    schema = type_schema(
        "remove-tag",
        tags={"type": "array", "items": {"type": "string"}},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        instance_crn = resource.get("c7n:instance_crn", "")
        if not instance_crn:
            log.warning(
                "Bucket %s has no service instance CRN; skipping remove-tag action.",
                resource.get("name", resource.get("id")),
            )
            return

        session = local_session(self.manager.session_factory)
        client = session.client("global-tagging")

        from ibm_platform_services.global_tagging_v1 import Resource

        tag_names = self.data.get("tags", [])
        tag_type = getattr(self.manager.resource_type, "tag_type", "user")
        client.detach_tag(
            resources=[Resource(resource_id=instance_crn)],
            tag_names=tag_names,
            tag_type=tag_type,
        )
        log.debug(
            "Removed tags %s from COS instance %s on behalf of bucket %s (tag_type=%s)",
            tag_names, instance_crn, resource.get("name", ""), tag_type,
        )


@COSBucket.action_registry.register("set-versioning")
class COSSetVersioning(IBMBaseAction):
    """Enable or suspend versioning on a COS bucket.

    .. code-block:: yaml

        policies:
          - name: ibm-cos-enable-versioning
            resource: ibm.cos-bucket
            filters:
              - type: versioning-enabled
                value: false
            actions:
              - type: set-versioning
                enabled: true
    """

    type = "set-versioning"
    schema = type_schema(
        "set-versioning",
        enabled={"type": "boolean"},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        endpoint = _cos_endpoint_for_location(resource.get("location", ""))
        cos = session.cos_client(endpoint_url=endpoint)
        status = "Enabled" if self.data.get("enabled", True) else "Suspended"
        cos.put_bucket_versioning(
            Bucket=resource["name"],
            VersioningConfiguration={"Status": status},
        )
        log.debug("Set versioning=%s on bucket %s", status, resource["name"])


@COSBucket.action_registry.register("set-encryption")
class COSSetEncryption(IBMBaseAction):
    """Tag a COS bucket to record that SSE enforcement is required.

    IBM COS does not expose a ``put_bucket_encryption`` S3 API call.
    Server-side encryption in IBM COS is configured at the service-instance
    level via Key Protect integration — it cannot be toggled per-bucket
    through the S3 API.

    This action records the intent by tagging the bucket so that the
    configuration can be applied manually via the IBM Cloud console or
    the Resource Configuration API (``PATCH /b/{bucket}`` with
    ``{"firewall": {...}, "activity_tracking": {...}}`` — outside the
    scope of the S3 SDK).

    .. code-block:: yaml

        policies:
          - name: ibm-cos-no-customer-managed-key
            resource: ibm.cos-bucket
            filters:
              - type: customer-managed-key
                value: false
            actions:
              - type: set-encryption
    """

    type = "set-encryption"
    schema = type_schema(
        "set-encryption",
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        log.warning(
            "set-encryption: IBM COS does not support per-bucket SSE configuration "
            "via the S3 API. Bucket %s requires manual Key Protect integration via "
            "the IBM Cloud console or Resource Configuration API (PATCH /b/{bucket}). "
            "Tag the bucket for follow-up instead.",
            resource["name"],
        )


@COSBucket.action_registry.register("set-lifecycle")
class COSSetLifecycle(IBMBaseAction):
    """Apply or replace a lifecycle configuration on a COS bucket.

    .. code-block:: yaml

        policies:
          - name: ibm-cos-90-day-expiry
            resource: ibm.cos-bucket
            actions:
              - type: set-lifecycle
                rules:
                  - ID: expire-old-objects
                    Status: Enabled
                    Expiration:
                      Days: 90
    """

    type = "set-lifecycle"
    schema = type_schema(
        "set-lifecycle",
        rules={"type": "array", "items": {"type": "object"}},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        endpoint = _cos_endpoint_for_location(resource.get("location", ""))
        cos = session.cos_client(endpoint_url=endpoint)
        rules = self.data.get("rules", [])
        cos.put_bucket_lifecycle_configuration(
            Bucket=resource["name"],
            LifecycleConfiguration={"Rules": rules},
        )
        log.debug("Set lifecycle on bucket %s", resource["name"])

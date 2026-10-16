# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""Tests for IBM Cloud Object Storage resources."""

import os
from unittest.mock import MagicMock, patch

from conftest import FakeSession, FakeSessionFactory, FakeResult


# ---------------------------------------------------------------------------
# Sample resource data
# ---------------------------------------------------------------------------

SAMPLE_BUCKETS_RAW = {
    "Buckets": [
        {"Name": "my-data-bucket", "LocationConstraint": "us-south", "CreationDate": "2023-01-01"},
        {"Name": "logs-bucket", "LocationConstraint": "eu-de", "CreationDate": "2022-06-15"},
    ],
    "ResponseMetadata": {},
}

SAMPLE_BUCKET_VERSIONING_ENABLED = {"Status": "Enabled"}
SAMPLE_BUCKET_VERSIONING_DISABLED = {"Status": "Disabled"}
# HEAD bucket response when Key Protect CMK is enabled
SAMPLE_HEAD_BUCKET_KP_ENABLED = {"IBMSSEKPEnabled": True,  "IBMSSEKPCrkId": "crn:v1:bluemix:public:kms:us-south:a/123:inst-001:key:key-001"}
SAMPLE_HEAD_BUCKET_KP_DISABLED = {"IBMSSEKPEnabled": False, "IBMSSEKPCrkId": ""}
SAMPLE_BUCKET_ACL_PUBLIC = {
    "Grants": [
        {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}
    ]
}
SAMPLE_BUCKET_ACL_PRIVATE = {"Grants": []}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cos_client(
    versioning=None,
    head_bucket=None,
    acl=None,
    lifecycle=None,
    buckets_response=None,
    list_buckets_response=None,
):
    cos = MagicMock()
    cos.list_buckets_extended.return_value = buckets_response or SAMPLE_BUCKETS_RAW
    cos.list_buckets.return_value = list_buckets_response or SAMPLE_BUCKETS_RAW
    cos.get_bucket_versioning.return_value = versioning or SAMPLE_BUCKET_VERSIONING_DISABLED
    cos.head_bucket.return_value = head_bucket or SAMPLE_HEAD_BUCKET_KP_DISABLED
    cos.get_bucket_acl.return_value = acl or SAMPLE_BUCKET_ACL_PRIVATE
    cos.get_bucket_lifecycle_configuration.return_value = lifecycle or {"Rules": []}
    cos.put_bucket_versioning.return_value = {}
    cos.put_bucket_lifecycle_configuration.return_value = {}
    return cos


def _make_rc_config_client(bucket_config=None):
    """Build a fake COSResourceConfigClient returning bucket config."""
    rc_config = MagicMock()
    rc_config.get_bucket_config.return_value = FakeResult(
        bucket_config or {
            "crn": "crn:v1:bluemix:public:cloud-object-storage:global:a/123:inst-001:bucket:test-bucket",
            "firewall": None,
        }
    )
    return rc_config


COS_INSTANCE_CRN = "crn:v1:bluemix:public:cloud-object-storage:global:a/123:cos-guid-001::"


def _make_rc_client(cos_instances=None):
    """Build a fake ResourceControllerV2 client returning COS instances."""
    rc = MagicMock()
    instances = cos_instances or [
        {
            "guid": "cos-guid-001",
            "name": "my-cos-instance",
            "crn": COS_INSTANCE_CRN,
        },
    ]
    rc.list_resource_instances.return_value = FakeResult(
        {"resources": instances, "next_url": None}
    )
    return rc


def _make_iam_policy_client(policies=None):
    """Build a fake IamPolicyManagementV1 client."""
    iam = MagicMock()
    iam.list_policies.return_value = FakeResult({"policies": policies or []})
    return iam


def _make_cos_session(rc_config=None, iam_policies=None, **kwargs):
    cos = _make_cos_client(**kwargs)
    rc = _make_rc_client()
    rc_cfg = rc_config if rc_config is not None else _make_rc_config_client()
    iam = _make_iam_policy_client(iam_policies)
    session = FakeSession(clients={"cos": cos, "resource-ctrl": rc, "iam-policy": iam})
    session._cos_client = cos
    # Override cos_client method to return the mock for any instance ID
    session.cos_client = lambda **kw: cos
    # Wire up the RC config client
    session.cos_resource_config_client = lambda: rc_cfg
    return session, cos


# ---------------------------------------------------------------------------
# Tests: COSDescribeSource augmentation
# ---------------------------------------------------------------------------

class TestCOSBucketAugmentation:

    def test_versioning_detection(self):
        """Augmented buckets should carry c7n:versioning metadata."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        session, cos = _make_cos_session(versioning=SAMPLE_BUCKET_VERSIONING_ENABLED)

        raw = [{"name": "my-data-bucket", "id": "my-data-bucket", "location": "us-south"}]

        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert enriched[0]["c7n:versioning"] == "Enabled"

    def test_public_access_detection_via_acl(self):
        """Augmented buckets should set c7n:public_access=True for AllUsers ACL grants."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        session, cos = _make_cos_session(acl=SAMPLE_BUCKET_ACL_PUBLIC)

        raw = [{"name": "my-data-bucket", "id": "my-data-bucket", "location": "us-south"}]

        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert enriched[0]["c7n:public_access"] is True

    def test_public_access_false_when_only_acl_private_and_no_iam_public_policy(self):
        """Private ACL + no IAM PUBLIC policy → bucket must NOT be flagged public.
        A missing firewall key is normal for all buckets and must not cause a false positive."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        # No firewall in RC config (the normal default), private ACL, no PUBLIC IAM policy
        rc_cfg = _make_rc_config_client({"crn": "crn:x", "service_instance_crn": COS_INSTANCE_CRN, "firewall": None})
        session, cos = _make_cos_session(acl=SAMPLE_BUCKET_ACL_PRIVATE, rc_config=rc_cfg)

        raw = [{"name": "private-bucket", "id": "private-bucket", "location": "us-south"}]
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert enriched[0]["c7n:public_access"] is False

    def test_crn_injected_from_rc_config(self):
        """Augmented bucket should carry the CRN from the RC Configuration API."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        expected_crn = "crn:v1:bluemix:public:cloud-object-storage:global:a/123:inst-001:bucket:test-bucket"
        rc_cfg = _make_rc_config_client({"crn": expected_crn, "firewall": {"allowed_ip": ["10.0.0.1"]}})
        session, cos = _make_cos_session(rc_config=rc_cfg)

        raw = [{"name": "test-bucket", "id": "test-bucket", "location": "us-south"}]

        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert enriched[0]["crn"] == expected_crn

    def test_crn_not_overwritten_if_already_present(self):
        """If the bucket already has a crn field, the RC API value must not overwrite it."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        existing_crn = "crn:already:present"
        rc_cfg = _make_rc_config_client({"crn": "crn:from:rc:api", "firewall": None})
        session, cos = _make_cos_session(rc_config=rc_cfg)

        raw = [{"name": "crn-bucket", "id": "crn-bucket", "crn": existing_crn, "location": "us-south"}]

        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert enriched[0]["crn"] == existing_crn

    def test_rc_config_failure_is_silent(self):
        """If the RC Configuration API fails, augmentation continues without raising."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        # RC config raises on every call
        rc_cfg = MagicMock()
        rc_cfg.get_bucket_config.side_effect = Exception("network error")
        session, cos = _make_cos_session(rc_config=rc_cfg)

        raw = [{"name": "fail-bucket", "id": "fail-bucket", "location": "us-south"}]

        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        # Must still return the bucket; no CRN, public_access defaults False
        assert len(enriched) == 1
        assert enriched[0].get("crn", "") == ""
        assert enriched[0]["c7n:public_access"] is False

    def test_public_access_detection_via_iam_public_access_group(self):
        """IBM Console 'Public access' toggle creates a policy on the built-in
        'Public Access' access group (AccessGroupId-PublicAccess). augment() must
        detect it via list_policies(access_group_id=...) even when ACL returns no
        public grants."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        rc_cfg = _make_rc_config_client({"crn": "crn:x", "service_instance_crn": COS_INSTANCE_CRN})
        # Policy attached to the Public Access group, bucket-scoped by resource name
        iam_policies = [
            {
                "id": "f5167019-1455-488c-94a9-48e87f22cb60",
                "resources": [{"attributes": [
                    {"name": "accountId",       "value": "6894df1861474982a4aa7b6c82e8f5cf"},
                    {"name": "serviceName",     "value": "cloud-object-storage"},
                    {"name": "serviceInstance", "value": "bf04b173-701b-4b3b-bcda-63ba0cd88719"},
                    {"name": "resource",        "value": "pub-bucket"},
                    {"name": "resourceType",    "value": "bucket"},
                ]}],
            }
        ]
        session, cos = _make_cos_session(
            acl=SAMPLE_BUCKET_ACL_PRIVATE,
            rc_config=rc_cfg,
            iam_policies=iam_policies,
        )

        raw = [{"name": "pub-bucket", "id": "pub-bucket", "location": "us-south"}]
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert enriched[0]["c7n:public_access"] is True

    def test_public_access_false_when_no_public_access_group_policy(self):
        """A bucket with no policies on the Public Access group must not be flagged."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        rc_cfg = _make_rc_config_client({"crn": "crn:x", "service_instance_crn": COS_INSTANCE_CRN})
        # Public Access group has no policies at all
        session, cos = _make_cos_session(
            acl=SAMPLE_BUCKET_ACL_PRIVATE,
            rc_config=rc_cfg,
            iam_policies=[],
        )

        raw = [{"name": "private-bucket", "id": "private-bucket", "location": "us-south"}]
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert enriched[0]["c7n:public_access"] is False

    def test_iam_policy_check_uses_access_group_id(self):
        """list_policies must be called with access_group_id=AccessGroupId-PublicAccess."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource, _PUBLIC_ACCESS_GROUP_ID
        from unittest.mock import MagicMock

        rc_cfg = _make_rc_config_client({"crn": "crn:x", "service_instance_crn": COS_INSTANCE_CRN})
        session, cos = _make_cos_session(acl=SAMPLE_BUCKET_ACL_PRIVATE, rc_config=rc_cfg)
        iam_client = session._clients["iam-policy"]

        raw = [{"name": "scoped-bucket", "id": "scoped-bucket", "location": "us-south"}]
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            source.augment(raw)

        iam_client.list_policies.assert_called_once()
        call_kwargs = iam_client.list_policies.call_args[1]
        assert call_kwargs["access_group_id"] == _PUBLIC_ACCESS_GROUP_ID
        assert "iam_id" not in call_kwargs
        assert "resource_service_name" not in call_kwargs

    def test_iam_policy_check_failure_is_silent(self):
        """If the IAM policy list call fails, augmentation continues without raising."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        rc_cfg = _make_rc_config_client({"crn": "crn:x", "service_instance_crn": COS_INSTANCE_CRN, "firewall": None})
        bad_iam = MagicMock()
        bad_iam.list_policies.side_effect = Exception("permission denied")
        session, cos = _make_cos_session(acl=SAMPLE_BUCKET_ACL_PRIVATE, rc_config=rc_cfg)
        session._clients["iam-policy"] = bad_iam

        raw = [{"name": "fail-iam-bucket", "id": "fail-iam-bucket", "location": "us-south"}]
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert len(enriched) == 1
        assert enriched[0]["c7n:public_access"] is False


    def test_public_access_detection_via_iam_instance_wide_policy(self):
        """Instance-wide PUBLIC policy (resourceType=bucket, no resource) flags all buckets in that instance."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        rc_cfg = _make_rc_config_client({"crn": "crn:x", "service_instance_crn": COS_INSTANCE_CRN})
        # Policy targets all buckets in this instance (no specific resource attribute)
        iam_policies = [
            {
                "subjects": [{"attributes": [{"name": "iam_id", "value": "PUBLIC"}]}],
                "roles": [{"role_id": "crn:v1:bluemix:public:cloud-object-storage::::role:ObjectReader"}],
                "resources": [{"attributes": [
                    {"name": "serviceName",    "value": "cloud-object-storage"},
                    {"name": "serviceInstance","value": "cos-guid-001"},
                    {"name": "resourceType",   "value": "bucket"},
                    # no "resource" attribute — matches ALL buckets in the instance
                ]}],
            }
        ]
        session, cos = _make_cos_session(
            acl=SAMPLE_BUCKET_ACL_PRIVATE,
            rc_config=rc_cfg,
            iam_policies=iam_policies,
        )

        raw = [{"name": "any-bucket", "id": "any-bucket", "location": "us-south",
                "c7n:instance_id": "cos-guid-001"}]
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert enriched[0]["c7n:public_access"] is True

    def test_public_access_false_iam_instance_wide_policy_different_instance(self):
        """Instance-wide PUBLIC policy for a different instance must NOT flag this bucket."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        rc_cfg = _make_rc_config_client({"crn": "crn:x", "service_instance_crn": COS_INSTANCE_CRN})
        # Policy targets a different COS instance
        iam_policies = [
            {
                "subjects": [{"attributes": [{"name": "iam_id", "value": "PUBLIC"}]}],
                "roles": [{"role_id": "crn:v1:bluemix:public:cloud-object-storage::::role:ObjectReader"}],
                "resources": [{"attributes": [
                    {"name": "serviceName",    "value": "cloud-object-storage"},
                    {"name": "serviceInstance","value": "other-guid-999"},
                    {"name": "resourceType",   "value": "bucket"},
                ]}],
            }
        ]
        session, cos = _make_cos_session(
            acl=SAMPLE_BUCKET_ACL_PRIVATE,
            rc_config=rc_cfg,
            iam_policies=iam_policies,
        )

        raw = [{"name": "my-bucket", "id": "my-bucket", "location": "us-south",
                "c7n:instance_id": "cos-guid-001"}]
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert enriched[0]["c7n:public_access"] is False

    def test_public_access_detection_via_iam_service_wide_policy(self):
        """Service-wide PUBLIC policy (serviceName=cos, no resourceType) flags all COS buckets."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        rc_cfg = _make_rc_config_client({"crn": "crn:x", "service_instance_crn": COS_INSTANCE_CRN})
        iam_policies = [
            {
                "subjects": [{"attributes": [{"name": "iam_id", "value": "PUBLIC"}]}],
                "roles": [{"role_id": "crn:v1:bluemix:public:cloud-object-storage::::role:ObjectReader"}],
                "resources": [{"attributes": [
                    {"name": "serviceName", "value": "cloud-object-storage"},
                    # no resourceType — applies to all resources in the service
                ]}],
            }
        ]
        session, cos = _make_cos_session(
            acl=SAMPLE_BUCKET_ACL_PRIVATE,
            rc_config=rc_cfg,
            iam_policies=iam_policies,
        )

        raw = [{"name": "wide-bucket", "id": "wide-bucket", "location": "us-south"}]
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert enriched[0]["c7n:public_access"] is True

    def test_public_access_detection_via_iam_account_wide_policy(self):
        """Account-wide PUBLIC policy (only accountId constrained) flags every resource."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        rc_cfg = _make_rc_config_client({"crn": "crn:x", "service_instance_crn": COS_INSTANCE_CRN})
        iam_policies = [
            {
                "subjects": [{"attributes": [{"name": "iam_id", "value": "PUBLIC"}]}],
                "roles": [{"role_id": "crn:v1:bluemix:public:iam::::role:Viewer"}],
                "resources": [{"attributes": [
                    {"name": "accountId", "value": "account-123"},
                    # no serviceName, resourceType, or resource — applies to everything
                ]}],
            }
        ]
        session, cos = _make_cos_session(
            acl=SAMPLE_BUCKET_ACL_PRIVATE,
            rc_config=rc_cfg,
            iam_policies=iam_policies,
        )

        raw = [{"name": "any-bucket", "id": "any-bucket", "location": "us-south"}]
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert enriched[0]["c7n:public_access"] is True


    def test_kp_enabled_detection(self):
        """Augmented buckets with Key Protect should carry c7n:kp_enabled=True and c7n:kp_key_crn."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        session, cos = _make_cos_session(head_bucket=SAMPLE_HEAD_BUCKET_KP_ENABLED)

        raw = [{"name": "secure-bucket", "id": "secure-bucket", "location": "us-south"}]

        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert enriched[0]["c7n:kp_enabled"] is True
        assert "key-001" in enriched[0]["c7n:kp_key_crn"]
        cos.head_bucket.assert_called_once_with(Bucket="secure-bucket")

    def test_kp_disabled_detection(self):
        """Augmented buckets without Key Protect carry c7n:kp_enabled=False."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        from unittest.mock import MagicMock

        session, cos = _make_cos_session(head_bucket=SAMPLE_HEAD_BUCKET_KP_DISABLED)

        raw = [{"name": "plain-bucket", "id": "plain-bucket", "location": "us-south"}]

        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        assert enriched[0]["c7n:kp_enabled"] is False
        assert enriched[0]["c7n:kp_key_crn"] == ""

    def test_augment_discovers_location_when_missing(self):
        """When location is empty (IAM list_buckets path), augment calls get_bucket_location
        and stores the discovered value so actions can build the correct endpoint."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource

        session, cos = _make_cos_session()
        # get_bucket_location returns the LocationConstraint
        cos.get_bucket_location = MagicMock(
            return_value={"LocationConstraint": "eu-de-standard"}
        )

        # Bucket has no location (as returned by IAM list_buckets)
        raw = [{"name": "iamonly-bucket", "id": "iamonly-bucket", "location": ""}]

        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        # Location must now be populated from GetBucketLocation
        assert enriched[0]["location"] == "eu-de-standard"
        cos.get_bucket_location.assert_called_once_with(Bucket="iamonly-bucket")

    def test_augment_location_discovery_failure_is_silent(self):
        """If get_bucket_location fails, augment must continue without raising."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource

        session, cos = _make_cos_session()
        cos.get_bucket_location = MagicMock(side_effect=Exception("permission denied"))

        raw = [{"name": "mystery-bucket", "id": "mystery-bucket", "location": ""}]

        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            enriched = source.augment(raw)

        # Must still return the bucket (with empty location)
        assert len(enriched) == 1
        assert enriched[0]["location"] == ""


# ---------------------------------------------------------------------------
# Tests: COS filters
# ---------------------------------------------------------------------------

class TestCOSFilters:

    def _sample_augmented(self, versioning="Disabled", kp_enabled=False, kp_key_crn="", public=False):
        return [
            {
                "name": "test-bucket",
                "id": "test-bucket",
                "location": "us-south",
                "c7n:versioning": versioning,
                "c7n:kp_enabled": kp_enabled,
                "c7n:kp_key_crn": kp_key_crn,
                "c7n:public_access": public,
                "c7n:lifecycle": [],
                "tags": [],
            }
        ]

    def test_versioning_filter_disabled(self):
        """versioning-enabled=false should match unversioned buckets."""
        from c7n_ibmcloud.resources.cos import COSBucketVersioningFilter

        buckets = self._sample_augmented(versioning="Disabled")
        f = COSBucketVersioningFilter({"type": "versioning-enabled", "value": False}, None)
        result = f.process(buckets)
        assert len(result) == 1

    def test_versioning_filter_enabled(self):
        """versioning-enabled=true should NOT match unversioned bucket."""
        from c7n_ibmcloud.resources.cos import COSBucketVersioningFilter

        buckets = self._sample_augmented(versioning="Disabled")
        f = COSBucketVersioningFilter({"type": "versioning-enabled", "value": True}, None)
        result = f.process(buckets)
        assert len(result) == 0

    def test_customer_managed_key_filter_no_cmk(self):
        """customer-managed-key=false matches buckets using only IBM-managed keys."""
        from c7n_ibmcloud.resources.cos import COSBucketCustomerManagedKeyFilter

        buckets = self._sample_augmented(kp_enabled=False)
        f = COSBucketCustomerManagedKeyFilter({"type": "customer-managed-key", "value": False}, None)
        result = f.process(buckets)
        assert len(result) == 1

    def test_customer_managed_key_filter_with_cmk(self):
        """customer-managed-key=true matches buckets that use a Key Protect CMK."""
        from c7n_ibmcloud.resources.cos import COSBucketCustomerManagedKeyFilter

        crn = "crn:v1:bluemix:public:kms:us-south:a/123:inst:key:k1"
        buckets = self._sample_augmented(kp_enabled=True, kp_key_crn=crn)
        f = COSBucketCustomerManagedKeyFilter({"type": "customer-managed-key", "value": True}, None)
        result = f.process(buckets)
        assert len(result) == 1

    def test_customer_managed_key_filter_excludes_cmk_buckets_when_false(self):
        """customer-managed-key=false must NOT return buckets that already have a CMK."""
        from c7n_ibmcloud.resources.cos import COSBucketCustomerManagedKeyFilter

        crn = "crn:v1:bluemix:public:kms:us-south:a/123:inst:key:k1"
        buckets = self._sample_augmented(kp_enabled=True, kp_key_crn=crn)
        f = COSBucketCustomerManagedKeyFilter({"type": "customer-managed-key", "value": False}, None)
        result = f.process(buckets)
        assert result == []

    def test_public_access_filter(self):
        """public-access=true should match publicly accessible buckets."""
        from c7n_ibmcloud.filters.base import PublicAccessFilter

        buckets = self._sample_augmented(public=True)
        f = PublicAccessFilter({"type": "public-access", "value": True}, None)
        result = f.process(buckets)
        assert len(result) == 1

    def test_lifecycle_configured_filter_false(self):
        """lifecycle-configured=false matches buckets with no lifecycle rules."""
        from c7n_ibmcloud.resources.cos import COSBucketLifecycleFilter

        buckets = self._sample_augmented()  # c7n:lifecycle defaults to []
        f = COSBucketLifecycleFilter({"type": "lifecycle-configured", "value": False}, None)
        result = f.process(buckets)
        assert len(result) == 1

    def test_lifecycle_configured_filter_true(self):
        """lifecycle-configured=true matches buckets that have at least one rule."""
        from c7n_ibmcloud.resources.cos import COSBucketLifecycleFilter

        buckets = [dict(self._sample_augmented()[0], **{"c7n:lifecycle": [{"ID": "expire-90", "Status": "Enabled"}]})]
        f = COSBucketLifecycleFilter({"type": "lifecycle-configured", "value": True}, None)
        result = f.process(buckets)
        assert len(result) == 1

    def test_lifecycle_configured_filter_excludes_configured_buckets(self):
        """lifecycle-configured=false must NOT return buckets that already have rules."""
        from c7n_ibmcloud.resources.cos import COSBucketLifecycleFilter

        buckets = [dict(self._sample_augmented()[0], **{"c7n:lifecycle": [{"ID": "expire-90", "Status": "Enabled"}]})]
        f = COSBucketLifecycleFilter({"type": "lifecycle-configured", "value": False}, None)
        result = f.process(buckets)
        assert result == []


# ---------------------------------------------------------------------------
# Tests: COS actions
# ---------------------------------------------------------------------------

class TestCOSActions:

    def test_set_versioning_action(self):
        """set-versioning action should call put_bucket_versioning on the bucket's regional endpoint."""
        session, cos = _make_cos_session()

        from c7n_ibmcloud.resources.cos import COSSetVersioning

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = COSSetVersioning({"type": "set-versioning", "enabled": True}, manager)
        resource = {"name": "my-data-bucket", "location": "us-south-standard"}

        endpoint_calls = []
        original_cos_client = session.cos_client
        def _capturing_cos_client(**kw):
            endpoint_calls.append(kw.get("endpoint_url"))
            return original_cos_client(**kw)
        session.cos_client = _capturing_cos_client

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            action.perform_action(resource)

        cos.put_bucket_versioning.assert_called_once_with(
            Bucket="my-data-bucket",
            VersioningConfiguration={"Status": "Enabled"},
        )
        # Endpoint must be derived from the bucket's location, not the session default
        assert endpoint_calls == ["https://s3.us-south.cloud-object-storage.appdomain.cloud"]

    def test_set_encryption_action_logs_warning(self):
        """set-encryption logs a WARNING and makes no S3 call.

        IBM COS has no put_bucket_encryption S3 API. Encryption is configured
        via Key Protect integration at the service level. The action emits a
        warning instead of raising so other resources in the batch still run.
        """
        from c7n_ibmcloud.resources.cos import COSSetEncryption

        manager = MagicMock()
        action = COSSetEncryption({"type": "set-encryption"}, manager)

        with patch("c7n_ibmcloud.resources.cos.log") as mock_log:
            action.perform_action({"name": "logs-bucket"})

        # Must log a WARNING, never call put_bucket_encryption
        mock_log.warning.assert_called_once()
        assert "logs-bucket" in mock_log.warning.call_args.args[1]

    def test_set_lifecycle_action(self):
        """set-lifecycle action should call put_bucket_lifecycle_configuration on the bucket's regional endpoint."""
        session, cos = _make_cos_session()

        from c7n_ibmcloud.resources.cos import COSSetLifecycle

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        rules = [{"ID": "expire-90", "Status": "Enabled", "Expiration": {"Days": 90}}]
        action = COSSetLifecycle({"type": "set-lifecycle", "rules": rules}, manager)
        resource = {"name": "logs-bucket", "location": "eu-de-flex"}

        endpoint_calls = []
        original_cos_client = session.cos_client
        def _capturing_cos_client(**kw):
            endpoint_calls.append(kw.get("endpoint_url"))
            return original_cos_client(**kw)
        session.cos_client = _capturing_cos_client

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            action.perform_action(resource)

        cos.put_bucket_lifecycle_configuration.assert_called_once_with(
            Bucket="logs-bucket",
            LifecycleConfiguration={"Rules": rules},
        )
        assert endpoint_calls == ["https://s3.eu-de.cloud-object-storage.appdomain.cloud"]


# ---------------------------------------------------------------------------
# Tests: _cos_endpoint_for_location helper
# ---------------------------------------------------------------------------

class TestCosEndpointForLocation:
    """_cos_endpoint_for_location must strip storage-class suffix and build endpoint URL."""

    def test_standard_suffix(self):
        from c7n_ibmcloud.resources.cos import _cos_endpoint_for_location
        assert _cos_endpoint_for_location("us-south-standard") == \
            "https://s3.us-south.cloud-object-storage.appdomain.cloud"

    def test_flex_suffix(self):
        from c7n_ibmcloud.resources.cos import _cos_endpoint_for_location
        assert _cos_endpoint_for_location("eu-de-flex") == \
            "https://s3.eu-de.cloud-object-storage.appdomain.cloud"

    def test_vault_suffix(self):
        from c7n_ibmcloud.resources.cos import _cos_endpoint_for_location
        assert _cos_endpoint_for_location("us-east-vault") == \
            "https://s3.us-east.cloud-object-storage.appdomain.cloud"

    def test_cold_suffix(self):
        from c7n_ibmcloud.resources.cos import _cos_endpoint_for_location
        assert _cos_endpoint_for_location("jp-tok-cold") == \
            "https://s3.jp-tok.cloud-object-storage.appdomain.cloud"

    def test_geo_location_no_suffix(self):
        from c7n_ibmcloud.resources.cos import _cos_endpoint_for_location
        # "us-geo-standard" → region "us-geo"
        assert _cos_endpoint_for_location("us-geo-standard") == \
            "https://s3.us-geo.cloud-object-storage.appdomain.cloud"

    def test_bare_region_no_suffix(self):
        from c7n_ibmcloud.resources.cos import _cos_endpoint_for_location
        # Bare region token (already stripped) should pass through unchanged
        assert _cos_endpoint_for_location("us-south") == \
            "https://s3.us-south.cloud-object-storage.appdomain.cloud"

    def test_empty_location_returns_none(self):
        from c7n_ibmcloud.resources.cos import _cos_endpoint_for_location
        assert _cos_endpoint_for_location("") is None



# ---------------------------------------------------------------------------
# Tests: _is_access_denied detection and process() WARNING vs ERROR behaviour
# ---------------------------------------------------------------------------

class TestAccessDeniedHandling:
    """_is_access_denied covers all three error shapes; process() logs WARNING not ERROR."""

    def _make_client_error(self, code="AccessDenied"):
        """Simulate an ibm_botocore ClientError (COS S3 operations)."""
        exc = Exception("AccessDenied")
        exc.response = {"Error": {"Code": code, "Message": "Access Denied"}}
        return exc

    def _make_api_exception(self, http_code=403):
        """Simulate an ibm_cloud_sdk_core ApiException (platform SDK)."""
        exc = Exception("Forbidden")
        exc.code = http_code
        return exc

    def _make_requests_error(self, message="(403) Forbidden"):
        return Exception(message)

    def test_detects_client_error_access_denied(self):
        from c7n_ibmcloud.actions.base import _is_access_denied
        assert _is_access_denied(self._make_client_error("AccessDenied")) is True

    def test_detects_client_error_unauthorized(self):
        from c7n_ibmcloud.actions.base import _is_access_denied
        assert _is_access_denied(self._make_client_error("Unauthorized")) is True

    def test_detects_api_exception_403(self):
        from c7n_ibmcloud.actions.base import _is_access_denied
        assert _is_access_denied(self._make_api_exception(403)) is True

    def test_detects_api_exception_401(self):
        from c7n_ibmcloud.actions.base import _is_access_denied
        assert _is_access_denied(self._make_api_exception(401)) is True

    def test_detects_string_access_denied(self):
        from c7n_ibmcloud.actions.base import _is_access_denied
        assert _is_access_denied(self._make_requests_error("access denied on bucket")) is True

    def test_detects_string_403(self):
        from c7n_ibmcloud.actions.base import _is_access_denied
        assert _is_access_denied(self._make_requests_error("(403) Forbidden")) is True

    def test_does_not_flag_unrelated_errors(self):
        from c7n_ibmcloud.actions.base import _is_access_denied
        assert _is_access_denied(ValueError("bucket not found")) is False
        assert _is_access_denied(ConnectionError("timeout")) is False

    def test_process_logs_warning_not_exception_on_access_denied(self):
        """IBMBaseAction.process() must log WARNING (no traceback) for AccessDenied."""
        from c7n_ibmcloud.actions.base import IBMBaseAction

        # Build a minimal concrete action whose perform_action raises AccessDenied
        client_err = self._make_client_error("AccessDenied")

        class _FailAction(IBMBaseAction):
            type = "test-fail"
            schema = {}
            def perform_action(self, resource):
                raise client_err

        action = _FailAction.__new__(_FailAction)
        action.data = {}
        action.manager = MagicMock()

        with patch("c7n_ibmcloud.actions.base.log") as mock_log:
            result = action.process([{"name": "bucket-x"}])

        # process() continues (result is empty — resource was not added)
        assert result == []
        # WARNING was emitted, not exception (no traceback)
        mock_log.warning.assert_called_once()
        mock_log.exception.assert_not_called()
        assert "bucket-x" in mock_log.warning.call_args.args[2]

    def test_process_logs_exception_for_non_access_denied(self):
        """IBMBaseAction.process() must log.exception for unexpected errors."""
        from c7n_ibmcloud.actions.base import IBMBaseAction

        boom = RuntimeError("unexpected failure")

        class _BoomAction(IBMBaseAction):
            type = "test-boom"
            schema = {}
            def perform_action(self, resource):
                raise boom

        action = _BoomAction.__new__(_BoomAction)
        action.data = {}
        action.manager = MagicMock()

        with patch("c7n_ibmcloud.actions.base.log") as mock_log:
            result = action.process([{"name": "bucket-y"}])

        assert result == []
        mock_log.exception.assert_called_once()
        mock_log.warning.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: _is_not_found detection and process() DEBUG behaviour
# ---------------------------------------------------------------------------

class TestNotFoundHandling:
    """_is_not_found covers ApiException 404, requests HTTPError 404, botocore NoSuchBucket."""

    def _make_api_exception_404(self):
        exc = Exception("Instance not found")
        exc.code = 404
        return exc

    def _make_requests_http_error_404(self):
        exc = Exception("Not Found")
        fake_response = MagicMock()
        fake_response.status_code = 404
        exc.response = fake_response
        return exc

    def _make_botocore_no_such_bucket(self):
        exc = Exception("NoSuchBucket")
        exc.response = {"Error": {"Code": "NoSuchBucket", "Message": "The bucket does not exist"}}
        return exc

    def _make_string_not_found(self):
        return Exception("Error: Instance not found, Status code: 404")

    def test_detects_api_exception_404(self):
        from c7n_ibmcloud.actions.base import _is_not_found
        assert _is_not_found(self._make_api_exception_404()) is True

    def test_detects_requests_http_error_404(self):
        from c7n_ibmcloud.actions.base import _is_not_found
        assert _is_not_found(self._make_requests_http_error_404()) is True

    def test_detects_botocore_no_such_bucket(self):
        from c7n_ibmcloud.actions.base import _is_not_found
        assert _is_not_found(self._make_botocore_no_such_bucket()) is True

    def test_detects_string_not_found(self):
        from c7n_ibmcloud.actions.base import _is_not_found
        assert _is_not_found(self._make_string_not_found()) is True

    def test_does_not_flag_403(self):
        from c7n_ibmcloud.actions.base import _is_not_found
        exc = Exception("Forbidden")
        exc.code = 403
        assert _is_not_found(exc) is False

    def test_does_not_flag_unrelated_error(self):
        from c7n_ibmcloud.actions.base import _is_not_found
        assert _is_not_found(RuntimeError("unexpected failure")) is False

    def test_process_logs_debug_not_error_on_404(self):
        """process() must emit log.debug (no traceback, no warning) for 404 not-found."""
        from c7n_ibmcloud.actions.base import IBMBaseAction

        not_found_exc = self._make_api_exception_404()

        class _DeleteAction(IBMBaseAction):
            type = "delete"
            schema = {}
            def perform_action(self, resource):
                raise not_found_exc

        action = _DeleteAction.__new__(_DeleteAction)
        action.data = {}
        action.manager = MagicMock()

        with patch("c7n_ibmcloud.actions.base.log") as mock_log:
            result = action.process([{"id": "inst-gone", "name": "inst-gone"}])

        assert result == []
        mock_log.debug.assert_called_once()
        mock_log.warning.assert_not_called()
        mock_log.exception.assert_not_called()
        assert "inst-gone" in mock_log.debug.call_args.args[2]

    def test_process_404_does_not_raise_by_default(self):
        """404 must not propagate even when fail_on_error is the default."""
        from c7n_ibmcloud.actions.base import IBMBaseAction

        not_found_exc = self._make_api_exception_404()

        class _DeleteAction(IBMBaseAction):
            type = "delete"
            schema = {}
            def perform_action(self, resource):
                raise not_found_exc

        action = _DeleteAction.__new__(_DeleteAction)
        action.data = {}
        action.manager = MagicMock()

        with patch("c7n_ibmcloud.actions.base.log"):
            # Must not raise
            result = action.process([{"id": "inst-gone"}])
        assert result == []


# ---------------------------------------------------------------------------
# Tests: COSDescribeSource enumeration strategies
# ---------------------------------------------------------------------------

class TestCOSDescribeSourceEnumeration:

    def test_hmac_path_uses_list_buckets_extended(self):
        """When HMAC env vars are set, get_resources uses list_buckets_extended."""
        session, cos = _make_cos_session()

        from c7n_ibmcloud.resources.cos import COSDescribeSource
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session), \
             patch.dict(os.environ, {"IBMCLOUD_COS_HMAC_ACCESS_KEY_ID": "test-hmac-key"}):
            result = source.get_resources({})

        cos.list_buckets_extended.assert_called_once()
        assert len(result) == 2

    def test_iam_path_env_guid_uses_list_buckets(self):
        """When HMAC is absent but COS_RESOURCE_INSTANCE_ID is set, uses list_buckets
        and fetches the instance CRN via RC so tag action can use it."""
        session, cos = _make_cos_session()
        cos.list_buckets.return_value = SAMPLE_BUCKETS_RAW
        # RC get_resource_instance returns the full instance record including CRN
        rc = session._clients["resource-ctrl"]
        rc.get_resource_instance = MagicMock(return_value=FakeResult({"crn": COS_INSTANCE_CRN}))

        from c7n_ibmcloud.resources.cos import COSDescribeSource
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        env_override = {
            "IBMCLOUD_COS_HMAC_ACCESS_KEY_ID": "",
            "IBMCLOUD_COS_RESOURCE_INSTANCE_ID": "cos-guid-from-env",
        }
        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session), \
             patch.dict(os.environ, env_override):
            result = source.get_resources({})

        cos.list_buckets.assert_called_once_with(IBMServiceInstanceId="cos-guid-from-env")
        # CRN lookup must have been called for the env-supplied GUID
        rc.get_resource_instance.assert_called_once_with(id="cos-guid-from-env")
        # Every bucket must carry the instance CRN
        assert all(b["c7n:instance_crn"] == COS_INSTANCE_CRN for b in result)
        assert len(result) == 2

    def test_iam_path_rc_discovery_when_no_env_guid(self):
        """When no env vars are set, RC discovery is used to find COS instances."""
        session, cos = _make_cos_session()
        cos.list_buckets.return_value = SAMPLE_BUCKETS_RAW
        rc = session._clients["resource-ctrl"]

        from c7n_ibmcloud.resources.cos import COSDescribeSource
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        env_override = {
            "IBMCLOUD_COS_HMAC_ACCESS_KEY_ID": "",
            "IBMCLOUD_COS_RESOURCE_INSTANCE_ID": "",
        }
        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session), \
             patch.dict(os.environ, env_override):
            result = source.get_resources({})

        # RC should have been called to discover instances
        rc.list_resource_instances.assert_called_once()
        # list_buckets called with the discovered GUID
        cos.list_buckets.assert_called_once_with(IBMServiceInstanceId="cos-guid-001")
        assert len(result) == 2

    def test_normalise_adds_instance_fields(self):
        """_normalise should populate c7n:instance_id, c7n:instance_name, c7n:instance_crn."""
        from c7n_ibmcloud.resources.cos import COSDescribeSource
        raw = [
            {
                "Name": "test-bucket",
                "CreationDate": "2023-01-01",
                "LocationConstraint": "us-south",
                "_cos_instance_id": "guid-001",
                "_cos_instance_name": "my-cos",
                "_cos_instance_crn": COS_INSTANCE_CRN,
            }
        ]
        result = COSDescribeSource._normalise(raw)
        assert result[0]["c7n:instance_id"] == "guid-001"
        assert result[0]["c7n:instance_name"] == "my-cos"
        assert result[0]["c7n:instance_crn"] == COS_INSTANCE_CRN
        assert result[0]["name"] == "test-bucket"

    def test_no_instances_returns_empty_list(self):
        """When RC finds no COS instances, get_resources returns []."""
        session, cos = _make_cos_session()
        # Override RC to return no instances
        session._clients["resource-ctrl"].list_resource_instances.return_value = FakeResult(
            {"resources": [], "next_url": None}
        )

        from c7n_ibmcloud.resources.cos import COSDescribeSource
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        env_override = {
            "IBMCLOUD_COS_HMAC_ACCESS_KEY_ID": "",
            "IBMCLOUD_COS_RESOURCE_INSTANCE_ID": "",
        }
        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session), \
             patch.dict(os.environ, env_override):
            result = source.get_resources({})

        assert result == []
        cos.list_buckets.assert_not_called()

    def test_rc_discovery_uses_type_not_resource_id(self):
        """RC call must use type='service_instance', not resource_id='cloud-object-storage'.

        Passing resource_id with the service name slug returns nothing from the RC API
        because it expects the global-catalog UUID. We filter client-side on the CRN
        instead, so the RC query uses type='service_instance'.
        """
        session, cos = _make_cos_session()
        cos.list_buckets.return_value = SAMPLE_BUCKETS_RAW
        rc = session._clients["resource-ctrl"]

        from c7n_ibmcloud.resources.cos import COSDescribeSource
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        env_override = {
            "IBMCLOUD_COS_HMAC_ACCESS_KEY_ID": "",
            "IBMCLOUD_COS_RESOURCE_INSTANCE_ID": "",
        }
        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session), \
             patch.dict(os.environ, env_override):
            source.get_resources({})

        call_kwargs = rc.list_resource_instances.call_args[1]
        assert call_kwargs.get("type") == "service_instance"
        assert "resource_id" not in call_kwargs

    def test_rc_discovery_skips_non_cos_instances(self):
        """RC instances whose CRN does not contain 'cloud-object-storage' are ignored."""
        session, cos = _make_cos_session()
        cos.list_buckets.return_value = SAMPLE_BUCKETS_RAW

        # Return a mix: one COS instance, one non-COS instance (e.g. Databases)
        mixed_instances = [
            {
                "guid": "cos-guid-001",
                "name": "my-cos",
                "crn": "crn:v1:bluemix:public:cloud-object-storage:global:a/123:cos-guid-001::",
            },
            {
                "guid": "db-guid-999",
                "name": "my-postgres",
                "crn": "crn:v1:bluemix:public:databases-for-postgresql:us-south:a/123:db-guid-999::",
            },
        ]
        session._clients["resource-ctrl"].list_resource_instances.return_value = FakeResult(
            {"resources": mixed_instances, "next_url": None}
        )

        from c7n_ibmcloud.resources.cos import COSDescribeSource
        source = COSDescribeSource.__new__(COSDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)

        env_override = {
            "IBMCLOUD_COS_HMAC_ACCESS_KEY_ID": "",
            "IBMCLOUD_COS_RESOURCE_INSTANCE_ID": "",
        }
        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session), \
             patch.dict(os.environ, env_override):
            result = source.get_resources({})

        # list_buckets called once — only for the COS instance, not the DB instance
        cos.list_buckets.assert_called_once_with(IBMServiceInstanceId="cos-guid-001")
        assert len(result) == 2  # two buckets from SAMPLE_BUCKETS_RAW


# ---------------------------------------------------------------------------
# Tests: COSBucketTagAction / COSBucketRemoveTagAction
# (tags are placed on the service instance, not the bucket)
# ---------------------------------------------------------------------------

class TestCOSBucketTagAction:

    def _sample_bucket(self, instance_crn=COS_INSTANCE_CRN):
        return {
            "name": "my-sensitive-bucket",
            "id": "my-sensitive-bucket",
            "location": "us-south",
            "c7n:instance_crn": instance_crn,
            "c7n:instance_id": "cos-guid-001",
        }

    def test_tag_attaches_to_instance_crn(self):
        """tag action must call attach_tag with the instance CRN, not the bucket CRN."""
        from c7n_ibmcloud.resources.cos import COSBucketTagAction
        from unittest.mock import MagicMock, patch

        session, cos = _make_cos_session()
        gt_client = MagicMock()
        session._clients["global-tagging"] = gt_client

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"

        action = COSBucketTagAction({"type": "tag", "tags": {"custodian-review": "public-access"}}, manager)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            action.perform_action(self._sample_bucket())

        gt_client.attach_tag.assert_called_once()
        call_kwargs = gt_client.attach_tag.call_args[1]
        # Must target the instance CRN
        assert call_kwargs["resources"][0].resource_id == COS_INSTANCE_CRN
        # Tag value must encode the bucket name
        assert any("my-sensitive-bucket" in t for t in call_kwargs["tag_names"])
        assert any("public-access" in t for t in call_kwargs["tag_names"])

    def test_tag_value_format_is_value_dashdash_bucket(self):
        """Tag value format must be '<policy-value>--<bucket-name>' (no slash allowed)."""
        from c7n_ibmcloud.resources.cos import COSBucketTagAction
        from unittest.mock import MagicMock, patch

        session, cos = _make_cos_session()
        gt_client = MagicMock()
        session._clients["global-tagging"] = gt_client

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"

        action = COSBucketTagAction({"type": "tag", "tags": {"custodian-review": "no-cmk"}}, manager)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            action.perform_action(self._sample_bucket())

        tag_names = gt_client.attach_tag.call_args[1]["tag_names"]
        assert "custodian-review:no-cmk--my-sensitive-bucket" in tag_names
        # Must NOT contain a slash
        assert all("/" not in t for t in tag_names)

    def test_tag_skips_when_no_instance_crn(self):
        """tag action must log WARNING and skip when c7n:instance_crn is absent."""
        from c7n_ibmcloud.resources.cos import COSBucketTagAction
        from unittest.mock import MagicMock, patch

        session, cos = _make_cos_session()
        gt_client = MagicMock()
        session._clients["global-tagging"] = gt_client

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"

        action = COSBucketTagAction({"type": "tag", "tags": {"custodian-review": "public-access"}}, manager)
        bucket = self._sample_bucket(instance_crn="")

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session), \
             patch("c7n_ibmcloud.resources.cos.log") as mock_log:
            action.perform_action(bucket)

        gt_client.attach_tag.assert_not_called()
        mock_log.warning.assert_called_once()
        assert "my-sensitive-bucket" in mock_log.warning.call_args.args[1]

    def test_remove_tag_detaches_from_instance_crn(self):
        """remove-tag must call detach_tag with the instance CRN."""
        from c7n_ibmcloud.resources.cos import COSBucketRemoveTagAction
        from unittest.mock import MagicMock, patch

        session, cos = _make_cos_session()
        gt_client = MagicMock()
        session._clients["global-tagging"] = gt_client

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"

        action = COSBucketRemoveTagAction({"type": "remove-tag", "tags": ["custodian-review"]}, manager)

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session):
            action.perform_action(self._sample_bucket())

        gt_client.detach_tag.assert_called_once()
        call_kwargs = gt_client.detach_tag.call_args[1]
        assert call_kwargs["resources"][0].resource_id == COS_INSTANCE_CRN
        assert "custodian-review" in call_kwargs["tag_names"]

    def test_remove_tag_skips_when_no_instance_crn(self):
        """remove-tag must log WARNING and skip when c7n:instance_crn is absent."""
        from c7n_ibmcloud.resources.cos import COSBucketRemoveTagAction
        from unittest.mock import MagicMock, patch

        session, cos = _make_cos_session()
        gt_client = MagicMock()
        session._clients["global-tagging"] = gt_client

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"

        action = COSBucketRemoveTagAction({"type": "remove-tag", "tags": ["custodian-review"]}, manager)
        bucket = self._sample_bucket(instance_crn="")

        with patch("c7n_ibmcloud.resources.cos.local_session", return_value=session), \
             patch("c7n_ibmcloud.resources.cos.log") as mock_log:
            action.perform_action(bucket)

        gt_client.detach_tag.assert_not_called()
        mock_log.warning.assert_called_once()

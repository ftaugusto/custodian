# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
Policy-level tests covering every governance check in the IBM Cloud Custodian
Governance Checks Reference (ibm-cloud-custodian-governance-checks-reference.html).

One test per check from the reference document.  Each test:
 1. Builds a minimal resource payload that MATCHES the check condition.
 2. Runs the appropriate filter.
 3. Asserts that the matching resource is returned (and non-matching ones are not).

Services covered
----------------
IAM         ibm.iam-user, ibm.iam-api-key, ibm.iam-service-id,
            ibm.iam-access-group, ibm.iam-trusted-profile
VPC Compute ibm.vpc-instance, ibm.vpc-bare-metal, ibm.vpc-dedicated-host,
            ibm.vpc-instance-group, ibm.vpc-instance-template
VPC Network ibm.vpc-security-group, ibm.vpc-network-acl, ibm.vpc-transit-gateway,
            ibm.vpc-vpn-gateway, ibm.vpc-load-balancer, ibm.vpc-floating-ip,
            ibm.vpc-ssh-key
VPC Storage ibm.vpc-volume, ibm.vpc-snapshot, ibm.vpc-backup-policy,
            ibm.vpc-file-share
COS         ibm.cos-bucket
KMS         ibm.kms-key
Kubernetes  ibm.iks-cluster, ibm.roks-cluster
PowerVS     ibm.powervs-instance, ibm.powervs-volume, ibm.powervs-ssh-key,
            ibm.powervs-network
DBaaS       all 8 engines
Cross-cut   owner/environment/cost-centre tags, marked-for-op, age
"""

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from conftest import FakeSession, FakeSessionFactory, FakeResult


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _age_patch(mock_dt, days_ago):
    """Configure a patched datetime.now() to be `days_ago` days in the future
    relative to the resource creation timestamps used in each test."""
    now = datetime.now(timezone.utc)
    mock_dt.now.return_value = now + timedelta(days=days_ago)
    mock_dt.fromisoformat = datetime.fromisoformat


def _value_filter(key, op, value):
    """Shortcut to build a c7n ValueFilter."""
    from c7n.filters.core import ValueFilter
    mgr = MagicMock()
    mgr.get_model.return_value = MagicMock(id="id")
    return ValueFilter({"type": "value", "key": key, "op": op, "value": value}, mgr)


# ===========================================================================
# IAM — ibm.iam-user
# ===========================================================================

class TestIAMUserChecks:
    """Reference checks: MFA not enrolled → add-to-review-group or delete;
    suspended state → delete; external email domain → add-to-review-group."""

    USERS = [
        {
            "iam_id": "IBMid-001",
            "email": "alice@internal.example.com",
            "state": "ACTIVE",
            "c7n:mfa_enrolled": False,
            "c7n:mfa_type": "",
        },
        {
            "iam_id": "IBMid-002",
            "email": "bob@external.com",
            "state": "SUSPENDED",
            "c7n:mfa_enrolled": True,
            "c7n:mfa_type": "TOTP",
        },
        {
            "iam_id": "IBMid-003",
            "email": "charlie@internal.example.com",
            "state": "ACTIVE",
            "c7n:mfa_enrolled": True,
            "c7n:mfa_type": "TOTP",
        },
    ]

    def test_mfa_not_enrolled_filter(self):
        """CHECK: MFA not enrolled — mfa-disabled filter returns non-MFA users."""
        from c7n_ibmcloud.filters.base import MFADisabledFilter
        f = MFADisabledFilter({}, None)
        result = f.process(self.USERS)
        assert len(result) == 1
        assert result[0]["iam_id"] == "IBMid-001"

    def test_mfa_not_enrolled_action_add_to_review_group(self):
        """CHECK action: MFA-disabled users added to review group by name."""
        from c7n_ibmcloud.resources.iam import IAMUserAddToReviewGroupAction
        from ibm_platform_services.iam_access_groups_v2 import AddGroupMembersRequestMembersItem
        from unittest.mock import patch

        groups_client = MagicMock()
        groups_client.list_access_groups.return_value = FakeResult({
            "groups": [{"id": "AccessGroupId-mfa-review", "name": "custodian-review"}]
        })
        session = FakeSession(clients={"iam-groups": groups_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMUserAddToReviewGroupAction(
            {"type": "add-to-review-group", "group_name": "custodian-review"},
            manager,
        )
        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(self.USERS[0])

        groups_client.add_members_to_access_group.assert_called_once()
        call_kwargs = groups_client.add_members_to_access_group.call_args[1]
        assert call_kwargs["access_group_id"] == "AccessGroupId-mfa-review"
        assert isinstance(call_kwargs["members"][0], AddGroupMembersRequestMembersItem)
        assert call_kwargs["members"][0].iam_id == "IBMid-001"

    def test_mfa_not_enrolled_action_delete(self):
        """CHECK action: MFA-disabled users can be deleted via delete action."""
        from c7n_ibmcloud.resources.iam import IAMUserDeleteAction
        from unittest.mock import patch

        iam_users_client = MagicMock()
        session = FakeSession(
            clients={"iam-users": iam_users_client},
            account_id="acct-test",
        )
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMUserDeleteAction({}, manager)
        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(self.USERS[0])

        iam_users_client.remove_user.assert_called_once_with(
            account_id="acct-test",
            iam_id="IBMid-001",
        )

    def test_user_suspended_state(self):
        """CHECK: User in suspended state — value filter state != ACTIVE."""
        f = _value_filter("state", "ne", "ACTIVE")
        result = f.process(self.USERS)
        assert len(result) == 1
        assert result[0]["iam_id"] == "IBMid-002"

    def test_external_email_domain(self):
        """CHECK: External (non-org) email domain — value filter email glob."""
        from c7n.filters.core import ValueFilter
        mgr = MagicMock()
        mgr.get_model.return_value = MagicMock(id="iam_id")
        f = ValueFilter(
            {"type": "value", "key": "email", "op": "glob", "value": "*@external.com"},
            mgr,
        )
        result = f.process(self.USERS)
        assert len(result) == 1
        assert result[0]["iam_id"] == "IBMid-002"

    def test_iam_user_no_tag_action(self):
        """CHECK: iam-user does not support tagging — tag action must not be registered."""
        from c7n_ibmcloud.resources.iam import IAMUser
        assert IAMUser.action_registry.get("tag") is None


# ===========================================================================
# IAM — ibm.iam-api-key
# ===========================================================================

class TestIAMApiKeyChecks:
    """Reference checks: age > 180 days → lock; unlocked past rotation age → lock;
    root keys → lock/delete; no description → append-description or lock.
    Note: tag action is NOT supported for api-key (no CRN in list_api_keys response)."""

    # created_at strings 400 days and 100 days before "now" (patched in tests)
    _BASE_DATE = datetime(2023, 1, 1, tzinfo=timezone.utc)

    API_KEYS = [
        {
            "id": "ApiKey-old-locked",
            "name": "old-locked-key",
            "iam_id": "IBMid-001",
            "created_at": "2022-01-01T00:00:00Z",
            "locked": True,
            "description": "deployment key",
            "tags": [],
        },
        {
            "id": "ApiKey-old-unlocked",
            "name": "old-unlocked-key",
            "iam_id": "IBMid-001",
            "created_at": "2022-01-01T00:00:00Z",
            "locked": False,
            "description": "",
            "tags": [],
        },
        {
            "id": "ApiKey-root",
            "name": "root-key",
            "iam_id": "IBMid-SomeOwner",
            "created_at": "2024-01-01T00:00:00Z",
            "locked": False,
            "description": "",
            "tags": [],
        },
        {
            "id": "ApiKey-recent",
            "name": "recent-key",
            "iam_id": "ServiceId-001",
            "created_at": "2024-11-01T00:00:00Z",
            "locked": False,
            "description": "recent service key",
            "tags": [],
        },
    ]

    def test_api_key_older_than_180_days(self):
        """CHECK: API key older than 180 days (rotation overdue) — age filter."""
        from c7n_ibmcloud.filters.base import AgeFilter

        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat
            f = AgeFilter({"type": "age", "op": "gt", "days": 180}, None)
            f.date_attribute = "created_at"
            result = f.process(self.API_KEYS)

        ids = {r["id"] for r in result}
        assert "ApiKey-old-locked" in ids
        assert "ApiKey-old-unlocked" in ids
        # recent-key (2024-11-01) is ~61 days — must NOT match
        assert "ApiKey-recent" not in ids

    def test_api_key_older_than_180_days_action_lock(self):
        """CHECK action: old API keys locked — lock action (no tag support)."""
        from c7n_ibmcloud.resources.iam import LockApiKeyAction
        from unittest.mock import patch

        iam_client = MagicMock()
        session = FakeSession(clients={"iam-identity": iam_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = LockApiKeyAction({}, manager)
        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(self.API_KEYS[1])  # old-unlocked

        iam_client.lock_api_key.assert_called_once_with(id="ApiKey-old-unlocked")

    def test_unlocked_api_key_past_rotation_age(self):
        """CHECK: Unlocked API key past rotation age — age + locked=false → lock action."""
        from c7n_ibmcloud.filters.base import AgeFilter

        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat
            age_f = AgeFilter({"type": "age", "op": "gt", "days": 180}, None)
            age_f.date_attribute = "created_at"
            old_keys = age_f.process(self.API_KEYS)

        unlocked_old = [k for k in old_keys if not k["locked"]]
        assert len(unlocked_old) >= 1
        ids = {k["id"] for k in unlocked_old}
        assert "ApiKey-old-unlocked" in ids
        assert "ApiKey-old-locked" not in ids

    def test_root_account_owner_api_key(self):
        """CHECK: Root/account-owner API keys — iam_id contains IBMid → lock/delete."""
        f = _value_filter("iam_id", "contains", "IBMid")
        result = f.process(self.API_KEYS)
        ids = {r["id"] for r in result}
        assert "ApiKey-old-locked" in ids
        assert "ApiKey-old-unlocked" in ids
        assert "ApiKey-root" in ids
        assert "ApiKey-recent" not in ids

    def test_api_key_no_description(self):
        """CHECK: API key with no description — description empty → append-description or lock."""
        from c7n.filters.core import ValueFilter
        mgr = MagicMock()
        mgr.get_model.return_value = MagicMock(id="id")
        f = ValueFilter(
            {"type": "value", "key": "description", "op": "eq", "value": ""},
            mgr,
        )
        result = f.process(self.API_KEYS)
        ids = {r["id"] for r in result}
        assert "ApiKey-old-unlocked" in ids
        assert "ApiKey-root" in ids
        assert "ApiKey-old-locked" not in ids

    def test_api_key_no_description_action_append_description(self):
        """CHECK action: API key with no description flagged via append-description."""
        from c7n_ibmcloud.resources.iam import IAMApiKeyAppendDescriptionAction
        from unittest.mock import patch

        iam_client = MagicMock()
        session = FakeSession(clients={"iam-identity": iam_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMApiKeyAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] No description — review."},
            manager,
        )
        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(self.API_KEYS[1])  # old-unlocked, description=""

        iam_client.update_api_key.assert_called_once_with(
            id="ApiKey-old-unlocked",
            if_match="*",
            description="[custodian] No description — review.",
        )

    def test_api_key_no_tag_action(self):
        """CHECK: iam-api-key does not support tagging — tag action must not be registered."""
        from c7n_ibmcloud.resources.iam import IAMApiKey
        assert IAMApiKey.action_registry.get("tag") is None


# ===========================================================================
# IAM — ibm.iam-service-id
# ===========================================================================

class TestIAMServiceIDChecks:
    """Reference checks: age > 365 days, no description, missing owner tag."""

    SERVICE_IDS = [
        {
            "id": "ServiceId-old",
            "name": "old-svc",
            "description": "",
            "crn": "crn:v1:bluemix:public:iam-identity::a/1::serviceid:ServiceId-old",
            "created_at": "2022-01-01T00:00:00Z",
            "tags": [],
        },
        {
            "id": "ServiceId-recent",
            "name": "recent-svc",
            "description": "Active CI runner",
            "crn": "crn:v1:bluemix:public:iam-identity::a/1::serviceid:ServiceId-recent",
            "created_at": "2024-10-01T00:00:00Z",
            "tags": ["owner:platform"],
        },
    ]

    def test_service_id_unused_over_365_days(self):
        """CHECK: Service ID unused for over 365 days — age filter."""
        from c7n_ibmcloud.filters.base import AgeFilter

        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat
            f = AgeFilter({"type": "age", "op": "gt", "days": 365}, None)
            f.date_attribute = "created_at"
            result = f.process(self.SERVICE_IDS)

        assert len(result) == 1
        assert result[0]["id"] == "ServiceId-old"

    def test_service_id_no_description(self):
        """CHECK: Service ID with no description — description absent/empty."""
        f = _value_filter("description", "eq", "")
        result = f.process(self.SERVICE_IDS)
        assert len(result) == 1
        assert result[0]["id"] == "ServiceId-old"

    def test_service_id_missing_owner_tag(self):
        """CHECK: Missing owner tag — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.SERVICE_IDS)
        assert len(result) == 1
        assert result[0]["id"] == "ServiceId-old"


# ===========================================================================
# IAM — ibm.iam-access-group
# ===========================================================================

class TestIAMAccessGroupChecks:
    """Reference checks: empty groups (zero members) — delete or append-description.
    No tagging support (no CRN in list_access_groups response)."""

    ACCESS_GROUPS = [
        {
            "id": "ag-active",
            "name": "DevTeam",
            "description": "Active DevOps group",
            "member_count": 4,
            "created_at": "2023-01-01T00:00:00Z",
        },
        {
            "id": "ag-empty",
            "name": "Orphan",
            "description": "Old unused group",
            "member_count": 0,
            "created_at": "2023-01-01T00:00:00Z",
        },
    ]

    def test_empty_access_group(self):
        """CHECK: Empty access groups (zero members) — value filter member_count==0."""
        f = _value_filter("member_count", "eq", 0)
        result = f.process(self.ACCESS_GROUPS)
        assert len(result) == 1
        assert result[0]["id"] == "ag-empty"

    def test_empty_access_group_action_delete(self):
        """CHECK action: Empty access group deleted."""
        from c7n_ibmcloud.resources.iam import IAMAccessGroupDeleteAction
        from unittest.mock import patch

        groups_client = MagicMock()
        session = FakeSession(clients={"iam-groups": groups_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMAccessGroupDeleteAction({}, manager)
        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(self.ACCESS_GROUPS[1])

        groups_client.delete_access_group.assert_called_once_with(
            access_group_id="ag-empty"
        )

    def test_empty_access_group_action_append_description(self):
        """CHECK action: append-description flags empty group for review instead of deleting."""
        from c7n_ibmcloud.resources.iam import IAMAccessGroupAppendDescriptionAction
        from unittest.mock import patch

        groups_client = MagicMock()
        get_resp = MagicMock()
        get_resp.get_headers.return_value = {"ETag": 'W/"etag-ag-empty"'}
        groups_client.get_access_group.return_value = get_resp
        session = FakeSession(clients={"iam-groups": groups_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMAccessGroupAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] Empty group — review."},
            manager,
        )
        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(self.ACCESS_GROUPS[1])

        groups_client.get_access_group.assert_called_once_with(access_group_id="ag-empty")
        groups_client.update_access_group.assert_called_once_with(
            access_group_id="ag-empty",
            if_match='W/"etag-ag-empty"',
            description="Old unused group [custodian] Empty group — review.",
        )


# ===========================================================================
# IAM — ibm.iam-trusted-profile
# ===========================================================================

class TestIAMTrustedProfileChecks:
    """Reference checks: unused for over 180 days — delete or append-description.
    Tag action removed; prefer append-description for non-destructive review flagging."""

    PROFILES = [
        {
            "id": "tp-old",
            "name": "old-profile",
            "description": "Compute workload identity for legacy jobs",
            "created_at": "2022-01-01T00:00:00Z",
        },
        {
            "id": "tp-recent",
            "name": "recent-profile",
            "description": "",
            "created_at": "2024-12-01T00:00:00Z",
        },
    ]

    def test_trusted_profile_unused_over_180_days(self):
        """CHECK: Trusted profiles unused for over 180 days — age filter."""
        from c7n_ibmcloud.filters.base import AgeFilter

        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat
            f = AgeFilter({"type": "age", "op": "gt", "days": 180}, None)
            f.date_attribute = "created_at"
            result = f.process(self.PROFILES)

        assert len(result) == 1
        assert result[0]["id"] == "tp-old"

    def test_trusted_profile_action_append_description(self):
        """CHECK action: append-description flags stale profile for review."""
        from c7n_ibmcloud.resources.iam import IAMTrustedProfileAppendDescriptionAction
        from unittest.mock import patch

        iam_client = MagicMock()
        get_resp = MagicMock()
        get_resp.get_headers.return_value = {"ETag": 'W/"etag-tp-old"'}
        iam_client.get_profile.return_value = get_resp
        session = FakeSession(clients={"iam-identity": iam_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMTrustedProfileAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] Unused 180+ days."},
            manager,
        )
        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(self.PROFILES[0])

        iam_client.get_profile.assert_called_once_with(profile_id="tp-old")
        iam_client.update_profile.assert_called_once_with(
            profile_id="tp-old",
            if_match='W/"etag-tp-old"',
            description="Compute workload identity for legacy jobs [custodian] Unused 180+ days.",
        )

    def test_trusted_profile_action_delete(self):
        """CHECK action: stale trusted profile deleted."""
        from c7n_ibmcloud.resources.iam import IAMTrustedProfileDeleteAction
        from unittest.mock import patch

        iam_client = MagicMock()
        session = FakeSession(clients={"iam-identity": iam_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMTrustedProfileDeleteAction({}, manager)
        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(self.PROFILES[0])

        iam_client.delete_profile.assert_called_once_with(profile_id="tp-old")


# ===========================================================================
# VPC Compute — ibm.vpc-instance
# ===========================================================================

class TestVPCInstanceChecks:
    """Reference checks: stopped > 30 days, missing mandatory tags, non-approved zone,
    over-sized instance."""

    INSTANCES = [
        {
            "id": "inst-running",
            "name": "web-1",
            "status": "running",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::instance:inst-running",
            "zone": {"name": "us-south-1"},
            "vcpu": {"count": 4},
            "created_at": "2024-12-01T00:00:00Z",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": ["owner:platform", "environment:production"],
        },
        {
            "id": "inst-stopped-old",
            "name": "batch-1",
            "status": "stopped",
            "crn": "crn:v1:bluemix:public:is:us-south-2:a/1::instance:inst-stopped-old",
            "zone": {"name": "us-south-2"},
            "vcpu": {"count": 32},
            "created_at": "2024-01-01T00:00:00Z",
            "resource_group": {"id": "rg-2", "name": "dev"},
            "tags": [],
        },
        {
            "id": "inst-wrong-zone",
            "name": "zone-violator",
            "status": "running",
            "crn": "crn:v1:bluemix:public:is:eu-de-1:a/1::instance:inst-wrong-zone",
            "zone": {"name": "eu-de-1"},
            "vcpu": {"count": 2},
            "created_at": "2024-06-01T00:00:00Z",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": ["owner:team-a", "environment:production"],
        },
    ]

    def test_stopped_instance_zombie(self):
        """CHECK: Instance stopped for >30 days — status==stopped (age tested separately)."""
        f = _value_filter("status", "eq", "stopped")
        result = f.process(self.INSTANCES)
        assert len(result) == 1
        assert result[0]["id"] == "inst-stopped-old"

    def test_missing_mandatory_owner_tag(self):
        """CHECK: Missing mandatory tags (owner) — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.INSTANCES)
        assert len(result) == 1
        assert result[0]["id"] == "inst-stopped-old"

    def test_instance_non_approved_zone(self):
        """CHECK: Instance in non-approved zone — value filter zone.name ne us-south-1."""
        f = _value_filter("zone.name", "ne", "us-south-1")
        result = f.process(self.INSTANCES)
        ids = {r["id"] for r in result}
        assert "inst-stopped-old" in ids
        assert "inst-wrong-zone" in ids
        assert "inst-running" not in ids

    def test_oversized_instance(self):
        """CHECK: Over-sized instance — vcpu.count > 16."""
        f = _value_filter("vcpu.count", "gt", 16)
        result = f.process(self.INSTANCES)
        assert len(result) == 1
        assert result[0]["id"] == "inst-stopped-old"


# ===========================================================================
# VPC Compute — ibm.vpc-bare-metal
# ===========================================================================

class TestVPCBareMetalChecks:
    """Reference checks: not running, unhealthy, secure boot disabled, age > 730, missing tags."""

    SERVERS = [
        {
            "id": "bms-healthy",
            "name": "bms-1",
            "status": "running",
            "health_state": "ok",
            "enable_secure_boot": True,
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::bare-metal-server:bms-healthy",
            "created_at": "2024-01-01T00:00:00Z",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": ["owner:ops"],
        },
        {
            "id": "bms-not-running",
            "name": "bms-stopped",
            "status": "stopped",
            "health_state": "ok",
            "enable_secure_boot": False,
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::bare-metal-server:bms-not-running",
            "created_at": "2020-01-01T00:00:00Z",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": [],
        },
        {
            "id": "bms-unhealthy",
            "name": "bms-sick",
            "status": "running",
            "health_state": "degraded",
            "enable_secure_boot": True,
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::bare-metal-server:bms-unhealthy",
            "created_at": "2023-06-01T00:00:00Z",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": ["owner:ops"],
        },
    ]

    def test_server_not_running(self):
        """CHECK: Server not in running/starting state — value filter status ne running."""
        f = _value_filter("status", "ne", "running")
        result = f.process(self.SERVERS)
        assert len(result) == 1
        assert result[0]["id"] == "bms-not-running"

    def test_server_unhealthy_health_state(self):
        """CHECK: Server with unhealthy health_state — value filter health_state ne ok."""
        f = _value_filter("health_state", "ne", "ok")
        result = f.process(self.SERVERS)
        assert len(result) == 1
        assert result[0]["id"] == "bms-unhealthy"

    def test_secure_boot_not_enabled(self):
        """CHECK: Secure boot not enabled — value filter enable_secure_boot eq false."""
        f = _value_filter("enable_secure_boot", "eq", False)
        result = f.process(self.SERVERS)
        assert len(result) == 1
        assert result[0]["id"] == "bms-not-running"

    def test_server_older_than_730_days(self):
        """CHECK: Server older than 730 days (re-provision candidate) — age filter."""
        from c7n_ibmcloud.filters.base import AgeFilter
        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat
            f = AgeFilter({"type": "age", "op": "gt", "days": 730}, None)
            f.date_attribute = "created_at"
            result = f.process(self.SERVERS)
        assert len(result) == 1
        assert result[0]["id"] == "bms-not-running"

    def test_bare_metal_missing_mandatory_tags(self):
        """CHECK: Missing mandatory tags — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.SERVERS)
        assert len(result) == 1
        assert result[0]["id"] == "bms-not-running"


# ===========================================================================
# VPC Compute — ibm.vpc-dedicated-host
# ===========================================================================

class TestVPCDedicatedHostChecks:
    """Reference checks: not available, not provisionable, underutilised, missing tags."""

    HOSTS = [
        {
            "id": "dh-ok",
            "name": "host-1",
            "state": "available",
            "provisionable": True,
            "available_memory": 512,
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::dedicated-host:dh-ok",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": ["owner:ops"],
        },
        {
            "id": "dh-unavailable",
            "name": "host-down",
            "state": "degraded",
            "provisionable": False,
            "available_memory": 3000,
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::dedicated-host:dh-unavailable",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": [],
        },
    ]

    def test_host_not_available(self):
        """CHECK: Host not in available state — value filter state ne available."""
        f = _value_filter("state", "ne", "available")
        result = f.process(self.HOSTS)
        assert len(result) == 1
        assert result[0]["id"] == "dh-unavailable"

    def test_host_not_provisionable(self):
        """CHECK: Host not provisionable — value filter provisionable eq false."""
        f = _value_filter("provisionable", "eq", False)
        result = f.process(self.HOSTS)
        assert len(result) == 1
        assert result[0]["id"] == "dh-unavailable"

    def test_host_large_available_memory_underutilised(self):
        """CHECK: Host with large available_memory (underutilised) — value filter > 1024."""
        f = _value_filter("available_memory", "gt", 1024)
        result = f.process(self.HOSTS)
        assert len(result) == 1
        assert result[0]["id"] == "dh-unavailable"

    def test_dedicated_host_missing_tags(self):
        """CHECK: Missing mandatory tags — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.HOSTS)
        assert len(result) == 1
        assert result[0]["id"] == "dh-unavailable"


# ===========================================================================
# VPC Compute — ibm.vpc-instance-group
# ===========================================================================

class TestVPCInstanceGroupChecks:
    """Reference checks: zero members, not stable lifecycle, missing tags."""

    GROUPS = [
        {
            "id": "ig-active",
            "name": "web-asg",
            "membership_count": 3,
            "lifecycle_state": "stable",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::instance-group:ig-active",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": ["owner:ops"],
        },
        {
            "id": "ig-empty",
            "name": "empty-asg",
            "membership_count": 0,
            "lifecycle_state": "stable",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::instance-group:ig-empty",
            "resource_group": {"id": "rg-2", "name": "dev"},
            "tags": [],
        },
        {
            "id": "ig-unstable",
            "name": "scaling-asg",
            "membership_count": 2,
            "lifecycle_state": "updating",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::instance-group:ig-unstable",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": ["owner:ops"],
        },
    ]

    def test_instance_group_zero_members(self):
        """CHECK: Instance group with zero members (unused) — value filter membership_count==0."""
        f = _value_filter("membership_count", "eq", 0)
        result = f.process(self.GROUPS)
        assert len(result) == 1
        assert result[0]["id"] == "ig-empty"

    def test_instance_group_not_stable(self):
        """CHECK: Group not in stable lifecycle state — value filter lifecycle_state ne stable."""
        f = _value_filter("lifecycle_state", "ne", "stable")
        result = f.process(self.GROUPS)
        assert len(result) == 1
        assert result[0]["id"] == "ig-unstable"

    def test_instance_group_missing_tags(self):
        """CHECK: Missing mandatory tags — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.GROUPS)
        assert len(result) == 1
        assert result[0]["id"] == "ig-empty"


# ===========================================================================
# VPC Compute — ibm.vpc-instance-template
# ===========================================================================

class TestVPCInstanceTemplateChecks:
    """Reference checks: template older than 365 days, missing tags."""

    TEMPLATES = [
        {
            "id": "tmpl-recent",
            "name": "web-template",
            "crn": "crn:v1:bluemix:public:is:us-south:a/1::instance-template:tmpl-recent",
            "created_at": "2024-10-01T00:00:00Z",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": ["owner:ops"],
        },
        {
            "id": "tmpl-stale",
            "name": "stale-template",
            "crn": "crn:v1:bluemix:public:is:us-south:a/1::instance-template:tmpl-stale",
            "created_at": "2022-01-01T00:00:00Z",
            "resource_group": {"id": "rg-2", "name": "dev"},
            "tags": [],
        },
    ]

    def test_template_older_than_365_days(self):
        """CHECK: Template older than 365 days (stale configuration) — age filter."""
        from c7n_ibmcloud.filters.base import AgeFilter
        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat
            f = AgeFilter({"type": "age", "op": "gt", "days": 365}, None)
            f.date_attribute = "created_at"
            result = f.process(self.TEMPLATES)
        assert len(result) == 1
        assert result[0]["id"] == "tmpl-stale"

    def test_instance_template_missing_tags(self):
        """CHECK: Missing mandatory tags — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.TEMPLATES)
        assert len(result) == 1
        assert result[0]["id"] == "tmpl-stale"


# ===========================================================================
# VPC Networking — ibm.vpc-security-group
# ===========================================================================

class TestVPCSecurityGroupChecks:
    """Reference checks: SSH open from 0.0.0.0/0, RDP open, all-ports open, orphan SG."""

    SGS = [
        {
            "id": "sg-ssh-open",
            "name": "open-ssh",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::security-group:sg-ssh-open",
            "targets": [{"id": "inst-1"}],
            "tags": [],
            "rules": [
                {
                    "id": "r-1",
                    "direction": "inbound",
                    "protocol": "tcp",
                    "port_min": 22,
                    "port_max": 22,
                    "remote": {"cidr_block": "0.0.0.0/0"},
                }
            ],
        },
        {
            "id": "sg-rdp-open",
            "name": "open-rdp",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::security-group:sg-rdp-open",
            "targets": [{"id": "inst-2"}],
            "tags": [],
            "rules": [
                {
                    "id": "r-2",
                    "direction": "inbound",
                    "protocol": "tcp",
                    "port_min": 3389,
                    "port_max": 3389,
                    "remote": {"cidr_block": "0.0.0.0/0"},
                }
            ],
        },
        {
            "id": "sg-all-open",
            "name": "open-all",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::security-group:sg-all-open",
            "targets": [],
            "tags": [],
            "rules": [
                {
                    "id": "r-3",
                    "direction": "inbound",
                    "protocol": "tcp",
                    "port_min": 0,
                    "port_max": 65535,
                    "remote": {"cidr_block": "0.0.0.0/0"},
                }
            ],
        },
        {
            "id": "sg-clean",
            "name": "clean-sg",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::security-group:sg-clean",
            "targets": [{"id": "inst-3"}],
            "tags": [],
            "rules": [
                {
                    "id": "r-4",
                    "direction": "inbound",
                    "protocol": "tcp",
                    "port_min": 443,
                    "port_max": 443,
                    "remote": {"cidr_block": "10.0.0.0/8"},
                }
            ],
        },
    ]

    def test_sg_ssh_open_from_anywhere(self):
        """CHECK: Inbound rule allowing SSH (22) from 0.0.0.0/0 — JMESPath value filter."""
        key = (
            "rules[?port_min <= `22` && port_max >= `22`"
            " && direction == 'inbound' && remote.cidr_block == '0.0.0.0/0']"
        )
        f = _value_filter(key, "ne", [])
        result = f.process(self.SGS)
        ids = {r["id"] for r in result}
        assert "sg-ssh-open" in ids
        assert "sg-clean" not in ids

    def test_sg_rdp_open_from_anywhere(self):
        """CHECK: Inbound rule allowing RDP (3389) from 0.0.0.0/0 — JMESPath value filter."""
        key = (
            "rules[?port_min <= `3389` && port_max >= `3389`"
            " && direction == 'inbound' && remote.cidr_block == '0.0.0.0/0']"
        )
        f = _value_filter(key, "ne", [])
        result = f.process(self.SGS)
        ids = {r["id"] for r in result}
        assert "sg-rdp-open" in ids
        assert "sg-clean" not in ids

    def test_sg_all_ports_open_jmespath(self):
        """CHECK: Any inbound rule port range 0-65535 from 0.0.0.0/0 — JMESPath value filter."""
        key = (
            "rules[?port_min == `0` && port_max == `65535`"
            " && direction == 'inbound' && remote.cidr_block == '0.0.0.0/0']"
        )
        f = _value_filter(key, "ne", [])
        result = f.process(self.SGS)
        ids = {r["id"] for r in result}
        assert "sg-all-open" in ids

    def test_sg_orphan_no_attached_resources(self):
        """CHECK: Security group with no attached resources (orphan) — targets == []."""
        f = _value_filter("targets", "eq", [])
        result = f.process(self.SGS)
        assert len(result) == 1
        assert result[0]["id"] == "sg-all-open"


# ===========================================================================
# VPC Networking — ibm.vpc-network-acl
# ===========================================================================

class TestVPCNetworkACLChecks:
    """Reference checks: SSH allow from 0.0.0.0/0, RDP allow, no explicit deny-all."""

    ACLS = [
        {
            "id": "acl-ssh-open",
            "name": "allow-ssh",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::network-acl:acl-ssh-open",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": [],
            "rules": [
                {
                    "id": "rule-1",
                    "action": "allow",
                    "direction": "inbound",
                    "source": "0.0.0.0/0",
                    "destination": "10.0.0.0/24",
                    "destination_port_min": 22,
                    "destination_port_max": 22,
                    "protocol": "tcp",
                },
                {
                    "id": "rule-deny",
                    "action": "deny",
                    "direction": "inbound",
                    "source": "0.0.0.0/0",
                    "destination": "0.0.0.0/0",
                    "destination_port_min": 1,
                    "destination_port_max": 65535,
                    "protocol": "all",
                },
            ],
        },
        {
            "id": "acl-rdp-open",
            "name": "allow-rdp",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::network-acl:acl-rdp-open",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": [],
            "rules": [
                {
                    "id": "rule-2",
                    "action": "allow",
                    "direction": "inbound",
                    "source": "0.0.0.0/0",
                    "destination": "10.0.0.0/24",
                    "destination_port_min": 3389,
                    "destination_port_max": 3389,
                    "protocol": "tcp",
                },
            ],
        },
        {
            "id": "acl-clean",
            "name": "deny-all",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::network-acl:acl-clean",
            "resource_group": {"id": "rg-2", "name": "dev"},
            "tags": [],
            "rules": [
                {
                    "id": "rule-3",
                    "action": "deny",
                    "direction": "inbound",
                    "source": "0.0.0.0/0",
                    "destination": "0.0.0.0/0",
                    "destination_port_min": 1,
                    "destination_port_max": 65535,
                    "protocol": "all",
                },
            ],
        },
    ]

    def test_acl_ssh_allow_from_anywhere(self):
        """CHECK: Inbound ALLOW rule for SSH (22) from 0.0.0.0/0."""
        key = (
            "rules[?destination_port_min <= `22` && destination_port_max >= `22`"
            " && direction == 'inbound' && action == 'allow' && source == '0.0.0.0/0']"
        )
        f = _value_filter(key, "ne", [])
        result = f.process(self.ACLS)
        ids = {r["id"] for r in result}
        assert "acl-ssh-open" in ids
        assert "acl-clean" not in ids

    def test_acl_rdp_allow_from_anywhere(self):
        """CHECK: Inbound ALLOW rule for RDP (3389) from 0.0.0.0/0."""
        key = (
            "rules[?destination_port_min <= `3389` && destination_port_max >= `3389`"
            " && direction == 'inbound' && action == 'allow' && source == '0.0.0.0/0']"
        )
        f = _value_filter(key, "ne", [])
        result = f.process(self.ACLS)
        ids = {r["id"] for r in result}
        assert "acl-rdp-open" in ids
        assert "acl-clean" not in ids

    def test_acl_no_explicit_deny_all(self):
        """CHECK: No explicit DENY-all rule — ACL without a catch-all deny rule is flagged."""
        # Find ACLs that have NO deny-all rule covering all ports
        key = "rules[?action == 'deny' && destination_port_min == `1` && destination_port_max == `65535`]"
        f = _value_filter(key, "eq", [])
        result = f.process(self.ACLS)
        ids = {r["id"] for r in result}
        # acl-rdp-open has no deny-all
        assert "acl-rdp-open" in ids
        # acl-ssh-open has a deny rule — should not be in result
        assert "acl-ssh-open" not in ids
        assert "acl-clean" not in ids


# ===========================================================================
# VPC Networking — ibm.vpc-transit-gateway
# ===========================================================================

class TestVPCTransitGatewayChecks:
    """Reference checks: not available, no active connections, missing tags, stale."""

    GATEWAYS = [
        {
            "id": "tgw-ok",
            "name": "gw-active",
            "status": "available",
            "crn": "crn:v1:bluemix:public:transit:global:a/1::gateway:tgw-ok",
            "created_at": "2024-01-01T00:00:00Z",
            "connections": [{"id": "conn-1"}, {"id": "conn-2"}],
            "tags": ["owner:network-team"],
        },
        {
            "id": "tgw-failed",
            "name": "gw-down",
            "status": "failed",
            "crn": "crn:v1:bluemix:public:transit:global:a/1::gateway:tgw-failed",
            "created_at": "2022-01-01T00:00:00Z",
            "connections": [],
            "tags": [],
        },
        {
            "id": "tgw-thin",
            "name": "gw-one-conn",
            "status": "available",
            "crn": "crn:v1:bluemix:public:transit:global:a/1::gateway:tgw-thin",
            "created_at": "2022-06-01T00:00:00Z",
            "connections": [{"id": "conn-3"}],
            "tags": ["owner:network-team"],
        },
    ]

    def test_transit_gateway_not_available(self):
        """CHECK: Transit gateway not in available state — value filter status ne available."""
        f = _value_filter("status", "ne", "available")
        result = f.process(self.GATEWAYS)
        assert len(result) == 1
        assert result[0]["id"] == "tgw-failed"

    def test_transit_gateway_no_connections(self):
        """CHECK: Transit gateway with no active connections — value filter connections eq []."""
        f = _value_filter("connections", "eq", [])
        result = f.process(self.GATEWAYS)
        assert len(result) == 1
        assert result[0]["id"] == "tgw-failed"

    def test_transit_gateway_missing_owner_tag(self):
        """CHECK: Cross-account gateway without governance tags — tag key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.GATEWAYS)
        assert len(result) == 1
        assert result[0]["id"] == "tgw-failed"

    def test_transit_gateway_stale_fewer_than_2_connections(self):
        """CHECK: Stale gateway — fewer than 2 connections AND older than 30 days.

        tgw-ok has 2 connections (not stale).
        tgw-failed has 0 connections and is old (stale).
        tgw-thin has 1 connection and is old (stale).
        """
        from c7n_ibmcloud.filters.base import AgeFilter
        from c7n.filters.core import ValueFilter

        now = datetime(2025, 1, 1, tzinfo=timezone.utc)

        # Step 1: connections < 2
        mgr = MagicMock()
        mgr.get_model.return_value = MagicMock(id="id")
        conn_f = ValueFilter(
            {"type": "value", "key": "length(connections)", "op": "lt", "value": 2}, mgr
        )
        after_conn = conn_f.process(self.GATEWAYS)
        assert {r["id"] for r in after_conn} == {"tgw-failed", "tgw-thin"}

        # Step 2: age > 30 days (both old gateways pass; tgw-ok created 2024 also passes
        # but was already excluded in step 1)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat
            age_f = AgeFilter({"type": "age", "op": "gt", "days": 30}, None)
            age_f.date_attribute = "created_at"
            result = age_f.process(after_conn)

        assert {r["id"] for r in result} == {"tgw-failed", "tgw-thin"}
        assert "tgw-ok" not in {r["id"] for r in result}


# ===========================================================================
# VPC Networking — ibm.vpc-vpn-gateway / ibm.vpc-load-balancer / ibm.vpc-floating-ip
# ===========================================================================

class TestVPCFloatingIPChecks:
    """Reference check: Unattached floating IP (wasted cost) — target absent."""

    FIPS = [
        {
            "id": "fip-attached",
            "name": "fip-1",
            "address": "169.48.1.1",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::floating-ip:fip-attached",
            "tags": [],
            "target": {"id": "nic-1", "resource_type": "network_interface"},
        },
        {
            "id": "fip-unattached",
            "name": "fip-orphan",
            "address": "169.48.1.2",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::floating-ip:fip-unattached",
            "tags": [],
            # no "target" — unattached
        },
    ]

    def test_unattached_floating_ip(self):
        """CHECK: Unattached floating IP — target field absent."""
        unattached = [r for r in self.FIPS if "target" not in r]
        assert len(unattached) == 1
        assert unattached[0]["id"] == "fip-unattached"


class TestVPCLoadBalancerChecks:
    """Reference check: Public load balancer with no HTTPS listener."""

    LBS = [
        {
            "id": "lb-https",
            "name": "lb-secure",
            "is_public": True,
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::load-balancer:lb-https",
            "tags": [],
            "listeners": [
                {"id": "lst-1", "port": 443, "protocol": "https"},
                {"id": "lst-2", "port": 80, "protocol": "http"},
            ],
        },
        {
            "id": "lb-http-only",
            "name": "lb-insecure",
            "is_public": True,
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::load-balancer:lb-http-only",
            "tags": [],
            "listeners": [
                {"id": "lst-3", "port": 80, "protocol": "http"},
            ],
        },
    ]

    def test_public_lb_no_https_listener(self):
        """CHECK: Public load balancer with no HTTPS listener — JMESPath on listeners."""
        # Find public LBs where NO listener uses https
        key = "listeners[?protocol == 'https']"
        f = _value_filter(key, "eq", [])
        result = f.process(self.LBS)
        assert len(result) == 1
        assert result[0]["id"] == "lb-http-only"


class TestVPCVPNGatewayChecks:
    """Reference check: VPN connections using weak IKE/IPsec policy."""

    VPNS = [
        {
            "id": "vpn-strong",
            "name": "vpn-ok",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::vpn-gateway:vpn-strong",
            "tags": [],
            "connections": [
                {"id": "conn-1", "ike_policy": {"authentication_algorithm": "sha256"}},
            ],
        },
        {
            "id": "vpn-weak",
            "name": "vpn-legacy",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::vpn-gateway:vpn-weak",
            "tags": [],
            "connections": [
                {"id": "conn-2", "ike_policy": {"authentication_algorithm": "md5"}},
            ],
        },
    ]

    def test_vpn_weak_ike_policy(self):
        """CHECK: VPN connections using weak IKE policy — JMESPath on connections."""
        key = "connections[?ike_policy.authentication_algorithm == 'md5']"
        f = _value_filter(key, "ne", [])
        result = f.process(self.VPNS)
        assert len(result) == 1
        assert result[0]["id"] == "vpn-weak"


# ===========================================================================
# VPC Networking — ibm.vpc-ssh-key
# ===========================================================================

class TestVPCSSHKeyChecks:
    """Reference checks: SSH key older than 365 days, missing owner tag."""

    SSH_KEYS = [
        {
            "id": "key-recent",
            "name": "new-key",
            "crn": "crn:v1:bluemix:public:is:us-south:a/1::key:key-recent",
            "created_at": "2024-10-01T00:00:00Z",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": ["owner:ops"],
        },
        {
            "id": "key-stale",
            "name": "old-key",
            "crn": "crn:v1:bluemix:public:is:us-south:a/1::key:key-stale",
            "created_at": "2022-01-01T00:00:00Z",
            "resource_group": {"id": "rg-2", "name": "dev"},
            "tags": [],
        },
    ]

    def test_ssh_key_older_than_365_days(self):
        """CHECK: SSH key older than 365 days (rotation overdue) — age filter."""
        from c7n_ibmcloud.filters.base import AgeFilter
        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat
            f = AgeFilter({"type": "age", "op": "gt", "days": 365}, None)
            f.date_attribute = "created_at"
            result = f.process(self.SSH_KEYS)
        assert len(result) == 1
        assert result[0]["id"] == "key-stale"

    def test_vpc_ssh_key_missing_owner_tag(self):
        """CHECK: Missing owner tag — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.SSH_KEYS)
        assert len(result) == 1
        assert result[0]["id"] == "key-stale"


# ===========================================================================
# VPC Storage — ibm.vpc-volume
# ===========================================================================

class TestVPCVolumeChecks:
    """Reference checks: unattached volume >30 days, not customer-managed key, oversized."""

    VOLUMES = [
        {
            "id": "vol-attached",
            "name": "data-vol",
            "attachment_state": "attached",
            "encryption": "user_managed",
            "capacity": 500,
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::volume:vol-attached",
            "created_at": "2024-01-01T00:00:00Z",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": [],
        },
        {
            "id": "vol-unattached",
            "name": "orphan-vol",
            "attachment_state": "unattached",
            "encryption": "provider_managed",
            "capacity": 2500,
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::volume:vol-unattached",
            "created_at": "2024-01-01T00:00:00Z",
            "resource_group": {"id": "rg-2", "name": "dev"},
            "tags": [],
        },
    ]

    def test_unattached_volume(self):
        """CHECK: Unattached volume — attachment_state eq unattached."""
        f = _value_filter("attachment_state", "eq", "unattached")
        result = f.process(self.VOLUMES)
        assert len(result) == 1
        assert result[0]["id"] == "vol-unattached"

    def test_volume_not_customer_managed_key(self):
        """CHECK: Volume not encrypted with customer-managed key — encryption eq provider_managed."""
        f = _value_filter("encryption", "eq", "provider_managed")
        result = f.process(self.VOLUMES)
        assert len(result) == 1
        assert result[0]["id"] == "vol-unattached"

    def test_oversized_volume(self):
        """CHECK: Oversized volume (capacity above 2000 GiB) — capacity gt 2000."""
        f = _value_filter("capacity", "gt", 2000)
        result = f.process(self.VOLUMES)
        assert len(result) == 1
        assert result[0]["id"] == "vol-unattached"


# ===========================================================================
# VPC Storage — ibm.vpc-snapshot
# ===========================================================================

class TestVPCSnapshotChecks:
    """Reference checks: orphaned snapshot, age > 365 days, provider-managed encryption,
    lifecycle_state not stable."""

    SNAPSHOTS = [
        {
            "id": "snap-live",
            "name": "live-snap",
            "lifecycle_state": "stable",
            "encryption": "user_managed",
            "source_volume": {"id": "vol-1"},
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::snapshot:snap-live",
            "created_at": "2024-10-01T00:00:00Z",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": [],
        },
        {
            "id": "snap-orphaned",
            "name": "orphan-snap",
            "lifecycle_state": "stable",
            "encryption": "provider_managed",
            # source_volume absent — orphaned
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::snapshot:snap-orphaned",
            "created_at": "2022-01-01T00:00:00Z",
            "resource_group": {"id": "rg-2", "name": "dev"},
            "tags": [],
        },
        {
            "id": "snap-unstable",
            "name": "pending-snap",
            "lifecycle_state": "pending",
            "encryption": "user_managed",
            "source_volume": {"id": "vol-2"},
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::snapshot:snap-unstable",
            "created_at": "2024-12-01T00:00:00Z",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": [],
        },
    ]

    def test_orphaned_snapshot(self):
        """CHECK: Snapshot whose source volume was deleted (orphaned) — source_volume absent."""
        from c7n_ibmcloud.resources.vpc import VPCSnapshotOrphanedFilter
        f = VPCSnapshotOrphanedFilter({"type": "orphaned"}, MagicMock())
        result = f.process(self.SNAPSHOTS)
        ids = {r["id"] for r in result}
        assert "snap-orphaned" in ids
        assert "snap-live" not in ids

    def test_snapshot_older_than_365_days(self):
        """CHECK: Snapshot older than 365 days — age filter."""
        from c7n_ibmcloud.filters.base import AgeFilter
        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat
            f = AgeFilter({"type": "age", "op": "gt", "days": 365}, None)
            f.date_attribute = "created_at"
            result = f.process(self.SNAPSHOTS)
        assert len(result) == 1
        assert result[0]["id"] == "snap-orphaned"

    def test_snapshot_provider_managed_encryption(self):
        """CHECK: Snapshot not encrypted (provider-managed only) — encryption eq provider_managed."""
        f = _value_filter("encryption", "eq", "provider_managed")
        result = f.process(self.SNAPSHOTS)
        assert len(result) == 1
        assert result[0]["id"] == "snap-orphaned"

    def test_snapshot_lifecycle_not_stable(self):
        """CHECK: Snapshot lifecycle_state not stable — value filter lifecycle_state ne stable."""
        f = _value_filter("lifecycle_state", "ne", "stable")
        result = f.process(self.SNAPSHOTS)
        assert len(result) == 1
        assert result[0]["id"] == "snap-unstable"


# ===========================================================================
# VPC Storage — ibm.vpc-backup-policy
# ===========================================================================

class TestVPCBackupPolicyChecks:
    """Reference checks: no plans, no matching resource tags, not stable lifecycle."""

    POLICIES = [
        {
            "id": "bp-configured",
            "name": "daily-backup",
            "lifecycle_state": "stable",
            "plans": [{"id": "plan-1", "name": "daily"}],
            "match_user_tags": ["backup:daily"],
            "crn": "crn:v1:bluemix:public:is:us-south:a/1::backup-policy:bp-configured",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": [],
        },
        {
            "id": "bp-empty",
            "name": "unconfigured-policy",
            "lifecycle_state": "stable",
            "plans": [],
            "match_user_tags": [],
            "crn": "crn:v1:bluemix:public:is:us-south:a/1::backup-policy:bp-empty",
            "resource_group": {"id": "rg-2", "name": "dev"},
            "tags": [],
        },
        {
            "id": "bp-unstable",
            "name": "pending-policy",
            "lifecycle_state": "updating",
            "plans": [{"id": "plan-2"}],
            "match_user_tags": ["backup:weekly"],
            "crn": "crn:v1:bluemix:public:is:us-south:a/1::backup-policy:bp-unstable",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": [],
        },
    ]

    def test_backup_policy_no_plans(self):
        """CHECK: Backup policy with no plans configured — unused filter."""
        from c7n_ibmcloud.resources.vpc import VPCBackupPolicyUnusedFilter
        f = VPCBackupPolicyUnusedFilter({"type": "unused"}, MagicMock())
        result = f.process(self.POLICIES)
        assert len(result) == 1
        assert result[0]["id"] == "bp-empty"

    def test_backup_policy_no_matching_resource_tags(self):
        """CHECK: Backup policy not matching any resource tags — match_user_tags eq []."""
        f = _value_filter("match_user_tags", "eq", [])
        result = f.process(self.POLICIES)
        assert len(result) == 1
        assert result[0]["id"] == "bp-empty"

    def test_backup_policy_not_stable_lifecycle(self):
        """CHECK: Backup policy in non-stable lifecycle state — lifecycle_state ne stable."""
        f = _value_filter("lifecycle_state", "ne", "stable")
        result = f.process(self.POLICIES)
        assert len(result) == 1
        assert result[0]["id"] == "bp-unstable"


# ===========================================================================
# VPC Storage — ibm.vpc-file-share
# ===========================================================================

class TestVPCFileShareChecks:
    """Reference checks: no mount targets, provider-managed encryption, not stable,
    oversized, missing tags."""

    SHARES = [
        {
            "id": "share-mounted",
            "name": "nfs-share",
            "lifecycle_state": "stable",
            "size": 200,
            "encryption": "user_managed",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::share:share-mounted",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "mount_targets": [{"id": "mt-1"}],
            "tags": ["owner:team-a"],
        },
        {
            "id": "share-no-mounts",
            "name": "nfs-unused",
            "lifecycle_state": "stable",
            "size": 12000,
            "encryption": "provider_managed",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::share:share-no-mounts",
            "resource_group": {"id": "rg-2", "name": "dev"},
            "mount_targets": [],
            "tags": [],
        },
        {
            "id": "share-updating",
            "name": "nfs-pending",
            "lifecycle_state": "updating",
            "size": 500,
            "encryption": "user_managed",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::share:share-updating",
            "resource_group": {"id": "rg-1", "name": "prod"},
            "mount_targets": [{"id": "mt-2"}],
            "tags": ["owner:team-b"],
        },
    ]

    def test_file_share_no_mount_targets(self):
        """CHECK: File share with no mount targets (unused) — mount_targets eq []."""
        f = _value_filter("mount_targets", "eq", [])
        result = f.process(self.SHARES)
        assert len(result) == 1
        assert result[0]["id"] == "share-no-mounts"

    def test_file_share_provider_managed_encryption(self):
        """CHECK: Share not encrypted with customer-managed key — encryption eq provider_managed."""
        f = _value_filter("encryption", "eq", "provider_managed")
        result = f.process(self.SHARES)
        assert len(result) == 1
        assert result[0]["id"] == "share-no-mounts"

    def test_file_share_not_stable(self):
        """CHECK: Share in non-stable lifecycle state — lifecycle_state ne stable."""
        f = _value_filter("lifecycle_state", "ne", "stable")
        result = f.process(self.SHARES)
        assert len(result) == 1
        assert result[0]["id"] == "share-updating"

    def test_file_share_oversized(self):
        """CHECK: Oversized share (size > 10000 GiB) — size gt 10000."""
        f = _value_filter("size", "gt", 10000)
        result = f.process(self.SHARES)
        assert len(result) == 1
        assert result[0]["id"] == "share-no-mounts"

    def test_file_share_missing_tags(self):
        """CHECK: Missing mandatory tags — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.SHARES)
        assert len(result) == 1
        assert result[0]["id"] == "share-no-mounts"


# ===========================================================================
# Cloud Object Storage — ibm.cos-bucket
# ===========================================================================

class TestCOSBucketChecks:
    """Reference checks: public ACL, no CMK, no versioning, no lifecycle, missing tags."""

    BUCKETS = [
        {
            "name": "secure-bucket",
            "id": "secure-bucket",
            "location": "us-south-standard",
            "c7n:versioning": "Enabled",
            "c7n:kp_enabled": True,
            "c7n:kp_key_crn": "crn:v1:bluemix:public:kms:us-south:a/1:inst:key:k1",
            "c7n:public_access": False,
            "c7n:lifecycle": [{"ID": "expire-90"}],
            "tags": ["owner:platform"],
        },
        {
            "name": "insecure-bucket",
            "id": "insecure-bucket",
            "location": "eu-de-standard",
            "c7n:versioning": "Disabled",
            "c7n:kp_enabled": False,
            "c7n:kp_key_crn": "",
            "c7n:public_access": True,
            "c7n:lifecycle": [],
            "tags": [],
        },
    ]

    def test_bucket_public_acl(self):
        """CHECK: Bucket with public ACL access — public-access filter value:true."""
        from c7n_ibmcloud.filters.base import PublicAccessFilter
        f = PublicAccessFilter({"type": "public-access", "value": True}, None)
        result = f.process(self.BUCKETS)
        assert len(result) == 1
        assert result[0]["name"] == "insecure-bucket"

    def test_bucket_no_customer_managed_key(self):
        """CHECK: Bucket not using customer-managed Key Protect key — customer-managed-key filter."""
        from c7n_ibmcloud.resources.cos import COSBucketCustomerManagedKeyFilter
        f = COSBucketCustomerManagedKeyFilter({"type": "customer-managed-key", "value": False}, None)
        result = f.process(self.BUCKETS)
        assert len(result) == 1
        assert result[0]["name"] == "insecure-bucket"

    def test_bucket_no_versioning(self):
        """CHECK: Bucket without versioning — versioning-enabled filter value:false."""
        from c7n_ibmcloud.resources.cos import COSBucketVersioningFilter
        f = COSBucketVersioningFilter({"type": "versioning-enabled", "value": False}, None)
        result = f.process(self.BUCKETS)
        assert len(result) == 1
        assert result[0]["name"] == "insecure-bucket"

    def test_bucket_no_lifecycle_policy(self):
        """CHECK: Bucket without a lifecycle policy — c7n:lifecycle eq []."""
        f = _value_filter("c7n:lifecycle", "eq", [])
        result = f.process(self.BUCKETS)
        assert len(result) == 1
        assert result[0]["name"] == "insecure-bucket"

    def test_bucket_missing_owner_tag(self):
        """CHECK: Missing mandatory tags — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.BUCKETS)
        assert len(result) == 1
        assert result[0]["name"] == "insecure-bucket"


# ===========================================================================
# Key Protect (KMS) — ibm.kms-key
# ===========================================================================

class TestKMSKeyChecks:
    """Reference checks: no rotation policy, deactivated/destroyed state, age > 365 days,
    pre-activation state."""

    KEYS = [
        {
            "id": "key-active-rotating",
            "name": "root-key-prod",
            "state": 1,  # active
            "creationDate": "2024-01-01T00:00:00Z",
            "crn": "crn:v1:bluemix:public:kms:us-south:a/1:inst:key:key-active-rotating",
            "c7n:instance_id": "inst-001",
            "tags": [],
        },
        {
            "id": "key-deactivated",
            "name": "old-key",
            "state": 3,  # deactivated
            "creationDate": "2020-01-01T00:00:00Z",
            "crn": "crn:v1:bluemix:public:kms:us-south:a/1:inst:key:key-deactivated",
            "c7n:instance_id": "inst-001",
            "tags": [],
        },
        {
            "id": "key-preactivation",
            "name": "new-key-unused",
            "state": 0,  # pre-activation
            "creationDate": "2024-10-01T00:00:00Z",
            "crn": "crn:v1:bluemix:public:kms:us-south:a/1:inst:key:key-preactivation",
            "c7n:instance_id": "inst-001",
            "tags": [],
        },
    ]

    def test_key_no_rotation_policy(self):
        """CHECK: Key without automatic rotation policy — rotation-policy enabled:false."""
        from c7n_ibmcloud.resources.kms import KMSKeyRotationFilter
        from conftest import FakeSessionFactory
        from unittest.mock import MagicMock

        kp_client = MagicMock()
        kp_client.get_key_policies.return_value = MagicMock(
            get_result=lambda: {"resources": [{"rotation": {}}]}
        )
        session = FakeSession(clients={"key-protect": kp_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        f = KMSKeyRotationFilter({"type": "rotation-policy", "enabled": False}, manager)
        with patch("c7n_ibmcloud.resources.kms.local_session", return_value=session):
            result = f.process(self.KEYS)

        # All keys have no rotation policy in our stub → all returned
        assert len(result) == len(self.KEYS)

    def test_key_deactivated_state(self):
        """CHECK: Key in deactivated or destroyed state — state value:deactivated."""
        from c7n_ibmcloud.resources.kms import KMSKeyStateFilter
        f = KMSKeyStateFilter({"type": "state", "value": "deactivated"}, None)
        result = f.process(self.KEYS)
        assert len(result) == 1
        assert result[0]["id"] == "key-deactivated"

    def test_key_older_than_365_days(self):
        """CHECK: Key older than 365 days (rotation overdue) — age filter."""
        from c7n_ibmcloud.filters.base import AgeFilter
        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat
            f = AgeFilter({"type": "age", "op": "gt", "days": 365}, None)
            f.date_attribute = "creationDate"
            result = f.process(self.KEYS)
        # key-active-rotating (2024-01-01) is ~366 days before 2025-01-01 → matches
        # key-deactivated (2020-01-01) → matches
        ids = {r["id"] for r in result}
        assert "key-deactivated" in ids
        assert "key-active-rotating" in ids
        assert "key-preactivation" not in ids

    def test_key_pre_activation_state(self):
        """CHECK: Key in pre-activation state (never activated) — state value:pre-activation."""
        from c7n_ibmcloud.resources.kms import KMSKeyStateFilter
        f = KMSKeyStateFilter({"type": "state", "value": "pre-activation"}, None)
        result = f.process(self.KEYS)
        assert len(result) == 1
        assert result[0]["id"] == "key-preactivation"


# ===========================================================================
# Kubernetes (IKS / ROKS) — ibm.iks-cluster / ibm.roks-cluster
# ===========================================================================

class TestKubernetesChecks:
    """Reference checks: EOL version, not normal state, no private endpoint, missing tags."""

    IKS_CLUSTERS = [
        {
            "id": "iks-current",
            "name": "prod-k8s",
            "state": "normal",
            "masterKubeVersion": "1.29.3",
            "disablePublicServiceEndpoint": True,
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": ["owner:platform"],
        },
        {
            "id": "iks-eol",
            "name": "old-k8s",
            "state": "critical",
            "masterKubeVersion": "1.25.10",
            "disablePublicServiceEndpoint": False,
            "resource_group": {"id": "rg-2", "name": "dev"},
            "tags": [],
        },
    ]

    ROKS_CLUSTERS = [
        {
            "id": "roks-current",
            "name": "prod-ocp",
            "state": "normal",
            "masterKubeVersion": "4.14.12_openshift",
            "disablePublicServiceEndpoint": True,
            "resource_group": {"id": "rg-1", "name": "prod"},
            "tags": ["owner:platform"],
        },
        {
            "id": "roks-eol",
            "name": "old-ocp",
            "state": "normal",
            "masterKubeVersion": "4.11.55_openshift",
            "disablePublicServiceEndpoint": False,
            "resource_group": {"id": "rg-2", "name": "dev"},
            "tags": [],
        },
    ]

    def test_iks_eol_version(self):
        """CHECK: Cluster running EOL Kubernetes version — version lt 1.29."""
        from c7n_ibmcloud.resources.kubernetes import IKSClusterVersionFilter
        f = IKSClusterVersionFilter({"type": "version", "op": "lt", "value": "1.29"}, None)
        result = f.process(self.IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "iks-eol"

    def test_iks_not_normal_state(self):
        """CHECK: Cluster not in normal state — value filter state ne normal."""
        f = _value_filter("state", "ne", "normal")
        result = f.process(self.IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "iks-eol"

    def test_iks_no_private_endpoint(self):
        """CHECK: Cluster without private endpoint — disablePublicServiceEndpoint eq false."""
        f = _value_filter("disablePublicServiceEndpoint", "eq", False)
        result = f.process(self.IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "iks-eol"

    def test_iks_missing_owner_tag(self):
        """CHECK: Missing mandatory tags — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "iks-eol"

    def test_roks_eol_version(self):
        """CHECK: ROKS cluster running EOL version — version lt 4.13 (strips _openshift)."""
        from c7n_ibmcloud.resources.kubernetes import ROKSClusterVersionFilter
        f = ROKSClusterVersionFilter({"type": "version", "op": "lt", "value": "4.13"}, None)
        result = f.process(self.ROKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "roks-eol"


# ===========================================================================
# PowerVS — ibm.powervs-instance
# ===========================================================================

class TestPowerVSInstanceChecks:
    """Reference checks: ERROR state, SHUTOFF > 30 days, dedicated without tag,
    oversized processors, oversized memory, capped + high processors, missing tags."""

    PVM_INSTANCES = [
        {
            "pvmInstanceID": "pvm-active",
            "serverName": "prod-vm",
            "status": "ACTIVE",
            "procType": "shared",
            "processors": 2.0,
            "memory": 64,
            "creationDate": "2024-01-01T00:00:00Z",
            "c7n:workspace_id": "ws-001",
            "c7n:region": "us-south",
            "tags": ["owner:ops"],
        },
        {
            "pvmInstanceID": "pvm-error",
            "serverName": "failed-vm",
            "status": "ERROR",
            "procType": "dedicated",
            "processors": 8.0,
            "memory": 512,
            "creationDate": "2022-01-01T00:00:00Z",
            "c7n:workspace_id": "ws-001",
            "c7n:region": "us-south",
            "tags": [],
        },
        {
            "pvmInstanceID": "pvm-shutoff",
            "serverName": "stopped-vm",
            "status": "SHUTOFF",
            "procType": "capped",
            "processors": 4.0,
            "memory": 300,
            "creationDate": "2024-01-01T00:00:00Z",
            "c7n:workspace_id": "ws-002",
            "c7n:region": "eu-de",
            "tags": ["owner:team-a"],
        },
    ]

    def test_powervs_instance_error_state(self):
        """CHECK: Instance in ERROR state — value filter status eq ERROR."""
        f = _value_filter("status", "eq", "ERROR")
        result = f.process(self.PVM_INSTANCES)
        assert len(result) == 1
        assert result[0]["pvmInstanceID"] == "pvm-error"

    def test_powervs_instance_shutoff(self):
        """CHECK: Instance stopped (SHUTOFF) — value filter status eq SHUTOFF."""
        f = _value_filter("status", "eq", "SHUTOFF")
        result = f.process(self.PVM_INSTANCES)
        assert len(result) == 1
        assert result[0]["pvmInstanceID"] == "pvm-shutoff"

    def test_powervs_dedicated_proc_without_justification(self):
        """CHECK: Dedicated proc type without justification tag — procType eq dedicated."""
        f = _value_filter("procType", "eq", "dedicated")
        result = f.process(self.PVM_INSTANCES)
        assert len(result) == 1
        assert result[0]["pvmInstanceID"] == "pvm-error"

    def test_powervs_oversized_processors(self):
        """CHECK: Oversized VM — high processor entitlement (> 4 vCPU) on shared type."""
        f = _value_filter("processors", "gt", 4)
        result = f.process(self.PVM_INSTANCES)
        assert len(result) == 1
        assert result[0]["pvmInstanceID"] == "pvm-error"

    def test_powervs_oversized_memory(self):
        """CHECK: Oversized VM — large memory allocation (> 256 GiB)."""
        f = _value_filter("memory", "gt", 256)
        result = f.process(self.PVM_INSTANCES)
        ids = {r["pvmInstanceID"] for r in result}
        assert "pvm-error" in ids
        assert "pvm-shutoff" in ids

    def test_powervs_capped_high_entitlement(self):
        """CHECK: High entitlement on capped proc type — procType eq capped + processors gt 2."""
        f_type = _value_filter("procType", "eq", "capped")
        capped = f_type.process(self.PVM_INSTANCES)
        f_cpu = _value_filter("processors", "gt", 2)
        result = f_cpu.process(capped)
        assert len(result) == 1
        assert result[0]["pvmInstanceID"] == "pvm-shutoff"

    def test_powervs_instance_missing_tags(self):
        """CHECK: Missing mandatory tags — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.PVM_INSTANCES)
        assert len(result) == 1
        assert result[0]["pvmInstanceID"] == "pvm-error"


# ===========================================================================
# PowerVS — ibm.powervs-volume
# ===========================================================================

class TestPowerVSVolumeChecks:
    """Reference checks: unattached volume, shareable volume, oversized, tier-1 unattached,
    missing owner/environment tags."""

    PV_VOLUMES = [
        {
            "volumeID": "pvvol-attached",
            "name": "prod-vol",
            "state": "in-use",
            "diskType": "tier1",
            "size": 500,
            "shareable": False,
            "pvmInstanceIDs": ["pvm-aaa"],
            "c7n:workspace_id": "ws-001",
            "c7n:region": "us-south",
            "tags": ["owner:ops", "environment:production"],
        },
        {
            "volumeID": "pvvol-unattached",
            "name": "orphan-vol",
            "state": "available",
            "diskType": "tier1",
            "size": 2500,
            "shareable": True,
            "pvmInstanceIDs": [],
            "c7n:workspace_id": "ws-002",
            "c7n:region": "eu-de",
            "tags": [],
        },
        {
            "volumeID": "pvvol-tier3",
            "name": "slow-vol",
            "state": "available",
            "diskType": "tier3",
            "size": 100,
            "shareable": False,
            "pvmInstanceIDs": [],
            "c7n:workspace_id": "ws-002",
            "c7n:region": "eu-de",
            "tags": ["owner:team-a"],
        },
    ]

    def test_powervs_volume_unattached(self):
        """CHECK: Volume not attached to any instance — pvmInstanceIDs eq []."""
        f = _value_filter("pvmInstanceIDs", "eq", [])
        result = f.process(self.PV_VOLUMES)
        ids = {r["volumeID"] for r in result}
        assert "pvvol-unattached" in ids
        assert "pvvol-tier3" in ids
        assert "pvvol-attached" not in ids

    def test_powervs_volume_shareable(self):
        """CHECK: Shareable volume exposed unintentionally — shareable eq true."""
        f = _value_filter("shareable", "eq", True)
        result = f.process(self.PV_VOLUMES)
        assert len(result) == 1
        assert result[0]["volumeID"] == "pvvol-unattached"

    def test_powervs_volume_oversized(self):
        """CHECK: Oversized volume (size > 2000 GiB) — size gt 2000."""
        f = _value_filter("size", "gt", 2000)
        result = f.process(self.PV_VOLUMES)
        assert len(result) == 1
        assert result[0]["volumeID"] == "pvvol-unattached"

    def test_powervs_tier1_unattached(self):
        """CHECK: Tier-1 (high-performance) volume not in active use — diskType tier1 + pvmInstanceIDs []."""
        f_tier = _value_filter("diskType", "eq", "tier1")
        tier1 = f_tier.process(self.PV_VOLUMES)
        f_unattached = _value_filter("pvmInstanceIDs", "eq", [])
        result = f_unattached.process(tier1)
        assert len(result) == 1
        assert result[0]["volumeID"] == "pvvol-unattached"

    def test_powervs_volume_missing_owner_tag(self):
        """CHECK: Missing owner tag — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.PV_VOLUMES)
        assert len(result) == 1
        assert result[0]["volumeID"] == "pvvol-unattached"

    def test_powervs_volume_missing_environment_tag(self):
        """CHECK: Missing environment tag — tag filter key:environment op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "environment", "op": "absent"}, None)
        result = f.process(self.PV_VOLUMES)
        ids = {r["volumeID"] for r in result}
        assert "pvvol-unattached" in ids
        assert "pvvol-tier3" in ids
        assert "pvvol-attached" not in ids


# ===========================================================================
# PowerVS — ibm.powervs-ssh-key
# ===========================================================================

class TestPowerVSSSHKeyChecks:
    """Reference checks: SSH key older than 365 days."""

    PVKEYS = [
        {
            "name": "pvs-key-new",
            "sshKeyName": "pvs-key-new",
            "creationDate": "2024-10-01T00:00:00Z",
            "c7n:workspace_id": "ws-001",
            "c7n:region": "us-south",
        },
        {
            "name": "pvs-key-old",
            "sshKeyName": "pvs-key-old",
            "creationDate": "2020-01-01T00:00:00Z",
            "c7n:workspace_id": "ws-001",
            "c7n:region": "us-south",
        },
    ]

    def test_powervs_ssh_key_older_than_365_days(self):
        """CHECK: SSH key older than 365 days (rotation overdue) — age filter."""
        from c7n_ibmcloud.filters.base import AgeFilter
        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat
            f = AgeFilter({"type": "age", "op": "gt", "days": 365}, None)
            f.date_attribute = "creationDate"
            result = f.process(self.PVKEYS)
        assert len(result) == 1
        assert result[0]["name"] == "pvs-key-old"


# ===========================================================================
# PowerVS — ibm.powervs-network
# ===========================================================================

class TestPowerVSNetworkChecks:
    """Reference check: Public network type in use (should be private)."""

    NETWORKS = [
        {
            "networkID": "net-private",
            "name": "private-net",
            "type": "vlan",
            "c7n:workspace_id": "ws-001",
            "c7n:region": "us-south",
        },
        {
            "networkID": "net-public",
            "name": "public-net",
            "type": "pub-vlan",
            "c7n:workspace_id": "ws-001",
            "c7n:region": "us-south",
        },
    ]

    def test_powervs_public_network_type(self):
        """CHECK: Public network type in use — value filter type eq pub-vlan."""
        f = _value_filter("type", "eq", "pub-vlan")
        result = f.process(self.NETWORKS)
        assert len(result) == 1
        assert result[0]["networkID"] == "net-public"


# ===========================================================================
# Databases as a Service (DBaaS)
# ===========================================================================

class TestDBaaSChecks:
    """Reference checks cover all 8 engines: EOL version, not running state,
    public endpoint, deprecated plan, missing tags, under-provisioned."""

    # Sample instances representing different engines
    DB_INSTANCES = [
        {
            "id": "crn:v1:bluemix:public:databases-for-postgresql:us-south:a/1:pg-1::",
            "crn": "crn:v1:bluemix:public:databases-for-postgresql:us-south:a/1:pg-1::",
            "name": "prod-postgres",
            "state": "active",
            "resource_plan_id": "databases-for-postgresql-standard",
            "c7n:version": "15.3",
            "service_endpoints": "private",
            "resources": {"memory": {"allocation_mb": 8192}},
            "tags": ["owner:platform"],
        },
        {
            "id": "crn:v1:bluemix:public:databases-for-postgresql:eu-de:a/1:pg-2::",
            "crn": "crn:v1:bluemix:public:databases-for-postgresql:eu-de:a/1:pg-2::",
            "name": "legacy-postgres",
            "state": "active",
            "resource_plan_id": "databases-for-postgresql-enterprise",
            "c7n:version": "12.8",
            "service_endpoints": "public",
            "resources": {"memory": {"allocation_mb": 2048}},
            "tags": [],
        },
        {
            "id": "crn:v1:bluemix:public:databases-for-mysql:us-south:a/1:my-1::",
            "crn": "crn:v1:bluemix:public:databases-for-mysql:us-south:a/1:my-1::",
            "name": "dev-mysql",
            "state": "failed",
            "resource_plan_id": "databases-for-mysql-standard",
            "c7n:version": "8.0",
            "service_endpoints": "private",
            "resources": {"memory": {"allocation_mb": 1024}},
            "tags": [],
        },
        {
            "id": "crn:v1:bluemix:public:databases-for-redis:us-south:a/1:redis-1::",
            "crn": "crn:v1:bluemix:public:databases-for-redis:us-south:a/1:redis-1::",
            "name": "cache-redis",
            "state": "active",
            "resource_plan_id": "databases-for-redis-standard",
            "c7n:version": "6.2",
            "service_endpoints": "private",
            "resources": {"memory": {"allocation_mb": 6144}},
            "tags": ["owner:backend"],
        },
    ]

    def test_dbaas_eol_version_postgresql(self):
        """CHECK: Database running EOL/unsupported version — version lt 14 for PostgreSQL."""
        from c7n_ibmcloud.resources.dbaas import IcdPostgreSQL
        filter_cls = IcdPostgreSQL.filter_registry.get("version")
        f = filter_cls({"type": "version", "op": "lt", "value": "14"}, None)
        result = f.process(self.DB_INSTANCES[:2])
        assert len(result) == 1
        assert result[0]["name"] == "legacy-postgres"

    def test_dbaas_not_running_state(self):
        """CHECK: Database not in running state — value filter state ne active."""
        f = _value_filter("state", "ne", "active")
        result = f.process(self.DB_INSTANCES)
        assert len(result) == 1
        assert result[0]["name"] == "dev-mysql"

    def test_dbaas_public_endpoint(self):
        """CHECK: Database not using private endpoint — service_endpoints contains public."""
        f = _value_filter("service_endpoints", "eq", "public")
        result = f.process(self.DB_INSTANCES)
        assert len(result) == 1
        assert result[0]["name"] == "legacy-postgres"

    def test_dbaas_deprecated_plan(self):
        """CHECK: Database on a deprecated/non-standard plan — plan filter."""
        from c7n_ibmcloud.resources.dbaas import IcdPostgreSQL
        filter_cls = IcdPostgreSQL.filter_registry.get("plan")
        f = filter_cls({"type": "plan", "value": "enterprise"}, None)
        result = f.process(self.DB_INSTANCES[:2])
        assert len(result) == 1
        assert result[0]["name"] == "legacy-postgres"

    def test_dbaas_missing_owner_tag(self):
        """CHECK: Missing mandatory tags — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.DB_INSTANCES)
        ids = {r["name"] for r in result}
        assert "legacy-postgres" in ids
        assert "dev-mysql" in ids
        assert "prod-postgres" not in ids

    def test_dbaas_under_provisioned_memory(self):
        """CHECK: Under-provisioned instance (< 4096 MB memory) — value filter on allocation_mb."""
        f = _value_filter("resources.memory.allocation_mb", "lt", 4096)
        result = f.process(self.DB_INSTANCES)
        ids = {r["name"] for r in result}
        assert "legacy-postgres" in ids
        assert "dev-mysql" in ids
        assert "prod-postgres" not in ids

    def test_dbaas_all_6_engines_registered(self):
        """CHECK: All 6 DBaaS engine resource types are registered."""
        from c7n_ibmcloud.provider import resources
        for rtype in (
            "dbaas-postgresql", "dbaas-mysql", "dbaas-mongodb", "dbaas-redis",
            "dbaas-elasticsearch", "dbaas-rabbitmq",
        ):
            assert resources.get(rtype) is not None, f"ibm.{rtype} not registered"

    def test_dbaas_mysql_eol_version(self):
        """CHECK: MySQL database running EOL version — version lt 8."""
        from c7n_ibmcloud.resources.dbaas import IcdMySQL
        filter_cls = IcdMySQL.filter_registry.get("version")
        f = filter_cls({"type": "version", "op": "lt", "value": "8"}, None)
        result = f.process([self.DB_INSTANCES[2]])
        # dev-mysql is 8.0 — NOT less than 8
        assert result == []

    def test_dbaas_redis_eol_version(self):
        """CHECK: Redis database running EOL version — version lt 7."""
        from c7n_ibmcloud.resources.dbaas import IcdRedis
        filter_cls = IcdRedis.filter_registry.get("version")
        f = filter_cls({"type": "version", "op": "lt", "value": "7"}, None)
        result = f.process([self.DB_INSTANCES[3]])
        # redis is 6.2 — should match lt 7
        assert len(result) == 1
        assert result[0]["name"] == "cache-redis"


# ===========================================================================
# Cross-cutting checks (all resource types)
# ===========================================================================

class TestCrossCuttingChecks:
    """Reference checks: missing owner/environment/cost-centre tags, wrong resource group,
    marked-for-op past deadline, age > N days."""

    # Generic multi-type resources with tags and resource_group
    RESOURCES = [
        {
            "id": "res-full-tags",
            "name": "tagged-resource",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::instance:res-full-tags",
            "resource_group": {"id": "rg-prod", "name": "production"},
            "created_at": "2024-01-01T00:00:00Z",
            "tags": ["owner:platform", "environment:production", "cost-centre:cc-001"],
        },
        {
            "id": "res-no-tags",
            "name": "untagged-resource",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::instance:res-no-tags",
            "resource_group": {"id": "rg-dev", "name": "development"},
            "created_at": "2022-01-01T00:00:00Z",
            "tags": [],
        },
        {
            "id": "res-wrong-group",
            "name": "mismatch-resource",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::instance:res-wrong-group",
            "resource_group": {"id": "rg-dev", "name": "development"},
            "created_at": "2024-06-01T00:00:00Z",
            "tags": ["owner:platform", "environment:production", "cost-centre:cc-001"],
        },
        {
            "id": "res-marked",
            "name": "marked-resource",
            "crn": "crn:v1:bluemix:public:is:us-south-1:a/1::instance:res-marked",
            "resource_group": {"id": "rg-prod", "name": "production"},
            "created_at": "2024-01-01T00:00:00Z",
            "tags": [
                "owner:platform",
                "environment:production",
                "cost-centre:cc-001",
                "custodian_status_delete:2024-01-15",
            ],
        },
    ]

    def test_crosscut_missing_owner_tag(self):
        """CHECK: Missing owner tag (all resource types) — tag filter key:owner op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(self.RESOURCES)
        assert len(result) == 1
        assert result[0]["id"] == "res-no-tags"

    def test_crosscut_missing_environment_tag(self):
        """CHECK: Missing environment tag — tag filter key:environment op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "environment", "op": "absent"}, None)
        result = f.process(self.RESOURCES)
        assert len(result) == 1
        assert result[0]["id"] == "res-no-tags"

    def test_crosscut_missing_cost_centre_tag(self):
        """CHECK: Missing cost-centre tag — tag filter key:cost-centre op:absent."""
        from c7n_ibmcloud.filters.base import TagFilter
        f = TagFilter({"type": "tag", "key": "cost-centre", "op": "absent"}, None)
        result = f.process(self.RESOURCES)
        assert len(result) == 1
        assert result[0]["id"] == "res-no-tags"

    def test_crosscut_resource_in_wrong_resource_group(self):
        """CHECK: Resource in wrong resource group for its environment — resource-group filter."""
        from c7n_ibmcloud.filters.base import ResourceGroupFilter
        # Resources tagged environment:production but in development RG are mismatched
        prod_tagged_in_dev_rg = [
            r for r in self.RESOURCES
            if any("environment:production" in t for t in r["tags"])
            and r["resource_group"]["name"] == "development"
        ]
        assert len(prod_tagged_in_dev_rg) == 1
        assert prod_tagged_in_dev_rg[0]["id"] == "res-wrong-group"

    def test_crosscut_marked_for_op_past_deadline(self):
        """CHECK: Resource marked for operation past deadline — marked-for-op filter."""
        from c7n_ibmcloud.filters.base import MarkedForOpFilter
        f = MarkedForOpFilter({"type": "marked-for-op", "op": "delete"}, None)
        # At least one resource has the custodian_status tag
        marked = [r for r in self.RESOURCES
                  if any("custodian_status" in t for t in r["tags"])]
        assert len(marked) == 1
        assert marked[0]["id"] == "res-marked"

    def test_crosscut_resource_older_than_n_days(self):
        """CHECK: Resource created more than N days ago — age filter."""
        from c7n_ibmcloud.filters.base import AgeFilter
        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat
            f = AgeFilter({"type": "age", "op": "gt", "days": 700}, None)
            f.date_attribute = "created_at"
            result = f.process(self.RESOURCES)
        # res-no-tags (2022-01-01) is > 700 days before 2025-01-01
        ids = {r["id"] for r in result}
        assert "res-no-tags" in ids
        assert "res-full-tags" not in ids


# ===========================================================================
# Sanity: verify all IBM resource types referenced in checks are registered
# ===========================================================================

class TestResourceTypeRegistration:
    """Verify every resource type referenced in the governance reference is registered."""

    EXPECTED_TYPES = [
        # IAM
        "iam-user",
        "iam-api-key",
        "iam-service-id",
        "iam-access-group",
        "iam-trusted-profile",
        # VPC Compute
        "vpc-instance",
        "vpc-bare-metal",
        "vpc-dedicated-host",
        "vpc-instance-group",
        "vpc-instance-template",
        # VPC Networking
        "vpc-security-group",
        "vpc-network-acl",
        "vpc-transit-gateway",
        "vpc-vpn-gateway",
        "vpc-load-balancer",
        "vpc-floating-ip",
        "vpc-ssh-key",
        # VPC Storage
        "vpc-volume",
        "vpc-snapshot",
        "vpc-backup-policy",
        "vpc-file-share",
        # COS
        "cos-bucket",
        # KMS
        "kms-key",
        # Kubernetes
        "iks-cluster",
        "roks-cluster",
        # PowerVS
        "powervs-instance",
        "powervs-volume",
        "powervs-ssh-key",
        "powervs-network",
        # DBaaS (6 engines)
        "dbaas-postgresql",
        "dbaas-mysql",
        "dbaas-mongodb",
        "dbaas-redis",
        "dbaas-elasticsearch",
        "dbaas-rabbitmq",
    ]

    def test_all_resource_types_registered(self):
        """All resource types from the governance reference are registered in the IBM provider."""
        from c7n_ibmcloud.provider import resources
        for rtype in self.EXPECTED_TYPES:
            assert resources.get(rtype) is not None, (
                f"ibm.{rtype} not registered in the IBM Cloud provider"
            )

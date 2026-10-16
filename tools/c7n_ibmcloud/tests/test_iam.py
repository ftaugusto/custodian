# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""Tests for IBM Cloud IAM resources."""

from unittest.mock import MagicMock, patch

import pytest

from conftest import FakeSession, FakeSessionFactory, FakeResult


# ---------------------------------------------------------------------------
# Sample resource data
# ---------------------------------------------------------------------------

# Raw UserProfile dicts as returned by UserManagementV1.list_users
# (no mfa_type — MFA is fetched separately via get_mfa_status)
SAMPLE_USERS_RAW = [
    {
        "iam_id": "IBMid-001",
        "email": "alice@example.com",
        "firstname": "Alice",
        "lastname": "Example",
        "state": "ACTIVE",
    },
    {
        "iam_id": "IBMid-002",
        "email": "bob@example.com",
        "firstname": "Bob",
        "lastname": "Example",
        "state": "ACTIVE",
    },
]

# Post-augmentation: MFA fields injected, tags present
SAMPLE_USERS = [
    {
        **SAMPLE_USERS_RAW[0],
        "c7n:mfa_enrolled": False,
        "c7n:mfa_type": "",
        "tags": [],
    },
    {
        **SAMPLE_USERS_RAW[1],
        "c7n:mfa_enrolled": True,
        "c7n:mfa_type": "TOTP",
        "tags": ["team:platform"],
    },
]

SAMPLE_SERVICE_IDS = [
    {
        "id": "ServiceId-abc123",
        "name": "ci-pipeline",
        "description": "CI/CD service identity",
        "crn": "crn:v1:bluemix:public:iam-identity::a/123::serviceid:ServiceId-abc123",
        "created_at": "2022-01-15T10:00:00Z",
        "tags": [],
    },
    {
        "id": "ServiceId-def456",
        "name": "monitoring-agent",
        "description": "Monitoring agent identity",
        "crn": "crn:v1:bluemix:public:iam-identity::a/123::serviceid:ServiceId-def456",
        "created_at": "2024-06-01T08:00:00Z",
        "tags": ["team:ops"],
    },
]

SAMPLE_API_KEYS = [
    {
        "id": "ApiKey-aaa111",
        "name": "deploy-key",
        "crn": "crn:v1:bluemix:public:iam-identity::a/123::apikey:ApiKey-aaa111",
        "iam_id": "IBMid-001",
        "created_at": "2021-03-01T00:00:00Z",
        "locked": False,
        "tags": [],
    },
]

SAMPLE_ACCESS_GROUPS = [
    {
        "id": "AccessGroupId-xyz",
        "name": "DevOps",
        "description": "DevOps team",
        "created_at": "2023-01-01T00:00:00Z",
        "member_count": 5,
    },
    {
        "id": "AccessGroupId-empty",
        "name": "Unused",
        "description": "No members",
        "created_at": "2023-01-01T00:00:00Z",
        "member_count": 0,
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_mfa_response(totp_enrolled=False, trait_effective="NONE_NO_ROPC",
                       id_complies=True, security_questions_enrolled=False):
    """Build a realistic ``UserMfaEnrollments`` response dict matching real IBM API output.

    Matches the shape observed from the live IBM Cloud API:
    - ``effective_mfa_type``: always ``"id_based_mfa"`` for IBMid users
    - ``id_based_mfa.trait_effective``: the effective MFA trait
    - ``id_based_mfa.complies``: whether user satisfies id-based requirement
    - ``account_based_mfa.totp.enrolled``: whether TOTP authenticator is enrolled
    - ``account_based_mfa.security_questions.enrolled``: whether security Qs enrolled
    """
    return {
        "effective_mfa_type": "id_based_mfa",
        "id_based_mfa": {
            "trait_account_default": "NONE_NO_ROPC",
            "trait_effective": trait_effective,
            "complies": id_complies,
            "comply_state": "CROSS_ACCOUNT",
        },
        "account_based_mfa": {
            "complies": totp_enrolled or security_questions_enrolled,
            "security_questions": {"required": False, "enrolled": security_questions_enrolled},
            "totp": {"required": False, "enrolled": totp_enrolled},
            "verisign": {"required": False, "enrolled": False},
        },
    }


def _make_mfa_client(mfa_map=None):
    """Build a fake IamIdentityV1 client for MFA status lookups.

    Parameters
    ----------
    mfa_map:
        Dict mapping iam_id → kwargs dict for ``_make_mfa_response``.
        e.g. ``{"IBMid-001": {"totp_enrolled": False}}``
             ``{"IBMid-002": {"totp_enrolled": True, "trait_effective": "TOTP4ALL"}}``
        Absent iam_id → no enrolled MFA (totp_enrolled=False, default response).
    """
    mfa_map = mfa_map or {}
    client = MagicMock()

    def _get_mfa_status(account_id, iam_id, **kw):
        entry = mfa_map.get(iam_id, {})
        resp = {"iam_id": iam_id, **_make_mfa_response(**entry)}
        return FakeResult(resp)

    client.get_mfa_status.side_effect = _get_mfa_status
    return client


def _make_iam_session(users=None, service_ids=None, api_keys=None,
                      access_groups=None, mfa_map=None):
    """Build a FakeSession with stubbed IAM clients.

    The ``iam-identity`` client now also handles ``get_mfa_status`` calls used
    during MFA augmentation.  ``mfa_map`` maps iam_id → effective_mfa_type.
    """
    # Shared iam-identity client handles both list_* calls and get_mfa_status
    iam_client = _make_mfa_client(mfa_map)
    # UserManagementV1 client — returns users under "resources" key
    iam_users_client = MagicMock()
    iam_users_client.list_users.return_value = FakeResult(
        {"resources": users if users is not None else [], "next_url": None}
    )
    iam_client.list_service_ids.return_value = FakeResult(
        {"serviceids": service_ids if service_ids is not None else [], "next": None}
    )
    iam_client.list_api_keys.return_value = FakeResult(
        {"apikeys": api_keys if api_keys is not None else [], "next": None}
    )
    iam_client.delete_service_id.return_value = None
    iam_client.lock_api_key.return_value = None
    iam_client.delete_api_key.return_value = None

    groups_client = MagicMock()
    groups_client.list_access_groups.return_value = FakeResult(
        {"groups": access_groups if access_groups is not None else [], "next": None}
    )
    groups_client.delete_access_group.return_value = None

    return FakeSession(clients={
        "iam-identity": iam_client,
        "iam-users": iam_users_client,
        "iam-groups": groups_client,
    })


# ---------------------------------------------------------------------------
# Tests: IAMUser
# ---------------------------------------------------------------------------

class TestIAMUser:

    def _make_policy(self, filters, session):
        from conftest import load_policy

        return load_policy(
            {
                "name": "test-iam-user",
                "resource": "ibm.iam-user",
                "filters": filters,
            },
            session=session,
        )

    def test_mfa_disabled_filter(self):
        """mfa-disabled should return only users where c7n:mfa_enrolled is False."""
        from c7n_ibmcloud.filters.base import MFADisabledFilter

        f = MFADisabledFilter({}, None)
        result = f.process(SAMPLE_USERS)

        assert len(result) == 1
        assert result[0]["iam_id"] == "IBMid-001"

    def test_mfa_disabled_filter_all_unenrolled(self):
        """mfa-disabled returns all users when none have MFA enrolled."""
        from c7n_ibmcloud.filters.base import MFADisabledFilter

        users_no_mfa = [
            {**u, "c7n:mfa_enrolled": False, "c7n:mfa_type": ""} for u in SAMPLE_USERS_RAW
        ]
        f = MFADisabledFilter({}, None)
        result = f.process(users_no_mfa)

        assert len(result) == 2

    def test_tag_filter_absent(self):
        """tag filter with op=absent should return resources missing the tag key."""
        from c7n_ibmcloud.filters.base import TagFilter

        f = TagFilter({"type": "tag", "key": "team", "op": "absent"}, None)
        result = f.process(SAMPLE_USERS)
        assert len(result) == 1
        assert result[0]["iam_id"] == "IBMid-001"

    def test_tag_filter_present(self):
        """tag filter with op=present returns resources that have the tag."""
        from c7n_ibmcloud.filters.base import TagFilter

        f = TagFilter({"type": "tag", "key": "team", "op": "present"}, None)
        result = f.process(SAMPLE_USERS)
        assert len(result) == 1
        assert result[0]["iam_id"] == "IBMid-002"

    def test_tag_filter_eq(self):
        """tag filter eq matches exact tag value."""
        from c7n_ibmcloud.filters.base import TagFilter

        f = TagFilter({"type": "tag", "key": "team", "op": "eq", "value": "platform"}, None)
        result = f.process(SAMPLE_USERS)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Tests: IAMServiceID
# ---------------------------------------------------------------------------

class TestIAMServiceID:

    def test_age_filter(self):
        """age filter should match service IDs older than threshold."""
        from c7n_ibmcloud.filters.base import AgeFilter
        from unittest.mock import patch
        from datetime import datetime, timezone

        now = datetime(2024, 9, 1, tzinfo=timezone.utc)

        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat

            f = AgeFilter({"type": "age", "op": "gt", "days": 365}, None)
            f.date_attribute = "created_at"
            result = f.process(SAMPLE_SERVICE_IDS)

        # ci-pipeline created 2022-01-15 is > 365 days before 2024-09-01
        # monitoring-agent created 2024-06-01 is not
        assert len(result) == 1
        assert result[0]["id"] == "ServiceId-abc123"

    def test_delete_action(self):
        """delete action should call delete_service_id with the resource id."""
        session = _make_iam_session(service_ids=SAMPLE_SERVICE_IDS)
        iam_client = session._clients["iam-identity"]

        from c7n_ibmcloud.resources.iam import IAMServiceIDDeleteAction
        from unittest.mock import MagicMock, patch

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMServiceIDDeleteAction({}, manager)

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(SAMPLE_SERVICE_IDS[0])

        iam_client.delete_service_id.assert_called_once_with(id="ServiceId-abc123")

    def test_tag_action_creates_then_attaches_access_tag(self):
        """tag action on service-id must create_tag first, then attach_tag with tag_type=access."""
        from c7n_ibmcloud.resources.iam import IAMServiceIDTagAction
        from unittest.mock import MagicMock, patch

        tagging_client = MagicMock()
        session = FakeSession(clients={
            "iam-identity": MagicMock(),
            "global-tagging": tagging_client,
        })

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "access"

        action = IAMServiceIDTagAction(
            {"type": "tag", "tags": {"custodian-finding": "stale-service-id"}},
            manager,
        )

        with patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
            action.perform_action(SAMPLE_SERVICE_IDS[0])

        # create_tag must be called before attach_tag
        tagging_client.create_tag.assert_called_once_with(
            tag_names=["custodian-finding:stale-service-id"],
            tag_type="access",
        )
        from ibm_platform_services.global_tagging_v1 import Resource
        tagging_client.attach_tag.assert_called_once_with(
            resources=[Resource(resource_id=SAMPLE_SERVICE_IDS[0]["crn"])],
            tag_names=["custodian-finding:stale-service-id"],
            tag_type="access",
        )
        assert tagging_client.create_tag.call_count == 1
        assert tagging_client.attach_tag.call_count == 1

    def test_tag_action_skips_resource_without_crn(self):
        """tag action must warn and skip resources that have no CRN (neither crn nor crn-id)."""
        from c7n_ibmcloud.resources.iam import IAMServiceIDTagAction
        from unittest.mock import MagicMock, patch

        tagging_client = MagicMock()
        session = FakeSession(clients={
            "iam-identity": MagicMock(),
            "global-tagging": tagging_client,
        })

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "access"

        action = IAMServiceIDTagAction(
            {"type": "tag", "tags": {"owner": "team-a"}},
            manager,
        )

        resource_no_crn = {"id": "ServiceId-nocrnXYZ", "name": "no-crn-svc"}

        with patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
            action.perform_action(resource_no_crn)

        tagging_client.attach_tag.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: IAMAccessGroup
# ---------------------------------------------------------------------------

class TestIAMAccessGroup:

    def test_empty_group_filter(self):
        """value filter on member_count=0 should return empty groups only."""
        from c7n.filters import ValueFilter

        f = ValueFilter({"type": "value", "key": "member_count", "value": 0}, None)
        result = f.process(SAMPLE_ACCESS_GROUPS)
        assert len(result) == 1
        assert result[0]["id"] == "AccessGroupId-empty"

    def test_delete_action(self):
        """delete action should call delete_access_group."""
        session = _make_iam_session(access_groups=SAMPLE_ACCESS_GROUPS)
        groups_client = session._clients["iam-groups"]

        from c7n_ibmcloud.resources.iam import IAMAccessGroupDeleteAction
        from unittest.mock import MagicMock, patch

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMAccessGroupDeleteAction({}, manager)

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(SAMPLE_ACCESS_GROUPS[1])

        groups_client.delete_access_group.assert_called_once_with(
            access_group_id="AccessGroupId-empty"
        )


# ---------------------------------------------------------------------------
# Tests: IAMApiKey
# ---------------------------------------------------------------------------

class TestIAMApiKey:

    def test_lock_action(self):
        """lock action should call lock_api_key."""
        session = _make_iam_session(api_keys=SAMPLE_API_KEYS)
        iam_client = session._clients["iam-identity"]

        from c7n_ibmcloud.resources.iam import LockApiKeyAction
        from unittest.mock import MagicMock, patch

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = LockApiKeyAction({}, manager)

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(SAMPLE_API_KEYS[0])

        iam_client.lock_api_key.assert_called_once_with(id="ApiKey-aaa111")

    def test_delete_action(self):
        """delete action should call delete_api_key."""
        session = _make_iam_session(api_keys=SAMPLE_API_KEYS)
        iam_client = session._clients["iam-identity"]

        from c7n_ibmcloud.resources.iam import IAMApiKeyDeleteAction
        from unittest.mock import MagicMock, patch

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMApiKeyDeleteAction({}, manager)

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(SAMPLE_API_KEYS[0])

        iam_client.delete_api_key.assert_called_once_with(id="ApiKey-aaa111")

    def test_tag_action_not_registered(self):
        """IAMApiKey must NOT have a tag action — no CRN field in list_api_keys response."""
        from c7n_ibmcloud.resources.iam import IAMApiKey
        assert IAMApiKey.action_registry.get("tag") is None

    def test_append_description_calls_update_api_key(self):
        """append-description must call update_api_key with concatenated description."""
        from c7n_ibmcloud.resources.iam import IAMApiKeyAppendDescriptionAction
        from unittest.mock import MagicMock, patch

        iam_client = MagicMock()
        session = FakeSession(clients={"iam-identity": iam_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMApiKeyAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] Rotation overdue."},
            manager,
        )

        resource = {
            "id": "ApiKey-aaa111",
            "name": "deploy-key",
            "description": "Deployment key for CI",
        }

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        iam_client.update_api_key.assert_called_once_with(
            id="ApiKey-aaa111",
            if_match="*",
            description="Deployment key for CI [custodian] Rotation overdue.",
        )

    def test_append_description_unlocks_and_relocks_when_locked(self):
        """append-description must unlock, update, and re-lock when API key is locked."""
        from c7n_ibmcloud.resources.iam import IAMApiKeyAppendDescriptionAction
        from unittest.mock import MagicMock, patch

        iam_client = MagicMock()
        # First update_api_key call raises locked error; second succeeds
        from ibm_cloud_sdk_core import ApiException
        iam_client.update_api_key.side_effect = [
            ApiException(400, message="Error: The API Key is locked."),
            MagicMock(),
        ]
        session = FakeSession(clients={"iam-identity": iam_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMApiKeyAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] Rotation overdue."},
            manager,
        )

        resource = {
            "id": "ApiKey-locked-123",
            "name": "locked-deploy-key",
            "description": "Deployment key for CI",
        }

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        iam_client.unlock_api_key.assert_called_once_with(id="ApiKey-locked-123")
        iam_client.lock_api_key.assert_called_once_with(id="ApiKey-locked-123")
        assert iam_client.update_api_key.call_count == 2

    def test_append_description_skips_when_notice_already_present(self):
        """append-description must not call update_api_key if notice already in description."""
        from c7n_ibmcloud.resources.iam import IAMApiKeyAppendDescriptionAction
        from unittest.mock import MagicMock, patch

        iam_client = MagicMock()
        session = FakeSession(clients={"iam-identity": iam_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMApiKeyAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] Rotation overdue."},
            manager,
        )

        resource = {
            "id": "ApiKey-aaa111",
            "name": "deploy-key",
            "description": "Deployment key [custodian] Rotation overdue.",
        }

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        iam_client.update_api_key.assert_not_called()

    def test_append_description_handles_empty_description(self):
        """append-description on a key with no description sets the notice as the full description."""
        from c7n_ibmcloud.resources.iam import IAMApiKeyAppendDescriptionAction
        from unittest.mock import MagicMock, patch

        iam_client = MagicMock()
        session = FakeSession(clients={"iam-identity": iam_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMApiKeyAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] No description found."},
            manager,
        )

        resource = {"id": "ApiKey-bbb222", "name": "mystery-key", "description": ""}

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        call_kwargs = iam_client.update_api_key.call_args.kwargs
        assert call_kwargs["description"] == "[custodian] No description found."

    def test_append_description_uses_default_notice(self):
        """append-description with no notice param uses the default text."""
        from c7n_ibmcloud.resources.iam import IAMApiKeyAppendDescriptionAction
        from unittest.mock import MagicMock, patch

        iam_client = MagicMock()
        session = FakeSession(clients={"iam-identity": iam_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMApiKeyAppendDescriptionAction({"type": "append-description"}, manager)
        resource = {"id": "ApiKey-ccc333", "name": "key", "description": ""}

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        call_kwargs = iam_client.update_api_key.call_args.kwargs
        assert "[custodian]" in call_kwargs["description"]


# ---------------------------------------------------------------------------
# Tests: IAMUser new actions
# ---------------------------------------------------------------------------

class TestIAMUserActions:

    def test_delete_action_calls_remove_user(self):
        """IAMUserDeleteAction must call UserManagementV1.remove_user with account_id + iam_id."""
        from c7n_ibmcloud.resources.iam import IAMUserDeleteAction
        from unittest.mock import MagicMock, patch

        iam_users_client = MagicMock()
        session = FakeSession(
            clients={"iam-users": iam_users_client},
            account_id="acct-123",
        )

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMUserDeleteAction({}, manager)

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(SAMPLE_USERS_RAW[0])

        iam_users_client.remove_user.assert_called_once_with(
            account_id="acct-123",
            iam_id="IBMid-001",
        )

    def test_delete_action_skips_missing_iam_id(self):
        """IAMUserDeleteAction must not call remove_user when iam_id is absent."""
        from c7n_ibmcloud.resources.iam import IAMUserDeleteAction
        from unittest.mock import MagicMock, patch

        iam_users_client = MagicMock()
        session = FakeSession(clients={"iam-users": iam_users_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMUserDeleteAction({}, manager)

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action({"email": "ghost@example.com"})

        iam_users_client.remove_user.assert_not_called()

    def test_add_to_review_group_via_group_name_resolves_id(self):
        """group_name: looks up the ID via list_access_groups and passes it to add_members."""
        from c7n_ibmcloud.resources.iam import IAMUserAddToReviewGroupAction
        from ibm_platform_services.iam_access_groups_v2 import AddGroupMembersRequestMembersItem
        from unittest.mock import MagicMock, patch

        groups_client = MagicMock()
        groups_client.list_access_groups.return_value = FakeResult({
            "groups": [
                {"id": "AccessGroupId-abc-123", "name": "custodian-review"},
                {"id": "AccessGroupId-other",   "name": "other-group"},
            ]
        })
        session = FakeSession(clients={"iam-groups": groups_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMUserAddToReviewGroupAction(
            {"type": "add-to-review-group", "group_name": "custodian-review"},
            manager,
        )

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(SAMPLE_USERS_RAW[0])

        groups_client.list_access_groups.assert_called_once_with(
            account_id=session.account_id,
            search="name:custodian-review",
        )
        call_kwargs = groups_client.add_members_to_access_group.call_args[1]
        assert call_kwargs["access_group_id"] == "AccessGroupId-abc-123"
        assert isinstance(call_kwargs["members"][0], AddGroupMembersRequestMembersItem)
        assert call_kwargs["members"][0].iam_id == "IBMid-001"

    def test_add_to_review_group_name_resolution_cached(self):
        """group_name: list_access_groups is called only once across multiple perform_action calls."""
        from c7n_ibmcloud.resources.iam import IAMUserAddToReviewGroupAction
        from unittest.mock import MagicMock, patch

        groups_client = MagicMock()
        groups_client.list_access_groups.return_value = FakeResult({
            "groups": [{"id": "AccessGroupId-abc-123", "name": "custodian-review"}]
        })
        session = FakeSession(clients={"iam-groups": groups_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMUserAddToReviewGroupAction(
            {"type": "add-to-review-group", "group_name": "custodian-review"},
            manager,
        )

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(SAMPLE_USERS_RAW[0])
            action.perform_action(SAMPLE_USERS_RAW[0])

        # list_access_groups must only be called once despite two perform_action calls
        assert groups_client.list_access_groups.call_count == 1

    def test_add_to_review_group_name_not_found_raises(self):
        """group_name: raises ValueError if no group with that name exists."""
        from c7n_ibmcloud.resources.iam import IAMUserAddToReviewGroupAction
        from unittest.mock import MagicMock, patch
        import pytest

        groups_client = MagicMock()
        groups_client.list_access_groups.return_value = FakeResult({"groups": []})
        session = FakeSession(clients={"iam-groups": groups_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMUserAddToReviewGroupAction(
            {"type": "add-to-review-group", "group_name": "nonexistent-group"},
            manager,
        )

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            with pytest.raises(ValueError, match="nonexistent-group"):
                action.perform_action(SAMPLE_USERS_RAW[0])

    def test_add_to_review_group_via_group_id_direct(self):
        """group_id: passes the ID directly without calling list_access_groups."""
        from c7n_ibmcloud.resources.iam import IAMUserAddToReviewGroupAction
        from ibm_platform_services.iam_access_groups_v2 import AddGroupMembersRequestMembersItem
        from unittest.mock import MagicMock, patch

        groups_client = MagicMock()
        session = FakeSession(clients={"iam-groups": groups_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMUserAddToReviewGroupAction(
            {"type": "add-to-review-group", "group_id": "AccessGroupId-review-xyz"},
            manager,
        )

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(SAMPLE_USERS_RAW[0])

        groups_client.list_access_groups.assert_not_called()
        call_kwargs = groups_client.add_members_to_access_group.call_args[1]
        assert call_kwargs["access_group_id"] == "AccessGroupId-review-xyz"
        members = call_kwargs["members"]
        assert isinstance(members[0], AddGroupMembersRequestMembersItem)
        assert members[0].iam_id == "IBMid-001"

    def test_add_to_review_group_skips_missing_iam_id(self):
        """add-to-review-group must not call the API when iam_id is absent."""
        from c7n_ibmcloud.resources.iam import IAMUserAddToReviewGroupAction
        from unittest.mock import MagicMock, patch

        groups_client = MagicMock()
        session = FakeSession(clients={"iam-groups": groups_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMUserAddToReviewGroupAction(
            {"type": "add-to-review-group", "group_id": "AccessGroupId-review-xyz"},
            manager,
        )

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action({"email": "ghost@example.com"})

        groups_client.add_members_to_access_group.assert_not_called()

    def test_add_to_review_group_validate_requires_one_of_name_or_id(self):
        """validate() must raise when neither group_name nor group_id is given."""
        from c7n_ibmcloud.resources.iam import IAMUserAddToReviewGroupAction
        from unittest.mock import MagicMock
        import pytest

        action = IAMUserAddToReviewGroupAction(
            {"type": "add-to-review-group"},
            MagicMock(),
        )
        with pytest.raises(ValueError, match="group_name"):
            action.validate()

    def test_add_to_review_group_validate_rejects_both(self):
        """validate() must raise when both group_name and group_id are given."""
        from c7n_ibmcloud.resources.iam import IAMUserAddToReviewGroupAction
        from unittest.mock import MagicMock
        import pytest

        action = IAMUserAddToReviewGroupAction(
            {"type": "add-to-review-group",
             "group_name": "custodian-review",
             "group_id": "AccessGroupId-xyz"},
            MagicMock(),
        )
        with pytest.raises(ValueError, match="not both"):
            action.validate()

    def test_add_to_review_group_validate_rejects_bad_group_id(self):
        """validate() must raise if group_id doesn't start with AccessGroupId-."""
        from c7n_ibmcloud.resources.iam import IAMUserAddToReviewGroupAction
        from unittest.mock import MagicMock
        import pytest

        action = IAMUserAddToReviewGroupAction(
            {"type": "add-to-review-group", "group_id": "custodian-review"},
            MagicMock(),
        )
        with pytest.raises(ValueError, match="AccessGroupId-"):
            action.validate()

    def test_add_to_review_group_validate_accepts_group_name(self):
        """validate() must accept a plain group_name string."""
        from c7n_ibmcloud.resources.iam import IAMUserAddToReviewGroupAction
        from unittest.mock import MagicMock

        action = IAMUserAddToReviewGroupAction(
            {"type": "add-to-review-group", "group_name": "custodian-review"},
            MagicMock(),
        )
        assert action.validate() is action

    def test_add_to_review_group_validate_accepts_group_id(self):
        """validate() must accept a properly formatted AccessGroupId-."""
        from c7n_ibmcloud.resources.iam import IAMUserAddToReviewGroupAction
        from unittest.mock import MagicMock

        action = IAMUserAddToReviewGroupAction(
            {"type": "add-to-review-group", "group_id": "AccessGroupId-abc12345"},
            MagicMock(),
        )
        assert action.validate() is action


# ---------------------------------------------------------------------------
# Tests: IAMAccessGroup append-description
# ---------------------------------------------------------------------------

class TestIAMAccessGroupAppendDescription:

    def _make_groups_client(self, etag="W/\"abc123\""):
        """Build a mock IAM groups client that returns a real-looking ETag."""
        groups_client = MagicMock()
        get_resp = MagicMock()
        get_resp.get_headers.return_value = {"ETag": etag}
        groups_client.get_access_group.return_value = get_resp
        return groups_client

    def test_append_description_calls_update(self):
        """append-description must fetch ETag via get_access_group then call update_access_group."""
        from c7n_ibmcloud.resources.iam import IAMAccessGroupAppendDescriptionAction
        from unittest.mock import MagicMock, patch

        groups_client = self._make_groups_client(etag='W/"etag-001"')
        session = FakeSession(clients={"iam-groups": groups_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMAccessGroupAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] Review needed."},
            manager,
        )

        resource = {"id": "AccessGroupId-empty", "name": "Unused", "description": "Old desc"}

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        groups_client.get_access_group.assert_called_once_with(
            access_group_id="AccessGroupId-empty"
        )
        groups_client.update_access_group.assert_called_once_with(
            access_group_id="AccessGroupId-empty",
            if_match='W/"etag-001"',
            description="Old desc [custodian] Review needed.",
        )

    def test_append_description_skips_when_notice_already_present(self):
        """append-description must not update if the notice is already in the description."""
        from c7n_ibmcloud.resources.iam import IAMAccessGroupAppendDescriptionAction
        from unittest.mock import MagicMock, patch

        groups_client = MagicMock()
        session = FakeSession(clients={"iam-groups": groups_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMAccessGroupAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] Review needed."},
            manager,
        )

        resource = {
            "id": "AccessGroupId-empty",
            "name": "Unused",
            "description": "Old desc [custodian] Review needed.",
        }

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        groups_client.update_access_group.assert_not_called()

    def test_append_description_uses_default_notice(self):
        """append-description with no notice param uses the default text."""
        from c7n_ibmcloud.resources.iam import IAMAccessGroupAppendDescriptionAction
        from unittest.mock import MagicMock, patch

        groups_client = self._make_groups_client()
        session = FakeSession(clients={"iam-groups": groups_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMAccessGroupAppendDescriptionAction({"type": "append-description"}, manager)

        resource = {"id": "ag-1", "name": "Test", "description": ""}

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        call_kwargs = groups_client.update_access_group.call_args.kwargs
        assert "[custodian]" in call_kwargs["description"]


# ---------------------------------------------------------------------------
# Tests: IAMTrustedProfile append-description
# ---------------------------------------------------------------------------

class TestIAMTrustedProfileAppendDescription:

    def _make_iam_client(self, etag='W/"tp-etag-001"'):
        """Build a mock IAM identity client that returns a real-looking ETag from get_profile."""
        iam_client = MagicMock()
        get_resp = MagicMock()
        get_resp.get_headers.return_value = {"ETag": etag}
        iam_client.get_profile.return_value = get_resp
        return iam_client

    def test_append_description_calls_update_profile(self):
        """append-description must fetch ETag via get_profile then call update_profile."""
        from c7n_ibmcloud.resources.iam import IAMTrustedProfileAppendDescriptionAction
        from unittest.mock import MagicMock, patch

        iam_client = self._make_iam_client(etag='W/"tp-etag-001"')
        session = FakeSession(clients={"iam-identity": iam_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMTrustedProfileAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] Stale profile."},
            manager,
        )

        resource = {
            "id": "tp-old",
            "name": "old-profile",
            "description": "Original description",
        }

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        iam_client.get_profile.assert_called_once_with(profile_id="tp-old")
        iam_client.update_profile.assert_called_once_with(
            profile_id="tp-old",
            if_match='W/"tp-etag-001"',
            description="Original description [custodian] Stale profile.",
        )

    def test_append_description_skips_when_already_present(self):
        """append-description must not update_profile if notice already present."""
        from c7n_ibmcloud.resources.iam import IAMTrustedProfileAppendDescriptionAction
        from unittest.mock import MagicMock, patch

        iam_client = MagicMock()
        session = FakeSession(clients={"iam-identity": iam_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMTrustedProfileAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] Stale profile."},
            manager,
        )

        resource = {
            "id": "tp-old",
            "name": "old-profile",
            "description": "Already has [custodian] Stale profile.",
        }

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        iam_client.update_profile.assert_not_called()


    def test_append_description_skips_enterprise_managed_profile(self):
        """Enterprise-managed trusted profiles raise 403 'Resource is managed by Enterprise'.
        perform_action must catch it, log at DEBUG, and not re-raise."""
        from c7n_ibmcloud.resources.iam import IAMTrustedProfileAppendDescriptionAction
        from ibm_cloud_sdk_core.api_exception import ApiException
        from unittest.mock import MagicMock, patch

        iam_client = self._make_iam_client()
        iam_client.update_profile.side_effect = ApiException(
            403, message="Resource is managed by Enterprise"
        )
        session = FakeSession(clients={"iam-identity": iam_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMTrustedProfileAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] Review needed."},
            manager,
        )

        resource = {"id": "Profile-enterprise-001", "name": "enterprise-profile", "description": ""}

        # Must not raise
        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        iam_client.update_profile.assert_called_once()

    def test_append_description_reraises_non_enterprise_errors(self):
        """Non-enterprise 403 errors (genuine access denied) must still be re-raised."""
        from c7n_ibmcloud.resources.iam import IAMTrustedProfileAppendDescriptionAction
        from ibm_cloud_sdk_core.api_exception import ApiException
        from unittest.mock import MagicMock, patch
        import pytest

        iam_client = self._make_iam_client()
        iam_client.update_profile.side_effect = ApiException(403, message="Forbidden")
        session = FakeSession(clients={"iam-identity": iam_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = IAMTrustedProfileAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] Review needed."},
            manager,
        )

        resource = {"id": "Profile-noperm-001", "name": "no-perm-profile", "description": ""}

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            with pytest.raises(ApiException):
                action.perform_action(resource)



# ---------------------------------------------------------------------------
# Tests: empty-description policies (access group + trusted profile)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Tests: IAMCustomRole
# ---------------------------------------------------------------------------

SAMPLE_CUSTOM_ROLES = [
    {
        "id": "role-aaa-111",
        "name": "MyReadRole",
        "display_name": "My Read Role",
        "description": "Grants read access to my service",
        "service_name": "my-service",
        "account_id": "acct-123",
        "actions": ["my-service.resource.read"],
        "crn": "crn:v1:bluemix:public:iam-access-management::a/acct-123::customRole:MyReadRole",
    },
    {
        "id": "role-bbb-222",
        "name": "MyWriteRole",
        "display_name": "My Write Role",
        "description": None,   # no description — as returned by list_roles
        "service_name": "my-service",
        "account_id": "acct-123",
        "actions": ["my-service.resource.write", "my-service.resource.read"],
        "crn": "crn:v1:bluemix:public:iam-access-management::a/acct-123::customRole:MyWriteRole",
    },
]


class TestIAMCustomRole:

    def _make_policy_client(self, etag='W/"role-etag-001"'):
        client = MagicMock()
        get_resp = MagicMock()
        get_resp.get_headers.return_value = {"ETag": etag}
        client.get_role.return_value = get_resp
        return client

    def test_no_description_filter_matches_all_empty_shapes(self):
        """The or-filter must match all three shapes of 'no description'.

        IBM API may return description as:
        - absent (key missing from JSON) — common for roles created without a description
        - null   (Python None)           — SDK serialisation of a null JSON field
        - ""     (empty string)          — roles where description was set then cleared

        The policy uses an 'or' block to catch all three; this test verifies each one.
        """
        from c7n.filters import ValueFilter

        roles = [
            {"id": "role-has-desc",  "description": "Some description"},
            {"id": "role-null-desc", "description": None},   # null from API
            {"id": "role-no-key"},                            # key absent
            {"id": "role-empty",     "description": ""},     # empty string
        ]
        f_absent = ValueFilter({"type": "value", "key": "description", "value": "absent"}, None)
        f_empty  = ValueFilter({"type": "value", "key": "description", "op": "eq", "value": ""}, None)

        absent_ids = {r["id"] for r in f_absent.process(roles)}
        empty_ids  = {r["id"] for r in f_empty.process(roles)}
        matched    = absent_ids | empty_ids

        assert "role-has-desc"  not in matched
        assert "role-null-desc" in matched
        assert "role-no-key"    in matched
        assert "role-empty"     in matched

    def test_append_description_on_null_description(self):
        """append-description fetches ETag via get_role then calls replace_role with the notice."""
        from c7n_ibmcloud.resources.iam import IAMCustomRoleAppendDescriptionAction
        from unittest.mock import patch

        policy_client = self._make_policy_client(etag='W/"role-etag-bbb"')
        session = FakeSession(clients={"iam-policy": policy_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        notice = "[custodian] No description provided — document the purpose and owner of this custom role."
        action = IAMCustomRoleAppendDescriptionAction(
            {"type": "append-description", "notice": notice},
            manager,
        )

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(SAMPLE_CUSTOM_ROLES[1])

        policy_client.get_role.assert_called_once_with(role_id="role-bbb-222")
        policy_client.replace_role.assert_called_once_with(
            role_id="role-bbb-222",
            if_match='W/"role-etag-bbb"',
            display_name="My Write Role",
            actions=["my-service.resource.write", "my-service.resource.read"],
            description=notice,
        )

    def test_append_description_preserves_existing_description(self):
        """append-description appends to an existing description, not overwrites."""
        from c7n_ibmcloud.resources.iam import IAMCustomRoleAppendDescriptionAction
        from unittest.mock import patch

        policy_client = self._make_policy_client()
        session = FakeSession(clients={"iam-policy": policy_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        notice = "[custodian] No description provided."
        action = IAMCustomRoleAppendDescriptionAction(
            {"type": "append-description", "notice": notice},
            manager,
        )
        role_with_desc = dict(SAMPLE_CUSTOM_ROLES[0])  # has "Grants read access..."

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(role_with_desc)

        call_kwargs = policy_client.replace_role.call_args.kwargs
        assert "Grants read access" in call_kwargs["description"]
        assert notice in call_kwargs["description"]

    def test_append_description_idempotent(self):
        """Running twice must not duplicate the notice."""
        from c7n_ibmcloud.resources.iam import IAMCustomRoleAppendDescriptionAction
        from unittest.mock import patch

        policy_client = self._make_policy_client()
        session = FakeSession(clients={"iam-policy": policy_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        notice = "[custodian] No description provided."
        action = IAMCustomRoleAppendDescriptionAction(
            {"type": "append-description", "notice": notice},
            manager,
        )
        # Second run — notice already present
        role_already_noticed = dict(SAMPLE_CUSTOM_ROLES[1], description=notice)

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(role_already_noticed)

        policy_client.replace_role.assert_not_called()

    def test_resource_registered(self):
        """ibm.iam-custom-role must be registered in the resource registry."""
        from c7n_ibmcloud.provider import resources
        assert resources.get("iam-custom-role") is not None


class TestIAMAccessGroupNoDescription:

    def test_empty_description_filter_matches(self):
        """value filter description='' must match groups with empty description."""
        from c7n.filters import ValueFilter

        groups = [
            {"id": "ag-1", "name": "documented", "description": "Owns prod access"},
            {"id": "ag-2", "name": "undocumented", "description": ""},
            {"id": "ag-3", "name": "also-undocumented", "description": None},
        ]
        f = ValueFilter({"type": "value", "key": "description", "op": "eq", "value": ""}, None)
        result = f.process(groups)
        assert len(result) == 1
        assert result[0]["id"] == "ag-2"

    def test_append_description_on_empty_group(self):
        """append-description on a group with empty description sets the notice as description."""
        from c7n_ibmcloud.resources.iam import IAMAccessGroupAppendDescriptionAction
        from unittest.mock import MagicMock, patch

        groups_client = MagicMock()
        session = FakeSession(clients={"iam-groups": groups_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        notice = "[custodian] No description provided — document the purpose and owner of this group."
        action = IAMAccessGroupAppendDescriptionAction(
            {"type": "append-description", "notice": notice},
            manager,
        )

        resource = {"id": "ag-2", "name": "undocumented", "description": ""}

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        call_kwargs = groups_client.update_access_group.call_args.kwargs
        assert call_kwargs["access_group_id"] == "ag-2"
        assert notice in call_kwargs["description"]

    def test_append_description_idempotent_on_empty_group(self):
        """Running the policy twice must not duplicate the notice."""
        from c7n_ibmcloud.resources.iam import IAMAccessGroupAppendDescriptionAction
        from unittest.mock import MagicMock, patch

        groups_client = MagicMock()
        session = FakeSession(clients={"iam-groups": groups_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        notice = "[custodian] No description provided — document the purpose and owner of this group."
        action = IAMAccessGroupAppendDescriptionAction(
            {"type": "append-description", "notice": notice},
            manager,
        )
        # Simulate second run — description already contains the notice
        resource = {"id": "ag-2", "name": "undocumented", "description": notice}

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        groups_client.update_access_group.assert_not_called()


class TestIAMTrustedProfileNoDescription:

    def _make_tp_client(self, etag='W/"tp-etag-nd"'):
        from unittest.mock import MagicMock
        iam_client = MagicMock()
        get_resp = MagicMock()
        get_resp.get_headers.return_value = {"ETag": etag}
        iam_client.get_profile.return_value = get_resp
        return iam_client

    def test_absent_description_filter_matches(self):
        """value filter description=absent must match profiles where description is None.

        list_profiles returns description=null (Python None) when not set — not ''.
        The policy uses 'value: absent' to catch this correctly.
        """
        from c7n.filters import ValueFilter

        profiles = [
            {"id": "tp-1", "name": "documented", "description": "CI pipeline identity"},
            {"id": "tp-2", "name": "undocumented", "description": None},   # as returned by API
            {"id": "tp-3", "name": "also-undocumented"},                    # key absent
        ]
        f = ValueFilter({"type": "value", "key": "description", "value": "absent"}, None)
        result = f.process(profiles)
        ids = {r["id"] for r in result}
        assert ids == {"tp-2", "tp-3"}

    def test_append_description_on_null_description_profile(self):
        """append-description on a profile with description=None (as returned by API) sets notice."""
        from c7n_ibmcloud.resources.iam import IAMTrustedProfileAppendDescriptionAction
        from unittest.mock import patch

        iam_client = self._make_tp_client()
        session = FakeSession(clients={"iam-identity": iam_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        notice = "[custodian] No description provided — document the purpose and owner of this trusted profile."
        action = IAMTrustedProfileAppendDescriptionAction(
            {"type": "append-description", "notice": notice},
            manager,
        )

        # description=None as returned by list_profiles
        resource = {"id": "tp-2", "name": "undocumented", "description": None}

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        call_kwargs = iam_client.update_profile.call_args.kwargs
        assert call_kwargs["profile_id"] == "tp-2"
        assert notice in call_kwargs["description"]

    def test_append_description_idempotent_on_profile(self):
        """Running the policy twice must not duplicate the notice."""
        from c7n_ibmcloud.resources.iam import IAMTrustedProfileAppendDescriptionAction
        from unittest.mock import patch

        iam_client = self._make_tp_client()
        session = FakeSession(clients={"iam-identity": iam_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        notice = "[custodian] No description provided — document the purpose and owner of this trusted profile."
        action = IAMTrustedProfileAppendDescriptionAction(
            {"type": "append-description", "notice": notice},
            manager,
        )
        # Second run — notice already present
        resource = {"id": "tp-2", "name": "undocumented", "description": notice}

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            action.perform_action(resource)

        iam_client.update_profile.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: IAM MFA augmentation (_augment_mfa)
# ---------------------------------------------------------------------------

class TestIAMMFAAugmentation:

    def test_augment_mfa_injects_enrolled_true(self):
        """Users with TOTP enrolled get c7n:mfa_enrolled=True; others get False.

        Uses the real IBM API response shape observed in production:
        - IBMid-001: trait_effective=NONE_NO_ROPC, no totp enrolled → enrolled=False
        - IBMid-002: trait_effective=TOTP4ALL, complies=True         → enrolled=True
        """
        from c7n_ibmcloud.resources.iam import _augment_mfa

        mfa_map = {
            # No MFA enrolled — default response (totp_enrolled=False)
            "IBMid-001": {},
            # Per-user TOTP4ALL override, complies=True (like ftoledo in production)
            "IBMid-002": {"totp_enrolled": False, "trait_effective": "TOTP4ALL", "id_complies": True},
        }
        session = _make_iam_session(mfa_map=mfa_map)

        result = _augment_mfa(SAMPLE_USERS_RAW, session)

        by_id = {r["iam_id"]: r for r in result}
        assert by_id["IBMid-001"]["c7n:mfa_enrolled"] is False
        assert by_id["IBMid-002"]["c7n:mfa_enrolled"] is True

    def test_augment_mfa_handles_api_failure_returns_none(self):
        """If get_mfa_status raises, the user gets mfa_enrolled=None (unknown, not False)
        so the mfa-disabled filter excludes them rather than causing a false positive."""
        from c7n_ibmcloud.resources.iam import _augment_mfa

        iam_client = MagicMock()
        iam_client.get_mfa_status.side_effect = Exception("403 Forbidden")
        session = FakeSession(clients={"iam-identity": iam_client})

        result = _augment_mfa([SAMPLE_USERS_RAW[0]], session)

        assert result[0]["c7n:mfa_enrolled"] is None

    def test_augment_mfa_skips_users_without_iam_id(self):
        """Users with no iam_id get mfa_enrolled=None (unknown) without API call."""
        from c7n_ibmcloud.resources.iam import _augment_mfa

        iam_client = MagicMock()
        session = FakeSession(clients={"iam-identity": iam_client})

        user_no_id = {"email": "ghost@example.com", "state": "ACTIVE"}
        result = _augment_mfa([user_no_id], session)

        assert result[0]["c7n:mfa_enrolled"] is None
        iam_client.get_mfa_status.assert_not_called()

    def test_augment_mfa_skips_non_ibmid_users(self):
        """BSS-* and other non-IBMid users must be skipped without calling get_mfa_status.

        The IBM get_mfa_status API only supports IBMid-* (human) accounts.
        BSS-* are IBM Cloud billing/service system accounts — the API returns
        400 "The user name cannot be found" for them.  They must be excluded
        silently (mfa_enrolled=None) with no WARNING log, and no API call made.
        """
        from c7n_ibmcloud.resources.iam import _augment_mfa

        iam_client = MagicMock()
        session = FakeSession(clients={"iam-identity": iam_client})

        bss_users = [
            {"iam_id": "BSS-bc7f2030073044f1b0c4c7218e888650", "email": "svc1@ibm.com"},
            {"iam_id": "BSS-4b919fead22e4e4099afb8e49410c793", "email": "svc2@ibm.com"},
        ]
        result = _augment_mfa(bss_users, session)

        # All BSS users excluded with None (not False — do not flag as MFA-disabled)
        assert all(r["c7n:mfa_enrolled"] is None for r in result)
        # No API call must be made for BSS accounts
        iam_client.get_mfa_status.assert_not_called()

    def test_augment_mfa_mixed_ibmid_and_bss(self):
        """Mixed list: IBMid users get real MFA check; BSS users are skipped."""
        from c7n_ibmcloud.resources.iam import _augment_mfa

        mfa_map = {
            "IBMid-001": {},                                                        # no MFA enrolled
            "IBMid-002": {"totp_enrolled": True, "trait_effective": "TOTP4ALL",    # TOTP enrolled
                          "id_complies": True},
        }
        session = _make_iam_session(mfa_map=mfa_map)

        mixed_users = [
            {"iam_id": "IBMid-001", "email": "alice@example.com"},
            {"iam_id": "BSS-bc7f2030073044f1b0c4c7218e888650", "email": "svc@ibm.com"},
            {"iam_id": "IBMid-002", "email": "bob@example.com"},
        ]
        result = _augment_mfa(mixed_users, session)
        by_id = {r["iam_id"]: r for r in result}

        assert by_id["IBMid-001"]["c7n:mfa_enrolled"] is False   # no MFA enrolled
        assert by_id["IBMid-002"]["c7n:mfa_enrolled"] is True    # TOTP enrolled
        assert by_id["BSS-bc7f2030073044f1b0c4c7218e888650"]["c7n:mfa_enrolled"] is None  # skipped

    def test_mfa_disabled_filter_excludes_unknown_status(self):
        """mfa-disabled must NOT match users where c7n:mfa_enrolled is None (API error)."""
        from c7n_ibmcloud.filters.base import MFADisabledFilter

        users = [
            {"iam_id": "IBMid-001", "c7n:mfa_enrolled": False},   # no MFA — should match
            {"iam_id": "IBMid-002", "c7n:mfa_enrolled": True},    # enrolled — excluded
            {"iam_id": "IBMid-003", "c7n:mfa_enrolled": None},    # unknown — excluded
        ]
        f = MFADisabledFilter({}, None)
        result = f.process(users)

        assert len(result) == 1
        assert result[0]["iam_id"] == "IBMid-001"

    def test_get_resources_calls_augment(self):
        """IAMUserDescribeSource.get_resources must return users with c7n:mfa_enrolled set.

        Regression test for bug where augment() was defined on the source but
        never called — _fetch_resources calls self.source.get_resources() and
        then self.augment() (no-op on the manager), so MFA enrichment was silently
        skipped and all users came out without c7n:mfa_enrolled, causing the
        mfa-disabled filter to find zero matches.
        """
        from c7n_ibmcloud.resources.iam import IAMUserDescribeSource

        mfa_map = {
            "IBMid-001": {},                                                     # no MFA → False
            "IBMid-002": {"totp_enrolled": True, "trait_effective": "TOTP4ALL", # enrolled → True
                          "id_complies": True},
        }
        session = _make_iam_session(users=SAMPLE_USERS_RAW, mfa_map=mfa_map)

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        # resource_type must expose enum_spec so ResourceQuery.filter can call list_users
        from c7n_ibmcloud.resources.iam import IAMUser
        manager.resource_type = IAMUser.resource_type

        source = IAMUserDescribeSource(manager)

        with patch("c7n_ibmcloud.resources.iam.local_session", return_value=session):
            with patch("c7n_ibmcloud.query.local_session", return_value=session):
                result = source.get_resources(None)

        assert len(result) == 2, "Both users must be returned"
        by_id = {r["iam_id"]: r for r in result}
        # c7n:mfa_enrolled must be set — not missing, not None due to skipped augment
        assert "c7n:mfa_enrolled" in by_id["IBMid-001"], \
            "c7n:mfa_enrolled must be present — augment() was not called"
        assert by_id["IBMid-001"]["c7n:mfa_enrolled"] is False
        assert by_id["IBMid-002"]["c7n:mfa_enrolled"] is True


class TestMFAEnrolledFromResult:
    """Unit tests for _mfa_enrolled_from_result using real IBM API response shapes.

    All payloads are derived from live API output observed in production
    (diagnose_mfa.py) — not invented.
    """

    def _fn(self, result):
        from c7n_ibmcloud.resources.iam import _mfa_enrolled_from_result
        return _mfa_enrolled_from_result(result)

    # ── Real production payload: user with no MFA enrolled (Alvaro / pontin) ──

    def test_none_no_ropc_no_enrolled_methods_is_not_enrolled(self):
        """trait_effective=NONE_NO_ROPC + all account_based_mfa methods enrolled=false → False.

        This is the exact response for Alvaro.Capai and pontin from production.
        These users should be flagged by mfa-disabled.
        """
        enrolled, trait = self._fn(_make_mfa_response(
            totp_enrolled=False,
            trait_effective="NONE_NO_ROPC",
            id_complies=True,
        ))
        assert enrolled is False

    # ── Real production payload: user WITH MFA active (ftoledo) ──────────────

    def test_totp4all_with_id_complies_true_is_enrolled(self):
        """trait_effective=TOTP4ALL + id_based_mfa.complies=True → enrolled=True.

        ftoledo has trait_user_specific=TOTP4ALL (per-user override), complies=True.
        This user must NOT be flagged.
        """
        enrolled, trait = self._fn(_make_mfa_response(
            totp_enrolled=False,   # account_based_mfa methods not physically enrolled
            trait_effective="TOTP4ALL",
            id_complies=True,
        ))
        assert enrolled is True
        assert trait == "TOTP4ALL"

    # ── Account-wide MFA: totp.enrolled=true in account_based_mfa ────────────

    def test_account_based_totp_enrolled_is_enrolled(self):
        """account_based_mfa.totp.enrolled=true → enrolled=True even if id_based trait is NONE."""
        enrolled, trait = self._fn(_make_mfa_response(
            totp_enrolled=True,
            trait_effective="NONE_NO_ROPC",
            id_complies=True,
        ))
        assert enrolled is True
        assert trait == "totp"

    def test_account_based_security_questions_enrolled_is_enrolled(self):
        """account_based_mfa.security_questions.enrolled=true → enrolled=True."""
        enrolled, trait = self._fn(_make_mfa_response(
            security_questions_enrolled=True,
            trait_effective="NONE_NO_ROPC",
            id_complies=True,
        ))
        assert enrolled is True
        assert trait == "security_questions"

    # ── Strong traits with complies=False (account enforces MFA, user hasn't set it up) ──

    def test_totp_trait_complies_false_no_enrolled_methods_is_not_enrolled(self):
        """trait_effective=TOTP, complies=False, no enrolled methods → not enrolled."""
        result = {
            "effective_mfa_type": "id_based_mfa",
            "id_based_mfa": {
                "trait_account_default": "TOTP",
                "trait_effective": "TOTP",
                "complies": False,
                "comply_state": "NO",
            },
            "account_based_mfa": {
                "complies": False,
                "security_questions": {"required": True, "enrolled": False},
                "totp": {"required": True, "enrolled": False},
                "verisign": {"required": False, "enrolled": False},
            },
        }
        enrolled, trait = self._fn(result)
        assert enrolled is False

    def test_level2_trait_complies_true_is_enrolled(self):
        """trait_effective=LEVEL2, id_based_mfa.complies=True → enrolled=True."""
        result = {
            "effective_mfa_type": "id_based_mfa",
            "id_based_mfa": {
                "trait_account_default": "LEVEL2",
                "trait_effective": "LEVEL2",
                "complies": True,
                "comply_state": "CROSS_ACCOUNT",
            },
            "account_based_mfa": {
                "complies": False,
                "security_questions": {"required": False, "enrolled": False},
                "totp": {"required": False, "enrolled": False},
                "verisign": {"required": False, "enrolled": False},
            },
        }
        enrolled, trait = self._fn(result)
        assert enrolled is True
        assert trait == "LEVEL2"

    # ── Empty response (should not crash) ────────────────────────────────────

    def test_empty_response_is_not_enrolled(self):
        """Completely empty result dict → no enrolled methods → enrolled=False."""
        enrolled, trait = self._fn({})
        assert enrolled is False


# ---------------------------------------------------------------------------
# Tests: _ensure_access_tags helper
# ---------------------------------------------------------------------------

class TestEnsureAccessTags:

    def test_calls_create_tag_with_access_type(self):
        """_ensure_access_tags must call create_tag(tag_type='access')."""
        from c7n_ibmcloud.actions.base import _ensure_access_tags

        client = MagicMock()
        _ensure_access_tags(client, ["env:prod", "team:sre"])

        client.create_tag.assert_called_once_with(
            tag_names=["env:prod", "team:sre"],
            tag_type="access",
        )

    def test_no_op_on_empty_list(self):
        """_ensure_access_tags does nothing when tag_names is empty."""
        from c7n_ibmcloud.actions.base import _ensure_access_tags

        client = MagicMock()
        _ensure_access_tags(client, [])
        client.create_tag.assert_not_called()

    def test_create_tag_failure_is_swallowed(self):
        """If create_tag raises, _ensure_access_tags logs a warning and does not re-raise."""
        from c7n_ibmcloud.actions.base import _ensure_access_tags

        client = MagicMock()
        client.create_tag.side_effect = Exception("403 Forbidden")

        # Must not raise
        _ensure_access_tags(client, ["custodian-finding:stale"])

    def test_user_tag_type_does_not_call_create_tag(self):
        """tag action with tag_type=user must NOT call create_tag."""
        from c7n_ibmcloud.actions.base import TagAction

        tagging_client = MagicMock()
        session = FakeSession(clients={"global-tagging": tagging_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"

        action = TagAction({"type": "tag", "tags": {"env": "prod"}}, manager)

        # Use a VPC-style resource with CRN in the id field
        vpc_resource = {
            "id": "crn:v1:bluemix:public:is::a/1:us-south::instance:inst-1",
            "name": "test",
        }

        with patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
            action.perform_action(vpc_resource)

        tagging_client.create_tag.assert_not_called()
        tagging_client.attach_tag.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: Pagination correctness
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Tests: _get_crn helper
# ---------------------------------------------------------------------------

class TestGetCrn:

    def test_returns_crn_field_when_present(self):
        """Explicit crn field is always preferred."""
        from c7n_ibmcloud.actions.base import TagAction

        r = {"id": "ServiceId-abc", "crn": "crn:v1:bluemix:public:iam-identity::a/1::serviceid:ServiceId-abc"}
        assert TagAction._get_crn(r) == r["crn"]

    def test_falls_back_to_id_when_id_is_crn(self):
        """id is used when it starts with 'crn:' and crn field is absent."""
        from c7n_ibmcloud.actions.base import TagAction

        crn_id = "crn:v1:bluemix:public:is::a/1:us-south::instance:abc-123"
        r = {"id": crn_id}
        assert TagAction._get_crn(r) == crn_id

    def test_returns_none_when_no_crn(self):
        """Returns None for plain non-CRN ids with no crn field."""
        from c7n_ibmcloud.actions.base import TagAction

        assert TagAction._get_crn({"id": "ServiceId-abc123"}) is None
        assert TagAction._get_crn({"id": "AccessGroupId-xyz"}) is None
        assert TagAction._get_crn({}) is None

    def test_crn_field_beats_crn_style_id(self):
        """crn field wins even when id also looks like a CRN."""
        from c7n_ibmcloud.actions.base import TagAction

        r = {
            "id": "crn:v1:bluemix:public:is::a/1:us-south::instance:old",
            "crn": "crn:v1:bluemix:public:is::a/1:us-south::instance:new",
        }
        assert TagAction._get_crn(r) == r["crn"]


class TestIAMPagination:

    def test_next_url_pagination(self):
        """UserManagementV1-style next_url is parsed correctly."""
        from c7n_ibmcloud.query import _extract_next_token

        response = {
            "resources": [],
            "next_url": "https://iam.cloud.ibm.com/v2/accounts/123/users?start=TOKEN123&limit=50",
        }
        token = _extract_next_token(response)
        assert token == "TOKEN123"

    def test_next_href_dict_pagination(self):
        """VPC-style next.href dict is parsed correctly."""
        from c7n_ibmcloud.query import _extract_next_token

        response = {
            "instances": [],
            "next": {"href": "https://us-south.iaas.cloud.ibm.com/v1/instances?start=ABCDEF&limit=50"},
        }
        token = _extract_next_token(response)
        assert token == "ABCDEF"

    def test_next_plain_string_pagination(self):
        """IamIdentityV1-style next as a plain string is parsed correctly."""
        from c7n_ibmcloud.query import _extract_next_token

        response = {
            "serviceids": [],
            "next": "https://iam.cloud.ibm.com/v1/serviceids?start=SVCTOKEN&limit=20",
        }
        token = _extract_next_token(response)
        assert token == "SVCTOKEN"

    def test_no_next_returns_none(self):
        """Responses with no next page return None."""
        from c7n_ibmcloud.query import _extract_next_token

        assert _extract_next_token({"resources": []}) is None
        assert _extract_next_token({"next_url": None}) is None
        assert _extract_next_token({"next": None}) is None
        assert _extract_next_token({}) is None

    def test_list_users_uses_resources_key(self):
        """IAMUser enum_spec result path is 'resources' matching UserManagementV1."""
        from c7n_ibmcloud.resources.iam import IAMUser

        assert IAMUser.resource_type.enum_spec[1] == "resources"

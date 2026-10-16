# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""Tests for IBM Cloud Key Protect (KMS) resources."""

import os
from unittest.mock import MagicMock, patch

from conftest import FakeSession, FakeSessionFactory, FakeResult

KMS_INSTANCE_ID = "kp-inst-guid-001"

# ---------------------------------------------------------------------------
# Sample resource data
# ---------------------------------------------------------------------------

SAMPLE_KEYS = [
    {
        "id": "key-aaa-111",
        "name": "root-key-prod",
        "state": 1,          # active
        "creationDate": "2022-01-10T00:00:00Z",
        "crn": "crn:v1:bluemix:public:kms:us-south:a/123:kp-inst-1:key:key-aaa-111",
        "tags": ["env:prod"],
        "c7n:instance_id": KMS_INSTANCE_ID,
        "c7n:instance_name": "prod-kms",
    },
    {
        "id": "key-bbb-222",
        "name": "old-key",
        "state": 3,          # deactivated
        "creationDate": "2020-06-01T00:00:00Z",
        "crn": "crn:v1:bluemix:public:kms:us-south:a/123:kp-inst-1:key:key-bbb-222",
        "tags": [],
        "c7n:instance_id": KMS_INSTANCE_ID,
        "c7n:instance_name": "prod-kms",
    },
    {
        "id": "key-ccc-333",
        "name": "destroyed-key",
        "state": 5,          # destroyed
        "creationDate": "2019-03-15T00:00:00Z",
        "crn": "crn:v1:bluemix:public:kms:us-south:a/123:kp-inst-1:key:key-ccc-333",
        "tags": [],
        "c7n:instance_id": KMS_INSTANCE_ID,
        "c7n:instance_name": "prod-kms",
    },
]

SAMPLE_KEY_RINGS = [
    {"id": "default", "creationDate": "2021-01-01T00:00:00Z"},
    {"id": "prod-ring", "creationDate": "2022-06-01T00:00:00Z"},
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeKeyProtectClient:
    """Stub for KeyProtectClient used in tests."""

    def __init__(self, keys=None, key_rings=None, rotation_policies=None):
        self._keys = keys or SAMPLE_KEYS
        self._key_rings = key_rings or SAMPLE_KEY_RINGS
        self._rotation_policies = rotation_policies or {}
        self.disabled_keys = []
        self.enabled_keys = []
        self.rotated_keys = []
        self.deleted_keys = []

    def get_keys(self, instance_id, limit=50, offset=0, **kwargs):
        start = offset
        page = self._keys[start: start + limit]
        return FakeResult({"resources": page})

    def get_key_rings_in_instance(self, instance_id, **kwargs):
        return FakeResult({"resources": self._key_rings})

    def get_key_policies(self, id, instance_id="", **kwargs):
        policy = self._rotation_policies.get(id, {})
        return FakeResult({"resources": [{"rotation": policy}]})

    def action_on_key(self, id, action, instance_id="", **kwargs):
        if action == "disable":
            self.disabled_keys.append(id)
        elif action == "enable":
            self.enabled_keys.append(id)
        elif action == "rotate":
            self.rotated_keys.append(id)

    def delete_key(self, id, prefer="", **kwargs):
        self.deleted_keys.append(id)

    def set_key_for_deletion(self, id, **kwargs):
        pass

    def delete_key_ring(self, key_ring_id, **kwargs):
        pass


def _make_kms_session(keys=None, key_rings=None, rotation_policies=None):
    kp_client = FakeKeyProtectClient(
        keys=keys,
        key_rings=key_rings,
        rotation_policies=rotation_policies,
    )
    # rc client needed by _list_kms_instance_ids (returns the pinned env var instance)
    rc_client = MagicMock()
    rc_client.list_resource_instances.return_value = FakeResult(
        {"resources": [{"guid": KMS_INSTANCE_ID, "name": "prod-kms"}], "next_url": None}
    )
    return FakeSession(clients={"key-protect": kp_client, "resource-ctrl": rc_client}), kp_client


# ---------------------------------------------------------------------------
# Tests: KMSKeyStateFilter
# ---------------------------------------------------------------------------

class TestKMSKeyStateFilter:

    def test_active_state(self):
        """state filter 'active' should return only keys with state==1."""
        from c7n_ibmcloud.resources.kms import KMSKeyStateFilter

        f = KMSKeyStateFilter({"type": "state", "value": "active"}, None)
        result = f.process(SAMPLE_KEYS)
        assert len(result) == 1
        assert result[0]["id"] == "key-aaa-111"

    def test_deactivated_state(self):
        """state filter 'deactivated' should return keys with state==3."""
        from c7n_ibmcloud.resources.kms import KMSKeyStateFilter

        f = KMSKeyStateFilter({"type": "state", "value": "deactivated"}, None)
        result = f.process(SAMPLE_KEYS)
        assert len(result) == 1
        assert result[0]["id"] == "key-bbb-222"

    def test_destroyed_state(self):
        """state filter 'destroyed' should return keys with state==5."""
        from c7n_ibmcloud.resources.kms import KMSKeyStateFilter

        f = KMSKeyStateFilter({"type": "state", "value": "destroyed"}, None)
        result = f.process(SAMPLE_KEYS)
        assert len(result) == 1
        assert result[0]["id"] == "key-ccc-333"

    def test_no_match(self):
        """state filter 'suspended' returns empty when no suspended keys exist."""
        from c7n_ibmcloud.resources.kms import KMSKeyStateFilter

        f = KMSKeyStateFilter({"type": "state", "value": "suspended"}, None)
        result = f.process(SAMPLE_KEYS)
        assert result == []


# ---------------------------------------------------------------------------
# Tests: KMSKeyAgeFilter
# ---------------------------------------------------------------------------

class TestKMSKeyAgeFilter:

    def test_age_filter_old_keys(self):
        """age filter gt 1000 days should match old keys only."""
        from c7n_ibmcloud.filters.base import AgeFilter
        from datetime import datetime, timezone

        now = datetime(2024, 9, 1, tzinfo=timezone.utc)

        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat

            f = AgeFilter({"type": "age", "op": "gt", "days": 1000}, None)
            f.date_attribute = "creationDate"
            result = f.process(SAMPLE_KEYS)

        # key-aaa-111: 2022-01-10 → ~957 days before 2024-09-01 (not > 1000)
        # key-bbb-222: 2020-06-01 → ~1553 days (> 1000)
        # key-ccc-333: 2019-03-15 → ~1996 days (> 1000)
        assert len(result) == 2
        ids = {r["id"] for r in result}
        assert "key-bbb-222" in ids
        assert "key-ccc-333" in ids


# ---------------------------------------------------------------------------
# Tests: KMSKeyRotationFilter
# ---------------------------------------------------------------------------

class TestKMSKeyRotationFilter:

    def test_rotation_enabled_false_matches_keys_without_rotation(self):
        """rotation-policy enabled=false should return keys without rotation."""
        from c7n_ibmcloud.resources.kms import KMSKeyRotationFilter

        session, kp_client = _make_kms_session(
            rotation_policies={
                "key-aaa-111": {"enabled": True, "interval_month": 3},
            }
        )
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        f = KMSKeyRotationFilter({"type": "rotation-policy", "enabled": False}, manager)

        with patch("c7n_ibmcloud.resources.kms.local_session", return_value=session):
            result = f.process(SAMPLE_KEYS)

        # key-aaa-111 has rotation enabled → excluded
        # key-bbb-222 and key-ccc-333 have no rotation → included
        assert len(result) == 2
        ids = {r["id"] for r in result}
        assert "key-bbb-222" in ids
        assert "key-ccc-333" in ids

    def test_rotation_enabled_true_matches_keys_with_rotation(self):
        """rotation-policy enabled=true should return only keys with rotation."""
        from c7n_ibmcloud.resources.kms import KMSKeyRotationFilter

        session, kp_client = _make_kms_session(
            rotation_policies={
                "key-aaa-111": {"enabled": True, "interval_month": 3},
            }
        )
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        f = KMSKeyRotationFilter({"type": "rotation-policy", "enabled": True}, manager)

        with patch("c7n_ibmcloud.resources.kms.local_session", return_value=session):
            result = f.process(SAMPLE_KEYS)

        assert len(result) == 1
        assert result[0]["id"] == "key-aaa-111"


# ---------------------------------------------------------------------------
# Tests: KMS actions
# ---------------------------------------------------------------------------

class TestKMSKeyActions:

    def test_disable_action(self):
        """disable action should call action_on_key with action='disable'."""
        session, kp_client = _make_kms_session()

        from c7n_ibmcloud.resources.kms import KMSKeyDisable

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = KMSKeyDisable({}, manager)

        with patch("c7n_ibmcloud.resources.kms.local_session", return_value=session):
            action.perform_action(SAMPLE_KEYS[0])

        assert "key-aaa-111" in kp_client.disabled_keys

    def test_rotate_action(self):
        """rotate action should call action_on_key with action='rotate'."""
        session, kp_client = _make_kms_session()

        from c7n_ibmcloud.resources.kms import KMSKeyRotate

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = KMSKeyRotate({}, manager)

        with patch("c7n_ibmcloud.resources.kms.local_session", return_value=session):
            action.perform_action(SAMPLE_KEYS[0])

        assert "key-aaa-111" in kp_client.rotated_keys

    def test_delete_action(self):
        """delete action should call delete_key."""
        session, kp_client = _make_kms_session()

        from c7n_ibmcloud.resources.kms import KMSKeyDelete

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = KMSKeyDelete({}, manager)

        with patch("c7n_ibmcloud.resources.kms.local_session", return_value=session):
            action.perform_action(SAMPLE_KEYS[1])

        assert "key-bbb-222" in kp_client.deleted_keys

    def test_tag_action_targets_instance_crn(self):
        """KMSKeyTagAction should tag the parent instance CRN rather than key CRN."""
        from c7n_ibmcloud.resources.kms import KMSKeyTagAction

        tagging_client = MagicMock()
        session = FakeSession(clients={"global-tagging": tagging_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type = MagicMock(tag_type="user")

        action = KMSKeyTagAction({"type": "tag", "tags": {"review": "needed"}}, manager)
        with patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
            action.perform_action(SAMPLE_KEYS[0])

        assert tagging_client.attach_tag.called
        call_kwargs = tagging_client.attach_tag.call_args[1]
        res = call_kwargs["resources"][0]
        # Verify key suffix :key:... is stripped and :: attached
        assert res.resource_id == "crn:v1:bluemix:public:kms:us-south:a/123:kp-inst-1::"

    def test_remove_tag_action_targets_instance_crn(self):
        """KMSKeyRemoveTagAction should detach tag from parent instance CRN."""
        from c7n_ibmcloud.resources.kms import KMSKeyRemoveTagAction

        tagging_client = MagicMock()
        session = FakeSession(clients={"global-tagging": tagging_client})
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type = MagicMock(tag_type="user")

        action = KMSKeyRemoveTagAction({"type": "remove-tag", "tags": ["review:needed"]}, manager)
        with patch("c7n_ibmcloud.resources.kms.local_session", return_value=session):
            action.perform_action(SAMPLE_KEYS[0])

        assert tagging_client.detach_tag.called
        call_kwargs = tagging_client.detach_tag.call_args[1]
        res = call_kwargs["resources"][0]
        assert res.resource_id == "crn:v1:bluemix:public:kms:us-south:a/123:kp-inst-1::"

    def test_list_kms_instance_ids_discovery(self):
        """_list_kms_instance_ids should discover KMS instances by resource_id or CRN fallback."""
        from c7n_ibmcloud.resources.kms import _list_kms_instance_ids

        rc_client = MagicMock()
        # First call by resource_id returns empty, fallback by type returns instance with CRN
        rc_client.list_resource_instances.side_effect = [
            FakeResult({"resources": [], "next_url": None}),
            FakeResult({"resources": [], "next_url": None}),
            FakeResult({
                "resources": [
                    {
                        "guid": "fallback-kms-guid",
                        "name": "my-key-protect",
                        "crn": "crn:v1:bluemix:public:kms:us-south:a/account::",
                    }
                ],
                "next_url": None,
            }),
        ]
        session = FakeSession(clients={"resource-ctrl": rc_client})
        with patch.dict("os.environ", {}, clear=True):
            instances = _list_kms_instance_ids(session)
        assert len(instances) == 1
        assert instances[0] == ("fallback-kms-guid", "my-key-protect")


# ---------------------------------------------------------------------------
# Tests: 409 Conflict handling (_is_conflict + process())
# ---------------------------------------------------------------------------

class TestConflictHandling:
    """Verify that 409 Conflict from KMS actions produces WARNING, not ERROR."""

    def _make_409_http_error(self):
        import requests
        err_response = MagicMock()
        err_response.status_code = 409
        return requests.exceptions.HTTPError(
            "409 Client Error: Conflict for url: https://us-south.kms.cloud.ibm.com/...",
            response=err_response,
        )

    def test_is_conflict_detects_requests_409(self):
        """_is_conflict should return True for requests.HTTPError with status 409."""
        from c7n_ibmcloud.actions.base import _is_conflict
        assert _is_conflict(self._make_409_http_error()) is True

    def test_is_conflict_false_for_404(self):
        """_is_conflict should return False for a 404 error."""
        from c7n_ibmcloud.actions.base import _is_conflict
        import requests
        err_response = MagicMock()
        err_response.status_code = 404
        err = requests.exceptions.HTTPError("404 Not Found", response=err_response)
        assert _is_conflict(err) is False

    def test_is_conflict_false_for_403(self):
        """_is_conflict should return False for a 403 error."""
        from c7n_ibmcloud.actions.base import _is_conflict
        import requests
        err_response = MagicMock()
        err_response.status_code = 403
        err = requests.exceptions.HTTPError("403 Forbidden", response=err_response)
        assert _is_conflict(err) is False

    def test_disable_409_logs_warning_not_error(self, caplog):
        """disable action receiving 409 should emit WARNING, not log.exception (ERROR)."""
        import logging
        import requests
        session, kp_client = _make_kms_session()
        http_err = self._make_409_http_error()
        kp_client.action_on_key = MagicMock(side_effect=http_err)

        from c7n_ibmcloud.resources.kms import KMSKeyDisable

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = KMSKeyDisable({}, manager)

        with patch("c7n_ibmcloud.resources.kms.local_session", return_value=session):
            with caplog.at_level(logging.WARNING, logger="custodian.ibm.actions"):
                results = action.process([SAMPLE_KEYS[0]])

        # Resource is not returned when action fails
        assert results == []
        # A WARNING was emitted, not an ERROR traceback
        assert any("409 Conflict" in r.message for r in caplog.records)
        assert all(r.levelno < logging.ERROR for r in caplog.records
                   if "409 Conflict" in r.message)

    def test_rotate_409_logs_warning_not_error(self, caplog):
        """rotate action receiving 409 should emit WARNING, not log.exception (ERROR)."""
        import logging
        import requests
        session, kp_client = _make_kms_session()
        http_err = self._make_409_http_error()
        kp_client.action_on_key = MagicMock(side_effect=http_err)

        from c7n_ibmcloud.resources.kms import KMSKeyRotate

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = KMSKeyRotate({}, manager)

        with patch("c7n_ibmcloud.resources.kms.local_session", return_value=session):
            with caplog.at_level(logging.WARNING, logger="custodian.ibm.actions"):
                results = action.process([SAMPLE_KEYS[0]])

        assert results == []
        assert any("409 Conflict" in r.message for r in caplog.records)
        assert all(r.levelno < logging.ERROR for r in caplog.records
                   if "409 Conflict" in r.message)


# ---------------------------------------------------------------------------
# Tests: kms.yaml policy logic — corrected filter combinations
# ---------------------------------------------------------------------------

class TestKMSPolicyFilterLogic:
    """Unit-test the filter combinations that the updated kms.yaml policies use."""

    # Pre-activation key (state=0) — used to test the no-rotation + state:active combo
    KEY_PRE_ACTIVATION = {
        "id": "key-pre-000",
        "name": "pre-activation-key",
        "state": 0,
        "creationDate": "2020-01-01T00:00:00Z",
        "crn": "crn:v1:bluemix:public:kms:us-south:a/123:kp-inst-1:key:key-pre-000",
        "c7n:instance_id": KMS_INSTANCE_ID,
        "c7n:instance_name": "prod-kms",
    }

    def test_no_rotation_policy_excludes_pre_activation_key(self):
        """kms-key-no-rotation-policy adds state:active — pre-activation keys are excluded."""
        from c7n_ibmcloud.resources.kms import KMSKeyStateFilter, KMSKeyRotationFilter

        all_keys = list(SAMPLE_KEYS) + [self.KEY_PRE_ACTIVATION]

        # Step 1: rotation-policy filter — key-pre-000 has no rotation policy → included
        session, kp_client = _make_kms_session(keys=all_keys)
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        rot_filter = KMSKeyRotationFilter({"type": "rotation-policy", "enabled": False}, manager)
        with patch("c7n_ibmcloud.resources.kms.local_session", return_value=session):
            after_rotation = rot_filter.process(all_keys)

        # Step 2: state:active filter — key-pre-000 (state=0) is excluded
        state_filter = KMSKeyStateFilter({"type": "state", "value": "active"}, None)
        after_state = state_filter.process(after_rotation)

        # Only key-aaa-111 (active, no rotation) should remain
        # key-bbb-222 and key-ccc-333 are deactivated/destroyed
        ids = {r["id"] for r in after_state}
        assert "key-aaa-111" in ids
        assert "key-pre-000" not in ids, "Pre-activation key must be excluded by state:active filter"

    def test_rotation_overdue_only_acts_on_active_keys(self):
        """kms-key-rotation-overdue adds state:active — deactivated/destroyed keys are excluded."""
        from c7n_ibmcloud.resources.kms import KMSKeyStateFilter

        state_filter = KMSKeyStateFilter({"type": "state", "value": "active"}, None)
        result = state_filter.process(SAMPLE_KEYS)

        # Only key-aaa-111 is active; key-bbb-222 (deactivated) and key-ccc-333 (destroyed) excluded
        assert len(result) == 1
        assert result[0]["id"] == "key-aaa-111"

    def test_pre_activation_policy_uses_delete_not_disable(self):
        """kms-key-pre-activation now uses delete; verify delete_key is called."""
        from c7n_ibmcloud.resources.kms import KMSKeyStateFilter, KMSKeyDelete

        # Filter: state:pre-activation
        state_filter = KMSKeyStateFilter({"type": "state", "value": "pre-activation"}, None)
        all_keys = list(SAMPLE_KEYS) + [self.KEY_PRE_ACTIVATION]
        matched = state_filter.process(all_keys)
        assert len(matched) == 1
        assert matched[0]["id"] == "key-pre-000"

        # Action: delete (not disable)
        session, kp_client = _make_kms_session(keys=all_keys)
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        delete_action = KMSKeyDelete({}, manager)

        with patch("c7n_ibmcloud.resources.kms.local_session", return_value=session):
            delete_action.perform_action(matched[0])

        assert "key-pre-000" in kp_client.deleted_keys, "delete_key should be called for pre-activation key"


# ---------------------------------------------------------------------------
# Tests: KeyProtectClient.action_on_key Content-Type header
# ---------------------------------------------------------------------------

class TestActionOnKeyContentType:
    """Verify that action_on_key sends the correct action-specific Content-Type.

    The IBM Key Protect API requires e.g. Content-Type:
    application/vnd.ibm.kms.key_action_disable+json for /actions/disable.
    Without it the API returns 409 Conflict.
    """

    def _make_client(self):
        from c7n_ibmcloud.session import KeyProtectClient
        auth = MagicMock()
        auth.token_manager.get_token.return_value = "fake-token"
        return KeyProtectClient(authenticator=auth, region="us-south")

    def _captured_request(self, client, action):
        """Call action_on_key with a mocked requests.post; return captured kwargs."""
        import unittest.mock as um
        captured = {}
        def fake_post(url, headers=None, json=None, timeout=None):
            captured["url"] = url
            captured["headers"] = dict(headers or {})
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            return resp

        with um.patch("requests.post", side_effect=fake_post):
            client.action_on_key(id="key-abc", action=action, instance_id="inst-123")
        return captured

    def test_disable_sends_correct_content_type(self):
        client = self._make_client()
        captured = self._captured_request(client, "disable")
        assert captured["headers"]["Content-Type"] == \
            "application/vnd.ibm.kms.key_action_disable+json"

    def test_enable_sends_correct_content_type(self):
        client = self._make_client()
        captured = self._captured_request(client, "enable")
        assert captured["headers"]["Content-Type"] == \
            "application/vnd.ibm.kms.key_action_enable+json"

    def test_rotate_sends_correct_content_type(self):
        client = self._make_client()
        captured = self._captured_request(client, "rotate")
        assert captured["headers"]["Content-Type"] == \
            "application/vnd.ibm.kms.key_action_rotate+json"

    def test_unknown_action_sends_generic_content_type(self):
        client = self._make_client()
        captured = self._captured_request(client, "setKeyForDeletion")
        assert captured["headers"]["Content-Type"] == \
            "application/vnd.ibm.kms.key_action+json"

    def test_instance_id_in_bluemix_header(self):
        client = self._make_client()
        captured = self._captured_request(client, "disable")
        assert captured["headers"]["bluemix-instance"] == "inst-123"

    def test_no_rotation_policy_active_key_calls_disable(self):
        """kms-key-no-rotation-policy: active key without rotation → disable called."""
        session, kp_client = _make_kms_session()
        from c7n_ibmcloud.resources.kms import KMSKeyDisable
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = KMSKeyDisable({}, manager)

        with patch("c7n_ibmcloud.resources.kms.local_session", return_value=session):
            action.perform_action(SAMPLE_KEYS[0])  # key-aaa-111, state=1 (active)

        assert "key-aaa-111" in kp_client.disabled_keys

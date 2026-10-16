# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""Tests for IBM Cloud PowerVS resources."""

from unittest.mock import MagicMock, patch

from conftest import FakeSession, FakeSessionFactory, FakeResult


# ---------------------------------------------------------------------------
# Sample resource data
# ---------------------------------------------------------------------------

# Instances returned by GET /pvm-instances (PVMInstanceReference schema).
# Each entry has a 'networks' array of PVMInstanceNetwork objects.
# A network attachment is public when:
#   - 'externalIP' is non-empty, OR
#   - 'networkName' starts with "public-" (IBM naming convention for pub-vlan networks
#     where externalIP is absent from the payload, as observed in production).
SAMPLE_PVM_INSTANCES = [
    {
        "pvmInstanceID": "pvm-aaa-111",
        "serverName": "prod-vm-1",
        "status": "ACTIVE",
        "storageType": "tier1",
        "procType": "shared",
        "memory": 16,
        "creationDate": "2023-05-01T00:00:00Z",
        "c7n:workspace_id": "ws-guid-001",
        "c7n:workspace_name": "prod-workspace",
        "c7n:region": "us-south",
        "tags": ["env:prod"],
        "networks": [
            {"ipAddress": "172.25.1.10", "networkName": "subnet-priv01", "type": "fixed"},
        ],
    },
    {
        "pvmInstanceID": "pvm-bbb-222",
        "serverName": "dev-vm-2",
        "status": "SHUTOFF",
        "storageType": "tier3",
        "procType": "dedicated",
        "memory": 4,
        "creationDate": "2021-11-15T00:00:00Z",
        "c7n:workspace_id": "ws-guid-002",
        "c7n:workspace_name": "dev-workspace",
        "c7n:region": "eu-de",
        "tags": [],
        "networks": [],
    },
]

# Instance matching real-world production payload (from live API log):
#   networks=[
#     {'ipAddress': '192.168.132.53', 'networkName': 'public-192_168_132_48-29-VLAN_2114', 'type': 'fixed'},
#     {'ipAddress': '172.25.1.142',   'networkName': 'subnet-priv01', 'type': 'fixed'},
#   ]
# No 'externalIP' field — public interface identified by networkName prefix "public-".
SAMPLE_PVM_INSTANCE_PUBLIC_NET = {
    "pvmInstanceID": "pvm-ccc-333",
    "serverName": "exposed-vm",
    "status": "ACTIVE",
    "storageType": "tier1",
    "procType": "shared",
    "memory": 8,
    "creationDate": "2024-01-10T00:00:00Z",
    "c7n:workspace_id": "ws-guid-001",
    "c7n:workspace_crn": "crn:v1:bluemix:public:power-iaas:us-south:a/123:ws-guid-001::",
    "c7n:workspace_name": "prod-workspace",
    "c7n:region": "us-south",
    "tags": [],
    "networks": [
        {"ipAddress": "192.168.132.53", "networkName": "public-192_168_132_48-29-VLAN_2114", "type": "fixed"},
        {"ipAddress": "172.25.1.142",   "networkName": "subnet-priv01", "type": "fixed"},
    ],
}

# Instance with externalIP set (alternate real-world shape for pub-vlan).
SAMPLE_PVM_INSTANCE_EXTERNAL_IP = {
    "pvmInstanceID": "pvm-ddd-444",
    "serverName": "external-ip-vm",
    "status": "ACTIVE",
    "storageType": "tier1",
    "procType": "shared",
    "memory": 4,
    "creationDate": "2024-03-01T00:00:00Z",
    "c7n:workspace_id": "ws-guid-001",
    "c7n:workspace_crn": "crn:v1:bluemix:public:power-iaas:us-south:a/123:ws-guid-001::",
    "c7n:workspace_name": "prod-workspace",
    "c7n:region": "us-south",
    "tags": [],
    "networks": [
        {"ipAddress": "169.48.1.5", "networkName": "pub-net", "externalIP": "52.116.100.1", "type": "fixed"},
    ],
}

SAMPLE_VOLUMES = [
    {
        "volumeID": "vol-aaa-001",
        "name": "prod-data-vol",
        "state": "in-use",
        "diskType": "tier1",
        "size": 500,
        "shareable": False,
        "pvmInstanceIDs": ["pvm-aaa-111"],
        "c7n:workspace_id": "ws-guid-001",
        "c7n:workspace_name": "prod-workspace",
        "c7n:region": "us-south",
    },
    {
        "volumeID": "vol-bbb-002",
        "name": "orphaned-vol",
        "state": "available",
        "diskType": "tier3",
        "size": 200,
        "shareable": False,
        "pvmInstanceIDs": [],
        "c7n:workspace_id": "ws-guid-002",
        "c7n:workspace_name": "dev-workspace",
        "c7n:region": "eu-de",
    },
]

SAMPLE_NETWORKS = [
    {
        "networkID": "net-aaa-001",
        "name": "private-net",
        "type": "vlan",
        "cidr": "10.0.0.0/24",
        "c7n:workspace_id": "ws-guid-001",
        "c7n:workspace_crn": "crn:v1:bluemix:public:power-iaas:us-south:a/123:ws-guid-001::",
        "c7n:workspace_name": "prod-workspace",
        "c7n:region": "us-south",
    },
    {
        "networkID": "net-bbb-002",
        "name": "pub-net",
        "type": "pub-vlan",
        "cidr": "192.168.1.0/24",
        "c7n:workspace_id": "ws-guid-001",
        "c7n:workspace_crn": "crn:v1:bluemix:public:power-iaas:us-south:a/123:ws-guid-001::",
        "c7n:workspace_name": "prod-workspace",
        "c7n:region": "us-south",
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakePowerVSClient:
    """Stub for PowerVSClient used in tests."""

    def __init__(self, instance_detail=None):
        self.stopped = []
        self.started = []
        self.deleted = []
        self.posts = []
        self.gets = []
        # Per-instance detail responses keyed by pvmInstanceID (last path segment)
        self._instance_detail = instance_detail or {}

    def list(self, path, result_key=None, v1=False):
        return []

    def get(self, path, v1=False):
        self.gets.append(path)
        # Extract pvmInstanceID from path like "/pvm-instances/<id>"
        pvm_id = path.rstrip("/").rsplit("/", 1)[-1]
        return self._instance_detail.get(pvm_id, {})

    def post(self, path, body, v1=False):
        self.posts.append((path, body))

    def put(self, path, body, v1=False):
        self.posts.append((path, body))

    def delete(self, path, v1=False):
        self.deleted.append(path)


def _make_powervs_session():
    pv_client = FakePowerVSClient()
    session = FakeSession()
    session._powervs_clients = {}
    # Override powervs_client to return our stub for any workspace
    session.powervs_client = lambda workspace_id, region=None, workspace_crn=None: pv_client
    return session, pv_client


# ---------------------------------------------------------------------------
# Tests: PowerVS instance filters
# ---------------------------------------------------------------------------

class TestPowerVSInstanceFilters:

    def test_status_filter_active(self):
        """value filter status=ACTIVE should match only running instances."""
        from c7n.filters import ValueFilter

        f = ValueFilter({"type": "value", "key": "status", "value": "ACTIVE"}, None)
        result = f.process(SAMPLE_PVM_INSTANCES)
        assert len(result) == 1
        assert result[0]["pvmInstanceID"] == "pvm-aaa-111"

    def test_status_filter_shutoff(self):
        """value filter status=SHUTOFF should match only stopped instances."""
        from c7n.filters import ValueFilter

        f = ValueFilter({"type": "value", "key": "status", "value": "SHUTOFF"}, None)
        result = f.process(SAMPLE_PVM_INSTANCES)
        assert len(result) == 1
        assert result[0]["pvmInstanceID"] == "pvm-bbb-222"

    def test_age_filter(self):
        """age filter gt 365 should match instances older than a year."""
        from c7n_ibmcloud.filters.base import AgeFilter
        from datetime import datetime, timezone

        now = datetime(2024, 9, 1, tzinfo=timezone.utc)

        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat

            f = AgeFilter({"type": "age", "op": "gt", "days": 365}, None)
            f.date_attribute = "creationDate"
            result = f.process(SAMPLE_PVM_INSTANCES)

        # pvm-aaa-111: 2023-05-01 → ~488 days (> 365) ✓
        # pvm-bbb-222: 2021-11-15 → ~1020 days (> 365) ✓
        assert len(result) == 2

    def test_tag_filter_present(self):
        """tag filter present should match instances with the tag."""
        from c7n_ibmcloud.filters.base import TagFilter

        f = TagFilter({"type": "tag", "key": "env", "op": "present"}, None)
        result = f.process(SAMPLE_PVM_INSTANCES)
        assert len(result) == 1
        assert result[0]["pvmInstanceID"] == "pvm-aaa-111"


# ---------------------------------------------------------------------------
# Tests: PowerVS instance public-network-interface filter
# ---------------------------------------------------------------------------

class TestPowerVSInstancePublicNetworkFilter:

    def test_no_match_private_networks_only(self):
        """Instances whose networks have no externalIP must not be matched."""
        from c7n_ibmcloud.resources.powervs import PowerVSInstancePublicNetworkFilter

        f = PowerVSInstancePublicNetworkFilter({"type": "public-network-interface"}, None)
        assert f.process(SAMPLE_PVM_INSTANCES) == []

    def test_matches_network_with_external_ip(self):
        """An instance with externalIP on a network entry must be matched."""
        from c7n_ibmcloud.resources.powervs import PowerVSInstancePublicNetworkFilter

        f = PowerVSInstancePublicNetworkFilter({"type": "public-network-interface"}, None)
        result = f.process([SAMPLE_PVM_INSTANCE_PUBLIC_NET])
        assert len(result) == 1
        assert result[0]["pvmInstanceID"] == "pvm-ccc-333"

    def test_no_match_empty_networks_list(self):
        """An instance with an empty networks list must not be matched."""
        from c7n_ibmcloud.resources.powervs import PowerVSInstancePublicNetworkFilter

        instance = {"pvmInstanceID": "pvm-empty", "networks": []}
        f = PowerVSInstancePublicNetworkFilter({"type": "public-network-interface"}, None)
        assert f.process([instance]) == []

    def test_no_match_missing_networks_key(self):
        """An instance without a networks key must not be matched."""
        from c7n_ibmcloud.resources.powervs import PowerVSInstancePublicNetworkFilter

        instance = {"pvmInstanceID": "pvm-no-key", "status": "ACTIVE"}
        f = PowerVSInstancePublicNetworkFilter({"type": "public-network-interface"}, None)
        assert f.process([instance]) == []

    def test_no_match_empty_external_ip_string(self):
        """An instance with externalIP='' on a network entry must not be matched."""
        from c7n_ibmcloud.resources.powervs import PowerVSInstancePublicNetworkFilter

        instance = {
            "pvmInstanceID": "pvm-empty-ip",
            "networks": [{"networkID": "net-x", "ipAddress": "10.0.0.1", "externalIP": ""}],
        }
        f = PowerVSInstancePublicNetworkFilter({"type": "public-network-interface"}, None)
        assert f.process([instance]) == []

    def test_matches_canonical_api_payload_with_external_ip(self):
        """Match the exact payload shape from the IBM Power IaaS API docs.

        Canonical response from GET /pvm-instances/{id}/networks:
          networks: [{externalIP: "x.x.x.x", networkName: "public-...", type: "fixed", ...}]
        The externalIP field is present and non-empty — must match.
        """
        from c7n_ibmcloud.resources.powervs import PowerVSInstancePublicNetworkFilter

        instance = {
            "pvmInstanceID": "8ab7ede5-540e-44bc-99cf-9c8bf1ac6297",
            "serverName": "canonical-test-vm",
            "networks": [
                {
                    "externalIP": "169.55.100.1",
                    "href": "/pcloud/v1/cloud-instances/66b2c271/pvm-instances/8ab7ede5/networks/8838dcff",
                    "ip": "192.168.140.38",
                    "ipAddress": "192.168.140.38",
                    "macAddress": "fa:38:e6:a8:19:20",
                    "networkID": "8838dcff-d423-4490-aa95-7bfed54adbae",
                    "networkName": "public-192_168_140_32-29-VLAN_3305",
                    "type": "fixed",
                    "version": 4,
                }
            ],
        }
        f = PowerVSInstancePublicNetworkFilter({"type": "public-network-interface"}, None)
        result = f.process([instance])
        assert len(result) == 1
        assert result[0]["pvmInstanceID"] == "8ab7ede5-540e-44bc-99cf-9c8bf1ac6297"

    def test_matches_production_payload_no_external_ip(self):
        """Match the real-world payload observed in production where externalIP is absent.

        Live log showed: networks=[{'ipAddress': '192.168.132.53',
        'networkName': 'public-192_168_132_48-29-VLAN_2114', 'type': 'fixed'}, ...]
        No externalIP field — must still match via networkName prefix "public-".
        """
        from c7n_ibmcloud.resources.powervs import PowerVSInstancePublicNetworkFilter

        instance = {
            "pvmInstanceID": "c306e9ef-ee0b-450a-9f33-076d3de977f2",
            "serverName": "production-vm",
            "networks": [
                {"ipAddress": "192.168.132.53", "networkName": "public-192_168_132_48-29-VLAN_2114", "type": "fixed"},
                {"ipAddress": "172.25.1.142", "networkName": "subnet-priv01", "type": "fixed"},
            ],
        }
        f = PowerVSInstancePublicNetworkFilter({"type": "public-network-interface"}, None)
        result = f.process([instance])
        assert len(result) == 1
        assert result[0]["pvmInstanceID"] == "c306e9ef-ee0b-450a-9f33-076d3de977f2"

    def test_mixed_set_matches_only_public(self):
        """Both detection paths (externalIP and networkName prefix) work across a mixed set."""
        from c7n_ibmcloud.resources.powervs import PowerVSInstancePublicNetworkFilter

        instances = SAMPLE_PVM_INSTANCES + [SAMPLE_PVM_INSTANCE_PUBLIC_NET, SAMPLE_PVM_INSTANCE_EXTERNAL_IP]
        f = PowerVSInstancePublicNetworkFilter({"type": "public-network-interface"}, None)
        result = f.process(instances)
        ids = {r["pvmInstanceID"] for r in result}
        assert ids == {"pvm-ccc-333", "pvm-ddd-444"}

    def test_stop_action_on_public_network_instance(self):
        """stop action should issue immediate-shutdown for a matched public-network instance."""
        session, pv_client = _make_powervs_session()

        from c7n_ibmcloud.resources.powervs import PowerVSInstanceStop, PowerVSInstancePublicNetworkFilter

        f = PowerVSInstancePublicNetworkFilter({"type": "public-network-interface"}, None)
        matched = f.process([SAMPLE_PVM_INSTANCE_PUBLIC_NET])
        assert len(matched) == 1

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = PowerVSInstanceStop({}, manager)

        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            action.perform_action(matched[0])

        post_bodies = [b for _, b in pv_client.posts]
        assert any(b.get("action") == "immediate-shutdown" for b in post_bodies)

    def test_delete_action_on_public_network_instance(self):
        """delete action should call client.delete for a matched public-network instance."""
        session, pv_client = _make_powervs_session()

        from c7n_ibmcloud.resources.powervs import PowerVSInstanceDelete, PowerVSInstancePublicNetworkFilter

        f = PowerVSInstancePublicNetworkFilter({"type": "public-network-interface"}, None)
        matched = f.process([SAMPLE_PVM_INSTANCE_PUBLIC_NET])
        assert len(matched) == 1

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = PowerVSInstanceDelete({}, manager)

        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            action.perform_action(matched[0])

        assert any("pvm-ccc-333" in p for p in pv_client.deleted)


# ---------------------------------------------------------------------------
# Tests: PowerVS instance actions
# ---------------------------------------------------------------------------

class TestPowerVSInstanceActions:

    def test_stop_action(self):
        """stop action should post immediate-shutdown to the instance path."""
        session, pv_client = _make_powervs_session()

        from c7n_ibmcloud.resources.powervs import PowerVSInstanceStop

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = PowerVSInstanceStop({}, manager)

        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            action.perform_action(SAMPLE_PVM_INSTANCES[0])

        post_paths = [p for p, _ in pv_client.posts]
        assert any("pvm-aaa-111/action" in p for p in post_paths)
        post_bodies = [b for _, b in pv_client.posts]
        assert any(b.get("action") == "immediate-shutdown" for b in post_bodies)

    def test_start_action(self):
        """start action should post start to the instance path."""
        session, pv_client = _make_powervs_session()

        from c7n_ibmcloud.resources.powervs import PowerVSInstanceStart

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = PowerVSInstanceStart({}, manager)

        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            action.perform_action(SAMPLE_PVM_INSTANCES[1])

        post_paths = [p for p, _ in pv_client.posts]
        assert any("pvm-bbb-222/action" in p for p in post_paths)
        post_bodies = [b for _, b in pv_client.posts]
        assert any(b.get("action") == "start" for b in post_bodies)

    def test_delete_action(self):
        """delete action should call delete on the pvm-instance path."""
        session, pv_client = _make_powervs_session()

        from c7n_ibmcloud.resources.powervs import PowerVSInstanceDelete

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = PowerVSInstanceDelete({}, manager)

        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            action.perform_action(SAMPLE_PVM_INSTANCES[0])

        assert any("pvm-aaa-111" in p for p in pv_client.deleted)


# ---------------------------------------------------------------------------
# Tests: PowerVS volume filters
# ---------------------------------------------------------------------------

class TestPowerVSVolumeFilters:

    def test_orphaned_volume_filter(self):
        """value filter pvmInstanceIDs=[] should match unattached volumes."""
        from c7n.filters import ValueFilter

        f = ValueFilter({"type": "value", "key": "pvmInstanceIDs", "value": []}, None)
        result = f.process(SAMPLE_VOLUMES)
        assert len(result) == 1
        assert result[0]["volumeID"] == "vol-bbb-002"

    def test_state_filter_available(self):
        """value filter state=available matches detached volumes."""
        from c7n.filters import ValueFilter

        f = ValueFilter({"type": "value", "key": "state", "value": "available"}, None)
        result = f.process(SAMPLE_VOLUMES)
        assert len(result) == 1
        assert result[0]["name"] == "orphaned-vol"


# ---------------------------------------------------------------------------
# Tests: PowerVS volume delete action
# ---------------------------------------------------------------------------

class TestPowerVSVolumeActions:

    def test_delete_volume(self):
        """delete action should call client.delete with the volume path."""
        session, pv_client = _make_powervs_session()

        from c7n_ibmcloud.resources.powervs import PowerVSVolumeDelete

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = PowerVSVolumeDelete({}, manager)

        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            action.perform_action(SAMPLE_VOLUMES[1])

        assert any("vol-bbb-002" in p for p in pv_client.deleted)


# ---------------------------------------------------------------------------
# Tests: PowerVS network filters
# ---------------------------------------------------------------------------

class TestPowerVSNetworkFilters:

    def test_network_type_filter(self):
        """value filter type=pub-vlan should match public networks."""
        from c7n.filters import ValueFilter

        f = ValueFilter({"type": "value", "key": "type", "value": "pub-vlan"}, None)
        result = f.process(SAMPLE_NETWORKS)
        assert len(result) == 1
        assert result[0]["networkID"] == "net-bbb-002"

    def test_delete_network(self):
        """delete action should call client.delete with the network path."""
        session, pv_client = _make_powervs_session()

        from c7n_ibmcloud.resources.powervs import PowerVSNetworkDelete

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = PowerVSNetworkDelete({}, manager)

        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            action.perform_action(SAMPLE_NETWORKS[0])

        assert any("net-aaa-001" in p for p in pv_client.deleted)

    def test_delete_network_409_conflict_handled_gracefully(self):
        """delete action on network in use (409 Conflict) should log warning and tag workspace."""
        session, pv_client = _make_powervs_session()
        # Simulate 409 Conflict from requests
        import requests
        err_response = MagicMock()
        err_response.status_code = 409
        http_err = requests.exceptions.HTTPError("409 Client Error: Conflict", response=err_response)
        pv_client.delete = MagicMock(side_effect=http_err)

        from c7n_ibmcloud.resources.powervs import PowerVSNetworkDelete

        tagging_client = MagicMock()
        session._clients["global-tagging"] = tagging_client
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type = MagicMock(tag_type="user")
        action = PowerVSNetworkDelete({}, manager)

        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            with patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
                # Should not raise exception
                action.perform_action(SAMPLE_NETWORKS[0])

        assert tagging_client.attach_tag.called

    def test_append_description_ssh_key_uses_id_field(self):
        """append-description must PUT to /v1/ssh-keys/{id} using the UUID 'id' field.

        The v1 SSH key endpoint uses the UUID 'id' as the path parameter, not the
        human-readable 'name'.  Using 'name' returns 404.
        """
        session, pv_client = _make_powervs_session()

        from c7n_ibmcloud.resources.powervs import PowerVSSSHKeyAppendDescriptionAction

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = PowerVSSSHKeyAppendDescriptionAction(
            {"type": "append-description", "notice": "custodian No description."},
            manager,
        )

        sample_key = {
            "id": "abc-uuid-123",
            "name": "my-test-key",
            "description": "",
            "primaryWorkspace": True,
            "c7n:workspace_id": "ws-guid-001",
            "c7n:workspace_crn": "crn:v1:bluemix:public:power-iaas:us-south:a/123:ws-1::",
            "c7n:region": "us-south",
        }

        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            action.perform_action(sample_key)

        # Must use the UUID id in the path, not the name
        assert len(pv_client.posts) == 1
        path, body = pv_client.posts[0]
        assert "ssh-keys/abc-uuid-123" in path
        assert "my-test-key" not in path
        assert body.get("description") == "custodian No description"

    def test_sanitize_strips_disallowed_characters(self):
        """_sanitize must replace em dashes, accented chars, and other non-ASCII with spaces.

        The IBM PowerVS API description field only accepts [a-zA-Z0-9-_ ] —
        anything else returns 400 Bad Request.
        """
        from c7n_ibmcloud.resources.powervs import PowerVSSSHKeyAppendDescriptionAction as A

        # em dash and accented letters must be replaced
        assert A._sanitize("No description — please document") == \
            "No description please document"
        # brackets are replaced too (not in allowed set)
        assert A._sanitize("[custodian] review") == "custodian review"
        # already-clean strings pass through unchanged
        assert A._sanitize("clean-text_here 123") == "clean-text_here 123"
        # multiple spaces collapsed
        assert A._sanitize("a  —  b") == "a b"
        # leading/trailing whitespace stripped
        assert A._sanitize("  hello  ") == "hello"

    def test_append_description_sanitizes_notice_before_put(self):
        """append-description must sanitize the notice before sending to the API."""
        session, pv_client = _make_powervs_session()

        from c7n_ibmcloud.resources.powervs import PowerVSSSHKeyAppendDescriptionAction

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        # Notice contains em dash and brackets — both disallowed by the API
        action = PowerVSSSHKeyAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] No description — please fix."},
            manager,
        )

        sample_key = {
            "id": "abc-uuid-123",
            "name": "my-test-key",
            "description": "",
            "primaryWorkspace": True,
            "c7n:workspace_id": "ws-guid-001",
            "c7n:workspace_crn": "crn:v1:bluemix:public:power-iaas:us-south:a/123:ws-1::",
            "c7n:region": "us-south",
        }

        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            action.perform_action(sample_key)

        assert len(pv_client.posts) == 1
        _, body = pv_client.posts[0]
        desc = body.get("description", "")
        # No disallowed characters in the sent description
        import re
        assert re.fullmatch(r"[a-zA-Z0-9\-_ ]+", desc), \
            "description sent to API must only contain [a-zA-Z0-9-_ ], got: %r" % desc

    def test_append_description_skips_when_notice_already_present(self):
        """append-description must not issue a PUT if the notice is already in the description."""
        session, pv_client = _make_powervs_session()

        from c7n_ibmcloud.resources.powervs import PowerVSSSHKeyAppendDescriptionAction

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = PowerVSSSHKeyAppendDescriptionAction(
            {"type": "append-description", "notice": "custodian No description."},
            manager,
        )

        sample_key = {
            "id": "abc-uuid-123",
            "name": "my-test-key",
            # description already contains the sanitized notice — must not PUT again
            "description": "custodian No description",
            "primaryWorkspace": True,
            "c7n:workspace_id": "ws-guid-001",
            "c7n:workspace_crn": "",
            "c7n:region": "us-south",
        }

        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            action.perform_action(sample_key)

        assert pv_client.posts == []

    def test_append_description_skips_non_primary_workspace_key(self):
        """append-description must skip keys where primaryWorkspace=False.

        The API returns 400 when you attempt to PUT a key owned by a different
        workspace (visibility=account, primaryWorkspace=False).
        """
        session, pv_client = _make_powervs_session()

        from c7n_ibmcloud.resources.powervs import PowerVSSSHKeyAppendDescriptionAction

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = PowerVSSSHKeyAppendDescriptionAction(
            {"type": "append-description", "notice": "[custodian] No description."},
            manager,
        )

        shared_key = {
            "id": "shared-uuid-999",
            "name": "account-wide-key",
            "description": "",
            "primaryWorkspace": False,   # owned by a different workspace
            "visibility": "account",
            "c7n:workspace_id": "ws-guid-001",
            "c7n:workspace_crn": "crn:v1:bluemix:public:power-iaas:us-south:a/123:ws-1::",
            "c7n:region": "us-south",
        }

        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            action.perform_action(shared_key)

        assert pv_client.posts == [], "Must not PUT for non-primary-workspace keys"

    def test_delete_ssh_key_skips_non_primary_workspace_key(self):
        """delete must skip keys where primaryWorkspace=False (not owned by this workspace)."""
        session, pv_client = _make_powervs_session()

        from c7n_ibmcloud.resources.powervs import PowerVSSSHKeyDelete

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = PowerVSSSHKeyDelete({}, manager)

        shared_key = {
            "id": "shared-uuid-999",
            "name": "account-wide-key",
            "primaryWorkspace": False,
            "visibility": "account",
            "c7n:workspace_id": "ws-guid-001",
            "c7n:workspace_crn": "crn:v1:bluemix:public:power-iaas:us-south:a/123:ws-1::",
            "c7n:region": "us-south",
        }

        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            action.perform_action(shared_key)

        assert pv_client.deleted == [], "Must not DELETE non-primary-workspace keys"


# ---------------------------------------------------------------------------
# Tests: Resource registration
# ---------------------------------------------------------------------------

class TestPowerVSResourceRegistration:

    def test_all_powervs_types_registered(self):
        """All 4 PowerVS resource types should be registered."""
        from c7n_ibmcloud.provider import resources

        for rtype in ("powervs-instance", "powervs-volume", "powervs-network", "powervs-image"):
            assert resources.get(rtype) is not None, (
                "ibm.%s not registered" % rtype
            )

    def test_get_powervs_workspaces_discovery(self):
        """_get_powervs_workspaces should discover workspaces via RC with service ID or CRN matching."""
        from c7n_ibmcloud.resources.powervs import _get_powervs_workspaces

        rc_client = MagicMock()
        rc_client.list_resource_instances.side_effect = [
            FakeResult({"resources": [], "next_url": None}),
            FakeResult({
                "resources": [
                    {
                        "guid": "discovered-ws-guid",
                        "name": "my-powervs-workspace",
                        "crn": "crn:v1:bluemix:public:power-iaas:dal10:a/123:ws-1::",
                        "resource_id": "power-iaas",
                        "region_id": "dal10",
                    }
                ],
                "next_url": None,
            }),
        ]
        session = FakeSession(clients={"resource-ctrl": rc_client})
        with patch.dict("os.environ", {}, clear=True):
            workspaces = _get_powervs_workspaces(session)
        assert len(workspaces) == 1
        assert workspaces[0]["guid"] == "discovered-ws-guid"


# ---------------------------------------------------------------------------
# Tests: PowerVSClient CRN header behaviour
# ---------------------------------------------------------------------------

class TestPowerVSClientCRNHeader:
    """CRN header must be sent on BOTH pcloud and /v1/ endpoints.

    The IBM Power IaaS API uses the CRN header to scope /v1/ workspace
    endpoints (e.g. /v1/ssh-keys) to the correct workspace — exactly the
    same as pcloud endpoints.  Omitting it returns 403.
    """

    def _make_client(self, crn="crn:v1:bluemix:public:power-iaas:us-south:a/123:ws-1::"):
        from c7n_ibmcloud.session import PowerVSClient
        from conftest import FakeIAMAuthenticator
        return PowerVSClient(
            workspace_id="ws-guid-001",
            authenticator=FakeIAMAuthenticator(),
            region="us-south",
            workspace_crn=crn,
        )

    def test_pcloud_path_sends_crn_header(self):
        """GET /pvm-instances (pcloud path) must include the CRN header."""
        import requests
        from unittest.mock import patch, MagicMock

        client = self._make_client()
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {"pvmInstances": []}
        fake_resp.raise_for_status = MagicMock()

        with patch("requests.request", return_value=fake_resp) as mock_req:
            client.list("/pvm-instances", "pvmInstances", v1=False)

        _, kwargs = mock_req.call_args
        headers = kwargs.get("headers", mock_req.call_args[0][2] if len(mock_req.call_args[0]) > 2 else {})
        # positional: requests.request(method, url, headers=...) — pick from kwargs
        headers = mock_req.call_args.kwargs.get("headers", {})
        assert "CRN" in headers, "CRN header must be present on pcloud requests"
        assert headers["CRN"] == "crn:v1:bluemix:public:power-iaas:us-south:a/123:ws-1::"

    def test_v1_path_sends_crn_header(self):
        """GET /ssh-keys (/v1/ path) must also include the CRN header.

        Without CRN the API cannot scope the request to a workspace → 403.
        """
        import requests
        from unittest.mock import patch, MagicMock

        client = self._make_client()
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {"sshKeys": []}
        fake_resp.raise_for_status = MagicMock()

        with patch("requests.request", return_value=fake_resp) as mock_req:
            client.list("/ssh-keys", "sshKeys", v1=True)

        headers = mock_req.call_args.kwargs.get("headers", {})
        assert "CRN" in headers, "CRN header must be present on /v1/ requests"
        assert headers["CRN"] == "crn:v1:bluemix:public:power-iaas:us-south:a/123:ws-1::"

    def test_request_retries_on_401_with_fresh_token(self):
        """A 401 response must trigger a single retry with a refreshed token."""
        from unittest.mock import patch, MagicMock, call

        client = self._make_client()
        resp_401 = MagicMock()
        resp_401.status_code = 401
        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.json.return_value = {}
        resp_200.raise_for_status = MagicMock()

        with patch("requests.request", side_effect=[resp_401, resp_200]) as mock_req:
            client.get("/pvm-instances/abc")

        assert mock_req.call_count == 2, "Must retry exactly once on 401"

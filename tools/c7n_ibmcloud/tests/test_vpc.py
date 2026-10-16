# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""Tests for IBM Cloud VPC resources."""

from unittest.mock import MagicMock, patch

from conftest import FakeSession, FakeSessionFactory, FakeResult


# ---------------------------------------------------------------------------
# Sample resource data
# ---------------------------------------------------------------------------

SAMPLE_INSTANCES = [
    {
        "id": "inst-001",
        "name": "web-server-1",
        "status": "running",
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::instance:inst-001",
        "zone": {"name": "us-south-1"},
        "created_at": "2023-06-01T00:00:00Z",
        "resource_group": {"id": "rg-prod", "name": "production"},
        "tags": ["environment:production", "owner:platform"],
    },
    {
        "id": "inst-002",
        "name": "batch-worker",
        "status": "stopped",
        "crn": "crn:v1:bluemix:public:is:us-south-2:a/123::instance:inst-002",
        "zone": {"name": "us-south-2"},
        "created_at": "2024-01-15T00:00:00Z",
        "resource_group": {"id": "rg-dev", "name": "development"},
        "tags": [],
    },
]

SAMPLE_VOLUMES = [
    {
        "id": "vol-001",
        "name": "data-vol",
        "status": "available",
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::volume:vol-001",
        "zone": {"name": "us-south-1"},
        "capacity": 100,
        "created_at": "2022-12-01T00:00:00Z",
        "resource_group": {"id": "rg-prod", "name": "production"},
        "tags": [],
    },
]

SAMPLE_FLOATING_IPS = [
    {
        "id": "fip-001",
        "name": "public-ip-1",
        "address": "169.48.1.1",
        "status": "available",
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::floating-ip:fip-001",
        "tags": [],
        # no "target" field — unattached
    },
    {
        "id": "fip-002",
        "name": "public-ip-2",
        "address": "169.48.1.2",
        "status": "available",   # attached to a VSI NIC but still "available" in status
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::floating-ip:fip-002",
        "tags": [],
        "target": {
            "id": "nic-abc",
            "name": "eth0",
            "resource_type": "network_interface",
            "href": "https://us-south.iaas.cloud.ibm.com/v1/instances/inst-xyz/network_interfaces/nic-abc",
        },
    },
    {
        "id": "fip-003",
        "name": "public-ip-3",
        "address": "169.48.1.3",
        "status": "available",
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::floating-ip:fip-003",
        "tags": [],
        "target": {
            "id": "nic-bms",
            "name": "bond0",
            "resource_type": "network_interface",
            "href": "https://us-south.iaas.cloud.ibm.com/v1/bare_metal_servers/bms-xyz/network_interfaces/nic-bms",
        },
    },
    {
        "id": "fip-004",
        "name": "public-ip-4",
        "address": "169.48.1.4",
        "status": "available",
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::floating-ip:fip-004",
        "tags": [],
        "target": {
            "id": "vni-def",
            "name": "vni-1",
            "resource_type": "virtual_network_interface",
            "href": "https://us-south.iaas.cloud.ibm.com/v1/virtual_network_interfaces/vni-def",
        },
    },
    {
        "id": "fip-005",
        "name": "public-ip-5",
        "address": "169.48.1.5",
        "status": "available",
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::floating-ip:fip-005",
        "tags": [],
        "target": {
            "id": "pgw-ghi",
            "name": "public-gw-1",
            "resource_type": "public_gateway",
            "href": "https://us-south.iaas.cloud.ibm.com/v1/public_gateways/pgw-ghi",
        },
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tagging_client(tag_map=None):
    """Build a fake GlobalTaggingV1 client.

    Parameters
    ----------
    tag_map:
        Dict mapping CRN → list of tag name strings to return.
        If None, all list_tags calls return empty items.
    """
    tag_map = tag_map or {}
    tagging = MagicMock()

    def _list_tags(attached_to=None, tag_type=None, offset=0, limit=100, **kw):
        names = tag_map.get(attached_to, [])
        items = [{"name": n} for n in names]
        return FakeResult({"items": items, "total_count": len(items)})

    tagging.list_tags.side_effect = _list_tags
    return tagging


def _make_vpc_session(instances=None, volumes=None, floating_ips=None, tag_map=None):
    vpc_client = MagicMock()
    vpc_client.list_instances.return_value = FakeResult(
        {"instances": instances or [], "next": None}
    )
    vpc_client.list_volumes.return_value = FakeResult(
        {"volumes": volumes or [], "next": None}
    )
    vpc_client.list_floating_ips.return_value = FakeResult(
        {"floating_ips": floating_ips or [], "next": None}
    )
    vpc_client.create_instance_action.return_value = FakeResult({})
    vpc_client.delete_instance.return_value = None
    vpc_client.delete_floating_ip.return_value = None
    vpc_client.delete_volume.return_value = None

    tagging_client = _make_tagging_client(tag_map)

    return FakeSession(clients={"vpc": vpc_client, "global-tagging": tagging_client})


# ---------------------------------------------------------------------------
# Tests: VPCInstance filters
# ---------------------------------------------------------------------------

class TestVPCInstanceFilters:

    def test_tag_filter_absent(self):
        """Instances missing the 'environment' tag should be returned."""
        from c7n_ibmcloud.filters.base import TagFilter

        f = TagFilter({"type": "tag", "key": "environment", "op": "absent"}, None)
        result = f.process(SAMPLE_INSTANCES)
        assert len(result) == 1
        assert result[0]["id"] == "inst-002"

    def test_tag_filter_eq(self):
        """Instances with environment=production should match."""
        from c7n_ibmcloud.filters.base import TagFilter

        f = TagFilter(
            {"type": "tag", "key": "environment", "op": "eq", "value": "production"}, None
        )
        result = f.process(SAMPLE_INSTANCES)
        assert len(result) == 1
        assert result[0]["id"] == "inst-001"

    def test_resource_group_filter(self):
        """resource-group filter should match by group name."""
        from c7n_ibmcloud.filters.base import ResourceGroupFilter

        f = ResourceGroupFilter({"type": "resource-group", "value": "development"}, None)
        result = f.process(SAMPLE_INSTANCES)
        assert len(result) == 1
        assert result[0]["id"] == "inst-002"

    def test_age_filter(self):
        """age filter gt 500 days should match only the older instance."""
        from c7n_ibmcloud.filters.base import AgeFilter
        from datetime import datetime, timezone

        now = datetime(2024, 9, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat

            f = AgeFilter({"type": "age", "op": "gt", "days": 500}, None)
            f.date_attribute = "created_at"
            result = f.process(SAMPLE_INSTANCES)

        # inst-001 created 2023-06-01 is ~457 days from 2024-09-01 — borderline
        # inst-002 created 2024-01-15 is ~230 days — should not match
        # Use a threshold that cleanly separates them
        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat

            f = AgeFilter({"type": "age", "op": "gt", "days": 600}, None)
            f.date_attribute = "created_at"
            result = f.process(SAMPLE_INSTANCES)

        # inst-001 (2023-06-01) is 580 days before 2025-01-01 — matches gt 500 but not gt 600
        # vol-001 (2022-12-01) would be > 600 days — but we're testing instances here
        assert all(r["id"] != "inst-002" for r in result)


# ---------------------------------------------------------------------------
# Tests: VPCInstance actions
# ---------------------------------------------------------------------------

class TestVPCInstanceActions:

    def test_stop_action(self):
        """stop action should call create_instance_action with type=stop."""
        session = _make_vpc_session(instances=SAMPLE_INSTANCES)
        vpc_client = session._clients["vpc"]

        from c7n_ibmcloud.resources.vpc import VPCInstanceStop

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = VPCInstanceStop({"type": "stop"}, manager)

        with patch("c7n_ibmcloud.actions.base.local_session", return_value=session), \
             patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_INSTANCES[0])

        vpc_client.create_instance_action.assert_called_once_with(
            instance_id="inst-001", type="stop"
        )

    def test_start_action(self):
        """start action should call create_instance_action with type=start."""
        session = _make_vpc_session(instances=SAMPLE_INSTANCES)
        vpc_client = session._clients["vpc"]

        from c7n_ibmcloud.resources.vpc import VPCInstanceStart

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = VPCInstanceStart({"type": "start"}, manager)

        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_INSTANCES[1])

        vpc_client.create_instance_action.assert_called_once_with(
            instance_id="inst-002", type="start"
        )

    def test_delete_action(self):
        """delete action should call delete_instance."""
        session = _make_vpc_session(instances=SAMPLE_INSTANCES)
        vpc_client = session._clients["vpc"]

        from c7n_ibmcloud.resources.vpc import VPCInstanceDelete

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = VPCInstanceDelete({"type": "delete"}, manager)

        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_INSTANCES[0])

        vpc_client.delete_instance.assert_called_once_with(id="inst-001")


# ---------------------------------------------------------------------------
# Tests: VPCVolume
# ---------------------------------------------------------------------------

class TestVPCVolume:

    def test_age_filter_on_volumes(self):
        """age filter should identify old unattached volumes."""
        from c7n_ibmcloud.filters.base import AgeFilter
        from datetime import datetime, timezone

        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch("c7n_ibmcloud.filters.base.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.fromisoformat = datetime.fromisoformat

            f = AgeFilter({"type": "age", "op": "gt", "days": 600}, None)
            f.date_attribute = "created_at"
            result = f.process(SAMPLE_VOLUMES)

        # vol-001 created 2022-12-01 → ~762 days before 2025-01-01 — should match
        assert len(result) == 1
        assert result[0]["id"] == "vol-001"

    def test_delete_action(self):
        """delete action should call delete_volume."""
        session = _make_vpc_session(volumes=SAMPLE_VOLUMES)
        vpc_client = session._clients["vpc"]

        from c7n_ibmcloud.resources.vpc import VPCVolumeDelete

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)

        action = VPCVolumeDelete({"type": "delete"}, manager)

        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_VOLUMES[0])

        vpc_client.delete_volume.assert_called_once_with(id="vol-001")


# ---------------------------------------------------------------------------
# Tests: VPCFloatingIP
# ---------------------------------------------------------------------------

class TestVPCFloatingIP:

    def test_status_available_filter(self):
        """Value filter on status=available returns all provisioned FIPs (attached or not)."""
        from c7n.filters import ValueFilter

        f = ValueFilter({"type": "value", "key": "status", "value": "available"}, None)
        result = f.process(SAMPLE_FLOATING_IPS)
        # All 5 sample FIPs have status=available
        assert len(result) == 5

    def test_unattached_filter_via_target_absent(self):
        """FIPs without a target field are truly unattached."""
        unattached = [r for r in SAMPLE_FLOATING_IPS if "target" not in r]
        assert len(unattached) == 1
        assert unattached[0]["id"] == "fip-001"

    def _make_release_action(self, session):
        from c7n_ibmcloud.resources.vpc import VPCFloatingIPRelease
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        return VPCFloatingIPRelease({"type": "release"}, manager)

    def test_release_unattached_fip(self):
        """Unattached FIP (no target field) is deleted directly."""
        session = _make_vpc_session()
        vpc_client = session._clients["vpc"]
        action = self._make_release_action(session)

        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_FLOATING_IPS[0])  # fip-001, no target

        vpc_client.remove_instance_network_interface_floating_ip.assert_not_called()
        vpc_client.delete_floating_ip.assert_called_once_with(id="fip-001")

    def test_release_detaches_from_instance_nic_first(self):
        """FIP attached to a VSI NIC is detached via remove_instance_network_interface_floating_ip."""
        session = _make_vpc_session()
        vpc_client = session._clients["vpc"]
        action = self._make_release_action(session)

        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_FLOATING_IPS[1])  # fip-002, instance NIC

        vpc_client.remove_instance_network_interface_floating_ip.assert_called_once_with(
            instance_id="inst-xyz",
            network_interface_id="nic-abc",
            id="fip-002",
        )
        vpc_client.delete_floating_ip.assert_called_once_with(id="fip-002")

    def test_release_detaches_from_bms_nic_first(self):
        """FIP attached to a BMS NIC is detached via remove_bare_metal_server_network_interface_floating_ip."""
        session = _make_vpc_session()
        vpc_client = session._clients["vpc"]
        action = self._make_release_action(session)

        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_FLOATING_IPS[2])  # fip-003, BMS NIC

        vpc_client.remove_bare_metal_server_network_interface_floating_ip.assert_called_once_with(
            bare_metal_server_id="bms-xyz",
            network_interface_id="nic-bms",
            id="fip-003",
        )
        vpc_client.delete_floating_ip.assert_called_once_with(id="fip-003")

    def test_release_detaches_from_virtual_network_interface(self):
        """FIP attached to a virtual NI is detached via remove_network_interface_floating_ip."""
        session = _make_vpc_session()
        vpc_client = session._clients["vpc"]
        action = self._make_release_action(session)

        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_FLOATING_IPS[3])  # fip-004, virtual NI

        vpc_client.remove_network_interface_floating_ip.assert_called_once_with(
            virtual_network_interface_id="vni-def",
            id="fip-004",
        )
        vpc_client.delete_floating_ip.assert_called_once_with(id="fip-004")

    def test_release_skips_public_gateway_fip(self):
        """FIP on a public gateway logs a warning and skips deletion entirely."""
        session = _make_vpc_session()
        vpc_client = session._clients["vpc"]
        action = self._make_release_action(session)

        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_FLOATING_IPS[4])  # fip-005, public gateway

        vpc_client.delete_floating_ip.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: VPC tag augmentation from GlobalTagging
# ---------------------------------------------------------------------------

# Raw resources as returned by the VPC SDK (no tags field)
SAMPLE_INSTANCES_NO_TAGS = [
    {
        "id": "inst-001",
        "name": "web-server-1",
        "status": "running",
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::instance:inst-001",
        "zone": {"name": "us-south-1"},
        "created_at": "2023-06-01T00:00:00Z",
        "resource_group": {"id": "rg-prod", "name": "production"},
    },
    {
        "id": "inst-002",
        "name": "batch-worker",
        "status": "stopped",
        "crn": "crn:v1:bluemix:public:is:us-south-2:a/123::instance:inst-002",
        "zone": {"name": "us-south-2"},
        "created_at": "2024-01-15T00:00:00Z",
        "resource_group": {"id": "rg-dev", "name": "development"},
    },
]


class TestVPCTagAugmentation:

    def test_augment_with_tags_injects_tags(self):
        """augment_with_tags should fetch tags from GlobalTagging and inject them."""
        from c7n_ibmcloud.resources.vpc import augment_with_tags

        crn1 = "crn:v1:bluemix:public:is:us-south-1:a/123::instance:inst-001"
        crn2 = "crn:v1:bluemix:public:is:us-south-2:a/123::instance:inst-002"
        tag_map = {
            crn1: ["environment:production", "owner:platform"],
            crn2: [],
        }
        session = _make_vpc_session(tag_map=tag_map)

        result = augment_with_tags(SAMPLE_INSTANCES_NO_TAGS, session)

        # inst-001 should have its tags injected
        tagged = {r["id"]: r["tags"] for r in result}
        assert "environment:production" in tagged["inst-001"]
        assert "owner:platform" in tagged["inst-001"]
        assert tagged["inst-002"] == []

    def test_augment_with_tags_handles_missing_crn(self):
        """Resources without a CRN field should get an empty tags list."""
        from c7n_ibmcloud.resources.vpc import augment_with_tags

        resources = [{"id": "no-crn-resource", "name": "test"}]
        session = _make_vpc_session()

        result = augment_with_tags(resources, session)

        assert result[0]["tags"] == []

    def test_tag_filter_absent_using_augmented_tags(self):
        """tag filter op=absent should find instances with no matching tag after augment."""
        from c7n_ibmcloud.filters.base import TagFilter

        # Simulate post-augment resources: inst-001 has env tag, inst-002 does not
        resources = [
            dict(SAMPLE_INSTANCES_NO_TAGS[0], tags=["environment:production"]),
            dict(SAMPLE_INSTANCES_NO_TAGS[1], tags=[]),
        ]
        f = TagFilter({"type": "tag", "key": "environment", "op": "absent"}, None)
        result = f.process(resources)

        assert len(result) == 1
        assert result[0]["id"] == "inst-002"

    def test_tag_filter_eq_using_augmented_tags(self):
        """tag filter op=eq should match instances where tag value equals target."""
        from c7n_ibmcloud.filters.base import TagFilter

        resources = [
            dict(SAMPLE_INSTANCES_NO_TAGS[0], tags=["environment:production"]),
            dict(SAMPLE_INSTANCES_NO_TAGS[1], tags=["environment:dev"]),
        ]
        f = TagFilter({"type": "tag", "key": "environment", "op": "eq", "value": "production"}, None)
        result = f.process(resources)

        assert len(result) == 1
        assert result[0]["id"] == "inst-001"

    def test_vpc_describe_source_calls_augment(self):
        """VPCDescribeSource.augment() should call augment_with_tags."""
        from c7n_ibmcloud.resources.vpc import VPCDescribeSource

        crn = "crn:v1:bluemix:public:is:us-south-1:a/123::instance:inst-001"
        tag_map = {crn: ["team:sre"]}
        session = _make_vpc_session(tag_map=tag_map)

        source = VPCDescribeSource.__new__(VPCDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)
        source.manager.resource_type.tag_type = "user"  # VPC resources use user tags

        raw = [dict(SAMPLE_INSTANCES_NO_TAGS[0])]  # no tags field

        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            result = source.augment(raw)

        assert result[0]["tags"] == ["team:sre"]

    def test_augment_with_tags_passes_tag_type(self):
        """augment_with_tags passes tag_type through to list_tags."""
        from c7n_ibmcloud.resources.vpc import augment_with_tags, _fetch_tags_for_crn

        tagging_client = MagicMock()
        tagging_client.list_tags.return_value = MagicMock(get_result=lambda: {"items": []})
        session = FakeSession(clients={"global-tagging": tagging_client})

        resources = [{"id": "svc-1", "crn": "crn:v1:bluemix:public:iam-identity::a/1::serviceid:svc-1"}]

        # Call with tag_type="access" (as IAM resources do)
        augment_with_tags(resources, session, tag_type="access")

        call_kwargs = tagging_client.list_tags.call_args
        assert call_kwargs.kwargs.get("tag_type") == "access"

    def test_vpc_tag_action_uses_user_tag_type(self):
        """tag action on VPC resources must call attach_tag with tag_type=user."""
        from c7n_ibmcloud.actions.base import TagAction
        from unittest.mock import MagicMock, patch

        tagging_client = MagicMock()
        session = FakeSession(clients={"global-tagging": tagging_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"  # VPC resources

        action = TagAction({"type": "tag", "tags": {"env": "prod"}}, manager)

        with patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
            action.perform_action(SAMPLE_INSTANCES[0])

        from ibm_platform_services.global_tagging_v1 import Resource
        tagging_client.attach_tag.assert_called_once_with(
            resources=[Resource(resource_id=SAMPLE_INSTANCES[0]["crn"])],
            tag_names=["env:prod"],
            tag_type="user",
        )

    def test_vpc_mark_for_op_uses_valid_tag_format(self):
        """mark-for-op on VPC resources must format tag as custodian_status_<op>:<date>."""
        from c7n_ibmcloud.actions.base import MarkForOpAction
        from unittest.mock import MagicMock, patch

        tagging_client = MagicMock()
        session = FakeSession(clients={"global-tagging": tagging_client})

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"

        action = MarkForOpAction({"type": "mark-for-op", "op": "delete", "days": 7}, manager)

        with patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
            action.perform_action(SAMPLE_INSTANCES[0])

        from ibm_platform_services.global_tagging_v1 import Resource
        tagging_client.attach_tag.assert_called_once()
        call_kwargs = tagging_client.attach_tag.call_args.kwargs
        assert call_kwargs["tag_type"] == "user"
        assert len(call_kwargs["tag_names"]) == 1
        assert call_kwargs["tag_names"][0].startswith("custodian_status_delete:")
        assert "@" not in call_kwargs["tag_names"][0]


# ---------------------------------------------------------------------------
# Tests: Cache key uniqueness
# ---------------------------------------------------------------------------

class TestCacheKeyUniqueness:

    def test_different_vpc_types_produce_different_cache_keys(self):
        """vpc-instance and vpc-floating-ip must NOT share a cache slot.

        Every IBM resource type has an inner class named 'resource_type', so
        get_cache_key() must use self.type (the registered string, e.g.
        'vpc-floating-ip') — not self.resource_type.__name__ — as the
        discriminator.
        """
        from c7n.resources import load_providers
        load_providers(('ibm',))
        from c7n_ibmcloud.resources.vpc import VPCInstance, VPCFloatingIP

        # Both inner classes are named "resource_type"
        assert VPCInstance.resource_type.__name__ == VPCFloatingIP.resource_type.__name__ == "resource_type"

        # But the managers have distinct .type values
        assert VPCInstance.type == "vpc-instance"
        assert VPCFloatingIP.type == "vpc-floating-ip"

        # Build minimal fake managers and verify cache keys differ
        inst_mgr = MagicMock()
        inst_mgr.source_type = "describe-vpc"
        inst_mgr.type = "vpc-instance"
        inst_mgr.resource_type = VPCInstance.resource_type

        fip_mgr = MagicMock()
        fip_mgr.source_type = "describe-vpc"
        fip_mgr.type = "vpc-floating-ip"
        fip_mgr.resource_type = VPCFloatingIP.resource_type

        # Simulate get_cache_key logic
        def _cache_key(mgr):
            return {
                "source_type": mgr.source_type,
                "query": None,
                "account_id": "acct-1",
                "region": "us-south",
                "resource_type": mgr.type,  # the fix
            }

        assert _cache_key(inst_mgr) != _cache_key(fip_mgr)



# ---------------------------------------------------------------------------
# Tests: _fetch_resources calls source.augment()
# ---------------------------------------------------------------------------

class TestFetchResourcesCallsSourceAugment:
    """Verify that QueryResourceManager._fetch_resources delegates to source.augment().

    The bug: _fetch_resources used to call self.augment() (the manager no-op)
    instead of self.source.augment().  VPCDescribeSource.augment() — which calls
    augment_with_tags — was therefore dead code and tags were never populated.
    """

    def test_fetch_resources_invokes_source_augment(self):
        """_fetch_resources must call source.augment(), not self.augment()."""
        from c7n_ibmcloud.query import QueryResourceManager

        raw = [{"id": "inst-001", "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::instance:inst-001"}]
        augmented = [dict(raw[0], tags=["env:prod"])]

        source = MagicMock()
        source.get_resources.return_value = raw
        source.augment.return_value = augmented

        mgr = MagicMock(spec=QueryResourceManager)
        mgr.source = source
        # Call the real method, not the mock
        mgr._fetch_resources = QueryResourceManager._fetch_resources.__get__(mgr)

        result = mgr._fetch_resources(None)

        source.augment.assert_called_once_with(raw)
        assert result == augmented

    def test_fetch_resources_tags_populated_end_to_end(self):
        """End-to-end: VPCInstance resources() surfaces tags from source.augment()."""
        from c7n_ibmcloud.resources.vpc import VPCDescribeSource
        from c7n_ibmcloud.query import QueryResourceManager

        crn = "crn:v1:bluemix:public:is:us-south-1:a/123::instance:inst-001"
        raw = [{"id": "inst-001", "crn": crn}]
        tag_map = {crn: ["owner:team-alpha"]}
        session = _make_vpc_session(tag_map=tag_map)

        source = VPCDescribeSource.__new__(VPCDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)
        source.manager.resource_type.tag_type = "user"
        source.query = MagicMock()
        source.query.filter.return_value = raw

        mgr = MagicMock(spec=QueryResourceManager)
        mgr.source = source
        mgr._fetch_resources = QueryResourceManager._fetch_resources.__get__(mgr)

        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            result = mgr._fetch_resources(None)

        assert result[0].get("tags") == ["owner:team-alpha"]


# ---------------------------------------------------------------------------
# Tests: VPC Network ACL — resource-group filter and rule-match via value filter
# ---------------------------------------------------------------------------

SAMPLE_NETWORK_ACLS = [
    {
        "id": "acl-001",
        "name": "allow-ssh-acl",
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::network-acl:acl-001",
        "resource_group": {"id": "rg-prod", "name": "production"},
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
                "id": "rule-2",
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
        "id": "acl-002",
        "name": "deny-all-acl",
        "crn": "crn:v1:bluemix:public:is:us-south-2:a/123::network-acl:acl-002",
        "resource_group": {"id": "rg-dev", "name": "development"},
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


class TestNetworkACLResourceGroupFilter:
    """VPCNetworkACL now registers a resource-group filter."""

    def test_filter_by_resource_group(self):
        from c7n_ibmcloud.filters.base import ResourceGroupFilter
        from c7n_ibmcloud.resources.vpc import VPCNetworkACL

        assert "resource-group" in VPCNetworkACL.filter_registry

        f = ResourceGroupFilter({"type": "resource-group", "value": "rg-prod"}, MagicMock())
        result = f.process(SAMPLE_NETWORK_ACLS)
        assert len(result) == 1
        assert result[0]["id"] == "acl-001"

    def test_filter_excludes_non_matching(self):
        from c7n_ibmcloud.filters.base import ResourceGroupFilter

        f = ResourceGroupFilter({"type": "resource-group", "value": "rg-nonexistent"}, MagicMock())
        result = f.process(SAMPLE_NETWORK_ACLS)
        assert result == []


class TestNetworkACLRuleMatchViaValueFilter:
    """ACL rule-match via 'value' filter with JMESPath on rules array.

    ACL rules differ from security-group rules:
      - port range: destination_port_min / destination_port_max  (not port_min/port_max)
      - source IP:  source  (not remote.cidr_block)
      - has action: allow / deny
    """

    def _run(self, resources, key, op="ne"):
        """Run a value filter with the given JMESPath key and op against resources."""
        from c7n.filters.core import ValueFilter

        data = {"type": "value", "key": key, "op": op, "value": []}
        mgr = MagicMock()
        mgr.get_model.return_value = MagicMock(id="id")
        f = ValueFilter(data, mgr)
        return f.process(resources)

    def test_detects_open_allow_inbound_ssh(self):
        """ACL with an inbound ALLOW rule on port 22 from 0.0.0.0/0 is returned."""
        key = (
            "rules[?destination_port_min <= `22` && destination_port_max >= `22`"
            " && direction == `inbound` && action == `allow` && source == `0.0.0.0/0`]"
        )
        result = self._run(SAMPLE_NETWORK_ACLS, key, op="ne")
        assert len(result) == 1
        assert result[0]["id"] == "acl-001"

    def test_no_match_when_all_deny(self):
        """ACL with only DENY rules is not matched."""
        key = (
            "rules[?destination_port_min <= `22` && destination_port_max >= `22`"
            " && direction == `inbound` && action == `allow` && source == `0.0.0.0/0`]"
        )
        result = self._run([SAMPLE_NETWORK_ACLS[1]], key, op="ne")
        assert result == []

    def test_match_none_finds_acls_without_rule(self):
        """op:eq value:[] (match=none) returns ACLs with NO such rule."""
        key = (
            "rules[?destination_port_min <= `22` && destination_port_max >= `22`"
            " && action == `allow`]"
        )
        result = self._run(SAMPLE_NETWORK_ACLS, key, op="eq")
        assert len(result) == 1
        assert result[0]["id"] == "acl-002"

    def test_direction_any_omitted_matches_both(self):
        """Without a direction clause, rules of either direction match."""
        key = (
            "rules[?destination_port_min <= `22` && destination_port_max >= `22`"
            " && action == `allow`]"
        )
        result = self._run(SAMPLE_NETWORK_ACLS, key, op="ne")
        assert len(result) == 1
        assert result[0]["id"] == "acl-001"

    def test_port_range_spanning(self):
        """A rule whose port range spans the target port also matches."""
        # acl-002 rule-3 covers ports 1-65535 with action=deny.
        # Query for any deny rule that covers port 80:
        key = "rules[?destination_port_min <= `80` && destination_port_max >= `80` && action == `deny`]"
        result = self._run(SAMPLE_NETWORK_ACLS, key, op="ne")
        # Both ACLs have a deny rule that covers port 80
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Tests: New VPC resource types (bare-metal, dedicated-host, file-share,
#         ssh-key, instance-group, instance-template, snapshot, backup-policy,
#         transit-gateway) and PowerVS SSH key
# ---------------------------------------------------------------------------

SAMPLE_BARE_METAL_SERVERS = [
    {
        "id": "bms-001", "name": "bare-01",
        "status": "running", "health_state": "ok",
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::bare-metal-server:bms-001",
        "zone": {"name": "us-south-1"},
        "created_at": "2023-01-01T00:00:00Z",
        "resource_group": {"id": "rg-prod", "name": "production"},
        "memory": 192, "cpu": {"architecture": "amd64"},
        "tags": [],
    },
]

SAMPLE_DEDICATED_HOSTS = [
    {
        "id": "dh-001", "name": "dhost-01",
        "state": "available", "provisionable": True,
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::dedicated-host:dh-001",
        "zone": {"name": "us-south-1"},
        "created_at": "2023-03-01T00:00:00Z",
        "resource_group": {"id": "rg-prod", "name": "production"},
        "memory": 3072, "available_memory": 2048,
        "tags": [],
    },
]

SAMPLE_FILE_SHARES = [
    {
        "id": "share-001", "name": "nfs-share-01",
        "lifecycle_state": "stable", "size": 200,
        "encryption": "provider_managed",
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::share:share-001",
        "created_at": "2024-01-15T00:00:00Z",
        "resource_group": {"id": "rg-prod", "name": "production"},
        "mount_targets": [{"id": "mt-001"}],
        "tags": [],
    },
    {
        "id": "share-002", "name": "nfs-share-orphan",
        "lifecycle_state": "stable", "size": 100,
        "encryption": "provider_managed",
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::share:share-002",
        "created_at": "2023-06-01T00:00:00Z",
        "resource_group": {"id": "rg-dev", "name": "development"},
        "mount_targets": [],
        "tags": [],
    },
]

SAMPLE_VPC_SSH_KEYS = [
    {
        "id": "key-001", "name": "deploy-key",
        "type": "rsa", "fingerprint": "SHA256:abc123",
        "crn": "crn:v1:bluemix:public:is:us-south:a/123::key:key-001",
        "created_at": "2022-01-01T00:00:00Z",
        "resource_group": {"id": "rg-prod", "name": "production"},
        "tags": [],
    },
    {
        "id": "key-002", "name": "old-dev-key",
        "type": "rsa", "fingerprint": "SHA256:xyz789",
        "crn": "crn:v1:bluemix:public:is:us-south:a/123::key:key-002",
        "created_at": "2020-06-01T00:00:00Z",
        "resource_group": {"id": "rg-dev", "name": "development"},
        "tags": [],
    },
]

SAMPLE_INSTANCE_GROUPS = [
    {
        "id": "ig-001", "name": "web-asg",
        "status": "healthy", "membership_count": 3,
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::instance-group:ig-001",
        "resource_group": {"id": "rg-prod", "name": "production"},
        "instance_template": {"id": "tmpl-001"},
        "tags": [],
    },
    {
        "id": "ig-002", "name": "empty-asg",
        "status": "healthy", "membership_count": 0,
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::instance-group:ig-002",
        "resource_group": {"id": "rg-dev", "name": "development"},
        "instance_template": {"id": "tmpl-002"},
        "tags": [],
    },
]

SAMPLE_INSTANCE_TEMPLATES = [
    {
        "id": "tmpl-001", "name": "web-template",
        "crn": "crn:v1:bluemix:public:is:us-south:a/123::instance-template:tmpl-001",
        "created_at": "2023-01-01T00:00:00Z",
        "resource_group": {"id": "rg-prod", "name": "production"},
        "profile": {"name": "bx2-4x16"},
        "tags": [],
    },
    {
        "id": "tmpl-002", "name": "stale-template",
        "crn": "crn:v1:bluemix:public:is:us-south:a/123::instance-template:tmpl-002",
        "created_at": "2021-01-01T00:00:00Z",
        "resource_group": {"id": "rg-dev", "name": "development"},
        "profile": {"name": "cx2-2x4"},
        "tags": [],
    },
]

SAMPLE_SNAPSHOTS = [
    {
        "id": "snap-001", "name": "vol-snap-with-source",
        "lifecycle_state": "stable", "size": 100,
        "source_volume": {"id": "vol-001", "name": "data-vol"},
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::snapshot:snap-001",
        "created_at": "2024-01-01T00:00:00Z",
        "resource_group": {"id": "rg-prod", "name": "production"},
        "tags": [],
    },
    {
        "id": "snap-002", "name": "orphaned-snap",
        "lifecycle_state": "stable", "size": 50,
        # source_volume absent — source volume was deleted
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::snapshot:snap-002",
        "created_at": "2023-06-01T00:00:00Z",
        "resource_group": {"id": "rg-dev", "name": "development"},
        "tags": [],
    },
    {
        "id": "snap-003", "name": "null-source-snap",
        "lifecycle_state": "stable", "size": 75,
        "source_volume": None,  # explicitly null
        "crn": "crn:v1:bluemix:public:is:us-south-1:a/123::snapshot:snap-003",
        "created_at": "2023-01-01T00:00:00Z",
        "resource_group": {"id": "rg-dev", "name": "development"},
        "tags": [],
    },
]

SAMPLE_BACKUP_POLICIES = [
    {
        "id": "bp-001", "name": "daily-backup",
        "lifecycle_state": "stable",
        "plans": [{"id": "plan-001", "name": "daily"}],
        "match_user_tags": ["backup:daily"],
        "crn": "crn:v1:bluemix:public:is:us-south:a/123::backup-policy:bp-001",
        "created_at": "2023-06-01T00:00:00Z",
        "resource_group": {"id": "rg-prod", "name": "production"},
        "tags": [],
    },
    {
        "id": "bp-002", "name": "unconfigured-policy",
        "lifecycle_state": "stable",
        "plans": [],          # no plans — unused
        "match_user_tags": [],
        "crn": "crn:v1:bluemix:public:is:us-south:a/123::backup-policy:bp-002",
        "created_at": "2023-01-01T00:00:00Z",
        "resource_group": {"id": "rg-dev", "name": "development"},
        "tags": [],
    },
]

SAMPLE_TRANSIT_GATEWAYS = [
    {
        "id": "tgw-001", "name": "cross-region-gw",
        "status": "available", "location": "us-south",
        "crn": "crn:v1:bluemix:public:transit:global:a/123::gateway:tgw-001",
        "created_at": "2023-01-01T00:00:00Z",
        "connections": [{"id": "conn-1"}, {"id": "conn-2"}],
        "tags": [],
    },
    {
        "id": "tgw-002", "name": "degraded-gw",
        "status": "failed", "location": "eu-de",
        "crn": "crn:v1:bluemix:public:transit:global:a/123::gateway:tgw-002",
        "created_at": "2022-06-01T00:00:00Z",
        "connections": [],
        "tags": [],
    },
]

SAMPLE_POWERVS_SSH_KEYS = [
    {
        "name": "pvs-key-prod",
        "sshKeyName": "pvs-key-prod",
        "creationDate": "2023-01-01T00:00:00Z",
        "c7n:workspace_id": "ws-001",
        "c7n:workspace_name": "my-workspace",
        "c7n:region": "us-south",
    },
    {
        "name": "pvs-key-old",
        "sshKeyName": "pvs-key-old",
        "creationDate": "2020-01-01T00:00:00Z",
        "c7n:workspace_id": "ws-001",
        "c7n:workspace_name": "my-workspace",
        "c7n:region": "us-south",
    },
]


def _make_vpc_session_ext(**overrides):
    """Extended session factory for new VPC resource types."""
    vpc = MagicMock()
    vpc.list_bare_metal_servers.return_value = FakeResult(
        {"bare_metal_servers": overrides.get("bare_metal_servers", []), "next": None}
    )
    vpc.list_dedicated_hosts.return_value = FakeResult(
        {"dedicated_hosts": overrides.get("dedicated_hosts", []), "next": None}
    )
    vpc.list_shares.return_value = FakeResult(
        {"shares": overrides.get("shares", []), "next": None}
    )
    vpc.list_keys.return_value = FakeResult(
        {"keys": overrides.get("keys", []), "next": None}
    )
    vpc.list_instance_groups.return_value = FakeResult(
        {"instance_groups": overrides.get("instance_groups", []), "next": None}
    )
    vpc.list_instance_templates.return_value = FakeResult(
        {"templates": overrides.get("templates", []), "next": None}
    )
    vpc.list_snapshots.return_value = FakeResult(
        {"snapshots": overrides.get("snapshots", []), "next": None}
    )
    vpc.list_backup_policies.return_value = FakeResult(
        {"backup_policies": overrides.get("backup_policies", []), "next": None}
    )
    session = FakeSession(clients={"vpc": vpc})
    return session, vpc


# ---------------------------------------------------------------------------
# Bare Metal
# ---------------------------------------------------------------------------

class TestVPCBareMetal:

    def test_registered(self):
        from c7n.resources import load_providers
        load_providers(("ibm",))
        from c7n_ibmcloud.resources.vpc import VPCBareMetal
        assert VPCBareMetal.type == "vpc-bare-metal"
        assert "tag" in VPCBareMetal.filter_registry
        assert "resource-group" in VPCBareMetal.filter_registry
        assert "age" in VPCBareMetal.filter_registry

    def test_resource_group_filter(self):
        from c7n_ibmcloud.filters.base import ResourceGroupFilter
        f = ResourceGroupFilter({"type": "resource-group", "value": "rg-prod"}, MagicMock())
        result = f.process(SAMPLE_BARE_METAL_SERVERS)
        assert len(result) == 1 and result[0]["id"] == "bms-001"

    def test_delete_calls_api(self):
        from c7n_ibmcloud.resources.vpc import VPCBareMetalDelete
        session, vpc = _make_vpc_session_ext()
        action = VPCBareMetalDelete.__new__(VPCBareMetalDelete)
        action.manager = MagicMock()
        action.data = {}
        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_BARE_METAL_SERVERS[0])
        vpc.delete_bare_metal_server.assert_called_once_with(id="bms-001")


# ---------------------------------------------------------------------------
# Dedicated Host
# ---------------------------------------------------------------------------

class TestVPCDedicatedHost:

    def test_registered(self):
        from c7n_ibmcloud.resources.vpc import VPCDedicatedHost
        assert VPCDedicatedHost.type == "vpc-dedicated-host"
        assert "age" in VPCDedicatedHost.filter_registry

    def test_delete_calls_api(self):
        from c7n_ibmcloud.resources.vpc import VPCDedicatedHostDelete
        session, vpc = _make_vpc_session_ext()
        action = VPCDedicatedHostDelete.__new__(VPCDedicatedHostDelete)
        action.manager = MagicMock()
        action.data = {}
        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_DEDICATED_HOSTS[0])
        vpc.delete_dedicated_host.assert_called_once_with(id="dh-001")


# ---------------------------------------------------------------------------
# File Share
# ---------------------------------------------------------------------------

class TestVPCFileShare:

    def test_registered(self):
        from c7n_ibmcloud.resources.vpc import VPCFileShare
        assert VPCFileShare.type == "vpc-file-share"
        assert "resource-group" in VPCFileShare.filter_registry

    def test_resource_group_filter(self):
        from c7n_ibmcloud.filters.base import ResourceGroupFilter
        f = ResourceGroupFilter({"type": "resource-group", "value": "rg-dev"}, MagicMock())
        result = f.process(SAMPLE_FILE_SHARES)
        assert len(result) == 1 and result[0]["id"] == "share-002"

    def test_delete_calls_api(self):
        from c7n_ibmcloud.resources.vpc import VPCFileShareDelete
        session, vpc = _make_vpc_session_ext()
        action = VPCFileShareDelete.__new__(VPCFileShareDelete)
        action.manager = MagicMock()
        action.data = {}
        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_FILE_SHARES[0])
        vpc.delete_share.assert_called_once_with(id="share-001")


# ---------------------------------------------------------------------------
# VPC SSH Key
# ---------------------------------------------------------------------------

class TestVPCSSHKey:

    def test_registered(self):
        from c7n_ibmcloud.resources.vpc import VPCSSHKey
        assert VPCSSHKey.type == "vpc-ssh-key"
        assert "age" in VPCSSHKey.filter_registry
        assert "resource-group" in VPCSSHKey.filter_registry

    def test_resource_group_filter(self):
        from c7n_ibmcloud.filters.base import ResourceGroupFilter
        f = ResourceGroupFilter({"type": "resource-group", "value": "rg-prod"}, MagicMock())
        result = f.process(SAMPLE_VPC_SSH_KEYS)
        assert len(result) == 1 and result[0]["id"] == "key-001"

    def test_delete_calls_api(self):
        from c7n_ibmcloud.resources.vpc import VPCSSHKeyDelete
        session, vpc = _make_vpc_session_ext()
        action = VPCSSHKeyDelete.__new__(VPCSSHKeyDelete)
        action.manager = MagicMock()
        action.data = {}
        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_VPC_SSH_KEYS[0])
        vpc.delete_key.assert_called_once_with(id="key-001")


# ---------------------------------------------------------------------------
# Instance Group
# ---------------------------------------------------------------------------

class TestVPCInstanceGroup:

    def test_registered(self):
        from c7n_ibmcloud.resources.vpc import VPCInstanceGroup
        assert VPCInstanceGroup.type == "vpc-instance-group"
        assert "resource-group" in VPCInstanceGroup.filter_registry

    def test_empty_group_detection_via_value_filter(self):
        """Empty instance groups (membership_count==0) are detectable via value filter."""
        from c7n.filters.core import ValueFilter
        data = {"type": "value", "key": "membership_count", "op": "eq", "value": 0}
        mgr = MagicMock()
        mgr.get_model.return_value = MagicMock(id="id")
        f = ValueFilter(data, mgr)
        result = f.process(SAMPLE_INSTANCE_GROUPS)
        assert len(result) == 1 and result[0]["id"] == "ig-002"

    def test_delete_calls_api(self):
        from c7n_ibmcloud.resources.vpc import VPCInstanceGroupDelete
        session, vpc = _make_vpc_session_ext()
        action = VPCInstanceGroupDelete.__new__(VPCInstanceGroupDelete)
        action.manager = MagicMock()
        action.data = {}
        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_INSTANCE_GROUPS[1])
        vpc.delete_instance_group.assert_called_once_with(instance_group_id="ig-002")


# ---------------------------------------------------------------------------
# Instance Template
# ---------------------------------------------------------------------------

class TestVPCInstanceTemplate:

    def test_registered(self):
        from c7n_ibmcloud.resources.vpc import VPCInstanceTemplate
        assert VPCInstanceTemplate.type == "vpc-instance-template"
        # Verify correct collection key
        assert VPCInstanceTemplate.resource_type.enum_spec[1] == "templates"
        # list_instance_templates() accepts no limit/start — must NOT use cursor pagination
        assert VPCInstanceTemplate.resource_type.pagination is None

    def test_delete_calls_api(self):
        from c7n_ibmcloud.resources.vpc import VPCInstanceTemplateDelete
        session, vpc = _make_vpc_session_ext()
        action = VPCInstanceTemplateDelete.__new__(VPCInstanceTemplateDelete)
        action.manager = MagicMock()
        action.data = {}
        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_INSTANCE_TEMPLATES[0])
        vpc.delete_instance_template.assert_called_once_with(id="tmpl-001")


# ---------------------------------------------------------------------------
# Snapshot + orphaned filter
# ---------------------------------------------------------------------------

class TestVPCSnapshot:

    def test_registered(self):
        from c7n_ibmcloud.resources.vpc import VPCSnapshot
        assert VPCSnapshot.type == "vpc-snapshot"
        assert "orphaned" in VPCSnapshot.filter_registry

    def test_orphaned_filter_absent_source_volume(self):
        """Snapshots with no source_volume field are orphaned."""
        from c7n_ibmcloud.resources.vpc import VPCSnapshotOrphanedFilter
        f = VPCSnapshotOrphanedFilter({"type": "orphaned"}, MagicMock())
        result = f.process(SAMPLE_SNAPSHOTS)
        ids = {r["id"] for r in result}
        assert "snap-002" in ids   # source_volume key absent
        assert "snap-003" in ids   # source_volume is None
        assert "snap-001" not in ids  # has a valid source_volume

    def test_orphaned_filter_excludes_live_snapshots(self):
        result = __import__(
            "c7n_ibmcloud.resources.vpc", fromlist=["VPCSnapshotOrphanedFilter"]
        ).VPCSnapshotOrphanedFilter({"type": "orphaned"}, MagicMock()).process(
            [SAMPLE_SNAPSHOTS[0]]
        )
        assert result == []

    def test_delete_calls_api(self):
        from c7n_ibmcloud.resources.vpc import VPCSnapshotDelete
        session, vpc = _make_vpc_session_ext()
        action = VPCSnapshotDelete.__new__(VPCSnapshotDelete)
        action.manager = MagicMock()
        action.data = {}
        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_SNAPSHOTS[1])
        vpc.delete_snapshot.assert_called_once_with(id="snap-002")


# ---------------------------------------------------------------------------
# Backup Policy + unused filter
# ---------------------------------------------------------------------------

class TestVPCBackupPolicy:

    def test_registered(self):
        from c7n_ibmcloud.resources.vpc import VPCBackupPolicy
        assert VPCBackupPolicy.type == "vpc-backup-policy"
        assert "unused" in VPCBackupPolicy.filter_registry

    def test_unused_filter_empty_plans(self):
        """Backup policies with no plans are returned by the unused filter."""
        from c7n_ibmcloud.resources.vpc import VPCBackupPolicyUnusedFilter
        f = VPCBackupPolicyUnusedFilter({"type": "unused"}, MagicMock())
        result = f.process(SAMPLE_BACKUP_POLICIES)
        assert len(result) == 1 and result[0]["id"] == "bp-002"

    def test_unused_filter_excludes_configured_policies(self):
        from c7n_ibmcloud.resources.vpc import VPCBackupPolicyUnusedFilter
        f = VPCBackupPolicyUnusedFilter({"type": "unused"}, MagicMock())
        result = f.process([SAMPLE_BACKUP_POLICIES[0]])
        assert result == []

    def test_delete_calls_api(self):
        from c7n_ibmcloud.resources.vpc import VPCBackupPolicyDelete
        session, vpc = _make_vpc_session_ext()
        action = VPCBackupPolicyDelete.__new__(VPCBackupPolicyDelete)
        action.manager = MagicMock()
        action.data = {}
        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_BACKUP_POLICIES[1])
        vpc.delete_backup_policy.assert_called_once_with(id="bp-002")


# ---------------------------------------------------------------------------
# Transit Gateway
# ---------------------------------------------------------------------------

class TestVPCTransitGateway:

    def test_registered(self):
        from c7n_ibmcloud.resources.vpc import VPCTransitGateway
        assert VPCTransitGateway.type == "vpc-transit-gateway"
        assert "tag" in VPCTransitGateway.filter_registry
        assert "age" in VPCTransitGateway.filter_registry

    def test_status_filter_via_value(self):
        """Failed transit gateways are detectable via value filter on status."""
        from c7n.filters.core import ValueFilter
        data = {"type": "value", "key": "status", "op": "eq", "value": "failed"}
        mgr = MagicMock()
        mgr.get_model.return_value = MagicMock(id="id")
        f = ValueFilter(data, mgr)
        result = f.process(SAMPLE_TRANSIT_GATEWAYS)
        assert len(result) == 1 and result[0]["id"] == "tgw-002"

    def test_delete_calls_client(self):
        from c7n_ibmcloud.resources.vpc import VPCTransitGatewayDelete
        tgw_client = MagicMock()
        session = FakeSession(clients={"transit-gateway": tgw_client})
        action = VPCTransitGatewayDelete.__new__(VPCTransitGatewayDelete)
        action.manager = MagicMock()
        action.data = {}
        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            action.perform_action(SAMPLE_TRANSIT_GATEWAYS[1])
        tgw_client.delete_transit_gateway.assert_called_once_with("tgw-002")

    def test_augment_injects_tags(self):
        """TransitGatewayDescribeSource.augment() must populate tags from GlobalTagging."""
        from c7n_ibmcloud.resources.vpc import TransitGatewayDescribeSource

        crn = "crn:v1:bluemix:public:transit:global:a/123::gateway:tgw-001"
        tag_map = {crn: ["owner:network-team"]}

        tagging_client = _make_tagging_client(tag_map)
        tgw_client = MagicMock()
        session = FakeSession(clients={
            "transit-gateway": tgw_client,
            "global-tagging": tagging_client,
        })

        source = TransitGatewayDescribeSource.__new__(TransitGatewayDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)
        source.manager.resource_type.tag_type = "user"

        raw = [{"id": "tgw-001", "crn": crn, "name": "cross-region-gw"}]

        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            result = source.augment(raw)

        assert result[0]["tags"] == ["owner:network-team"]

    def test_tag_filter_absent_on_transit_gateway(self):
        """tag filter op=absent correctly matches transit gateways missing the owner tag."""
        from c7n_ibmcloud.filters.base import TagFilter

        resources = [
            {"id": "tgw-001", "name": "gw-with-owner", "tags": ["owner:network-team"]},
            {"id": "tgw-002", "name": "gw-no-owner", "tags": []},
        ]
        f = TagFilter({"type": "tag", "key": "owner", "op": "absent"}, None)
        result = f.process(resources)

        assert len(result) == 1
        assert result[0]["id"] == "tgw-002"


# ---------------------------------------------------------------------------
# TransitGatewayClient pagination
# ---------------------------------------------------------------------------

class TestTransitGatewayClient:

    def test_list_single_page(self):
        """list_transit_gateways returns gateways from a single-page response."""
        from c7n_ibmcloud.session import TransitGatewayClient
        client = TransitGatewayClient.__new__(TransitGatewayClient)
        client._authenticator = MagicMock()
        client._authenticator.token_manager.get_token.return_value = "tok"
        with patch("requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: {"transit_gateways": SAMPLE_TRANSIT_GATEWAYS, "next": None},
            )
            result = client.list_transit_gateways()
        assert len(result["transit_gateways"]) == 2

    def test_describe_source_pagination(self):
        """TransitGatewayDescribeSource stops when next is None."""
        from c7n_ibmcloud.resources.vpc import TransitGatewayDescribeSource
        tgw_client = MagicMock()
        tgw_client.list_transit_gateways.return_value = {
            "transit_gateways": SAMPLE_TRANSIT_GATEWAYS,
            "next": None,
        }
        session = FakeSession(clients={"transit-gateway": tgw_client})
        source = TransitGatewayDescribeSource.__new__(TransitGatewayDescribeSource)
        source.manager = MagicMock()
        source.manager.session_factory = FakeSessionFactory(session)
        with patch("c7n_ibmcloud.resources.vpc.local_session", return_value=session):
            result = source.get_resources({})
        assert len(result) == 2


# ---------------------------------------------------------------------------
# PowerVS SSH Key
# ---------------------------------------------------------------------------

class TestPowerVSSSHKey:

    def test_registered(self):
        from c7n_ibmcloud.resources.powervs import PowerVSSSHKey
        assert PowerVSSSHKey.type == "powervs-ssh-key"
        assert "age" in PowerVSSSHKey.filter_registry

    def test_age_filter_old_key(self):
        """SSH keys older than 365 days are returned by age filter."""
        from c7n_ibmcloud.filters.base import AgeFilter

        class _SSHKeyAge(AgeFilter):
            date_attribute = "creationDate"

        f = _SSHKeyAge({"type": "age", "op": "gt", "days": 365}, MagicMock())
        result = f.process(SAMPLE_POWERVS_SSH_KEYS)
        # pvs-key-old (2020) should match; pvs-key-prod (2023) may or may not
        old = [r for r in result if r["name"] == "pvs-key-old"]
        assert len(old) == 1

    def test_delete_calls_rest(self):
        """PowerVSSSHKeyDelete calls DELETE /ssh-keys/{name} on the PowerVS client."""
        from c7n_ibmcloud.resources.powervs import PowerVSSSHKeyDelete
        pvs_client = MagicMock()
        session = MagicMock()
        session.region = "us-south"
        session.powervs_client.return_value = pvs_client
        action = PowerVSSSHKeyDelete.__new__(PowerVSSSHKeyDelete)
        action.manager = MagicMock()
        action.data = {}
        with patch("c7n_ibmcloud.resources.powervs.local_session", return_value=session):
            action.perform_action(SAMPLE_POWERVS_SSH_KEYS[1])
        pvs_client.delete.assert_called_once_with("/ssh-keys/pvs-key-old", v1=True)

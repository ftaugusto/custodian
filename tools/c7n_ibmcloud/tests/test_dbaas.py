# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""Tests for IBM Cloud Databases (ICD / DBaaS) resources."""

from unittest.mock import MagicMock, patch

from conftest import FakeSession, FakeSessionFactory, FakeResult


# ---------------------------------------------------------------------------
# Sample resource data
# ---------------------------------------------------------------------------

SAMPLE_POSTGRES_INSTANCES = [
    {
        "id": "crn:v1:bluemix:public:databases-for-postgresql:us-south:a/123:pg-1::",
        "crn": "crn:v1:bluemix:public:databases-for-postgresql:us-south:a/123:pg-1::",
        "name": "prod-postgres",
        "state": "active",
        "region_id": "us-south",
        "resource_group_id": "rg-prod",
        "resource_plan_id": "databases-for-postgresql-standard",
        "created_at": "2022-03-01T00:00:00Z",
        "c7n:version": "14.5",
        "tags": ["env:prod"],
    },
    {
        "id": "crn:v1:bluemix:public:databases-for-postgresql:eu-de:a/123:pg-2::",
        "crn": "crn:v1:bluemix:public:databases-for-postgresql:eu-de:a/123:pg-2::",
        "name": "dev-postgres",
        "state": "active",
        "region_id": "eu-de",
        "resource_group_id": "rg-dev",
        "resource_plan_id": "databases-for-postgresql-enterprise",
        "created_at": "2023-09-01T00:00:00Z",
        "c7n:version": "15.3",
        "tags": ["env:dev"],
    },
]

SAMPLE_REDIS_INSTANCES = [
    {
        "id": "crn:v1:bluemix:public:databases-for-redis:us-south:a/123:redis-1::",
        "crn": "crn:v1:bluemix:public:databases-for-redis:us-south:a/123:redis-1::",
        "name": "cache-redis",
        "state": "active",
        "region_id": "us-south",
        "resource_group_id": "rg-prod",
        "resource_plan_id": "databases-for-redis-standard",
        "created_at": "2023-01-15T00:00:00Z",
        "c7n:version": "7.0",
        "tags": [],
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rc_client(instances):
    """Build a mock ResourceControllerV2 client returning the given instances."""
    rc = MagicMock()
    rc.list_resource_instances.return_value = FakeResult(
        {"resources": instances, "next_url": None}
    )
    rc.delete_resource_instance.return_value = FakeResult({})
    return rc


def _make_icd_client():
    """Build a mock CloudDatabasesV5 client."""
    icd = MagicMock()
    icd.get_deployment_info.return_value = FakeResult(
        {"deployment": {"version": "14.5", "platform_version": "14.5.0"}}
    )
    icd.set_deployment_scaling_group.return_value = FakeResult({})
    return icd


# ---------------------------------------------------------------------------
# Tests: ICD version filter
# ---------------------------------------------------------------------------

class TestIcdVersionFilter:

    def test_version_lt_matches_older(self):
        """version lt 15 should match only instances running < v15."""
        from c7n_ibmcloud.resources.dbaas import IcdPostgreSQL
        # IcdPostgreSQL has 'version' filter registered via _register_icd_common
        filter_cls = IcdPostgreSQL.filter_registry.get("version")
        f = filter_cls({"type": "version", "op": "lt", "value": "15"}, None)
        result = f.process(SAMPLE_POSTGRES_INSTANCES)
        assert len(result) == 1
        assert result[0]["name"] == "prod-postgres"  # version 14.5

    def test_version_ge_matches_newer(self):
        """version ge 15 should match instances running >= v15."""
        from c7n_ibmcloud.resources.dbaas import IcdPostgreSQL
        filter_cls = IcdPostgreSQL.filter_registry.get("version")
        f = filter_cls({"type": "version", "op": "ge", "value": "15"}, None)
        result = f.process(SAMPLE_POSTGRES_INSTANCES)
        assert len(result) == 1
        assert result[0]["name"] == "dev-postgres"   # version 15.3

    def test_version_eq(self):
        """version eq 15.3 matches exact version."""
        from c7n_ibmcloud.resources.dbaas import IcdPostgreSQL
        filter_cls = IcdPostgreSQL.filter_registry.get("version")
        f = filter_cls({"type": "version", "op": "eq", "value": "15.3"}, None)
        result = f.process(SAMPLE_POSTGRES_INSTANCES)
        assert len(result) == 1
        assert result[0]["name"] == "dev-postgres"

    def test_version_no_match(self):
        """version lt 14 returns empty when all instances are >= 14."""
        from c7n_ibmcloud.resources.dbaas import IcdPostgreSQL
        filter_cls = IcdPostgreSQL.filter_registry.get("version")
        f = filter_cls({"type": "version", "op": "lt", "value": "14"}, None)
        result = f.process(SAMPLE_POSTGRES_INSTANCES)
        assert result == []


# ---------------------------------------------------------------------------
# Tests: ICD plan filter
# ---------------------------------------------------------------------------

class TestIcdPlanFilter:

    def test_plan_standard(self):
        """plan filter 'standard' should return only standard-plan instances."""
        from c7n_ibmcloud.resources.dbaas import IcdPostgreSQL
        filter_cls = IcdPostgreSQL.filter_registry.get("plan")
        f = filter_cls({"type": "plan", "value": "standard"}, None)
        result = f.process(SAMPLE_POSTGRES_INSTANCES)
        assert len(result) == 1
        assert result[0]["name"] == "prod-postgres"

    def test_plan_enterprise(self):
        """plan filter 'enterprise' returns enterprise plan instances."""
        from c7n_ibmcloud.resources.dbaas import IcdPostgreSQL
        filter_cls = IcdPostgreSQL.filter_registry.get("plan")
        f = filter_cls({"type": "plan", "value": "enterprise"}, None)
        result = f.process(SAMPLE_POSTGRES_INSTANCES)
        assert len(result) == 1
        assert result[0]["name"] == "dev-postgres"


# ---------------------------------------------------------------------------
# Tests: ICD tag filter
# ---------------------------------------------------------------------------

class TestIcdTagFilter:

    def test_tag_filter_present(self):
        """tag filter 'env' present should match tagged instances."""
        from c7n_ibmcloud.resources.dbaas import IcdPostgreSQL
        filter_cls = IcdPostgreSQL.filter_registry.get("tag")
        f = filter_cls({"type": "tag", "key": "env", "op": "present"}, None)
        result = f.process(SAMPLE_POSTGRES_INSTANCES)
        assert len(result) == 2  # both have env tag

    def test_tag_filter_absent(self):
        """tag filter env absent returns instances without env tag."""
        from c7n_ibmcloud.resources.dbaas import IcdRedis
        filter_cls = IcdRedis.filter_registry.get("tag")
        f = filter_cls({"type": "tag", "key": "env", "op": "absent"}, None)
        result = f.process(SAMPLE_REDIS_INSTANCES)
        assert len(result) == 1  # redis has no tags


# ---------------------------------------------------------------------------
# Tests: ICD delete action
# ---------------------------------------------------------------------------

class TestIcdDeleteAction:

    def test_delete_postgres_instance(self):
        """delete action should call delete_resource_instance with instance id."""
        rc = _make_rc_client(SAMPLE_POSTGRES_INSTANCES)
        session = FakeSession(clients={"resource-ctrl": rc})

        from c7n_ibmcloud.resources.dbaas import IcdPostgreSQL

        action_cls = IcdPostgreSQL.action_registry.get("delete")
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = action_cls({}, manager)

        with patch("c7n_ibmcloud.resources.dbaas.local_session", return_value=session):
            action.perform_action(SAMPLE_POSTGRES_INSTANCES[0])

        rc.delete_resource_instance.assert_called_once_with(
            id=SAMPLE_POSTGRES_INSTANCES[0]["id"],
            recursive=False,
        )

    def test_delete_with_recursive(self):
        """delete action with recursive=true passes recursive=True to SDK."""
        rc = _make_rc_client(SAMPLE_POSTGRES_INSTANCES)
        session = FakeSession(clients={"resource-ctrl": rc})

        from c7n_ibmcloud.resources.dbaas import IcdPostgreSQL

        action_cls = IcdPostgreSQL.action_registry.get("delete")
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = action_cls({"type": "delete", "recursive": True}, manager)

        with patch("c7n_ibmcloud.resources.dbaas.local_session", return_value=session):
            action.perform_action(SAMPLE_POSTGRES_INSTANCES[1])

        rc.delete_resource_instance.assert_called_once_with(
            id=SAMPLE_POSTGRES_INSTANCES[1]["id"],
            recursive=True,
        )


# ---------------------------------------------------------------------------
# Tests: ICD scale action
# ---------------------------------------------------------------------------

class TestIcdScaleAction:

    def test_scale_memory(self):
        """scale action with memory_allocation should call set_deployment_scaling_group."""
        icd = _make_icd_client()
        session = FakeSession(clients={"databases": icd, "resource-ctrl": MagicMock()})

        from c7n_ibmcloud.resources.dbaas import IcdPostgreSQL

        action_cls = IcdPostgreSQL.action_registry.get("scale")
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = action_cls({"type": "scale", "memory_allocation": 8192}, manager)

        with patch("c7n_ibmcloud.resources.dbaas.local_session", return_value=session):
            action.perform_action(SAMPLE_POSTGRES_INSTANCES[0])

        icd.set_deployment_scaling_group.assert_called_once()
        call_kwargs = icd.set_deployment_scaling_group.call_args.kwargs
        assert call_kwargs["id"] == SAMPLE_POSTGRES_INSTANCES[0]["crn"]
        assert call_kwargs["group_id"] == "member"
        assert call_kwargs["set_deployment_scaling_group_request"]["memory"]["allocation_mb"] == 8192

    def test_scale_no_op_when_no_params(self):
        """scale action with no allocation params should not call the SDK."""
        icd = _make_icd_client()
        session = FakeSession(clients={"databases": icd, "resource-ctrl": MagicMock()})

        from c7n_ibmcloud.resources.dbaas import IcdPostgreSQL

        action_cls = IcdPostgreSQL.action_registry.get("scale")
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = action_cls({"type": "scale"}, manager)

        with patch("c7n_ibmcloud.resources.dbaas.local_session", return_value=session):
            action.perform_action(SAMPLE_POSTGRES_INSTANCES[0])

        icd.set_deployment_scaling_group.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: Multiple ICD resource types register independently
# ---------------------------------------------------------------------------

class TestIcdResourceTypes:

    def test_all_icd_types_registered(self):
        """All 6 ICD resource types should be registered in the ibm provider."""
        from c7n_ibmcloud.provider import resources

        expected_types = [
            "dbaas-postgresql",
            "dbaas-mysql",
            "dbaas-mongodb",
            "dbaas-redis",
            "dbaas-elasticsearch",
            "dbaas-rabbitmq",
        ]
        for rtype in expected_types:
            assert resources.get(rtype) is not None, (
                "ibm.%s not registered" % rtype
            )

    def test_each_type_has_version_filter(self):
        """All ICD types should have the version filter registered."""
        from c7n_ibmcloud.resources.dbaas import (
            IcdMySQL, IcdMongoDB, IcdRedis, IcdElasticsearch,
        )
        for cls in (IcdMySQL, IcdMongoDB, IcdRedis, IcdElasticsearch):
            assert cls.filter_registry.get("version") is not None

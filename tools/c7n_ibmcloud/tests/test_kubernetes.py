# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""Tests for IBM Kubernetes Service (IKS) and ROKS resources."""

from unittest.mock import MagicMock, patch

from conftest import FakeSession, FakeSessionFactory


# ---------------------------------------------------------------------------
# Sample resource data
# ---------------------------------------------------------------------------

# CommonClusterKMS shape from Container API swagger:
#   desiredInstance: string CRN (non-empty = KMS configured)
#   actualInstance:  list of CRNs (non-empty = KMS active/applied)
_KMS_ENABLED = {
    "desiredInstance": "crn:v1:bluemix:public:kms:us-south:a/123:kp-instance-001::",
    "actualInstance": ["crn:v1:bluemix:public:kms:us-south:a/123:kp-instance-001::"],
}
_KMS_DISABLED = {}   # absent / empty = not configured

# Container API returns flat strings, NOT a nested resource_group dict.
# resourceGroup = the resource group ID
# resourceGroupName = the human-readable name
SAMPLE_IKS_CLUSTERS = [
    {
        "id": "cluster-aaaa-1111",
        "name": "prod-k8s",
        "state": "normal",
        "type": "kubernetes",
        "masterKubeVersion": "1.29.3",
        "location": "dal10",
        "createdDate": "2023-04-01T00:00:00Z",
        "resourceGroup": "rg-prod",
        "resourceGroupName": "production",
        "keyManagementService": _KMS_ENABLED,
        "tags": ["env:prod", "team:platform"],
    },
    {
        "id": "cluster-bbbb-2222",
        "name": "dev-k8s-old",
        "state": "normal",
        "type": "kubernetes",
        "masterKubeVersion": "1.26.8",
        "location": "lon02",
        "createdDate": "2022-01-15T00:00:00Z",
        "resourceGroup": "rg-dev",
        "resourceGroupName": "development",
        "keyManagementService": _KMS_DISABLED,
        "tags": ["env:dev"],
    },
]

SAMPLE_ROKS_CLUSTERS = [
    {
        "id": "cluster-cccc-3333",
        "name": "prod-ocp",
        "state": "normal",
        "type": "openshift",
        "masterKubeVersion": "4.14.12_openshift",
        "location": "eu-de-1",
        "createdDate": "2023-06-01T00:00:00Z",
        "resourceGroup": "rg-prod",
        "resourceGroupName": "production",
        "keyManagementService": _KMS_ENABLED,
        "tags": ["env:prod"],
    },
    {
        "id": "cluster-dddd-4444",
        "name": "dev-ocp-old",
        "state": "normal",
        "type": "openshift",
        "masterKubeVersion": "4.11.55_openshift",
        "location": "jp-tok-2",
        "createdDate": "2021-09-10T00:00:00Z",
        "resourceGroup": "rg-dev",
        "resourceGroupName": "development",
        "keyManagementService": _KMS_DISABLED,
        "tags": [],
    },
]

SAMPLE_WORKER_POOLS = [
    {
        "id": "pool-aaaa-1",
        "poolName": "default",
        "workerCount": 3,
        "c7n:cluster_id": "cluster-aaaa-1111",
        "c7n:cluster_name": "prod-k8s",
    },
    {
        "id": "pool-bbbb-2",
        "poolName": "spot-pool",
        "workerCount": 1,
        "c7n:cluster_id": "cluster-bbbb-2222",
        "c7n:cluster_name": "dev-k8s-old",
    },
]


# ---------------------------------------------------------------------------
# Tests: IKS version filter
# ---------------------------------------------------------------------------

class TestIKSVersionFilter:

    def test_version_lt_matches_old(self):
        """version lt 1.28 should match clusters running 1.26."""
        from c7n_ibmcloud.resources.kubernetes import IKSClusterVersionFilter

        f = IKSClusterVersionFilter({"type": "version", "op": "lt", "value": "1.28"}, None)
        result = f.process(SAMPLE_IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-bbbb-2222"

    def test_version_ge_matches_current(self):
        """version ge 1.28 should match clusters running 1.29."""
        from c7n_ibmcloud.resources.kubernetes import IKSClusterVersionFilter

        f = IKSClusterVersionFilter({"type": "version", "op": "ge", "value": "1.28"}, None)
        result = f.process(SAMPLE_IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-aaaa-1111"

    def test_version_eq(self):
        """version eq 1.29.3 matches exact version."""
        from c7n_ibmcloud.resources.kubernetes import IKSClusterVersionFilter

        f = IKSClusterVersionFilter({"type": "version", "op": "eq", "value": "1.29.3"}, None)
        result = f.process(SAMPLE_IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["name"] == "prod-k8s"


# ---------------------------------------------------------------------------
# Tests: ROKS version filter (strips _openshift suffix)
# ---------------------------------------------------------------------------

class TestROKSVersionFilter:

    def test_roks_version_lt_strips_suffix(self):
        """ROKS version filter should strip _openshift suffix before comparison."""
        from c7n_ibmcloud.resources.kubernetes import ROKSClusterVersionFilter

        f = ROKSClusterVersionFilter({"type": "version", "op": "lt", "value": "4.13"}, None)
        result = f.process(SAMPLE_ROKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-dddd-4444"

    def test_roks_version_ge(self):
        """ROKS version ge 4.13 matches clusters on 4.14."""
        from c7n_ibmcloud.resources.kubernetes import ROKSClusterVersionFilter

        f = ROKSClusterVersionFilter({"type": "version", "op": "ge", "value": "4.13"}, None)
        result = f.process(SAMPLE_ROKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-cccc-3333"


# ---------------------------------------------------------------------------
# Tests: IKS tag filter
# ---------------------------------------------------------------------------

class TestIKSTagFilter:

    def test_tag_filter_present(self):
        """tag filter 'team' present should return clusters that have it."""
        from c7n_ibmcloud.filters.base import TagFilter

        f = TagFilter({"type": "tag", "key": "team", "op": "present"}, None)
        result = f.process(SAMPLE_IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-aaaa-1111"

    def test_tag_filter_absent(self):
        """tag filter 'team' absent returns clusters missing the tag."""
        from c7n_ibmcloud.filters.base import TagFilter

        f = TagFilter({"type": "tag", "key": "team", "op": "absent"}, None)
        result = f.process(SAMPLE_IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-bbbb-2222"


# ---------------------------------------------------------------------------
# Tests: IKS and ROKS resource-group filter (flat-string Container API shape)
# ---------------------------------------------------------------------------

class TestIKSResourceGroupFilter:

    def test_resource_group_eq_by_name(self):
        """resource-group filter eq by name matches clusters using flat resourceGroupName."""
        from c7n_ibmcloud.filters.base import ResourceGroupFilter

        f = ResourceGroupFilter({"type": "resource-group", "value": "production"}, None)
        result = f.process(SAMPLE_IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-aaaa-1111"

    def test_resource_group_eq_by_id(self):
        """resource-group filter eq by ID matches clusters using flat resourceGroup field."""
        from c7n_ibmcloud.filters.base import ResourceGroupFilter

        f = ResourceGroupFilter({"type": "resource-group", "value": "rg-prod"}, None)
        result = f.process(SAMPLE_IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-aaaa-1111"

    def test_resource_group_ne(self):
        """resource-group filter ne excludes matched clusters."""
        from c7n_ibmcloud.filters.base import ResourceGroupFilter

        f = ResourceGroupFilter({"type": "resource-group", "op": "ne", "value": "production"}, None)
        result = f.process(SAMPLE_IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-bbbb-2222"

    def test_roks_resource_group_filter_registered(self):
        """resource-group filter must be registered on ibm.roks-cluster."""
        from c7n_ibmcloud.resources.kubernetes import ROKSCluster
        assert ROKSCluster.filter_registry.get("resource-group") is not None

    def test_roks_resource_group_eq(self):
        """resource-group filter eq 'production' should return ROKS production clusters only."""
        from c7n_ibmcloud.filters.base import ResourceGroupFilter

        f = ResourceGroupFilter({"type": "resource-group", "value": "production"}, None)
        result = f.process(SAMPLE_ROKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-cccc-3333"

    def test_nested_dict_shape_still_works(self):
        """resource-group filter must still work for VPC-style nested dict resources."""
        from c7n_ibmcloud.filters.base import ResourceGroupFilter

        resources = [
            {"id": "vpc-1", "resource_group": {"id": "rg-abc", "name": "production"}},
            {"id": "vpc-2", "resource_group": {"id": "rg-xyz", "name": "development"}},
        ]
        f = ResourceGroupFilter({"type": "resource-group", "value": "production"}, None)
        result = f.process(resources)
        assert len(result) == 1
        assert result[0]["id"] == "vpc-1"

    def test_flat_shape_matches_id(self):
        """Flat resourceGroup (ID) field must be matched by the filter."""
        from c7n_ibmcloud.filters.base import ResourceGroupFilter

        resources = [
            {"id": "c1", "resourceGroup": "rg-abc123", "resourceGroupName": "production"},
            {"id": "c2", "resourceGroup": "rg-def456", "resourceGroupName": "development"},
        ]
        f = ResourceGroupFilter({"type": "resource-group", "value": "rg-abc123"}, None)
        result = f.process(resources)
        assert len(result) == 1
        assert result[0]["id"] == "c1"

    def test_flat_shape_ne_excludes_matching_cluster(self):
        """Flat-shape ne operator must exclude the cluster in the matched group."""
        from c7n_ibmcloud.filters.base import ResourceGroupFilter

        resources = [
            {"id": "c1", "resourceGroup": "rg-abc123", "resourceGroupName": "production"},
            {"id": "c2", "resourceGroup": "rg-def456", "resourceGroupName": "development"},
        ]
        f = ResourceGroupFilter({"type": "resource-group", "op": "ne", "value": "production"}, None)
        result = f.process(resources)
        assert len(result) == 1
        assert result[0]["id"] == "c2"


# ---------------------------------------------------------------------------
# Tests: IKS delete action
# ---------------------------------------------------------------------------

class TestIKSDeleteAction:

    def test_delete_cluster(self):
        """delete action should call ContainerAPIClient.delete_cluster."""
        fake_auth = MagicMock()
        fake_auth.token_manager.get_token.return_value = "fake-token"

        session = FakeSession()
        session._authenticator = fake_auth

        from c7n_ibmcloud.resources.kubernetes import IKSClusterDelete

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = IKSClusterDelete({"type": "delete", "delete_resources": True}, manager)

        with patch("c7n_ibmcloud.resources.kubernetes.local_session", return_value=session), \
             patch("c7n_ibmcloud.resources.kubernetes.ContainerAPIClient") as mock_api:
            mock_client = MagicMock()
            mock_api.return_value = mock_client
            action.perform_action(SAMPLE_IKS_CLUSTERS[0])

        mock_client.delete_cluster.assert_called_once_with(
            "cluster-aaaa-1111",
            delete_resources=True,
        )

    def test_delete_cluster_default_no_resources(self):
        """delete action without delete_resources defaults to False."""
        fake_auth = MagicMock()
        fake_auth.token_manager.get_token.return_value = "fake-token"

        session = FakeSession()
        session._authenticator = fake_auth

        from c7n_ibmcloud.resources.kubernetes import IKSClusterDelete

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        action = IKSClusterDelete({}, manager)

        with patch("c7n_ibmcloud.resources.kubernetes.local_session", return_value=session), \
             patch("c7n_ibmcloud.resources.kubernetes.ContainerAPIClient") as mock_api:
            mock_client = MagicMock()
            mock_api.return_value = mock_client
            action.perform_action(SAMPLE_IKS_CLUSTERS[1])

        mock_client.delete_cluster.assert_called_once_with(
            "cluster-bbbb-2222",
            delete_resources=False,
        )


# ---------------------------------------------------------------------------
# Tests: Worker pool filter
# ---------------------------------------------------------------------------

class TestIKSWorkerPool:

    def test_worker_count_filter(self):
        """value filter on workerCount lt 2 should return small pools."""
        from c7n.filters import ValueFilter

        f = ValueFilter({"type": "value", "key": "workerCount", "op": "lt", "value": 2}, None)
        result = f.process(SAMPLE_WORKER_POOLS)
        assert len(result) == 1
        assert result[0]["id"] == "pool-bbbb-2"

    def test_worker_pool_tag_filter(self):
        """Worker pools support tag filter via IKSWorkerPoolTagFilter."""
        from c7n_ibmcloud.resources.kubernetes import IKSWorkerPool

        filter_cls = IKSWorkerPool.filter_registry.get("tag")
        assert filter_cls is not None

    def test_worker_pool_resources_are_registered(self):
        """iks-worker-pool resource type is registered in provider."""
        from c7n_ibmcloud.provider import resources
        assert resources.get("iks-worker-pool") is not None


# ---------------------------------------------------------------------------
# Tests: IKSWorkerPoolTagAction — tags the parent cluster, not the pool
# ---------------------------------------------------------------------------

# Pools with c7n:cluster_crn pre-populated (as WorkerPoolDescribeSource does)
SAMPLE_POOLS_WITH_CRN = [
    {
        "id": "pool-aaaa-1",
        "poolName": "default",
        "workerCount": 0,
        "c7n:cluster_id": "cluster-aaaa-1111",
        "c7n:cluster_name": "prod-k8s",
        "c7n:cluster_crn": "crn:v1:bluemix:public:containers-kubernetes:us-south:a/acct:cluster-aaaa-1111::",
    },
    {
        "id": "pool-bbbb-2",
        "poolName": "spot-pool",
        "workerCount": 1,
        "c7n:cluster_id": "cluster-bbbb-2222",
        "c7n:cluster_name": "dev-k8s-old",
        "c7n:cluster_crn": "crn:v1:bluemix:public:containers-kubernetes:lon02:a/acct:cluster-bbbb-2222::",
    },
]


class TestIKSWorkerPoolTagAction:
    """tag action on worker pools must target the parent cluster's CRN."""

    def _make_session(self):
        fake_auth = MagicMock()
        fake_auth.token_manager.get_token.return_value = "fake-token"
        session = FakeSession()
        session._authenticator = fake_auth
        return session

    def test_tag_action_uses_cluster_crn(self):
        """tag action must call attach_tag with the parent cluster CRN."""
        from c7n_ibmcloud.resources.kubernetes import IKSWorkerPoolTagAction

        session = self._make_session()
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"
        action = IKSWorkerPoolTagAction({"type": "tag", "tags": {"custodian-review": "empty-worker-pool"}}, manager)

        pool = dict(SAMPLE_POOLS_WITH_CRN[0])  # workerCount=0, has c7n:cluster_crn

        with patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
            fake_tagging = MagicMock()
            session._clients["global-tagging"] = fake_tagging
            action.perform_action(pool)

        fake_tagging.attach_tag.assert_called_once()
        call_kwargs = fake_tagging.attach_tag.call_args[1]
        tagged_crn = call_kwargs["resources"][0].resource_id
        assert tagged_crn == "crn:v1:bluemix:public:containers-kubernetes:us-south:a/acct:cluster-aaaa-1111::"

    def test_tag_action_fetches_crn_when_not_pre_populated(self):
        """tag action must fetch CRN via get_cluster when c7n:cluster_crn is absent."""
        from c7n_ibmcloud.resources.kubernetes import IKSWorkerPoolTagAction

        session = self._make_session()
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"
        action = IKSWorkerPoolTagAction({"type": "tag", "tags": {"custodian-review": "empty-worker-pool"}}, manager)

        # Pool without c7n:cluster_crn (e.g. built manually in tests)
        pool = {
            "id": "pool-manual",
            "poolName": "default",
            "workerCount": 0,
            "c7n:cluster_id": "cluster-aaaa-1111",
            "c7n:cluster_name": "prod-k8s",
        }
        fake_crn = "crn:v1:bluemix:public:containers-kubernetes:us-south:a/acct:cluster-aaaa-1111::"

        with patch("c7n_ibmcloud.resources.kubernetes.local_session", return_value=session), \
             patch("c7n_ibmcloud.resources.kubernetes.ContainerAPIClient") as mock_api, \
             patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
            mock_client = MagicMock()
            mock_api.return_value = mock_client
            mock_client.get_cluster.return_value = {"id": "cluster-aaaa-1111", "crn": fake_crn}

            fake_tagging = MagicMock()
            session._clients["global-tagging"] = fake_tagging

            action.perform_action(pool)

        mock_client.get_cluster.assert_called_once_with("cluster-aaaa-1111")
        assert pool["c7n:cluster_crn"] == fake_crn
        fake_tagging.attach_tag.assert_called_once()

    def test_tag_action_skips_when_no_cluster_id(self):
        """tag action must skip gracefully when neither CRN nor cluster_id is available."""
        from c7n_ibmcloud.resources.kubernetes import IKSWorkerPoolTagAction

        session = self._make_session()
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"
        action = IKSWorkerPoolTagAction({"type": "tag", "tags": {"custodian-review": "empty-worker-pool"}}, manager)

        pool = {"id": "pool-orphan", "poolName": "orphan", "workerCount": 0}

        with patch("c7n_ibmcloud.resources.kubernetes.local_session", return_value=session), \
             patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
            fake_tagging = MagicMock()
            session._clients["global-tagging"] = fake_tagging
            action.perform_action(pool)

        fake_tagging.attach_tag.assert_not_called()

    def test_describe_source_injects_cluster_crn(self):
        """WorkerPoolDescribeSource must inject c7n:cluster_crn into every pool."""
        from c7n_ibmcloud.resources.kubernetes import WorkerPoolDescribeSource

        fake_auth = MagicMock()
        fake_auth.token_manager.get_token.return_value = "fake-token"
        session = FakeSession()
        session._authenticator = fake_auth

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        source = WorkerPoolDescribeSource(manager)

        fake_crn = "crn:v1:bluemix:public:containers-kubernetes:us-south:a/acct:cluster-aaaa-1111::"
        fake_pools = [
            {"id": "pool-1", "poolName": "default", "workerCount": 0},
            {"id": "pool-2", "poolName": "spot",    "workerCount": 2},
        ]

        with patch("c7n_ibmcloud.resources.kubernetes.local_session", return_value=session), \
             patch("c7n_ibmcloud.resources.kubernetes.ContainerAPIClient") as mock_api:
            mock_client = MagicMock()
            mock_api.return_value = mock_client
            mock_client.list_clusters.return_value = [SAMPLE_IKS_CLUSTERS[0]]
            mock_client.list_worker_pools.return_value = fake_pools
            mock_client.get_cluster.return_value = {"id": "cluster-aaaa-1111", "crn": fake_crn}

            result = source.get_resources(None)

        assert len(result) == 2
        for pool in result:
            assert pool["c7n:cluster_crn"] == fake_crn
            assert pool["c7n:cluster_id"] == "cluster-aaaa-1111"
            assert pool["c7n:cluster_name"] == "prod-k8s"

    def test_describe_source_fetches_crn_once_per_cluster(self):
        """WorkerPoolDescribeSource must call get_cluster once per cluster, not per pool."""
        from c7n_ibmcloud.resources.kubernetes import WorkerPoolDescribeSource

        fake_auth = MagicMock()
        fake_auth.token_manager.get_token.return_value = "fake-token"
        session = FakeSession()
        session._authenticator = fake_auth

        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        source = WorkerPoolDescribeSource(manager)

        crn_a = "crn:v1:bluemix:public:containers-kubernetes:us-south:a/acct:cluster-aaaa::"
        crn_b = "crn:v1:bluemix:public:containers-kubernetes:lon02:a/acct:cluster-bbbb::"

        # 3 pools across 2 clusters
        pools_a = [{"id": "pa1", "poolName": "default", "workerCount": 3},
                   {"id": "pa2", "poolName": "gpu",     "workerCount": 1}]
        pools_b = [{"id": "pb1", "poolName": "default", "workerCount": 0}]

        def _list_pools(cluster_id):
            return pools_a if cluster_id == "cluster-aaaa-1111" else pools_b

        def _get_cluster(cluster_id):
            crn = crn_a if cluster_id == "cluster-aaaa-1111" else crn_b
            return {"id": cluster_id, "crn": crn}

        with patch("c7n_ibmcloud.resources.kubernetes.local_session", return_value=session), \
             patch("c7n_ibmcloud.resources.kubernetes.ContainerAPIClient") as mock_api:
            mock_client = MagicMock()
            mock_api.return_value = mock_client
            mock_client.list_clusters.return_value = list(SAMPLE_IKS_CLUSTERS)
            mock_client.list_worker_pools.side_effect = _list_pools
            mock_client.get_cluster.side_effect = _get_cluster

            result = source.get_resources(None)

        # get_cluster must be called exactly once per cluster (2 clusters)
        assert mock_client.get_cluster.call_count == 2
        # Pools from cluster-a get crn_a; pool from cluster-b gets crn_b
        a_pools = [p for p in result if p["c7n:cluster_id"] == "cluster-aaaa-1111"]
        b_pools = [p for p in result if p["c7n:cluster_id"] == "cluster-bbbb-2222"]
        assert all(p["c7n:cluster_crn"] == crn_a for p in a_pools)
        assert all(p["c7n:cluster_crn"] == crn_b for p in b_pools)


# ---------------------------------------------------------------------------
# Tests: kms-enabled filter
# ---------------------------------------------------------------------------

class TestKMSEnabledFilter:
    """Tests for the kms-enabled filter on IKS and ROKS clusters.

    The filter checks the ``keyManagementService`` field (CommonClusterKMS):
      - ``desiredInstance``: string CRN; non-empty means KMS is configured.
      - ``actualInstance``:  list of CRNs; non-empty means KMS is active.
    A cluster with both empty/absent is NOT KMS-enabled.
    """

    def test_iks_no_kms_matches_default(self):
        """kms-enabled filter (enabled: false) must match clusters without KMS."""
        from c7n_ibmcloud.resources.kubernetes import IKSClusterKMSFilter

        f = IKSClusterKMSFilter({"type": "kms-enabled", "enabled": False}, None)
        result = f.process(SAMPLE_IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-bbbb-2222"

    def test_iks_has_kms_matches_enabled_true(self):
        """kms-enabled filter (enabled: true) must match clusters WITH KMS."""
        from c7n_ibmcloud.resources.kubernetes import IKSClusterKMSFilter

        f = IKSClusterKMSFilter({"type": "kms-enabled", "enabled": True}, None)
        result = f.process(SAMPLE_IKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-aaaa-1111"

    def test_roks_no_kms_matches(self):
        """kms-enabled filter works identically for ROKS clusters."""
        from c7n_ibmcloud.resources.kubernetes import ROKSClusterKMSFilter

        f = ROKSClusterKMSFilter({"type": "kms-enabled", "enabled": False}, None)
        result = f.process(SAMPLE_ROKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-dddd-4444"

    def test_roks_has_kms_matches_enabled_true(self):
        """kms-enabled filter (enabled: true) matches ROKS clusters WITH KMS."""
        from c7n_ibmcloud.resources.kubernetes import ROKSClusterKMSFilter

        f = ROKSClusterKMSFilter({"type": "kms-enabled", "enabled": True}, None)
        result = f.process(SAMPLE_ROKS_CLUSTERS)
        assert len(result) == 1
        assert result[0]["id"] == "cluster-cccc-3333"

    def test_kms_absent_key_treated_as_disabled(self):
        """A cluster with no keyManagementService key at all must be treated as disabled."""
        from c7n_ibmcloud.resources.kubernetes import IKSClusterKMSFilter

        cluster = {"id": "no-kms-key", "name": "legacy"}  # no keyManagementService field
        f = IKSClusterKMSFilter({"type": "kms-enabled", "enabled": False}, None)
        assert f.process([cluster]) == [cluster]

    def test_kms_desired_only_counts_as_enabled(self):
        """A cluster with only desiredInstance set (actualInstance still empty) is KMS-enabled."""
        from c7n_ibmcloud.resources.kubernetes import IKSClusterKMSFilter

        cluster = {
            "id": "pending-kms",
            "keyManagementService": {
                "desiredInstance": "crn:v1:bluemix:public:kms:us-south:a/123:kp-1::",
                "actualInstance": [],
            },
        }
        f = IKSClusterKMSFilter({"type": "kms-enabled", "enabled": True}, None)
        assert f.process([cluster]) == [cluster]

    def test_kms_filter_registered_on_iks(self):
        """kms-enabled filter must be registered on ibm.iks-cluster."""
        from c7n_ibmcloud.resources.kubernetes import IKSCluster
        assert IKSCluster.filter_registry.get("kms-enabled") is not None

    def test_kms_filter_registered_on_roks(self):
        """kms-enabled filter must be registered on ibm.roks-cluster."""
        from c7n_ibmcloud.resources.kubernetes import ROKSCluster
        assert ROKSCluster.filter_registry.get("kms-enabled") is not None


# ---------------------------------------------------------------------------
# Tests: IKS/ROKS tag action CRN fetch
# ---------------------------------------------------------------------------

class TestIKSClusterTagActionCRN:
    """Tag action must fetch the CRN from GET /v2/getCluster when not in the resource."""

    def _make_session(self):
        fake_auth = MagicMock()
        fake_auth.token_manager.get_token.return_value = "fake-token"
        session = FakeSession()
        session._authenticator = fake_auth
        return session

    def test_tag_action_fetches_crn_when_missing(self):
        """tag action must call get_cluster and attach the CRN before tagging."""
        from c7n_ibmcloud.resources.kubernetes import IKSClusterTagAction

        session = self._make_session()
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"
        action = IKSClusterTagAction({"type": "tag", "tags": {"env": "test"}}, manager)

        cluster = dict(SAMPLE_IKS_CLUSTERS[1])  # no crn field
        assert "crn" not in cluster

        fake_crn = "crn:v1:bluemix:public:containers-kubernetes:us-south:a/acct:cluster-bbbb-2222::"

        with patch("c7n_ibmcloud.resources.kubernetes.local_session", return_value=session), \
             patch("c7n_ibmcloud.resources.kubernetes.ContainerAPIClient") as mock_api, \
             patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
            mock_client = MagicMock()
            mock_api.return_value = mock_client
            mock_client.get_cluster.return_value = {"id": cluster["id"], "crn": fake_crn}

            # global-tagging client stub
            fake_tagging = MagicMock()
            session._clients["global-tagging"] = fake_tagging

            action.perform_action(cluster)

        mock_client.get_cluster.assert_called_once_with("cluster-bbbb-2222")
        assert cluster["crn"] == fake_crn
        fake_tagging.attach_tag.assert_called_once()

    def test_tag_action_skips_fetch_when_crn_present(self):
        """tag action must NOT call get_cluster when crn is already on the resource."""
        from c7n_ibmcloud.resources.kubernetes import IKSClusterTagAction

        session = self._make_session()
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"
        action = IKSClusterTagAction({"type": "tag", "tags": {"env": "prod"}}, manager)

        existing_crn = "crn:v1:bluemix:public:containers-kubernetes:us-south:a/acct:cluster-aaaa::"
        cluster = dict(SAMPLE_IKS_CLUSTERS[0])
        cluster["crn"] = existing_crn

        with patch("c7n_ibmcloud.resources.kubernetes.local_session", return_value=session), \
             patch("c7n_ibmcloud.resources.kubernetes.ContainerAPIClient") as mock_api, \
             patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
            mock_client = MagicMock()
            mock_api.return_value = mock_client

            fake_tagging = MagicMock()
            session._clients["global-tagging"] = fake_tagging

            action.perform_action(cluster)

        mock_client.get_cluster.assert_not_called()
        fake_tagging.attach_tag.assert_called_once()

    def test_tag_action_skips_gracefully_when_crn_fetch_fails(self):
        """tag action must warn and skip (not raise) when get_cluster returns an error."""
        from c7n_ibmcloud.resources.kubernetes import IKSClusterTagAction

        session = self._make_session()
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"
        action = IKSClusterTagAction({"type": "tag", "tags": {"env": "test"}}, manager)

        cluster = {"id": "cluster-zzz", "name": "broken-cluster"}

        with patch("c7n_ibmcloud.resources.kubernetes.local_session", return_value=session), \
             patch("c7n_ibmcloud.resources.kubernetes.ContainerAPIClient") as mock_api, \
             patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
            mock_client = MagicMock()
            mock_api.return_value = mock_client
            mock_client.get_cluster.side_effect = Exception("500 Internal Server Error")

            fake_tagging = MagicMock()
            session._clients["global-tagging"] = fake_tagging

            # Should not raise — skips the resource gracefully
            action.perform_action(cluster)

        mock_client.get_cluster.assert_called_once()
        # CRN was never found — tagging is skipped
        fake_tagging.attach_tag.assert_not_called()

    def test_roks_tag_action_fetches_crn(self):
        """ROKSClusterTagAction must also fetch CRN via get_cluster."""
        from c7n_ibmcloud.resources.kubernetes import ROKSClusterTagAction

        session = self._make_session()
        manager = MagicMock()
        manager.session_factory = FakeSessionFactory(session)
        manager.resource_type.tag_type = "user"
        action = ROKSClusterTagAction({"type": "tag", "tags": {"env": "test"}}, manager)

        cluster = dict(SAMPLE_ROKS_CLUSTERS[1])  # no crn field
        fake_crn = "crn:v1:bluemix:public:containers-kubernetes:eu-de:a/acct:cluster-dddd-4444::"

        with patch("c7n_ibmcloud.resources.kubernetes.local_session", return_value=session), \
             patch("c7n_ibmcloud.resources.kubernetes.ContainerAPIClient") as mock_api, \
             patch("c7n_ibmcloud.actions.base.local_session", return_value=session):
            mock_client = MagicMock()
            mock_api.return_value = mock_client
            mock_client.get_cluster.return_value = {"id": cluster["id"], "crn": fake_crn}

            fake_tagging = MagicMock()
            session._clients["global-tagging"] = fake_tagging

            action.perform_action(cluster)

        mock_client.get_cluster.assert_called_once_with("cluster-dddd-4444")
        assert cluster["crn"] == fake_crn
        fake_tagging.attach_tag.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: list_worker_pools v2 endpoint
# ---------------------------------------------------------------------------

class TestListWorkerPoolsV2:
    """list_worker_pools must use the combined v2 endpoint and fall back to v1.

    Per the IBM Container API spec (containers-v1-v2):
    - GET /v2/getWorkerPools?cluster=<id>  — combined endpoint, returns
      GetCombinedWorkerPoolResponse items with ``poolName`` and ``workerCount``
    - GET /v1/clusters/{id}/workerpools    — fallback; uses ``name`` (not
      ``poolName``); normalised on return
    """

    def _make_client(self):
        fake_auth = MagicMock()
        fake_auth.token_manager.get_token.return_value = "fake-token"
        from c7n_ibmcloud.resources.kubernetes import ContainerAPIClient
        return ContainerAPIClient(fake_auth)

    def test_v2_combined_endpoint_used_and_returns_list(self):
        """list_worker_pools must call GET /v2/getWorkerPools (combined, not vpc-specific)."""
        import requests as req_mod

        client = self._make_client()
        pools = [{"id": "pool-1", "poolName": "default", "workerCount": 3}]

        with patch.object(req_mod, "get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = pools
            mock_get.return_value = mock_resp

            result = client.list_worker_pools("cluster-vpc-123")

        call_url = mock_get.call_args[0][0]
        # Must be the combined endpoint — NOT the vpc-specific one
        assert "/v2/getWorkerPools" in call_url
        assert "/v2/vpc/getWorkerPools" not in call_url
        assert result == pools

    def test_v2_endpoint_list_wrapped_in_object(self):
        """v2 response wrapped as {'workerPools': [...]} must be unwrapped."""
        import requests as req_mod

        client = self._make_client()
        pools = [{"id": "pool-2", "poolName": "gpu-pool", "workerCount": 2}]

        with patch.object(req_mod, "get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"workerPools": pools}
            mock_get.return_value = mock_resp

            result = client.list_worker_pools("cluster-vpc-456")

        assert result == pools

    def test_v2_400_falls_back_to_v1(self):
        """When v2 returns 400, list_worker_pools must fall back to the v1 endpoint."""
        import requests as req_mod

        client = self._make_client()
        # v1 response uses 'name' not 'poolName'
        pools_v1 = [{"id": "pool-classic", "name": "default", "sizePerZone": 2}]

        with patch.object(req_mod, "get") as mock_get:
            v2_resp = MagicMock()
            v2_resp.status_code = 400

            v1_resp = MagicMock()
            v1_resp.status_code = 200
            v1_resp.json.return_value = pools_v1
            v1_resp.raise_for_status = MagicMock()

            mock_get.side_effect = [v2_resp, v1_resp]

            result = client.list_worker_pools("cluster-classic-789")

        assert mock_get.call_count == 2
        v1_url = mock_get.call_args_list[1][0][0]
        assert "/v1/clusters/cluster-classic-789/workerpools" in v1_url
        # v1 'name' must be normalised to 'poolName'
        assert result[0]["poolName"] == "default"

    def test_v1_fallback_normalises_name_to_poolname(self):
        """v1 fallback response with 'name' must be normalised to 'poolName'."""
        import requests as req_mod

        client = self._make_client()
        pools_v1 = [
            {"id": "p1", "name": "default", "sizePerZone": 3},
            {"id": "p2", "name": "gpu-pool", "sizePerZone": 1},
        ]

        with patch.object(req_mod, "get") as mock_get:
            v2_resp = MagicMock()
            v2_resp.status_code = 503  # any non-200

            v1_resp = MagicMock()
            v1_resp.status_code = 200
            v1_resp.json.return_value = pools_v1
            v1_resp.raise_for_status = MagicMock()

            mock_get.side_effect = [v2_resp, v1_resp]

            result = client.list_worker_pools("cluster-old")

        assert result[0]["poolName"] == "default"
        assert result[1]["poolName"] == "gpu-pool"
        # original 'name' key is preserved
        assert result[0]["name"] == "default"

    def test_get_cluster_endpoint(self):
        """get_cluster must call GET /v2/getCluster?cluster=<id> and return json."""
        import requests as req_mod

        client = self._make_client()
        detail = {"id": "cluster-abc", "crn": "crn:v1:bluemix:public:containers-kubernetes:us-south:a/acct:cluster-abc::"}

        with patch.object(req_mod, "get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = detail
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp

            result = client.get_cluster("cluster-abc")

        call_url = mock_get.call_args[0][0]
        call_params = mock_get.call_args[1]["params"]
        assert "/v2/getCluster" in call_url
        assert call_params == {"cluster": "cluster-abc"}
        assert result == detail

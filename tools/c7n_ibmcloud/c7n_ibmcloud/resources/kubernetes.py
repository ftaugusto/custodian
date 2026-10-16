# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Kubernetes Service (IKS) and Red Hat OpenShift on IBM Cloud (ROKS) resources.

The IBM Container API has no official Python SDK; a thin REST wrapper is
implemented here using the IAM token from the session's authenticator.

- ibm.iks-cluster       — IKS Kubernetes clusters
- ibm.roks-cluster      — ROKS OpenShift clusters
- ibm.iks-worker-pool   — Worker pools (shared by both cluster types)

Key Protect / KMS detection
----------------------------
The Container API v1 ``GET /v1/clusters`` list response includes a
``keyManagementService`` object (``CommonClusterKMS``) on each cluster with two
fields:

* ``desiredInstance`` — CRN of the desired KMS instance (string, empty if not
  configured)
* ``actualInstance``  — list of CRNs of the active KMS instance(s) (array,
  empty if not yet applied)

A cluster is considered to have KMS **enabled** when at least one of those
fields is non-empty.  The ``kms-enabled`` filter matches clusters where KMS is
**not** enabled (i.e. missing or both empty), so operators can tag or act on
non-compliant clusters.
"""

import logging

from c7n.filters import Filter
from c7n.utils import local_session, type_schema

from c7n_ibmcloud.actions.base import IBMBaseAction, TagAction, RemoveTagAction
from c7n_ibmcloud.filters.base import TagFilter, AgeFilter, ResourceGroupFilter
from c7n_ibmcloud.provider import resources
from c7n_ibmcloud.query import QueryResourceManager, TypeInfo, DescribeSource, sources

log = logging.getLogger("custodian.ibm.kubernetes")

# IBM Container API base URL (global endpoint — no regional split)
CONTAINER_API_BASE = "https://containers.cloud.ibm.com/global"


# ---------------------------------------------------------------------------
# Thin Container API REST client
# ---------------------------------------------------------------------------

class ContainerAPIClient:
    """Minimal REST wrapper for the IBM Container API v1."""

    def __init__(self, authenticator):
        self._authenticator = authenticator

    def _headers(self):
        token = self._authenticator.token_manager.get_token()
        return {
            "Authorization": "Bearer %s" % token,
            "Content-Type": "application/json",
        }

    def list_clusters(self):
        """List all IKS/ROKS clusters across all locations.

        Uses the v2 VPC endpoint (``GET /v2/vpc/getClusters``) which returns
        clusters from all locations in one call and includes the
        ``keyManagementService`` field needed for KMS detection.
        Falls back to the v2 classic endpoint and merges both result sets so
        that classic-infrastructure clusters are also returned.
        """
        import requests

        clusters = []
        seen = set()

        for path in ("/v2/vpc/getClusters", "/v2/classic/getClusters"):
            url = "%s%s" % (CONTAINER_API_BASE, path)
            resp = requests.get(url, headers=self._headers(), timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                items = data if isinstance(data, list) else data.get("clusters", [])
                for c in items:
                    cid = c.get("id")
                    if cid and cid not in seen:
                        seen.add(cid)
                        clusters.append(c)
            else:
                log.debug("list_clusters %s returned %s", path, resp.status_code)

        return clusters

    def get_cluster(self, cluster_id):
        """Fetch a single cluster's detail (includes the ``crn`` field).

        Uses ``GET /v2/getCluster?cluster=<id>`` which returns the full
        ``GetClusterResponse`` — including the ``crn`` field missing from the
        list endpoint.
        """
        import requests

        url = "%s/v2/getCluster" % CONTAINER_API_BASE
        resp = requests.get(url, headers=self._headers(), params={"cluster": cluster_id}, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def list_worker_pools(self, cluster_id):
        """List worker pools for a cluster.

        Uses ``GET /v2/getWorkerPools?cluster=<id>`` — the combined v2 endpoint
        that handles both VPC and classic clusters and returns
        ``GetCombinedWorkerPoolResponse`` items with ``poolName`` and
        ``workerCount`` fields (the v1 endpoint returns 400 for VPC cluster IDs
        returned by the v2 list endpoint, and uses ``name`` instead of
        ``poolName``).

        Falls back to the v1 endpoint when v2 returns a non-200 status.
        The v1 response uses ``name`` instead of ``poolName`` — the fallback
        normalises this so callers always see ``poolName``.
        """
        import requests

        url = "%s/v2/getWorkerPools" % CONTAINER_API_BASE
        resp = requests.get(url, headers=self._headers(), params={"cluster": cluster_id}, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, list) else data.get("workerPools", [])

        log.debug("list_worker_pools v2 returned %s for %s, falling back to v1", resp.status_code, cluster_id)
        url_v1 = "%s/v1/clusters/%s/workerpools" % (CONTAINER_API_BASE, cluster_id)
        resp_v1 = requests.get(url_v1, headers=self._headers(), timeout=30)
        resp_v1.raise_for_status()
        pools = resp_v1.json()
        # v1 uses 'name'; normalise to 'poolName' so the resource type's
        # name = "poolName" field works regardless of which path was taken.
        for p in pools:
            if "poolName" not in p and "name" in p:
                p["poolName"] = p["name"]
        return pools

    def delete_cluster(self, cluster_id, delete_resources=False):
        import requests

        url = "%s/v1/clusters/%s" % (CONTAINER_API_BASE, cluster_id)
        params = {"deleteResources": str(delete_resources).lower()}
        resp = requests.delete(url, headers=self._headers(), params=params, timeout=30)
        resp.raise_for_status()

    def update_cluster(self, cluster_id, body):
        import requests

        url = "%s/v1/clusters/%s" % (CONTAINER_API_BASE, cluster_id)
        resp = requests.patch(url, json=body, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Container describe source
# ---------------------------------------------------------------------------

@sources.register("describe-containers")
class ContainerDescribeSource(DescribeSource):
    """Describe source that fetches clusters from the IBM Container API."""

    def get_resources(self, query):
        session = local_session(self.manager.session_factory)
        client = ContainerAPIClient(session._authenticator)
        all_clusters = client.list_clusters()
        # Filter by cluster type (kubernetes vs openshift)
        cluster_type = self.manager.resource_type.cluster_type
        if cluster_type:
            return [c for c in all_clusters if c.get("type") == cluster_type]
        return all_clusters

    def augment(self, resources):
        return resources


# ---------------------------------------------------------------------------
# ibm.iks-cluster
# ---------------------------------------------------------------------------

@resources.register("iks-cluster")
class IKSCluster(QueryResourceManager):
    """IBM Kubernetes Service (IKS) clusters.

    :example:

    Find IKS clusters running an old Kubernetes version:

    .. code-block:: yaml

        policies:
          - name: ibm-iks-old-version
            resource: ibm.iks-cluster
            filters:
              - type: value
                key: masterKubeVersion
                op: lt
                value: "1.28"
    """

    source_mapping = {"describe-containers": ContainerDescribeSource}

    class resource_type(TypeInfo):
        service = "container"
        global_service = True
        cluster_type = "kubernetes"
        enum_spec = (None, None, None)
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "state", "masterKubeVersion", "location")
        permissions = ("containers-kubernetes.cluster.read",)
        scope = "account"

    @property
    def source_type(self):
        return self.data.get("source", "describe-containers")


@IKSCluster.filter_registry.register("tag")
class IKSClusterTagFilter(TagFilter):
    pass


@IKSCluster.filter_registry.register("age")
class IKSClusterAgeFilter(AgeFilter):
    date_attribute = "createdDate"


@IKSCluster.filter_registry.register("resource-group")
class IKSClusterRGFilter(ResourceGroupFilter):
    pass


@IKSCluster.filter_registry.register("version")
class IKSClusterVersionFilter(Filter):
    """Filter IKS clusters by Kubernetes version.

    .. code-block:: yaml

        policies:
          - name: ibm-iks-outdated
            resource: ibm.iks-cluster
            filters:
              - type: version
                op: lt
                value: "1.28"
    """

    type = "version"
    schema = type_schema(
        "version",
        op={"type": "string", "enum": ["eq", "ne", "lt", "gt", "le", "ge"]},
        value={"type": "string"},
    )

    def process(self, resources, event=None):
        import operator as op_mod
        from packaging.version import Version

        op_map = {
            "eq": op_mod.eq, "ne": op_mod.ne,
            "lt": op_mod.lt, "gt": op_mod.gt,
            "le": op_mod.le, "ge": op_mod.ge,
        }
        op_fn = op_map.get(self.data.get("op", "lt"), op_mod.lt)
        target = Version(self.data.get("value", "0"))
        result = []
        for r in resources:
            raw = r.get("masterKubeVersion", "0")
            # Strip suffix like "_openshift"
            raw = raw.split("_")[0].strip()
            try:
                if op_fn(Version(raw), target):
                    result.append(r)
            except Exception:
                pass
        return result


@IKSCluster.filter_registry.register("kms-enabled")
class IKSClusterKMSFilter(Filter):
    """Match IKS clusters that do NOT have a Key Management Service (KMS/Key Protect) enabled.

    The Container API returns a ``keyManagementService`` object on each cluster
    with ``desiredInstance`` (string CRN) and ``actualInstance`` (list of CRNs).
    A cluster is considered KMS-enabled when either field is non-empty.

    By default (``enabled: false``) the filter matches clusters **without** KMS,
    which is the non-compliant case.  Set ``enabled: true`` to match clusters
    that DO have KMS enabled.

    .. code-block:: yaml

        policies:
          - name: iks-cluster-no-kms
            resource: ibm.iks-cluster
            filters:
              - type: kms-enabled
                enabled: false
            actions:
              - type: tag
                tags:
                  custodian-review: "kms-not-enabled"
    """

    type = "kms-enabled"
    schema = type_schema(
        "kms-enabled",
        enabled={"type": "boolean"},
    )

    @staticmethod
    def _has_kms(resource):
        """Return True if the cluster has KMS/Key Protect configured."""
        kms = resource.get("keyManagementService") or {}
        desired = kms.get("desiredInstance") or ""
        actual = kms.get("actualInstance") or []
        return bool(desired) or bool(actual)

    def process(self, resources, event=None):
        want_enabled = self.data.get("enabled", False)
        if want_enabled:
            return [r for r in resources if self._has_kms(r)]
        return [r for r in resources if not self._has_kms(r)]


def _fetch_cluster_crn(session, cluster_id):
    """Return the CRN for *cluster_id* by calling GET /v2/getCluster.

    The v2 list endpoints (getClusters) do not include a ``crn`` field on each
    cluster entry.  The single-cluster detail endpoint does.  The result is
    cached on the resource dict under ``c7n:crn`` so repeated tag actions
    against the same resource only make one extra API call.

    Returns ``None`` if the call fails so the caller can skip the action
    gracefully rather than raise.
    """
    client = ContainerAPIClient(session._authenticator)
    try:
        detail = client.get_cluster(cluster_id)
        return detail.get("crn")
    except Exception as exc:
        log.warning("Could not fetch CRN for cluster %s: %s", cluster_id, exc)
        return None


@IKSCluster.action_registry.register("tag")
class IKSClusterTagAction(TagAction):
    """Tag an IKS cluster via IBM Global Tagging.

    The v2 list endpoint does not return a ``crn`` field — this action fetches
    the cluster detail to obtain the CRN before tagging.
    """

    @staticmethod
    def _get_crn(resource):
        # Fast path: already cached from a previous action call
        cached = resource.get("c7n:crn")
        if cached:
            return cached
        # Fall back to base — handles resources that do have a crn field
        crn = TagAction._get_crn(resource)
        return crn

    def perform_action(self, resource):
        # Ensure CRN is populated before delegating to the base tag action
        if not resource.get("crn") and not resource.get("c7n:crn"):
            session = local_session(self.manager.session_factory)
            crn = _fetch_cluster_crn(session, resource["id"])
            if crn:
                resource["c7n:crn"] = crn
                resource["crn"] = crn
        super().perform_action(resource)


@IKSCluster.action_registry.register("remove-tag")
class IKSClusterRemoveTagAction(RemoveTagAction):
    """Remove tags from an IKS cluster via IBM Global Tagging."""

    def perform_action(self, resource):
        if not resource.get("crn"):
            session = local_session(self.manager.session_factory)
            crn = _fetch_cluster_crn(session, resource["id"])
            if crn:
                resource["crn"] = crn
        super().perform_action(resource)


@IKSCluster.action_registry.register("delete")
class IKSClusterDelete(IBMBaseAction):
    """Delete an IKS cluster.

    .. code-block:: yaml

        policies:
          - name: delete-old-iks-clusters
            resource: ibm.iks-cluster
            filters:
              - type: age
                days: 30
            actions:
              - type: delete
                delete_resources: true
    """

    type = "delete"
    schema = type_schema(
        "delete",
        delete_resources={"type": "boolean"},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = ContainerAPIClient(session._authenticator)
        client.delete_cluster(
            resource["id"],
            delete_resources=self.data.get("delete_resources", False),
        )
        log.debug("Deleted IKS cluster %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.roks-cluster
# ---------------------------------------------------------------------------

@resources.register("roks-cluster")
class ROKSCluster(QueryResourceManager):
    """Red Hat OpenShift on IBM Cloud (ROKS) clusters.

    :example:

    Find ROKS clusters on an old OpenShift version:

    .. code-block:: yaml

        policies:
          - name: ibm-roks-old-version
            resource: ibm.roks-cluster
            filters:
              - type: version
                op: lt
                value: "4.13"
    """

    source_mapping = {"describe-containers": ContainerDescribeSource}

    class resource_type(TypeInfo):
        service = "container"
        global_service = True
        cluster_type = "openshift"
        enum_spec = (None, None, None)
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "state", "masterKubeVersion", "location")
        permissions = ("containers-kubernetes.cluster.read",)
        scope = "account"

    @property
    def source_type(self):
        return self.data.get("source", "describe-containers")


@ROKSCluster.filter_registry.register("tag")
class ROKSClusterTagFilter(TagFilter):
    pass


@ROKSCluster.filter_registry.register("age")
class ROKSClusterAgeFilter(AgeFilter):
    date_attribute = "createdDate"


@ROKSCluster.filter_registry.register("resource-group")
class ROKSClusterRGFilter(ResourceGroupFilter):
    pass


@ROKSCluster.filter_registry.register("version")
class ROKSClusterVersionFilter(IKSClusterVersionFilter):
    pass


@ROKSCluster.filter_registry.register("kms-enabled")
class ROKSClusterKMSFilter(IKSClusterKMSFilter):
    """Match ROKS clusters that do NOT have a Key Management Service (KMS/Key Protect) enabled.

    See ``IKSClusterKMSFilter`` for full documentation.
    """
    pass


@ROKSCluster.action_registry.register("tag")
class ROKSClusterTagAction(IKSClusterTagAction):
    """Tag a ROKS cluster via IBM Global Tagging (same CRN-fetch logic as IKS)."""
    pass


@ROKSCluster.action_registry.register("remove-tag")
class ROKSClusterRemoveTagAction(IKSClusterRemoveTagAction):
    """Remove tags from a ROKS cluster via IBM Global Tagging."""
    pass


@ROKSCluster.action_registry.register("delete")
class ROKSClusterDelete(IKSClusterDelete):
    pass


# ---------------------------------------------------------------------------
# ibm.iks-worker-pool (shared by IKS and ROKS)
# ---------------------------------------------------------------------------

@sources.register("describe-worker-pools")
class WorkerPoolDescribeSource(DescribeSource):
    """Augments all clusters with their worker pools as child resources.

    Each pool dict is annotated with:

    * ``c7n:cluster_id``   — the parent cluster ID
    * ``c7n:cluster_name`` — the parent cluster name (for reporting)
    * ``c7n:cluster_crn``  — the parent cluster CRN fetched from
      ``GET /v2/getCluster``; used by the tag action because worker pools
      have no CRN of their own (``GetCombinedWorkerPoolResponse`` has no
      ``crn`` field per the IBM Container API spec).
    """

    def get_resources(self, query):
        session = local_session(self.manager.session_factory)
        client = ContainerAPIClient(session._authenticator)
        all_clusters = client.list_clusters()
        resources = []
        # Cache CRNs per cluster so one detail call serves all pools in that cluster
        cluster_crn_cache = {}
        for cluster in all_clusters:
            cluster_id = cluster["id"]
            pools = client.list_worker_pools(cluster_id)
            # Fetch the cluster CRN once per cluster (not once per pool)
            if cluster_id not in cluster_crn_cache:
                cluster_crn_cache[cluster_id] = _fetch_cluster_crn(session, cluster_id) or ""
            crn = cluster_crn_cache[cluster_id]
            for pool in pools:
                pool["c7n:cluster_id"] = cluster_id
                pool["c7n:cluster_name"] = cluster.get("name", "")
                pool["c7n:cluster_crn"] = crn
            resources.extend(pools)
        return resources

    def augment(self, resources):
        return resources


@resources.register("iks-worker-pool")
class IKSWorkerPool(QueryResourceManager):
    """IKS / ROKS worker pools.

    :example:

    Find worker pools with fewer than 3 workers:

    .. code-block:: yaml

        policies:
          - name: ibm-underpopulated-pools
            resource: ibm.iks-worker-pool
            filters:
              - type: value
                key: workerCount
                op: lt
                value: 3
    """

    source_mapping = {"describe-worker-pools": WorkerPoolDescribeSource}

    class resource_type(TypeInfo):
        service = "container"
        global_service = True
        enum_spec = (None, None, None)
        id = "id"
        name = "poolName"
        default_report_fields = ("id", "poolName", "workerCount", "c7n:cluster_name")
        permissions = ("containers-kubernetes.cluster.read",)
        scope = "account"

    @property
    def source_type(self):
        return self.data.get("source", "describe-worker-pools")


@IKSWorkerPool.filter_registry.register("tag")
class IKSWorkerPoolTagFilter(TagFilter):
    pass


@IKSWorkerPool.action_registry.register("tag")
class IKSWorkerPoolTagAction(TagAction):
    """Tag the parent cluster on behalf of a matched worker pool.

    Worker pools have no CRN of their own (``GetCombinedWorkerPoolResponse``
    has no ``crn`` field per the IBM Container API spec).  Tags are applied
    to the parent cluster's CRN instead, using the ``c7n:cluster_crn``
    annotation injected by ``WorkerPoolDescribeSource``.

    This lets you mark the cluster for operator review when one of its pools
    triggers a policy (e.g. empty pool, underpopulated pool).

    .. code-block:: yaml

        policies:
          - name: iks-empty-worker-pool
            resource: ibm.iks-worker-pool
            filters:
              - type: value
                key: workerCount
                op: eq
                value: 0
            actions:
              - type: tag
                tags:
                  custodian-review: "empty-worker-pool"
    """

    @staticmethod
    def _get_crn(resource):
        # Use the parent cluster CRN injected by WorkerPoolDescribeSource
        crn = resource.get("c7n:cluster_crn") or ""
        if crn:
            return crn
        # Fallback: check the raw crn field (future-proofing; currently absent)
        return TagAction._get_crn(resource)

    def perform_action(self, resource):
        # If the CRN was not pre-fetched (e.g. resource built outside the
        # normal describe path), try to fetch it on-demand from the cluster ID.
        if not resource.get("c7n:cluster_crn") and not resource.get("crn"):
            cluster_id = resource.get("c7n:cluster_id")
            if cluster_id:
                session = local_session(self.manager.session_factory)
                crn = _fetch_cluster_crn(session, cluster_id)
                if crn:
                    resource["c7n:cluster_crn"] = crn
        super().perform_action(resource)

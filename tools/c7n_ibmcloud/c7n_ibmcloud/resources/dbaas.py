# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Cloud Databases (ICD) resources.

All ICD offerings share the CloudDatabasesV5 API and are enumerated via
ResourceControllerV2 (filtered by resource_id / service name).

A shared base class ``IcdInstance`` handles the enumeration; each DB type
is a registered subclass parameterised by ``icd_service_name``.

Supported resource types:
- ibm.dbaas-postgresql      — Databases for PostgreSQL
- ibm.dbaas-mysql           — Databases for MySQL
- ibm.dbaas-mongodb         — Databases for MongoDB
- ibm.dbaas-redis           — Databases for Redis
- ibm.dbaas-elasticsearch   — Databases for Elasticsearch
- ibm.dbaas-rabbitmq        — Messages for RabbitMQ
"""

import logging

from c7n.filters import Filter
from c7n.utils import local_session, type_schema

from c7n_ibmcloud.actions.base import IBMBaseAction, TagAction, RemoveTagAction
from c7n_ibmcloud.filters.base import TagFilter, AgeFilter, ResourceGroupFilter
from c7n_ibmcloud.provider import resources
from c7n_ibmcloud.query import QueryResourceManager, TypeInfo, DescribeSource, sources

log = logging.getLogger("custodian.ibm.dbaas")

# Map from ICD resource type name to the service_id string used in RC
ICD_SERVICE_MAP = {
    "databases-for-postgresql":   "databases-for-postgresql",
    "databases-for-mysql":        "databases-for-mysql",
    "databases-for-mongodb":      "databases-for-mongodb",
    "databases-for-redis":        "databases-for-redis",
    "databases-for-elasticsearch": "databases-for-elasticsearch",
    "messages-for-rabbitmq":      "messages-for-rabbitmq",
}


# ---------------------------------------------------------------------------
# ICD describe source
# ---------------------------------------------------------------------------

@sources.register("describe-icd")
class ICDDescribeSource(DescribeSource):
    """Enumerate ICD instances via ResourceControllerV2, filtered by service name."""

    def get_resources(self, query):
        session = local_session(self.manager.session_factory)
        rc_client = session.client("resource-ctrl")
        icd_service = self.manager.resource_type.icd_service_name
        all_instances = []
        start = None
        while True:
            kw = {"resource_id": icd_service, "limit": 50}
            if start:
                kw["start"] = start
            response = rc_client.list_resource_instances(**kw).get_result()
            items = response.get("resources", [])
            all_instances.extend(items)
            next_url = response.get("next_url")
            if not next_url:
                break
            for part in next_url.split("?", 1)[-1].split("&"):
                if part.startswith("start="):
                    start = part[len("start="):]
                    break
            else:
                break
        return all_instances

    def augment(self, resources):
        """Enrich each ICD instance with deployment details (version, scaling, backup)."""
        session = local_session(self.manager.session_factory)
        try:
            icd_client = session.client("databases")
        except Exception:
            log.warning("CloudDatabasesV5 client unavailable; skipping ICD augmentation")
            return resources

        enriched = []
        for r in resources:
            r = dict(r)
            try:
                details = icd_client.get_deployment_info(
                    id=r["crn"]
                ).get_result().get("deployment", {})
                r["c7n:version"] = details.get("version")
                r["c7n:platform_version"] = details.get("platform_version")
            except Exception as exc:
                log.debug("Could not enrich ICD instance %s: %s", r.get("id"), exc)
            enriched.append(r)
        return enriched


# ---------------------------------------------------------------------------
# Base ICD QueryResourceManager
# ---------------------------------------------------------------------------

class IcdInstance(QueryResourceManager):
    """Base manager for all IBM Cloud Database resource types.

    Subclasses set ``icd_service_name`` on their ``resource_type`` inner class.
    """

    source_mapping = {"describe-icd": ICDDescribeSource}

    class resource_type(TypeInfo):
        service = "resource-ctrl"
        global_service = True
        icd_service_name = None   # set by subclasses
        enum_spec = (None, None, None)
        id = "id"
        name = "name"
        default_report_fields = (
            "id", "name", "state", "region_id", "resource_group_id",
            "c7n:version",
        )
        permissions = ("resource-controller.instance.list",)
        scope = "account"

    @property
    def source_type(self):
        return self.data.get("source", "describe-icd")


# ---------------------------------------------------------------------------
# Shared ICD filters and actions
# ---------------------------------------------------------------------------

def _register_icd_common(cls):
    """Register common filters and actions on an ICD resource class."""

    @cls.filter_registry.register("tag")
    class _TagFilter(TagFilter):
        pass

    @cls.filter_registry.register("age")
    class _AgeFilter(AgeFilter):
        date_attribute = "created_at"

    @cls.filter_registry.register("resource-group")
    class _RGFilter(ResourceGroupFilter):
        pass

    @cls.filter_registry.register("version")
    class _VersionFilter(Filter):
        """Filter ICD instances by database engine version."""
        type = "version"
        schema = type_schema(
            "version",
            op={"type": "string", "enum": ["eq", "ne", "lt", "gt", "le", "ge"]},
            value={"type": "string"},
        )

        def process(self, resources, event=None):
            import operator as op_mod
            op_map = {
                "eq": op_mod.eq, "ne": op_mod.ne,
                "lt": op_mod.lt, "gt": op_mod.gt,
                "le": op_mod.le, "ge": op_mod.ge,
            }
            op_fn = op_map.get(self.data.get("op", "lt"), op_mod.lt)
            target = self.data.get("value", "")
            result = []
            for r in resources:
                v = r.get("c7n:version") or ""
                try:
                    # Simple string comparison; version strings are semver-like
                    from packaging.version import Version
                    if op_fn(Version(v), Version(target)):
                        result.append(r)
                except Exception:
                    if op_fn(v, target):
                        result.append(r)
            return result

    @cls.filter_registry.register("plan")
    class _PlanFilter(Filter):
        """Filter ICD instances by their resource plan (e.g. standard, enterprise)."""
        type = "plan"
        schema = type_schema("plan", value={"type": "string"})

        def process(self, resources, event=None):
            target = self.data.get("value", "")
            return [r for r in resources if r.get("resource_plan_id", "").endswith(target)]

    @cls.action_registry.register("tag")
    class _TagAction(TagAction):
        pass

    @cls.action_registry.register("remove-tag")
    class _RemoveTagAction(RemoveTagAction):
        pass

    @cls.action_registry.register("delete")
    class _DeleteAction(IBMBaseAction):
        """Delete an ICD service instance."""
        type = "delete"
        schema = type_schema("delete", recursive={"type": "boolean"}, rinherit=IBMBaseAction.schema)

        def perform_action(self, resource):
            session = local_session(self.manager.session_factory)
            rc_client = session.client("resource-ctrl")
            rc_client.delete_resource_instance(
                id=resource["id"],
                recursive=self.data.get("recursive", False),
            )
            log.debug("Deleted ICD instance %s", resource["id"])

    @cls.action_registry.register("scale")
    class _ScaleAction(IBMBaseAction):
        """Scale an ICD instance (change memory, disk, or CPU).

        .. code-block:: yaml

            policies:
              - name: scale-up-small-postgres
                resource: ibm.dbaas-postgresql
                filters:
                  - type: value
                    key: c7n:version
                    op: ge
                    value: "15"
                actions:
                  - type: scale
                    memory_allocation: 8192
                    disk_allocation: 20480
        """
        type = "scale"
        schema = type_schema(
            "scale",
            memory_allocation={"type": "integer"},
            disk_allocation={"type": "integer"},
            cpu_allocation={"type": "integer"},
            rinherit=IBMBaseAction.schema,
        )

        def perform_action(self, resource):
            session = local_session(self.manager.session_factory)
            icd_client = session.client("databases")
            groups = {}
            if self.data.get("memory_allocation"):
                groups["memory"] = {"allocation_mb": self.data["memory_allocation"]}
            if self.data.get("disk_allocation"):
                groups["disk"] = {"allocation_mb": self.data["disk_allocation"]}
            if self.data.get("cpu_allocation"):
                groups["cpu"] = {"allocation_count": self.data["cpu_allocation"]}
            if groups:
                icd_client.set_deployment_scaling_group(
                    id=resource["crn"],
                    group_id="member",
                    set_deployment_scaling_group_request=groups,
                )
                log.debug("Scaled ICD instance %s: %s", resource["id"], groups)

    return cls


# ---------------------------------------------------------------------------
# ICD resource type registrations
# ---------------------------------------------------------------------------

@resources.register("dbaas-postgresql")
@_register_icd_common
class IcdPostgreSQL(IcdInstance):
    """IBM Cloud Databases for PostgreSQL.

    :example:

    .. code-block:: yaml

        policies:
          - name: ibm-postgres-old-version
            resource: ibm.dbaas-postgresql
            filters:
              - type: version
                op: lt
                value: "15"
    """

    class resource_type(IcdInstance.resource_type):
        icd_service_name = "databases-for-postgresql"
        default_report_fields = IcdInstance.resource_type.default_report_fields + (
            "region_id",
        )


@resources.register("dbaas-mysql")
@_register_icd_common
class IcdMySQL(IcdInstance):
    """IBM Cloud Databases for MySQL."""

    class resource_type(IcdInstance.resource_type):
        icd_service_name = "databases-for-mysql"


@resources.register("dbaas-mongodb")
@_register_icd_common
class IcdMongoDB(IcdInstance):
    """IBM Cloud Databases for MongoDB."""

    class resource_type(IcdInstance.resource_type):
        icd_service_name = "databases-for-mongodb"


@resources.register("dbaas-redis")
@_register_icd_common
class IcdRedis(IcdInstance):
    """IBM Cloud Databases for Redis."""

    class resource_type(IcdInstance.resource_type):
        icd_service_name = "databases-for-redis"


@resources.register("dbaas-elasticsearch")
@_register_icd_common
class IcdElasticsearch(IcdInstance):
    """IBM Cloud Databases for Elasticsearch."""

    class resource_type(IcdInstance.resource_type):
        icd_service_name = "databases-for-elasticsearch"


@resources.register("dbaas-rabbitmq")
@_register_icd_common
class IcdRabbitMQ(IcdInstance):
    """IBM Cloud Messages for RabbitMQ."""

    class resource_type(IcdInstance.resource_type):
        icd_service_name = "messages-for-rabbitmq"



# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Cloud PowerVS (Power Virtual Server) resources.

PowerVS uses a dedicated Power IaaS REST API. Each workspace (service instance)
has a unique GUID required for all API calls.  Workspaces are enumerated first
via ResourceControllerV2, then per-workspace resources are fetched from the
Power IaaS API endpoint.

- ibm.powervs-instance  — PowerVS virtual machine instances (PVM instances)
- ibm.powervs-volume    — PowerVS storage volumes
- ibm.powervs-network   — PowerVS networks
- ibm.powervs-image     — PowerVS OS images (stock and custom)
- ibm.powervs-ssh-key   — PowerVS SSH keys
"""

import logging

from c7n.filters import Filter
from c7n.utils import local_session, type_schema

from c7n_ibmcloud.actions.base import IBMBaseAction, TagAction, RemoveTagAction
from c7n_ibmcloud.filters.base import TagFilter, AgeFilter, ResourceGroupFilter
from c7n_ibmcloud.provider import resources
import os

from c7n_ibmcloud.query import QueryResourceManager, TypeInfo, DescribeSource, sources
from c7n_ibmcloud.session import POWERVS_REGION_MAP

log = logging.getLogger("custodian.ibm.powervs")

# IBM service plan GUID and service name for PowerVS in Resource Catalog / Controller
POWERVS_SERVICE_ID = "abd259f0-9990-11e8-acc8-b9f54a8f1661"  # power-iaas plan GUID
POWERVS_OLD_SERVICE_ID = "f165dd34-3a40-423b-9d95-e90a23f724dd"
POWERVS_RC_SERVICE_NAME = "power-iaas"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_powervs_workspaces(session):
    """List all PowerVS workspaces (service instances) in the account.

    Supports pinning via ``IBMCLOUD_POWERVS_WORKSPACE_ID`` environment variable.
    Discovers via ResourceController matching service ID, name, or CRN substring,
    with an account-wide fallback for service instances.
    """
    env_ws = os.environ.get("IBMCLOUD_POWERVS_WORKSPACE_ID", "").strip()
    if env_ws:
        return [{"guid": env_ws, "id": env_ws, "name": "pinned-workspace", "crn": env_ws, "region_id": session.region}]

    client = session.client("resource-ctrl")
    workspaces = []
    seen = set()

    def _collect(resp):
        for ws in resp.get("resources", []):
            guid = ws.get("guid", ws.get("id"))
            crn = ws.get("crn", "")
            res_id = ws.get("resource_id", "")
            if guid and guid not in seen:
                if (
                    res_id in (POWERVS_SERVICE_ID, POWERVS_RC_SERVICE_NAME)
                    or f":{POWERVS_RC_SERVICE_NAME}:" in crn
                    or "power-iaas" in crn
                ):
                    seen.add(guid)
                    workspaces.append(ws)

    # 1. Search by resource_id (UUID and service name)
    for res_id in (POWERVS_SERVICE_ID, POWERVS_OLD_SERVICE_ID, POWERVS_RC_SERVICE_NAME):
        start = None
        while True:
            kw = {"resource_id": res_id, "limit": 50}
            if start:
                kw["start"] = start
            try:
                response = client.list_resource_instances(**kw).get_result()
                _collect(response)
                next_url = response.get("next_url")
                if not next_url:
                    break
                for part in next_url.split("?", 1)[-1].split("&"):
                    if part.startswith("start="):
                        start = part[len("start="):]
                        break
                else:
                    break
            except Exception as exc:
                log.warning("list_resource_instances failed for resource_id=%s: %s", res_id, exc)
                break

    # 2. Fallback: list all service instances if specific queries found nothing
    if not workspaces:
        start = None
        while True:
            kw = {"type": "service_instance", "limit": 50}
            if start:
                kw["start"] = start
            try:
                response = client.list_resource_instances(**kw).get_result()
                _collect(response)
                next_url = response.get("next_url")
                if not next_url:
                    break
                for part in next_url.split("?", 1)[-1].split("&"):
                    if part.startswith("start="):
                        start = part[len("start="):]
                        break
                else:
                    break
            except Exception as exc:
                log.warning("list_resource_instances fallback failed: %s", exc)
                break

    return workspaces


def _powervs_region_for_workspace(workspace):
    """Derive the Power IaaS API region from a workspace's region_id or CRN."""
    region_id = workspace.get("region_id", "")
    # region_id is a datacenter code like "dal10", "eu-de-1", "sao01", "us-south", etc.
    for code, region in POWERVS_REGION_MAP.items():
        if region_id.startswith(code):
            return region

    crn = workspace.get("crn", "")
    # CRN format: crn:v1:bluemix:public:power-iaas:<region/location>:a/<account>:...
    if crn:
        parts = crn.split(":")
        if len(parts) > 5 and parts[5]:
            loc = parts[5]
            for code, region in POWERVS_REGION_MAP.items():
                if loc.startswith(code):
                    return region
            loc_parts = loc.split("-")
            if len(loc_parts) >= 2:
                return "-".join(loc_parts[:2])
            return loc

    parts = region_id.split("-")
    if len(parts) >= 2:
        return "-".join(parts[:2])
    return region_id


# ---------------------------------------------------------------------------
# PowerVS describe source base
# ---------------------------------------------------------------------------

class PowerVSDescribeSource(DescribeSource):
    """Base describe source for PowerVS resources.

    Enumerates all workspaces and collects resources across them.
    Subclasses set ``path`` and ``result_key`` for the specific resource type.
    """

    path = None       # e.g. "/pvm-instances"
    result_key = None  # e.g. "pvmInstances"
    use_v1 = False    # True for newer endpoints like /v1/ssh-keys

    def get_resources(self, query):
        session = local_session(self.manager.session_factory)
        target_region = session.region
        workspaces = _get_powervs_workspaces(session)
        all_resources = []
        for ws in workspaces:
            ws_id = ws.get("guid") or ws.get("id")
            ws_crn = ws.get("crn") or ""
            ws_name = ws.get("name", "")
            region = _powervs_region_for_workspace(ws)

            # Filter workspaces to match session.region if set, unless pinned
            if target_region and region and region != target_region:
                log.debug(
                    "Skipping workspace %s (%s) in region %s (targeting %s)",
                    ws_id,
                    ws_name,
                    region,
                    target_region,
                )
                continue

            log.info(
                "Querying PowerVS workspace %s (%s) in region %s crn=%s",
                ws_id, ws_name, region,
                ws_crn[:40] + "..." if len(ws_crn) > 40 else ws_crn or "<empty>",
            )
            client = session.powervs_client(workspace_id=ws_id, region=region, workspace_crn=ws_crn)
            try:
                items = client.list(self.path, self.result_key, v1=self.use_v1)
                for item in items:
                    item["c7n:workspace_id"] = ws_id
                    item["c7n:workspace_crn"] = ws_crn
                    item["c7n:workspace_name"] = ws.get("name", "")
                    item["c7n:region"] = region
                all_resources.extend(items)
            except Exception as exc:
                log.warning("Error fetching %s from workspace %s: %s", self.path, ws_id, exc)
        return self.augment(all_resources)

    def augment(self, resources):
        session = local_session(self.manager.session_factory)
        from c7n_ibmcloud.resources.vpc import augment_with_tags

        return augment_with_tags(resources, session, tag_type="user")


# ---------------------------------------------------------------------------
# ibm.powervs-instance
# ---------------------------------------------------------------------------

@sources.register("describe-powervs-instances")
class PowerVSInstanceSource(PowerVSDescribeSource):
    path = "/pvm-instances"
    result_key = "pvmInstances"


@resources.register("powervs-instance")
class PowerVSInstance(QueryResourceManager):
    """IBM PowerVS virtual machine instances.

    :example:

    Find stopped PowerVS instances:

    .. code-block:: yaml

        policies:
          - name: ibm-powervs-stopped
            resource: ibm.powervs-instance
            filters:
              - type: value
                key: status
                value: SHUTOFF
    """

    source_mapping = {"describe-powervs-instances": PowerVSInstanceSource}

    class resource_type(TypeInfo):
        service = "powervs"
        global_service = False
        enum_spec = (None, None, None)
        id = "pvmInstanceID"
        name = "serverName"
        default_report_fields = (
            "pvmInstanceID", "serverName", "status", "storageType",
            "procType", "memory", "c7n:workspace_name"
        )
        permissions = ("power-iaas.pvm-instance.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-powervs-instances")


@PowerVSInstance.filter_registry.register("age")
class PowerVSInstanceAgeFilter(AgeFilter):
    date_attribute = "creationDate"


@PowerVSInstance.filter_registry.register("tag")
class PowerVSInstanceTagFilter(TagFilter):
    pass


@PowerVSInstance.filter_registry.register("public-network-interface")
class PowerVSInstancePublicNetworkFilter(Filter):
    """Match PowerVS instances that have at least one public network interface.

    Per the IBM Power IaaS API (``PVMInstanceReference``), the list endpoint
    ``GET /pvm-instances`` returns a ``networks`` array on each instance.  Each
    entry is a ``PVMInstanceNetwork`` object.

    A network attachment is considered public when **any** of the following is
    true for an entry in ``networks``:

    * ``externalIP`` is non-empty (set on pub-vlan attachments that carry a
      routable external IP), **or**
    * ``networkName`` starts with ``"public-"`` (IBM names auto-created pub-vlan
      networks with this prefix when no externalIP is surfaced in the payload).

    .. code-block:: yaml

        policies:
          - name: powervs-instance-has-public-network
            resource: ibm.powervs-instance
            filters:
              - type: public-network-interface
            actions:
              - type: tag
                tags:
                  custodian-review: "public-network-interface"
    """

    type = "public-network-interface"
    schema = type_schema("public-network-interface")

    def process(self, resources, event=None):
        return [r for r in resources if self._has_public_network(r)]

    @staticmethod
    def _has_public_network(resource):
        for net in resource.get("networks", []):
            if net.get("externalIP"):
                return True
            name = net.get("networkName", "")
            if isinstance(name, str) and name.lower().startswith("public-"):
                return True
        return False


@PowerVSInstance.action_registry.register("tag")
class PowerVSInstanceTagAction(TagAction):
    """Attach tags to the parent PowerVS workspace on behalf of a PVM instance.

    Global Tagging operates on the service instance CRN (the PowerVS workspace)
    if the individual PVM instance has no direct standalone CRN.
    """

    @staticmethod
    def _get_crn(resource):
        crn = TagAction._get_crn(resource)
        if crn:
            return crn
        return resource.get("c7n:workspace_crn")


@PowerVSInstance.action_registry.register("remove-tag")
class PowerVSInstanceRemoveTagAction(RemoveTagAction):
    """Detach tags from the parent PowerVS workspace on behalf of a PVM instance."""

    def perform_action(self, resource):
        crn = resource.get("crn") or resource.get("c7n:workspace_crn")
        if not crn:
            log.warning("Resource %s has no CRN; skipping remove-tag action", resource.get("pvmInstanceID", resource.get("id")))
            return

        session = local_session(self.manager.session_factory)
        client = session.client("global-tagging")

        from ibm_platform_services.global_tagging_v1 import Resource

        tag_names = self.data.get("tags", [])
        tag_type = getattr(self.manager.resource_type, "tag_type", "user")
        client.detach_tag(
            resources=[Resource(resource_id=crn)],
            tag_names=tag_names,
            tag_type=tag_type,
        )
        log.debug("Removed tags %s from workspace %s (tag_type=%s)", tag_names, crn, tag_type)


@PowerVSInstance.action_registry.register("stop")
class PowerVSInstanceStop(IBMBaseAction):
    """Stop a running PowerVS instance.

    .. code-block:: yaml

        policies:
          - name: stop-dev-powervs
            resource: ibm.powervs-instance
            filters:
              - type: tag
                key: environment
                value: dev
              - type: value
                key: status
                value: ACTIVE
            actions:
              - stop
    """

    type = "stop"
    schema = type_schema(
        "stop",
        soft={"type": "boolean"},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        ws_id = resource["c7n:workspace_id"]
        ws_crn = resource.get("c7n:workspace_crn", "")
        region = resource.get("c7n:region", session.region)
        client = session.powervs_client(workspace_id=ws_id, region=region, workspace_crn=ws_crn)
        # "stop" = graceful shutdown; "immediate-shutdown" = hard stop
        action = "stop" if self.data.get("soft") else "immediate-shutdown"
        client.post(
            "/pvm-instances/%s/action" % resource["pvmInstanceID"],
            {"action": action},
        )
        log.debug("Stopped PowerVS instance %s (action=%s)", resource["pvmInstanceID"], action)


@PowerVSInstance.action_registry.register("start")
class PowerVSInstanceStart(IBMBaseAction):
    """Start a stopped PowerVS instance."""

    type = "start"
    schema = type_schema("start", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        ws_id = resource["c7n:workspace_id"]
        ws_crn = resource.get("c7n:workspace_crn", "")
        region = resource.get("c7n:region", session.region)
        client = session.powervs_client(workspace_id=ws_id, region=region, workspace_crn=ws_crn)
        client.post(
            "/pvm-instances/%s/action" % resource["pvmInstanceID"],
            {"action": "start"},
        )
        log.debug("Started PowerVS instance %s", resource["pvmInstanceID"])


@PowerVSInstance.action_registry.register("delete")
class PowerVSInstanceDelete(IBMBaseAction):
    """Delete a PowerVS instance."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        ws_id = resource["c7n:workspace_id"]
        ws_crn = resource.get("c7n:workspace_crn", "")
        region = resource.get("c7n:region", session.region)
        client = session.powervs_client(workspace_id=ws_id, region=region, workspace_crn=ws_crn)
        client.delete("/pvm-instances/%s" % resource["pvmInstanceID"])
        log.debug("Deleted PowerVS instance %s", resource["pvmInstanceID"])


# ---------------------------------------------------------------------------
# ibm.powervs-volume
# ---------------------------------------------------------------------------

@sources.register("describe-powervs-volumes")
class PowerVSVolumeSource(PowerVSDescribeSource):
    path = "/volumes"
    result_key = "volumes"


@resources.register("powervs-volume")
class PowerVSVolume(QueryResourceManager):
    """IBM PowerVS storage volumes.

    :example:

    Find unattached PowerVS volumes:

    .. code-block:: yaml

        policies:
          - name: ibm-powervs-orphaned-volumes
            resource: ibm.powervs-volume
            filters:
              - type: value
                key: shareable
                value: false
              - type: value
                key: pvmInstanceIDs
                value: []
    """

    source_mapping = {"describe-powervs-volumes": PowerVSVolumeSource}

    class resource_type(TypeInfo):
        service = "powervs"
        global_service = False
        enum_spec = (None, None, None)
        id = "volumeID"
        name = "name"
        default_report_fields = (
            "volumeID", "name", "state", "diskType", "size", "c7n:workspace_name"
        )
        permissions = ("power-iaas.pvm-instance-storage.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-powervs-volumes")


@PowerVSVolume.filter_registry.register("tag")
class PowerVSVolumeTagFilter(TagFilter):
    pass


@PowerVSVolume.action_registry.register("tag")
class PowerVSVolumeTagAction(TagAction):
    pass


@PowerVSVolume.action_registry.register("delete")
class PowerVSVolumeDelete(IBMBaseAction):
    """Delete a PowerVS volume (must be detached first)."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        ws_id = resource["c7n:workspace_id"]
        ws_crn = resource.get("c7n:workspace_crn", "")
        region = resource.get("c7n:region", session.region)
        client = session.powervs_client(workspace_id=ws_id, region=region, workspace_crn=ws_crn)
        client.delete("/volumes/%s" % resource["volumeID"])
        log.debug("Deleted PowerVS volume %s", resource["volumeID"])


# ---------------------------------------------------------------------------
# ibm.powervs-network
# ---------------------------------------------------------------------------

@sources.register("describe-powervs-networks")
class PowerVSNetworkSource(PowerVSDescribeSource):
    path = "/networks"
    result_key = "networks"


@resources.register("powervs-network")
class PowerVSNetwork(QueryResourceManager):
    """IBM PowerVS networks."""

    source_mapping = {"describe-powervs-networks": PowerVSNetworkSource}

    class resource_type(TypeInfo):
        service = "powervs"
        global_service = False
        enum_spec = (None, None, None)
        id = "networkID"
        name = "name"
        default_report_fields = ("networkID", "name", "type", "cidr", "c7n:workspace_name")
        permissions = ("power-iaas.pvm-instance-network.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-powervs-networks")


@PowerVSNetwork.filter_registry.register("tag")
class PowerVSNetworkTagFilter(TagFilter):
    pass


@PowerVSNetwork.action_registry.register("tag")
class PowerVSNetworkTagAction(TagAction):
    """Attach tags to the parent PowerVS workspace on behalf of a network."""

    @staticmethod
    def _get_crn(resource):
        crn = TagAction._get_crn(resource)
        if crn:
            return crn
        return resource.get("c7n:workspace_crn")


@PowerVSNetwork.action_registry.register("remove-tag")
class PowerVSNetworkRemoveTagAction(RemoveTagAction):
    """Detach tags from the parent PowerVS workspace on behalf of a network."""

    def perform_action(self, resource):
        crn = resource.get("crn") or resource.get("c7n:workspace_crn")
        if not crn:
            log.warning("Resource %s has no CRN; skipping remove-tag action", resource.get("networkID", resource.get("id")))
            return

        session = local_session(self.manager.session_factory)
        client = session.client("global-tagging")

        from ibm_platform_services.global_tagging_v1 import Resource

        tag_names = self.data.get("tags", [])
        tag_type = getattr(self.manager.resource_type, "tag_type", "user")
        client.detach_tag(
            resources=[Resource(resource_id=crn)],
            tag_names=tag_names,
            tag_type=tag_type,
        )
        log.debug("Removed tags %s from workspace %s (tag_type=%s)", tag_names, crn, tag_type)


@PowerVSNetwork.action_registry.register("delete")
class PowerVSNetworkDelete(IBMBaseAction):
    """Delete a PowerVS network.

    If the network is currently attached to one or more active PVM instances,
    IBM Cloud returns HTTP 409 Conflict. This action catches the conflict, logs
    a clear warning, and applies a warning tag to the workspace for operator review.
    """

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        ws_id = resource["c7n:workspace_id"]
        ws_crn = resource.get("c7n:workspace_crn", "")
        region = resource.get("c7n:region", session.region)
        net_id = resource.get("networkID", resource.get("id"))
        net_name = resource.get("name", net_id)
        client = session.powervs_client(workspace_id=ws_id, region=region, workspace_crn=ws_crn)

        try:
            client.delete("/networks/%s" % net_id)
            log.info("Deleted PowerVS network %s (%s)", net_name, net_id)
        except Exception as exc:
            # Check for 409 Conflict (network in use)
            status_code = getattr(getattr(exc, "response", None), "status_code", None)
            if status_code == 409 or "409" in str(exc) or "conflict" in str(exc).lower():
                log.warning(
                    "Cannot delete PowerVS network %s (%s): network is currently in use by active instances (409 Conflict). "
                    "Tagging workspace for review.",
                    net_name,
                    net_id,
                )
                try:
                    tag_action = PowerVSNetworkTagAction(
                        {"type": "tag", "tags": {"custodian-warning": f"network-in-use:{net_name}"}},
                        self.manager,
                    )
                    tag_action.perform_action(resource)
                except Exception as tag_exc:
                    log.debug("Could not attach fallback tag for network %s: %s", net_id, tag_exc)
                return
            raise


# ---------------------------------------------------------------------------
# ibm.powervs-image
# ---------------------------------------------------------------------------

@sources.register("describe-powervs-images")
class PowerVSImageSource(PowerVSDescribeSource):
    path = "/images"
    result_key = "images"


@resources.register("powervs-image")
class PowerVSImage(QueryResourceManager):
    """IBM PowerVS OS images.

    :example:

    Find custom (non-stock) images older than 180 days:

    .. code-block:: yaml

        policies:
          - name: ibm-old-custom-images
            resource: ibm.powervs-image
            filters:
              - type: value
                key: imageType
                value: stock
                op: ne
              - type: age
                days: 180
    """

    source_mapping = {"describe-powervs-images": PowerVSImageSource}

    class resource_type(TypeInfo):
        service = "powervs"
        global_service = False
        enum_spec = (None, None, None)
        id = "imageID"
        name = "name"
        default_report_fields = (
            "imageID", "name", "state", "imageType", "storageType", "c7n:workspace_name"
        )
        permissions = ("power-iaas.pvm-instance-image.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-powervs-images")


@PowerVSImage.filter_registry.register("age")
class PowerVSImageAgeFilter(AgeFilter):
    date_attribute = "creationDate"


@PowerVSImage.filter_registry.register("tag")
class PowerVSImageTagFilter(TagFilter):
    pass


@PowerVSImage.action_registry.register("tag")
class PowerVSImageTagAction(TagAction):
    """Attach tags to the parent PowerVS workspace on behalf of an image."""

    @staticmethod
    def _get_crn(resource):
        crn = TagAction._get_crn(resource)
        if crn:
            return crn
        return resource.get("c7n:workspace_crn")


@PowerVSImage.action_registry.register("remove-tag")
class PowerVSImageRemoveTagAction(RemoveTagAction):
    """Detach tags from the parent PowerVS workspace on behalf of an image."""

    def perform_action(self, resource):
        crn = resource.get("crn") or resource.get("c7n:workspace_crn")
        if not crn:
            log.warning("Resource %s has no CRN; skipping remove-tag action", resource.get("imageID", resource.get("id")))
            return

        session = local_session(self.manager.session_factory)
        client = session.client("global-tagging")

        from ibm_platform_services.global_tagging_v1 import Resource

        tag_names = self.data.get("tags", [])
        tag_type = getattr(self.manager.resource_type, "tag_type", "user")
        client.detach_tag(
            resources=[Resource(resource_id=crn)],
            tag_names=tag_names,
            tag_type=tag_type,
        )
        log.debug("Removed tags %s from workspace %s (tag_type=%s)", tag_names, crn, tag_type)


@PowerVSImage.action_registry.register("delete")
class PowerVSImageDelete(IBMBaseAction):
    """Delete a PowerVS image."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        ws_id = resource["c7n:workspace_id"]
        ws_crn = resource.get("c7n:workspace_crn", "")
        region = resource.get("c7n:region", session.region)
        client = session.powervs_client(workspace_id=ws_id, region=region, workspace_crn=ws_crn)
        client.delete("/images/%s" % resource["imageID"])
        log.debug("Deleted PowerVS image %s", resource["imageID"])


# ---------------------------------------------------------------------------
# ibm.powervs-ssh-key
# ---------------------------------------------------------------------------

@sources.register("describe-powervs-ssh-keys")
class PowerVSSSHKeySource(PowerVSDescribeSource):
    path = "/ssh-keys"
    result_key = "sshKeys"
    use_v1 = True


@resources.register("powervs-ssh-key")
class PowerVSSSHKey(QueryResourceManager):
    """IBM Cloud PowerVS SSH keys.

    Each workspace maintains its own set of SSH keys. Use the ``age`` filter to
    detect stale keys that should be rotated, or the ``value`` filter to find
    keys without an owner tag.
    """

    source_mapping = {"describe-powervs-ssh-keys": PowerVSSSHKeySource}

    class resource_type(TypeInfo):
        service = "powervs"
        global_service = False
        enum_spec = (None, None, None)
        id = "name"
        name = "name"
        default_report_fields = (
            "name", "sshKeyName", "creationDate", "c7n:workspace_name"
        )
        permissions = ("power-iaas.ssh-key.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-powervs-ssh-keys")


@PowerVSSSHKey.filter_registry.register("age")
class PowerVSSSHKeyAgeFilter(AgeFilter):
    date_attribute = "creationDate"


@PowerVSSSHKey.action_registry.register("tag")
class PowerVSSSHKeyTagAction(TagAction):
    """Attach tags to the parent PowerVS workspace on behalf of an SSH key."""

    @staticmethod
    def _get_crn(resource):
        crn = TagAction._get_crn(resource)
        if crn:
            return crn
        return resource.get("c7n:workspace_crn")


@PowerVSSSHKey.action_registry.register("remove-tag")
class PowerVSSSHKeyRemoveTagAction(RemoveTagAction):
    """Detach tags from the parent PowerVS workspace on behalf of an SSH key."""

    def perform_action(self, resource):
        crn = resource.get("crn") or resource.get("c7n:workspace_crn")
        if not crn:
            log.warning("Resource %s has no CRN; skipping remove-tag action", resource.get("name", resource.get("id")))
            return

        session = local_session(self.manager.session_factory)
        client = session.client("global-tagging")

        from ibm_platform_services.global_tagging_v1 import Resource

        tag_names = self.data.get("tags", [])
        tag_type = getattr(self.manager.resource_type, "tag_type", "user")
        client.detach_tag(
            resources=[Resource(resource_id=crn)],
            tag_names=tag_names,
            tag_type=tag_type,
        )
        log.debug("Removed tags %s from workspace %s (tag_type=%s)", tag_names, crn, tag_type)


@PowerVSSSHKey.action_registry.register("append-description")
class PowerVSSSHKeyAppendDescriptionAction(IBMBaseAction):
    """Append or set a custodian warning notice on a PowerVS SSH key's description.

    If the description is empty (or missing), sets the notice as the description.
    Updates the key description via the PowerVS REST API.

    .. code-block:: yaml

        policies:
          - name: powervs-ssh-key-empty-description
            resource: ibm.powervs-ssh-key
            filters:
              - type: value
                key: description
                op: eq
                value: ""
            actions:
              - type: append-description
                notice: "[custodian] No description provided — please document key owner and purpose."
    """

    type = "append-description"
    # IBM API allows only a-z A-Z 0-9 - _ and space in the description field.
    _ALLOWED_DESC_RE = None  # compiled lazily
    _DEFAULT_NOTICE = "[custodian] This SSH key requires review."
    schema = type_schema(
        "append-description",
        notice={"type": "string"},
        rinherit=IBMBaseAction.schema,
    )

    @staticmethod
    def _sanitize(text):
        """Replace characters not allowed by the PowerVS API with a space.

        The API accepts only ``[a-zA-Z0-9\\-_ ]`` in the description field;
        anything else (em dash, accented letters, special punctuation, …)
        returns a 400 Bad Request.
        """
        import re
        sanitized = re.sub(r"[^a-zA-Z0-9\-_ ]", " ", text)
        # Collapse runs of spaces that replacement may have introduced
        return re.sub(r" {2,}", " ", sanitized).strip()

    def perform_action(self, resource):
        # Keys with primaryWorkspace=False are shared from another workspace;
        # PUT returns 400 because we do not own them.
        if not resource.get("primaryWorkspace", True):
            log.debug(
                "Skipping append-description on PowerVS SSH key %s: not owned by this workspace "
                "(primaryWorkspace=False)",
                resource.get("name"),
            )
            return

        notice = self._sanitize(self.data.get("notice", self._DEFAULT_NOTICE))
        current_desc = resource.get("description") or ""
        if notice in current_desc:
            log.debug("Notice already present on PowerVS SSH key %s; skipping", resource.get("name"))
            return
        new_desc = self._sanitize(current_desc + " " + notice)

        session = local_session(self.manager.session_factory)
        ws_id = resource["c7n:workspace_id"]
        region = resource.get("c7n:region", session.region)
        ws_crn = resource.get("c7n:workspace_crn", "")
        client = session.powervs_client(workspace_id=ws_id, region=region, workspace_crn=ws_crn)

        # The v1 workspace SSH key endpoint uses the UUID 'id' field as the path parameter,
        # not the human-readable 'name'.  PUT /v1/ssh-keys/{id} accepts 'description'.
        key_id = resource.get("id") or resource.get("name") or resource.get("sshKeyName")
        try:
            client.put("/ssh-keys/%s" % key_id, {"description": new_desc}, v1=True)
            log.debug("Updated description on PowerVS SSH key %s: %r", key_id, new_desc)
        except Exception as exc:
            log.warning("Could not update description on PowerVS SSH key %s: %s", key_id, exc)


@PowerVSSSHKey.action_registry.register("delete")
class PowerVSSSHKeyDelete(IBMBaseAction):
    """Delete a PowerVS SSH key from its workspace."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        # Keys with primaryWorkspace=False are shared from another workspace;
        # only the owning workspace can delete them.
        if not resource.get("primaryWorkspace", True):
            log.warning(
                "Skipping delete of PowerVS SSH key %s: not owned by this workspace "
                "(primaryWorkspace=False)",
                resource.get("name"),
            )
            return
        session = local_session(self.manager.session_factory)
        ws_id = resource["c7n:workspace_id"]
        region = resource.get("c7n:region", session.region)
        ws_crn = resource.get("c7n:workspace_crn", "")
        client = session.powervs_client(workspace_id=ws_id, region=region, workspace_crn=ws_crn)
        key_id = resource.get("id") or resource.get("name") or resource.get("sshKeyName")
        client.delete("/ssh-keys/%s" % key_id, v1=True)
        log.debug("Deleted PowerVS SSH key %s from workspace %s", key_id, ws_id)

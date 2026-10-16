# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Cloud VPC Infrastructure resources.

Covers all 19 resource types from the VPC API:
- ibm.vpc-instance          — Virtual server instances
- ibm.vpc-network           — VPC networks
- ibm.vpc-subnet            — Subnets
- ibm.vpc-security-group    — Security groups
- ibm.vpc-floating-ip       — Floating IPs
- ibm.vpc-volume            — Block storage volumes
- ibm.vpc-load-balancer     — Load balancers
- ibm.vpc-public-gateway    — Public gateways
- ibm.vpc-network-acl       — Network ACLs
- ibm.vpc-vpn-gateway       — VPN gateways
- ibm.vpc-bare-metal        — Bare metal servers
- ibm.vpc-dedicated-host    — Dedicated hosts
- ibm.vpc-file-share        — File Storage shares (VPC)
- ibm.vpc-ssh-key           — SSH keys
- ibm.vpc-instance-group    — Instance groups
- ibm.vpc-instance-template — Instance templates
- ibm.vpc-snapshot          — Block storage snapshots
- ibm.vpc-backup-policy     — Backup policies
- ibm.vpc-transit-gateway   — Transit gateways (via thin REST client)

VPC is a regional service; the session layer sets the endpoint URL based on
the active region. Each resource's list method uses the start/limit cursor
pagination pattern.

Tag augmentation
----------------
IBM Cloud VPC resources do NOT include tags in their API responses.  Tags are
managed globally via ``GlobalTaggingV1`` and must be fetched separately using
``list_tags(attached_to=<crn>, tag_type="user")``.

``augment_tags()`` is called automatically by every VPC ``QueryResourceManager``
subclass that has a CRN field.  It fetches user tags for every resource in the
current batch concurrently (thread pool, max 10 workers) and injects them as
the ``tags`` list field expected by :class:`~c7n_ibmcloud.filters.base.TagFilter`.
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from c7n.utils import local_session, type_schema

from c7n_ibmcloud.actions.base import (
    IBMBaseAction,
    TagAction,
    RemoveTagAction,
    MarkForOpAction,
)
from c7n_ibmcloud.filters.base import (
    TagFilter,
    MarkedForOpFilter,
    AgeFilter,
    ResourceGroupFilter,
)
from c7n_ibmcloud.provider import resources
from c7n_ibmcloud.query import QueryResourceManager, TypeInfo, DescribeSource, sources

log = logging.getLogger("custodian.ibm.vpc")

# Maximum parallel tag-fetch workers per augment() call
_TAG_WORKERS = 10


def _fetch_tags_for_crn(tagging_client, crn, tag_type="user"):
    """Return a list of tag-name strings for a single resource CRN.

    Parameters
    ----------
    tag_type:
        ``"user"`` for Resource Controller resources (VPC, COS, ICD, KMS).
        ``"access"`` for IAM Identity resources (service-id, api-key, profile,
        access-group) which are not registered in the Resource Controller.
    """
    tags = []
    offset = 0
    limit = 100
    while True:
        try:
            result = tagging_client.list_tags(
                attached_to=crn,
                tag_type=tag_type,
                offset=offset,
                limit=limit,
            ).get_result()
        except Exception as exc:
            log.debug("list_tags failed for CRN %s: %s", crn, exc)
            break
        items = result.get("items", [])
        tags.extend(item["name"] for item in items)
        # Stop if we got fewer items than we asked for
        if len(items) < limit:
            break
        offset += limit
    return tags


def augment_with_tags(resources, session, tag_type="user"):
    """Inject ``tags`` list into each resource dict by fetching from GlobalTaggingV1.

    Resources without a ``crn`` field are left unchanged (tags=[]).
    Uses a thread pool for concurrent fetching.

    Parameters
    ----------
    tag_type:
        Passed through to ``_fetch_tags_for_crn``.  Use ``"access"`` for IAM
        Identity resources; ``"user"`` (default) for everything else.
    """
    # Only augment resources that have a CRN
    crn_resources = [(i, r) for i, r in enumerate(resources) if r.get("crn")]
    if not crn_resources:
        # No CRNs at all — still ensure every resource has a tags list
        return [dict(r, tags=r.get("tags", [])) for r in resources]

    try:
        tagging_client = session.client("global-tagging")
    except Exception as exc:
        log.warning("Could not create GlobalTaggingV1 client: %s", exc)
        for _, r in crn_resources:
            r.setdefault("tags", [])
        return resources

    def _fetch(idx_crn):
        idx, r = idx_crn
        crn = r["crn"]
        return idx, _fetch_tags_for_crn(tagging_client, crn, tag_type=tag_type)

    results = list(resources)  # shallow copy to avoid mutating caller's list
    with ThreadPoolExecutor(max_workers=_TAG_WORKERS) as pool:
        futures = {pool.submit(_fetch, (i, r)): i for i, r in crn_resources}
        for future in as_completed(futures):
            try:
                idx, tags = future.result()
                results[idx] = dict(results[idx])
                results[idx]["tags"] = tags
            except Exception as exc:
                log.debug("Tag fetch future failed: %s", exc)

    # Ensure every resource has a tags list (even those without CRN)
    for i, r in enumerate(results):
        if "tags" not in r:
            results[i] = dict(r)
            results[i]["tags"] = []

    return results


# ---------------------------------------------------------------------------
# VPC describe source with tag augmentation
# ---------------------------------------------------------------------------

@sources.register("describe-vpc")
class VPCDescribeSource(DescribeSource):
    """Describe source for VPC resources.

    Delegates enumeration to the default IBM query layer, then augments each
    resource with its user tags fetched from GlobalTaggingV1.
    """

    def augment(self, resources):
        if not resources:
            return resources
        session = local_session(self.manager.session_factory)
        tag_type = getattr(self.manager.resource_type, "tag_type", "user")
        return augment_with_tags(resources, session, tag_type=tag_type)


# ---------------------------------------------------------------------------
# Helper: VPC instance actions
# ---------------------------------------------------------------------------

class VPCInstanceBaseAction(IBMBaseAction):
    """Common base for VPC instance start/stop/reboot actions."""

    _vpc_action = None  # subclasses set to "stop", "start", "reboot"

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        method = getattr(client, "create_instance_action")
        method(
            instance_id=resource["id"],
            type=self._vpc_action,
        )
        log.debug("%s instance %s", self._vpc_action, resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-instance
# ---------------------------------------------------------------------------

@resources.register("vpc-instance")
class VPCInstance(QueryResourceManager):
    """IBM Cloud VPC virtual server instances.

    :example:

    Find running instances without the ``environment`` tag:

    .. code-block:: yaml

        policies:
          - name: ibm-vpc-untagged-instances
            resource: ibm.vpc-instance
            filters:
              - type: tag
                key: environment
                op: absent
    """

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_instances", "instances", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "status", "zone.name", "created_at", "crn")
        permissions = ("is.instance.instance.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCInstance.filter_registry.register("tag")
class VPCInstanceTagFilter(TagFilter):
    pass


@VPCInstance.filter_registry.register("marked-for-op")
class VPCInstanceMarkedFilter(MarkedForOpFilter):
    pass


@VPCInstance.filter_registry.register("age")
class VPCInstanceAgeFilter(AgeFilter):
    date_attribute = "created_at"


@VPCInstance.filter_registry.register("resource-group")
class VPCInstanceRGFilter(ResourceGroupFilter):
    pass


@VPCInstance.action_registry.register("stop")
class VPCInstanceStop(VPCInstanceBaseAction):
    """Stop a running VPC instance.

    .. code-block:: yaml

        policies:
          - name: stop-dev-instances
            resource: ibm.vpc-instance
            filters:
              - type: tag
                key: environment
                value: dev
            actions:
              - stop
    """

    type = "stop"
    _vpc_action = "stop"
    schema = type_schema("stop", rinherit=IBMBaseAction.schema)


@VPCInstance.action_registry.register("start")
class VPCInstanceStart(VPCInstanceBaseAction):
    """Start a stopped VPC instance."""

    type = "start"
    _vpc_action = "start"
    schema = type_schema("start", rinherit=IBMBaseAction.schema)


@VPCInstance.action_registry.register("reboot")
class VPCInstanceReboot(VPCInstanceBaseAction):
    """Reboot a VPC instance."""

    type = "reboot"
    _vpc_action = "reboot"
    schema = type_schema("reboot", rinherit=IBMBaseAction.schema)


@VPCInstance.action_registry.register("delete")
class VPCInstanceDelete(IBMBaseAction):
    """Delete a VPC instance."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_instance(id=resource["id"])
        log.debug("Deleted VPC instance %s", resource["id"])


@VPCInstance.action_registry.register("tag")
class VPCInstanceTagAction(TagAction):
    pass


@VPCInstance.action_registry.register("remove-tag")
class VPCInstanceRemoveTagAction(RemoveTagAction):
    pass


@VPCInstance.action_registry.register("mark-for-op")
class VPCInstanceMarkForOpAction(MarkForOpAction):
    pass


# ---------------------------------------------------------------------------
# ibm.vpc-network
# ---------------------------------------------------------------------------

@resources.register("vpc-network")
class VPCNetwork(QueryResourceManager):
    """IBM Cloud VPC networks."""

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_vpcs", "vpcs", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "status", "created_at", "crn")
        permissions = ("is.vpc.vpc.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCNetwork.filter_registry.register("tag")
class VPCNetworkTagFilter(TagFilter):
    pass


@VPCNetwork.filter_registry.register("resource-group")
class VPCNetworkRGFilter(ResourceGroupFilter):
    pass


@VPCNetwork.action_registry.register("tag")
class VPCNetworkTagAction(TagAction):
    pass


@VPCNetwork.action_registry.register("remove-tag")
class VPCNetworkRemoveTagAction(RemoveTagAction):
    pass


@VPCNetwork.action_registry.register("delete")
class VPCNetworkDelete(IBMBaseAction):
    """Delete a VPC network."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_vpc(id=resource["id"])
        log.debug("Deleted VPC %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-subnet
# ---------------------------------------------------------------------------

@resources.register("vpc-subnet")
class VPCSubnet(QueryResourceManager):
    """IBM Cloud VPC subnets."""

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_subnets", "subnets", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "status", "zone.name", "ipv4_cidr_block", "crn")
        permissions = ("is.subnet.subnet.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCSubnet.filter_registry.register("tag")
class VPCSubnetTagFilter(TagFilter):
    pass


@VPCSubnet.filter_registry.register("resource-group")
class VPCSubnetRGFilter(ResourceGroupFilter):
    pass


@VPCSubnet.action_registry.register("tag")
class VPCSubnetTagAction(TagAction):
    pass


@VPCSubnet.action_registry.register("delete")
class VPCSubnetDelete(IBMBaseAction):
    """Delete a VPC subnet."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_subnet(id=resource["id"])
        log.debug("Deleted subnet %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-security-group
# ---------------------------------------------------------------------------

@resources.register("vpc-security-group")
class VPCSecurityGroup(QueryResourceManager):
    """IBM Cloud VPC security groups."""

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_security_groups", "security_groups", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "crn", "created_at")
        permissions = ("is.security-group.security-group.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCSecurityGroup.filter_registry.register("tag")
class VPCSecurityGroupTagFilter(TagFilter):
    pass


@VPCSecurityGroup.filter_registry.register("resource-group")
class VPCSecurityGroupRGFilter(ResourceGroupFilter):
    pass


@VPCSecurityGroup.action_registry.register("tag")
class VPCSecurityGroupTagAction(TagAction):
    pass


@VPCSecurityGroup.action_registry.register("delete")
class VPCSecurityGroupDelete(IBMBaseAction):
    """Delete a VPC security group."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_security_group(id=resource["id"])
        log.debug("Deleted security group %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-floating-ip
# ---------------------------------------------------------------------------

@resources.register("vpc-floating-ip")
class VPCFloatingIP(QueryResourceManager):
    """IBM Cloud VPC floating IPs.

    IBM VPC API status values (``FloatingIP.StatusEnum``):

    * ``"available"`` — not attached to any resource (orphaned, incurring cost).
    * ``"pending"``   — in the process of being provisioned.
    * ``"deleting"``  — in the process of being deleted.
    * ``"failed"``    — provisioning failed.

    Use ``status == "available"`` to find unattached floating IPs.
    The ``target`` field is absent when the IP is not bound to an instance.
    """

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_floating_ips", "floating_ips", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "address", "status", "crn")
        permissions = ("is.floating-ip.floating-ip.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCFloatingIP.filter_registry.register("tag")
class VPCFloatingIPTagFilter(TagFilter):
    pass


@VPCFloatingIP.action_registry.register("tag")
class VPCFloatingIPTagAction(TagAction):
    pass


@VPCFloatingIP.action_registry.register("release")
class VPCFloatingIPRelease(IBMBaseAction):
    """Detach (if bound) and release a floating IP.

    If the floating IP has a ``target`` field it is attached to a resource.
    The action detaches it first, then deletes it.  Detach behaviour depends
    on ``target.resource_type``:

    * ``"network_interface"`` (VSI NIC) — calls
      ``remove_instance_network_interface_floating_ip``.  The instance ID is
      parsed from ``target.href``.
    * ``"network_interface"`` (BMS NIC) — calls
      ``remove_bare_metal_server_network_interface_floating_ip``.  The BMS ID
      is parsed from ``target.href``.
    * ``"virtual_network_interface"`` — calls
      ``remove_network_interface_floating_ip``.
    * ``"public_gateway"`` — floating IPs on public gateways cannot be
      independently detached; the action logs a warning and skips deletion.
    """

    type = "release"
    schema = type_schema("release", rinherit=IBMBaseAction.schema)

    # Regex patterns to extract parent resource ID from a NIC href
    _INSTANCE_NIC_RE = re.compile(r"/instances/([^/]+)/network_interfaces/")
    _BMS_NIC_RE = re.compile(r"/bare_metal_servers/([^/]+)/network_interfaces/")

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        fip_id = resource["id"]

        target = resource.get("target")
        if target:
            detached = self._detach(client, fip_id, target)
            if not detached:
                return  # logged inside _detach; skip deletion

        client.delete_floating_ip(id=fip_id)
        log.debug("Released floating IP %s", fip_id)

    def _detach(self, client, fip_id, target):
        """Detach the floating IP from its target.  Returns True on success."""
        resource_type = target.get("resource_type", "")
        nic_id = target.get("id", "")
        href = target.get("href", "")

        if resource_type == "public_gateway":
            log.warning(
                "Floating IP %s is attached to a public gateway (%s); "
                "it cannot be independently detached — skipping.",
                fip_id, target.get("name", nic_id),
            )
            return False

        if resource_type == "virtual_network_interface":
            client.remove_network_interface_floating_ip(
                virtual_network_interface_id=nic_id,
                id=fip_id,
            )
            log.debug("Detached FIP %s from virtual network interface %s", fip_id, nic_id)
            return True

        # resource_type == "network_interface" — could be VSI or BMS
        m_instance = self._INSTANCE_NIC_RE.search(href)
        if m_instance:
            client.remove_instance_network_interface_floating_ip(
                instance_id=m_instance.group(1),
                network_interface_id=nic_id,
                id=fip_id,
            )
            log.debug(
                "Detached FIP %s from instance %s NIC %s",
                fip_id, m_instance.group(1), nic_id,
            )
            return True

        m_bms = self._BMS_NIC_RE.search(href)
        if m_bms:
            client.remove_bare_metal_server_network_interface_floating_ip(
                bare_metal_server_id=m_bms.group(1),
                network_interface_id=nic_id,
                id=fip_id,
            )
            log.debug(
                "Detached FIP %s from BMS %s NIC %s",
                fip_id, m_bms.group(1), nic_id,
            )
            return True

        log.warning(
            "Floating IP %s has unrecognised target href %r (resource_type=%r); skipping.",
            fip_id, href, resource_type,
        )
        return False


# ---------------------------------------------------------------------------
# ibm.vpc-volume
# ---------------------------------------------------------------------------

@resources.register("vpc-volume")
class VPCVolume(QueryResourceManager):
    """IBM Cloud VPC block storage volumes."""

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_volumes", "volumes", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "status", "zone.name", "capacity", "crn")
        permissions = ("is.volume.volume.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCVolume.filter_registry.register("age")
class VPCVolumeAgeFilter(AgeFilter):
    date_attribute = "created_at"


@VPCVolume.filter_registry.register("tag")
class VPCVolumeTagFilter(TagFilter):
    pass


@VPCVolume.filter_registry.register("resource-group")
class VPCVolumeRGFilter(ResourceGroupFilter):
    pass


@VPCVolume.action_registry.register("tag")
class VPCVolumeTagAction(TagAction):
    pass


@VPCVolume.action_registry.register("delete")
class VPCVolumeDelete(IBMBaseAction):
    """Delete a VPC block storage volume."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_volume(id=resource["id"])
        log.debug("Deleted volume %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-load-balancer
# ---------------------------------------------------------------------------

@resources.register("vpc-load-balancer")
class VPCLoadBalancer(QueryResourceManager):
    """IBM Cloud VPC load balancers."""

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_load_balancers", "load_balancers", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "provisioning_status", "crn")
        permissions = ("is.load-balancer.load-balancer.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCLoadBalancer.filter_registry.register("tag")
class VPCLBTagFilter(TagFilter):
    pass


@VPCLoadBalancer.action_registry.register("tag")
class VPCLBTagAction(TagAction):
    pass


@VPCLoadBalancer.action_registry.register("delete")
class VPCLBDelete(IBMBaseAction):
    """Delete a VPC load balancer."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_load_balancer(id=resource["id"])
        log.debug("Deleted load balancer %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-public-gateway
# ---------------------------------------------------------------------------

@resources.register("vpc-public-gateway")
class VPCPublicGateway(QueryResourceManager):
    """IBM Cloud VPC public gateways."""

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_public_gateways", "public_gateways", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "status", "zone.name", "crn")
        permissions = ("is.public-gateway.public-gateway.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCPublicGateway.filter_registry.register("tag")
class VPCPGTagFilter(TagFilter):
    pass


@VPCPublicGateway.action_registry.register("tag")
class VPCPGTagAction(TagAction):
    pass


@VPCPublicGateway.action_registry.register("delete")
class VPCPGDelete(IBMBaseAction):
    """Delete a VPC public gateway."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_public_gateway(id=resource["id"])
        log.debug("Deleted public gateway %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-network-acl
# ---------------------------------------------------------------------------

@resources.register("vpc-network-acl")
class VPCNetworkACL(QueryResourceManager):
    """IBM Cloud VPC network ACLs."""

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_network_acls", "network_acls", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "crn")
        permissions = ("is.network-acl.network-acl.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCNetworkACL.filter_registry.register("tag")
class VPCNACLTagFilter(TagFilter):
    pass


@VPCNetworkACL.filter_registry.register("resource-group")
class VPCNACLRGFilter(ResourceGroupFilter):
    pass


@VPCNetworkACL.action_registry.register("tag")
class VPCNACLTagAction(TagAction):
    pass


@VPCNetworkACL.action_registry.register("delete")
class VPCNACLDelete(IBMBaseAction):
    """Delete a VPC network ACL."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_network_acl(id=resource["id"])
        log.debug("Deleted network ACL %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-vpn-gateway
# ---------------------------------------------------------------------------

@resources.register("vpc-vpn-gateway")
class VPCVPNGateway(QueryResourceManager):
    """IBM Cloud VPC VPN gateways."""

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_vpn_gateways", "vpn_gateways", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "status", "created_at", "crn")
        permissions = ("is.vpn.vpn-gateway.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCVPNGateway.filter_registry.register("tag")
class VPCVPNTagFilter(TagFilter):
    pass


@VPCVPNGateway.action_registry.register("tag")
class VPCVPNTagAction(TagAction):
    pass


@VPCVPNGateway.action_registry.register("delete")
class VPCVPNDelete(IBMBaseAction):
    """Delete a VPC VPN gateway."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_vpn_gateway(id=resource["id"])
        log.debug("Deleted VPN gateway %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-bare-metal
# ---------------------------------------------------------------------------

@resources.register("vpc-bare-metal")
class VPCBareMetal(QueryResourceManager):
    """IBM Cloud VPC bare metal servers."""

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_bare_metal_servers", "bare_metal_servers", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "status", "zone", "crn")
        permissions = ("is.bare-metal-server.bare-metal-server.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCBareMetal.filter_registry.register("tag")
class VPCBareMetalTagFilter(TagFilter):
    pass


@VPCBareMetal.filter_registry.register("resource-group")
class VPCBareMetalRGFilter(ResourceGroupFilter):
    pass


@VPCBareMetal.filter_registry.register("age")
class VPCBareMetalAgeFilter(AgeFilter):
    date_attribute = "created_at"


@VPCBareMetal.action_registry.register("tag")
class VPCBareMetalTagAction(TagAction):
    pass


@VPCBareMetal.action_registry.register("remove-tag")
class VPCBareMetalRemoveTagAction(RemoveTagAction):
    pass


@VPCBareMetal.action_registry.register("delete")
class VPCBareMetalDelete(IBMBaseAction):
    """Delete a VPC bare metal server."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_bare_metal_server(id=resource["id"])
        log.debug("Deleted bare metal server %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-dedicated-host
# ---------------------------------------------------------------------------

@resources.register("vpc-dedicated-host")
class VPCDedicatedHost(QueryResourceManager):
    """IBM Cloud VPC dedicated hosts."""

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_dedicated_hosts", "dedicated_hosts", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "state", "zone", "crn")
        permissions = ("is.dedicated-host.dedicated-host.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCDedicatedHost.filter_registry.register("tag")
class VPCDedicatedHostTagFilter(TagFilter):
    pass


@VPCDedicatedHost.filter_registry.register("resource-group")
class VPCDedicatedHostRGFilter(ResourceGroupFilter):
    pass


@VPCDedicatedHost.filter_registry.register("age")
class VPCDedicatedHostAgeFilter(AgeFilter):
    date_attribute = "created_at"


@VPCDedicatedHost.action_registry.register("tag")
class VPCDedicatedHostTagAction(TagAction):
    pass


@VPCDedicatedHost.action_registry.register("remove-tag")
class VPCDedicatedHostRemoveTagAction(RemoveTagAction):
    pass


@VPCDedicatedHost.action_registry.register("delete")
class VPCDedicatedHostDelete(IBMBaseAction):
    """Delete a VPC dedicated host."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_dedicated_host(id=resource["id"])
        log.debug("Deleted dedicated host %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-file-share
# ---------------------------------------------------------------------------

@resources.register("vpc-file-share")
class VPCFileShare(QueryResourceManager):
    """IBM Cloud VPC File Storage shares."""

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_shares", "shares", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "lifecycle_state", "size", "crn")
        permissions = ("is.share.share.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCFileShare.filter_registry.register("tag")
class VPCFileShareTagFilter(TagFilter):
    pass


@VPCFileShare.filter_registry.register("resource-group")
class VPCFileShareRGFilter(ResourceGroupFilter):
    pass


@VPCFileShare.filter_registry.register("age")
class VPCFileShareAgeFilter(AgeFilter):
    date_attribute = "created_at"


@VPCFileShare.action_registry.register("tag")
class VPCFileShareTagAction(TagAction):
    pass


@VPCFileShare.action_registry.register("remove-tag")
class VPCFileShareRemoveTagAction(RemoveTagAction):
    pass


@VPCFileShare.action_registry.register("delete")
class VPCFileShareDelete(IBMBaseAction):
    """Delete a VPC file share."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_share(id=resource["id"])
        log.debug("Deleted file share %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-ssh-key
# ---------------------------------------------------------------------------

@resources.register("vpc-ssh-key")
class VPCSSHKey(QueryResourceManager):
    """IBM Cloud VPC SSH keys."""

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_keys", "keys", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "type", "fingerprint", "crn")
        permissions = ("is.key.key.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCSSHKey.filter_registry.register("tag")
class VPCSSHKeyTagFilter(TagFilter):
    pass


@VPCSSHKey.filter_registry.register("resource-group")
class VPCSSHKeyRGFilter(ResourceGroupFilter):
    pass


@VPCSSHKey.filter_registry.register("age")
class VPCSSHKeyAgeFilter(AgeFilter):
    date_attribute = "created_at"


@VPCSSHKey.action_registry.register("tag")
class VPCSSHKeyTagAction(TagAction):
    pass


@VPCSSHKey.action_registry.register("remove-tag")
class VPCSSHKeyRemoveTagAction(RemoveTagAction):
    pass


@VPCSSHKey.action_registry.register("append-description")
class VPCSSHKeyAppendDescriptionAction(IBMBaseAction):
    """Append or set a custodian warning notice on a VPC SSH key's name / tag.

    VPC Key objects in IBM Cloud VPC API don't have a mutable description field,
    so this action tags the key with the custodian review notice.
    """

    type = "append-description"
    _DEFAULT_NOTICE = "[custodian] This SSH key requires review."
    schema = type_schema(
        "append-description",
        notice={"type": "string"},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        notice = self.data.get("notice", self._DEFAULT_NOTICE)
        tag_action = VPCSSHKeyTagAction({"type": "tag", "tags": {"custodian-warning": notice}}, self.manager)
        tag_action.perform_action(resource)


@VPCSSHKey.action_registry.register("delete")
class VPCSSHKeyDelete(IBMBaseAction):
    """Delete a VPC SSH key."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_key(id=resource["id"])
        log.debug("Deleted SSH key %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-instance-group
# ---------------------------------------------------------------------------

@resources.register("vpc-instance-group")
class VPCInstanceGroup(QueryResourceManager):
    """IBM Cloud VPC instance groups.

    Use the ``value`` filter to detect empty groups (membership_count == 0),
    which indicates unused instance groups wasting capacity or config.
    """

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_instance_groups", "instance_groups", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "status", "membership_count", "crn")
        permissions = ("is.instance-group.instance-group.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCInstanceGroup.filter_registry.register("tag")
class VPCInstanceGroupTagFilter(TagFilter):
    pass


@VPCInstanceGroup.filter_registry.register("resource-group")
class VPCInstanceGroupRGFilter(ResourceGroupFilter):
    pass


@VPCInstanceGroup.action_registry.register("tag")
class VPCInstanceGroupTagAction(TagAction):
    pass


@VPCInstanceGroup.action_registry.register("delete")
class VPCInstanceGroupDelete(IBMBaseAction):
    """Delete a VPC instance group."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_instance_group(instance_group_id=resource["id"])
        log.debug("Deleted instance group %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-instance-template
# ---------------------------------------------------------------------------

@resources.register("vpc-instance-template")
class VPCInstanceTemplate(QueryResourceManager):
    """IBM Cloud VPC instance templates.

    Use the ``value`` filter to detect templates not referenced by any
    instance group:
      ``key: id  op: ni  value_from: <instance-group-templates-list>``

    Or simply audit templates older than a threshold — templates are rarely
    deleted and tend to accumulate stale configuration.
    """

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        # InstanceTemplateCollection uses key "templates" (not "instance_templates").
        # list_instance_templates() accepts NO pagination parameters (limit/start) —
        # it returns all templates in a single call. pagination must be None.
        enum_spec = ("list_instance_templates", "templates", None)
        pagination = None
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "crn")
        permissions = ("is.instance.instance-template.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCInstanceTemplate.filter_registry.register("tag")
class VPCInstanceTemplateTagFilter(TagFilter):
    pass


@VPCInstanceTemplate.filter_registry.register("resource-group")
class VPCInstanceTemplateRGFilter(ResourceGroupFilter):
    pass


@VPCInstanceTemplate.filter_registry.register("age")
class VPCInstanceTemplateAgeFilter(AgeFilter):
    date_attribute = "created_at"


@VPCInstanceTemplate.action_registry.register("tag")
class VPCInstanceTemplateTagAction(TagAction):
    pass


@VPCInstanceTemplate.action_registry.register("delete")
class VPCInstanceTemplateDelete(IBMBaseAction):
    """Delete a VPC instance template."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_instance_template(id=resource["id"])
        log.debug("Deleted instance template %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-snapshot
# ---------------------------------------------------------------------------

from c7n.filters import Filter as _Filter  # noqa: E402


@resources.register("vpc-snapshot")
class VPCSnapshot(QueryResourceManager):
    """IBM Cloud VPC block storage snapshots.

    Use the ``orphaned`` filter to find snapshots whose source volume
    has been deleted (``source_volume`` field is absent or null).
    """

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_snapshots", "snapshots", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "lifecycle_state", "size", "crn")
        permissions = ("is.snapshot.snapshot.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCSnapshot.filter_registry.register("tag")
class VPCSnapshotTagFilter(TagFilter):
    pass


@VPCSnapshot.filter_registry.register("resource-group")
class VPCSnapshotRGFilter(ResourceGroupFilter):
    pass


@VPCSnapshot.filter_registry.register("age")
class VPCSnapshotAgeFilter(AgeFilter):
    date_attribute = "created_at"


@VPCSnapshot.filter_registry.register("orphaned")
class VPCSnapshotOrphanedFilter(_Filter):
    """Match snapshots whose source volume no longer exists.

    The VPC API sets ``source_volume`` to ``null`` (absent from the JSON) once
    the origin volume is deleted, making the snapshot unreachable for restore.

    .. code-block:: yaml

        policies:
          - name: ibm-vpc-orphaned-snapshots
            resource: ibm.vpc-snapshot
            filters:
              - type: orphaned
    """

    type = "orphaned"
    schema = type_schema("orphaned")

    def process(self, resources, event=None):
        return [r for r in resources if not r.get("source_volume")]


@VPCSnapshot.action_registry.register("tag")
class VPCSnapshotTagAction(TagAction):
    pass


@VPCSnapshot.action_registry.register("delete")
class VPCSnapshotDelete(IBMBaseAction):
    """Delete a VPC snapshot."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_snapshot(id=resource["id"])
        log.debug("Deleted snapshot %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-backup-policy
# ---------------------------------------------------------------------------

@resources.register("vpc-backup-policy")
class VPCBackupPolicy(QueryResourceManager):
    """IBM Cloud VPC backup policies.

    Use the ``unused`` filter to detect backup policies that have no plans
    defined, meaning they were created but never configured.

    .. code-block:: yaml

        policies:
          - name: ibm-vpc-unconfigured-backup-policies
            resource: ibm.vpc-backup-policy
            filters:
              - type: unused
    """

    source_mapping = {"describe-vpc": VPCDescribeSource}

    class resource_type(TypeInfo):
        service = "vpc"
        global_service = False
        enum_spec = ("list_backup_policies", "backup_policies", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "lifecycle_state", "crn")
        permissions = ("is.backup-policy.backup-policy.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-vpc")


@VPCBackupPolicy.filter_registry.register("tag")
class VPCBackupPolicyTagFilter(TagFilter):
    pass


@VPCBackupPolicy.filter_registry.register("resource-group")
class VPCBackupPolicyRGFilter(ResourceGroupFilter):
    pass


@VPCBackupPolicy.filter_registry.register("unused")
class VPCBackupPolicyUnusedFilter(_Filter):
    """Match backup policies that have no plans configured.

    A backup policy with an empty ``plans`` list was created but never
    given a schedule — it protects nothing and should be reviewed or deleted.

    .. code-block:: yaml

        filters:
          - type: unused
    """

    type = "unused"
    schema = type_schema("unused")

    def process(self, resources, event=None):
        return [r for r in resources if not r.get("plans")]


@VPCBackupPolicy.action_registry.register("tag")
class VPCBackupPolicyTagAction(TagAction):
    pass


@VPCBackupPolicy.action_registry.register("delete")
class VPCBackupPolicyDelete(IBMBaseAction):
    """Delete a VPC backup policy."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("vpc")
        client.delete_backup_policy(id=resource["id"])
        log.debug("Deleted backup policy %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.vpc-transit-gateway
# ---------------------------------------------------------------------------

@sources.register("describe-transit-gateway")
class TransitGatewayDescribeSource(DescribeSource):
    """Describe source for Transit Gateways via thin REST client."""

    def get_resources(self, query):
        session = local_session(self.manager.session_factory)
        client = session.client("transit-gateway")
        all_gws = []
        limit = 50
        start = None
        while True:
            try:
                result = client.list_transit_gateways(limit=limit, start=start)
                gws = result.get("transit_gateways", [])
                all_gws.extend(gws)
                next_page = result.get("next")
                if not next_page:
                    break
                # next is {"href": "...?start=TOKEN&..."} — extract start token
                href = next_page.get("href", "") if isinstance(next_page, dict) else ""
                start = None
                for part in href.split("?", 1)[-1].split("&"):
                    if part.startswith("start="):
                        start = part[len("start="):]
                        break
                if not start:
                    break
            except Exception as exc:
                log.warning("Error listing transit gateways: %s", exc)
                break
        return all_gws

    def augment(self, resources):
        if not resources:
            return resources
        session = local_session(self.manager.session_factory)
        tag_type = getattr(self.manager.resource_type, "tag_type", "user")
        return augment_with_tags(resources, session, tag_type=tag_type)


@resources.register("vpc-transit-gateway")
class VPCTransitGateway(QueryResourceManager):
    """IBM Cloud Transit Gateways.

    Transit Gateways connect VPCs and classic networks across regions.
    Use the ``value`` filter on ``status`` or connection counts to detect
    gateways that are degraded or have no active connections.
    """

    source_mapping = {"describe-transit-gateway": TransitGatewayDescribeSource}

    class resource_type(TypeInfo):
        service = "transit-gateway"
        global_service = True
        enum_spec = ("list_transit_gateways", "transit_gateways", None)
        pagination = "cursor"
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "status", "location", "crn")
        permissions = ("transit.gateway.list",)
        scope = "account"

    @property
    def source_type(self):
        return self.data.get("source", "describe-transit-gateway")


@VPCTransitGateway.filter_registry.register("tag")
class VPCTransitGatewayTagFilter(TagFilter):
    pass


@VPCTransitGateway.filter_registry.register("age")
class VPCTransitGatewayAgeFilter(AgeFilter):
    date_attribute = "created_at"


@VPCTransitGateway.action_registry.register("tag")
class VPCTransitGatewayTagAction(TagAction):
    pass


@VPCTransitGateway.action_registry.register("delete")
class VPCTransitGatewayDelete(IBMBaseAction):
    """Delete a Transit Gateway."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("transit-gateway")
        client.delete_transit_gateway(resource["id"])
        log.debug("Deleted transit gateway %s", resource["id"])

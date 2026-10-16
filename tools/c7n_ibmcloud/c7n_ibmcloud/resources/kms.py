# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Cloud Key Protect resources.

Key Protect uses a dedicated REST API with offset/limit pagination.
All API calls require a Key Protect **instance ID** (the GUID of the
service instance, not the CRN).

Instance discovery
------------------
Key Protect instances are enumerated via ``ResourceControllerV2`` filtered by
the ``kms`` service name.  The ``KMSDescribeSource`` then calls
``get_keys(instance_id=...)`` for each instance and annotates every key with
``c7n:instance_id`` so that actions can identify which instance to target.

A single instance ID can also be pinned via the ``IBMCLOUD_KMS_INSTANCE_ID``
environment variable to skip the RC discovery step.

- ibm.kms-key      — Encryption keys managed by Key Protect
- ibm.kms-key-ring — Key rings (logical groupings of keys)
"""

import logging
import os

from c7n.filters import Filter
from c7n.utils import local_session, type_schema

from c7n_ibmcloud.actions.base import IBMBaseAction, TagAction, RemoveTagAction
from c7n_ibmcloud.filters.base import TagFilter, AgeFilter
from c7n_ibmcloud.provider import resources
from c7n_ibmcloud.query import QueryResourceManager, TypeInfo, DescribeSource, sources

log = logging.getLogger("custodian.ibm.kms")

# IBM Resource Catalog service name for Key Protect
KMS_RC_SERVICE_NAME = "kms"
# IBM Resource Catalog service name for Hyper Protect Crypto Services (HPCS)
HPCS_RC_SERVICE_NAME = "hs-crypto"


def _list_kms_instance_ids(session):
    """Return a list of (guid, name) tuples for all Key Protect instances in the account.

    Checks ``IBMCLOUD_KMS_INSTANCE_ID`` env var first; falls back to RC discovery.
    """
    env_id = os.environ.get("IBMCLOUD_KMS_INSTANCE_ID", "").strip()
    if env_id:
        return [(env_id, "")]

    try:
        rc = session.client("resource-ctrl")
        guids = []
        seen = set()

        def _collect(resp):
            for inst in resp.get("resources", []):
                guid = inst.get("guid", inst.get("id"))
                crn = inst.get("crn", "")
                # Match kms / hs-crypto service instances
                if guid and guid not in seen:
                    if (
                        inst.get("resource_id") in (KMS_RC_SERVICE_NAME, HPCS_RC_SERVICE_NAME)
                        or f":{KMS_RC_SERVICE_NAME}:" in crn
                        or f":{HPCS_RC_SERVICE_NAME}:" in crn
                    ):
                        seen.add(guid)
                        guids.append((guid, inst.get("name", "")))

        for svc in (KMS_RC_SERVICE_NAME, HPCS_RC_SERVICE_NAME):
            start = None
            while True:
                kw = {"resource_id": svc, "limit": 50}
                if start:
                    kw["start"] = start
                resp = rc.list_resource_instances(**kw).get_result()
                _collect(resp)
                next_url = resp.get("next_url")
                if not next_url:
                    break
                for part in next_url.split("?", 1)[-1].split("&"):
                    if part.startswith("start="):
                        start = part[len("start="):]
                        break
                else:
                    break

        # Fallback: list all service instances if resource_id filter returned nothing
        if not guids:
            start = None
            while True:
                kw = {"type": "service_instance", "limit": 50}
                if start:
                    kw["start"] = start
                resp = rc.list_resource_instances(**kw).get_result()
                _collect(resp)
                next_url = resp.get("next_url")
                if not next_url:
                    break
                for part in next_url.split("?", 1)[-1].split("&"):
                    if part.startswith("start="):
                        start = part[len("start="):]
                        break
                else:
                    break

        return guids
    except Exception as exc:
        log.warning("Could not enumerate KMS instances via ResourceController: %s", exc)
        return []


@sources.register("describe-kms-keys")
class KMSDescribeSource(DescribeSource):
    """Describe source for KMS keys.

    Enumerates all Key Protect instances, then fetches all keys in each instance.
    Each key is annotated with ``c7n:instance_id`` for use in actions.
    """

    def get_resources(self, query):
        session = local_session(self.manager.session_factory)
        instance_ids = _list_kms_instance_ids(session)

        if not instance_ids:
            log.warning(
                "No Key Protect instance found.  "
                "Set IBMCLOUD_KMS_INSTANCE_ID or ensure the account has a KMS instance."
            )
            return []

        client = session.client("key-protect")
        all_keys = []
        limit = 50
        for guid, inst_name in instance_ids:
            offset = 0
            inst_key_count = 0
            while True:
                try:
                    result = client.get_keys(
                        instance_id=guid, limit=limit, offset=offset
                    ).get_result()
                except Exception as exc:
                    log.warning("get_keys failed for KMS instance %s: %s", guid, exc)
                    break
                page = result.get("resources") or []
                for key in page:
                    key["c7n:instance_id"] = guid
                    key["c7n:instance_name"] = inst_name
                all_keys.extend(page)
                inst_key_count += len(page)
                if len(page) < limit:
                    break
                offset += limit
            log.debug("KMS instance %s (%s): fetched %d keys", guid, inst_name, inst_key_count)
        log.debug("KMS total keys fetched across all instances: %d", len(all_keys))
        return all_keys

    def augment(self, resources):
        return resources


@sources.register("describe-kms-rings")
class KMSRingDescribeSource(DescribeSource):
    """Describe source for KMS key rings."""

    def get_resources(self, query):
        session = local_session(self.manager.session_factory)
        instance_ids = _list_kms_instance_ids(session)

        if not instance_ids:
            return []

        client = session.client("key-protect")
        all_rings = []
        for guid, inst_name in instance_ids:
            try:
                result = client.get_key_rings_in_instance(instance_id=guid).get_result()
                for ring in result.get("resources", []):
                    ring["c7n:instance_id"] = guid
                    ring["c7n:instance_name"] = inst_name
                all_rings.extend(result.get("resources", []))
            except Exception as exc:
                log.warning("get_key_rings failed for KMS instance %s: %s", guid, exc)
        return all_rings

    def augment(self, resources):
        return resources

# Key Protect key states
KMS_STATE_ACTIVE = 1
KMS_STATE_DEACTIVATED = 3
KMS_STATE_DESTROYED = 5


# ---------------------------------------------------------------------------
# ibm.kms-key
# ---------------------------------------------------------------------------

@resources.register("kms-key")
class KMSKey(QueryResourceManager):
    """IBM Cloud Key Protect encryption keys."""

    source_mapping = {"describe-kms-keys": KMSDescribeSource}

    class resource_type(TypeInfo):
        service = "key-protect"
        global_service = False
        enum_spec = ("get_keys", "resources", None)
        pagination = "offset"
        id = "id"
        name = "name"
        default_report_fields = (
            "id", "name", "state", "crn", "creationDate", "c7n:instance_id"
        )
        permissions = ("kms.secrets.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-kms-keys")


@KMSKey.filter_registry.register("age")
class KMSKeyAgeFilter(AgeFilter):
    date_attribute = "creationDate"


@KMSKey.filter_registry.register("tag")
class KMSKeyTagFilter(TagFilter):
    pass


@KMSKey.filter_registry.register("state")
class KMSKeyStateFilter(Filter):
    """Match keys by their Key Protect state.

    States: active (1), suspended (2), deactivated (3), destroyed (5).

    .. code-block:: yaml

        policies:
          - name: ibm-deactivated-keys
            resource: ibm.kms-key
            filters:
              - type: state
                value: deactivated
    """

    type = "state"
    STATE_MAP = {
        "pre-activation": 0,
        "active": 1,
        "suspended": 2,
        "deactivated": 3,
        "destroyed": 5,
    }
    schema = type_schema(
        "state",
        value={
            "type": "string",
            "enum": list(STATE_MAP.keys()),
        },
    )

    def process(self, resources, event=None):
        target_state = self.STATE_MAP.get(self.data.get("value", "active"), 1)
        return [r for r in resources if r.get("state") == target_state]


@KMSKey.filter_registry.register("rotation-policy")
class KMSKeyRotationFilter(Filter):
    """Match keys based on whether a rotation policy is enabled.

    .. code-block:: yaml

        policies:
          - name: ibm-kms-no-rotation
            resource: ibm.kms-key
            filters:
              - type: rotation-policy
                enabled: false
    """

    type = "rotation-policy"
    schema = type_schema("rotation-policy", enabled={"type": "boolean"})

    def process(self, resources, event=None):
        want = self.data.get("enabled", True)
        result = []
        session = local_session(self.manager.session_factory)
        client = session.client("key-protect")
        for r in resources:
            instance_id = r.get("c7n:instance_id", "")
            try:
                policy_resp = client.get_key_policies(
                    id=r["id"], instance_id=instance_id
                ).get_result()
                rotation = policy_resp.get("resources", [{}])[0].get("rotation", {})
                has_rotation = bool(rotation.get("enabled"))
            except Exception as exc:
                log.debug(
                    "rotation-policy filter: get_key_policies failed for key %s: %s "
                    "(treating as no rotation policy)",
                    r.get("id"), exc,
                )
                has_rotation = False
            log.debug(
                "rotation-policy filter: key %s has_rotation=%s want=%s -> %s",
                r.get("id"), has_rotation, want,
                "MATCH" if has_rotation == want else "skip",
            )
            if has_rotation == want:
                result.append(r)
        return result


@KMSKey.action_registry.register("tag")
class KMSKeyTagAction(TagAction):
    """Attach tags to the parent Key Protect instance on behalf of a key.

    IBM Cloud Global Tagging only allows tagging top-level service instances,
    not individual key sub-resources. This action extracts the parent instance CRN
    (stripping the ``:key:...`` suffix) and formats tags to identify the key finding.
    """

    @staticmethod
    def _get_crn(resource):
        crn = TagAction._get_crn(resource)
        if crn and ":key:" in crn:
            return crn.split(":key:")[0] + "::"
        return crn


@KMSKey.action_registry.register("remove-tag")
class KMSKeyRemoveTagAction(RemoveTagAction):
    """Detach tags from the parent Key Protect instance on behalf of a key."""

    def perform_action(self, resource):
        crn = resource.get("crn")
        if not crn:
            log.warning("Resource %s has no CRN; skipping remove-tag action", resource.get("id"))
            return
        if ":key:" in crn:
            crn = crn.split(":key:")[0] + "::"

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
        log.debug("Removed tags %s from KMS instance %s (tag_type=%s)", tag_names, crn, tag_type)


@KMSKey.action_registry.register("disable")
class KMSKeyDisable(IBMBaseAction):
    """Disable (deactivate) a Key Protect key.

    .. code-block:: yaml

        policies:
          - name: disable-unused-keys
            resource: ibm.kms-key
            filters:
              - type: age
                days: 365
            actions:
              - disable
    """

    type = "disable"
    schema = type_schema("disable", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("key-protect")
        client.action_on_key(
            id=resource["id"],
            action="disable",
            instance_id=resource.get("c7n:instance_id", ""),
        )
        log.debug("Disabled KMS key %s", resource["id"])


@KMSKey.action_registry.register("enable")
class KMSKeyEnable(IBMBaseAction):
    """Re-enable a disabled Key Protect key."""

    type = "enable"
    schema = type_schema("enable", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("key-protect")
        client.action_on_key(
            id=resource["id"],
            action="enable",
            instance_id=resource.get("c7n:instance_id", ""),
        )
        log.debug("Enabled KMS key %s", resource["id"])


@KMSKey.action_registry.register("rotate")
class KMSKeyRotate(IBMBaseAction):
    """Rotate (re-wrap) a Key Protect key.

    .. code-block:: yaml

        policies:
          - name: rotate-old-keys
            resource: ibm.kms-key
            filters:
              - type: age
                days: 90
            actions:
              - rotate
    """

    type = "rotate"
    schema = type_schema("rotate", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("key-protect")
        client.action_on_key(
            id=resource["id"],
            action="rotate",
            instance_id=resource.get("c7n:instance_id", ""),
        )
        log.debug("Rotated KMS key %s", resource["id"])


@KMSKey.action_registry.register("delete")
class KMSKeyDelete(IBMBaseAction):
    """Delete a Key Protect key (irreversible).

    .. code-block:: yaml

        policies:
          - name: delete-deactivated-keys
            resource: ibm.kms-key
            filters:
              - type: state
                value: deactivated
            actions:
              - type: delete
                force: true
    """

    type = "delete"
    schema = type_schema("delete", force={"type": "boolean"}, rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("key-protect")
        instance_id = resource.get("c7n:instance_id", "")
        prefer = "return=representation"
        if self.data.get("force"):
            client.set_key_for_deletion(id=resource["id"], instance_id=instance_id)
        client.delete_key(id=resource["id"], prefer=prefer, instance_id=instance_id)
        log.debug("Deleted KMS key %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.kms-key-ring
# ---------------------------------------------------------------------------

@resources.register("kms-key-ring")
class KMSKeyRing(QueryResourceManager):
    """IBM Cloud Key Protect key rings."""

    source_mapping = {"describe-kms-rings": KMSRingDescribeSource}

    class resource_type(TypeInfo):
        service = "key-protect"
        global_service = False
        enum_spec = ("get_key_rings_in_instance", "resources", None)
        pagination = None
        id = "id"
        name = "id"
        default_report_fields = ("id", "creationDate", "c7n:instance_id")
        permissions = ("kms.keyrings.list",)
        scope = "regional"

    @property
    def source_type(self):
        return self.data.get("source", "describe-kms-rings")


@KMSKeyRing.action_registry.register("delete")
class KMSKeyRingDelete(IBMBaseAction):
    """Delete a Key Protect key ring (must be empty)."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("key-protect")
        client.delete_key_ring(key_ring_id=resource["id"])
        log.debug("Deleted key ring %s", resource["id"])

# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Cloud shared filters.

These filters are re-usable across all IBM Cloud resource types.
"""

import logging
from datetime import datetime, timezone

from c7n.filters import Filter, ValueFilter
from c7n.utils import type_schema

log = logging.getLogger("custodian.ibm.filters")


class ResourceGroupFilter(Filter):
    """Filter resources by IBM Cloud Resource Group name or ID.

    Handles two different resource group shapes returned by IBM Cloud APIs:

    * **Nested dict** (VPC, COS, KMS, IAM, DBaaS, PowerVS …)::

        "resource_group": {"id": "abc123", "name": "production"}

    * **Flat strings** (Container API / IKS / ROKS)::

        "resourceGroup": "abc123",
        "resourceGroupName": "production"

    Both ``name`` and ``id`` are matched against the filter ``value`` so
    operators can write either the human-readable name or the internal ID.

    Example policy:

    .. code-block:: yaml

        policies:
          - name: vpc-instances-in-prod-rg
            resource: ibm.vpc-instance
            filters:
              - type: resource-group
                value: production-rg
    """

    type = "resource-group"
    schema = type_schema(
        "resource-group",
        value={"type": "string"},
        op={"type": "string", "enum": ["eq", "ne", "in", "not-in"]},
    )

    @staticmethod
    def _rg_name_and_id(resource):
        """Return (rg_name, rg_id) from whichever shape the API used."""
        # Nested dict shape: {"resource_group": {"id": "...", "name": "..."}}
        # Used by VPC, COS, KMS, IAM, PowerVS, DBaaS SDKs.
        rg = resource.get("resource_group")
        if isinstance(rg, dict):
            return rg.get("name", ""), rg.get("id", "")

        # Flat-string shape: {"resourceGroup": "<id>", "resourceGroupName": "<name>"}
        # Used by the Container API (IKS / ROKS clusters).
        flat_id = resource.get("resourceGroup", "")
        flat_name = resource.get("resourceGroupName", "")
        if flat_id or flat_name:
            return flat_name, flat_id

        return "", ""

    def process(self, resources, event=None):
        target = self.data.get("value")
        op = self.data.get("op", "eq")
        result = []
        for r in resources:
            rg_name, rg_id = self._rg_name_and_id(r)
            if op == "eq" and (rg_name == target or rg_id == target):
                result.append(r)
            elif op == "ne" and rg_name != target and rg_id != target:
                result.append(r)
            elif op == "in" and target and (rg_name in target or rg_id in target):
                result.append(r)
            elif op == "not-in" and target and (rg_name not in target and rg_id not in target):
                result.append(r)
        return result


class TagFilter(ValueFilter):
    """Filter resources by the presence / value of a user-managed tag.

    IBM Cloud tags on resources returned by GlobalTaggingV1 are stored in the
    ``tags`` list field as plain strings (``"key:value"`` or bare ``"key"``).

    Example policy:

    .. code-block:: yaml

        policies:
          - name: untagged-instances
            resource: ibm.vpc-instance
            filters:
              - type: tag
                key: environment
                op: absent
    """

    type = "tag"
    # value is not required for absent/present ops
    required_keys = {'key'}
    schema = type_schema(
        "tag",
        key={"type": "string"},
        value={"type": "string"},
        op={"type": "string", "enum": ["eq", "ne", "absent", "present"]},
    )

    def validate(self):
        # absent/present ops don't need a value and are not in c7n's OPERATORS;
        # handle them ourselves and skip the base-class op-validity check.
        op = self.data.get("op", "present")
        if op in ("absent", "present"):
            return self
        return super().validate()

    def process(self, resources, event=None):
        tag_key = self.data.get("key", "")
        op = self.data.get("op", "present")
        target_value = self.data.get("value")
        result = []
        for r in resources:
            tag_dict = _parse_tags(r.get("tags", []))
            if op == "absent":
                if tag_key not in tag_dict:
                    result.append(r)
            elif op == "present":
                if tag_key in tag_dict:
                    result.append(r)
            elif op == "eq":
                if tag_dict.get(tag_key) == target_value:
                    result.append(r)
            elif op == "ne":
                if tag_dict.get(tag_key) != target_value:
                    result.append(r)
        return result


def _parse_tags(tag_list):
    """Convert ``["key:value", "bare"]`` → ``{"key": "value", "bare": "bare"}``."""
    parsed = {}
    for tag in tag_list:
        if ":" in tag:
            k, _, v = tag.partition(":")
            parsed[k] = v
        else:
            parsed[tag] = tag
    return parsed


class MarkedForOpFilter(Filter):
    """Match resources previously marked with :class:`~c7n_ibmcloud.actions.base.MarkForOpAction`.

    Looks for a tag of the form ``custodian_status_<op>:<YYYY-MM-DD>`` (or legacy ``custodian_status:<op>@<YYYY-MM-DD>``) where
    the date is today or in the past.

    Example policy:

    .. code-block:: yaml

        policies:
          - name: stop-marked-instances
            resource: ibm.vpc-instance
            filters:
              - type: marked-for-op
                op: stop
            actions:
              - stop
    """

    type = "marked-for-op"
    schema = type_schema(
        "marked-for-op",
        op={"type": "string"},
        skew={"type": "integer", "minimum": 0},
    )

    def process(self, resources, event=None):
        op = self.data.get("op", "stop")
        skew = self.data.get("skew", 0)
        today = datetime.now(timezone.utc).date()
        result = []
        for r in resources:
            tag_dict = _parse_tags(r.get("tags", []))
            # Support user tag format: custodian_status:op@YYYY-MM-DD
            # and access tag format: custodian_status_op:YYYY-MM-DD
            status_tag = tag_dict.get("custodian_status", "")
            access_status_tag = tag_dict.get("custodian_status_%s" % op, "")
            
            date_str = None
            if status_tag and "@" in status_tag:
                tag_op, _, d_str = status_tag.partition("@")
                if tag_op == op:
                    date_str = d_str
            elif access_status_tag:
                date_str = access_status_tag

            if not date_str:
                continue

            try:
                tag_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            except ValueError:
                continue
            from datetime import timedelta

            if tag_date <= (today + timedelta(days=skew)):
                result.append(r)
        return result


class AgeFilter(Filter):
    """Filter resources by their creation date.

    Example policy:

    .. code-block:: yaml

        policies:
          - name: old-vpc-volumes
            resource: ibm.vpc-volume
            filters:
              - type: age
                days: 90
                op: gt
    """

    type = "age"
    date_attribute = "created_at"
    schema = type_schema(
        "age",
        op={"type": "string", "enum": ["eq", "ne", "gt", "lt", "ge", "le"]},
        days={"type": "number"},
    )

    def process(self, resources, event=None):
        import operator as op_module

        op_map = {
            "eq": op_module.eq,
            "ne": op_module.ne,
            "gt": op_module.gt,
            "lt": op_module.lt,
            "ge": op_module.ge,
            "le": op_module.le,
        }
        op_fn = op_map.get(self.data.get("op", "gt"), op_module.gt)
        threshold_days = self.data.get("days", 0)
        now = datetime.now(timezone.utc)
        result = []
        date_attr = self.data.get("date_attribute", self.date_attribute)
        for r in resources:
            raw = r.get(date_attr)
            if not raw:
                continue
            if isinstance(raw, str):
                # IBM SDK timestamps: ISO 8601 with Z or +00:00
                raw = raw.replace("Z", "+00:00")
                try:
                    created = datetime.fromisoformat(raw)
                except ValueError:
                    continue
            else:
                created = raw
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (now - created).total_seconds() / 86400
            if op_fn(age, threshold_days):
                result.append(r)
        return result


class MFADisabledFilter(Filter):
    """Match IAM users that do not have MFA configured.

    MFA status is fetched via ``IamIdentityV1.get_mfa_status`` during
    augmentation and injected as ``c7n:mfa_enrolled`` and ``c7n:mfa_type``
    on each user resource.

    ``c7n:mfa_enrolled`` has three possible values:

    * ``True``  — confirmed enrolled; user is **excluded** from this filter.
    * ``False`` — confirmed not enrolled; user is **matched** by this filter.
    * ``None``  — status could not be fetched (API error); user is **excluded**
                  to avoid false positives.

    Example policy:

    .. code-block:: yaml

        policies:
          - name: ibm-iam-no-mfa
            resource: ibm.iam-user
            filters:
              - type: mfa-disabled
    """

    type = "mfa-disabled"
    schema = type_schema("mfa-disabled")

    def process(self, resources, event=None):
        # Only match users where status is confirmed False.
        # None (unknown/API error) is excluded to avoid false positives.
        return [r for r in resources if r.get("c7n:mfa_enrolled") is False]


class PublicAccessFilter(Filter):
    """Match resources based on whether public access is enabled.

    Used primarily with ``ibm.cos-bucket`` to detect publicly accessible buckets.

    Example policy:

    .. code-block:: yaml

        policies:
          - name: ibm-cos-public-buckets
            resource: ibm.cos-bucket
            filters:
              - type: public-access
                value: true
    """

    type = "public-access"
    schema = type_schema(
        "public-access",
        value={"type": "boolean"},
    )

    def process(self, resources, event=None):
        want = self.data.get("value", True)
        return [r for r in resources if r.get("c7n:public_access", False) == want]

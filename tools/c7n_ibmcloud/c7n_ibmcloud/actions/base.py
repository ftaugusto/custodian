# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Cloud base action classes.

IBM Cloud uses a centralised Global Tagging service (GlobalTaggingV1) for
attaching and detaching user-managed tags on any resource identified by its
CRN (Cloud Resource Name).  All resource types share the same tag actions.
"""

import abc
import logging

from c7n.actions import BaseAction
from c7n.utils import local_session, type_schema


def _is_access_denied(exc):
    """Return True if *exc* is an IBM/AWS-style AccessDenied API error.

    Covers both ibm_botocore.exceptions.ClientError (COS S3 operations) and
    ibm_cloud_sdk_core.ApiException (platform SDK operations), as well as the
    generic requests HTTPError for our thin REST clients.
    """
    # ibm_botocore ClientError: exc.response["Error"]["Code"] == "AccessDenied"
    if hasattr(exc, "response") and isinstance(exc.response, dict):
        code = exc.response.get("Error", {}).get("Code", "")
        if "AccessDenied" in code or "Unauthorized" in code:
            return True
    # ibm_cloud_sdk_core ApiException: exc.code == 403 or 401
    if hasattr(exc, "code") and exc.code in (401, 403):
        return True
    # requests / generic HTTP errors surfaced as strings
    msg = str(exc).lower()
    if "access denied" in msg or "accessdenied" in msg or "(403)" in msg or "(401)" in msg:
        return True
    return False


def _is_not_found(exc):
    """Return True if *exc* is a 404 / resource-not-found API error.

    A 404 during an action (typically delete) means the resource was already
    removed between enumeration and action time — a benign race condition that
    should be silently skipped rather than logged as an error.

    Covers:
    - ibm_cloud_sdk_core.ApiException with status_code 404
    - requests.HTTPError raised by raise_for_status() with status_code 404
    - ibm_botocore.ClientError with Code "NoSuchBucket" / "NoSuchKey" / "404"
    """
    # ibm_cloud_sdk_core ApiException: exc.code == 404
    if hasattr(exc, "code") and exc.code == 404:
        return True
    # requests.HTTPError: exc.response.status_code == 404
    if hasattr(exc, "response") and hasattr(exc.response, "status_code"):
        if exc.response.status_code == 404:
            return True
    # ibm_botocore ClientError dict response
    if hasattr(exc, "response") and isinstance(exc.response, dict):
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchBucket", "NoSuchKey"):
            return True
    # Generic string match (thin REST clients, status code in message)
    msg = str(exc).lower()
    if "not found" in msg or "(404)" in msg or "status code: 404" in msg:
        return True
    return False


def _is_conflict(exc):
    """Return True if *exc* is a 409 Conflict API error.

    A 409 means the action is not allowed in the resource's current state
    (e.g. disabling an already-deactivated KMS key, or rotating a key that
    was rotated within the last hour).  This is a logical precondition
    failure — warn rather than log as an unexpected error.
    """
    # requests.HTTPError from raise_for_status()
    if hasattr(exc, "response") and hasattr(exc.response, "status_code"):
        if exc.response.status_code == 409:
            return True
    # ibm_cloud_sdk_core ApiException
    if hasattr(exc, "code") and exc.code == 409:
        return True
    msg = str(exc).lower()
    if "(409)" in msg or "conflict" in msg:
        return True
    return False

log = logging.getLogger("custodian.ibm.actions")


def _ensure_access_tags(client, tag_names):
    """Pre-create access tags in the account if they do not already exist.

    Unlike ``user`` and ``service`` tags — which are created automatically on
    first attach — ``access`` tags must exist in the account before
    ``attach_tag`` is called.  Calling ``create_tag`` on an already-existing
    tag is safe (it is idempotent).

    Parameters
    ----------
    client:
        An authenticated ``GlobalTaggingV1`` instance.
    tag_names:
        List of tag-name strings to ensure exist (e.g. ``["env:prod"]``).
    """
    if not tag_names:
        return
    try:
        client.create_tag(tag_names=tag_names, tag_type="access")
        log.debug("Ensured access tags exist: %s", tag_names)
    except Exception as exc:
        # create_tag may return a partial result; log and continue — attach_tag
        # will fail explicitly if a specific tag still doesn't exist.
        log.warning("create_tag failed for %s: %s", tag_names, exc)


class IBMBaseAction(BaseAction, abc.ABC):
    """Base class for all IBM Cloud actions.

    Subclasses implement :meth:`perform_action` which is called once per
    resource in the matched set.
    """

    fail_on_error = True

    schema = {
        "properties": {
            "fail_on_error": {"type": "boolean"},
        }
    }

    def process(self, resources):
        self.fail_on_error = self.data.get("fail_on_error", False)
        results = []
        for resource in resources:
            try:
                self.perform_action(resource)
                results.append(resource)
            except Exception as exc:
                rid = resource.get("id", resource.get("name", str(resource)))
                if _is_not_found(exc):
                    log.debug(
                        "Action %s skipped resource %s: already deleted (404).",
                        self.type, rid,
                    )
                elif _is_access_denied(exc):
                    log.warning(
                        "Action %s skipped resource %s: access denied. "
                        "Ensure the API key has the required IAM permissions. (%s)",
                        self.type, rid, exc,
                    )
                elif _is_conflict(exc):
                    log.warning(
                        "Action %s skipped resource %s: action not allowed in current "
                        "resource state (409 Conflict). Check state/preconditions. (%s)",
                        self.type, rid, exc,
                    )
                else:
                    log.exception(
                        "Action %s failed on resource %s: %s", self.type, rid, exc
                    )
                if self.fail_on_error:
                    raise
        return results

    @abc.abstractmethod
    def perform_action(self, resource):
        """Execute the action against a single resource dict."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Tag / Remove-tag actions — use GlobalTaggingV1
# ---------------------------------------------------------------------------

class TagAction(IBMBaseAction):
    """Attach user-managed tags to IBM Cloud resources via GlobalTaggingV1.

    All IBM Cloud resources are identified by their CRN; this action looks for
    the ``crn`` field on each resource dict.

    Example policy:

    .. code-block:: yaml

        policies:
          - name: tag-untagged-vpc-instances
            resource: ibm.vpc-instance
            filters:
              - "tag:environment": absent
            actions:
              - type: tag
                tags:
                  environment: production
    """

    type = "tag"
    schema = type_schema(
        "tag",
        tags={"type": "object", "additionalProperties": {"type": "string"}},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        crn = self._get_crn(resource)
        if not crn:
            log.warning("Resource %s has no CRN; skipping tag action", resource.get("id"))
            return

        session = local_session(self.manager.session_factory)
        client = session.client("global-tagging")

        tags = self.data.get("tags", {})
        tag_list = ["%s:%s" % (k, v) for k, v in tags.items()]
        tag_type = getattr(self.manager.resource_type, "tag_type", "user")

        from ibm_platform_services.global_tagging_v1 import Resource

        # access tags must be pre-created in the account before they can be
        # attached.  user/service tags are created on first attach automatically.
        if tag_type == "access":
            _ensure_access_tags(client, tag_list)

        client.attach_tag(
            resources=[Resource(resource_id=crn)],
            tag_names=tag_list,
            tag_type=tag_type,
        )
        log.debug("Tagged %s with %s (tag_type=%s)", crn, tag_list, tag_type)

    @staticmethod
    def _get_crn(resource):
        """Return the CRN for a resource.

        Prefer the explicit ``crn`` field.  Fall back to ``id`` only when
        ``id`` itself is a CRN (i.e. starts with ``"crn:"``).  Returns
        ``None`` when neither field yields a CRN.
        """
        crn = resource.get("crn")
        if crn:
            return crn
        resource_id = resource.get("id", "")
        if isinstance(resource_id, str) and resource_id.startswith("crn:"):
            return resource_id
        return None


class RemoveTagAction(IBMBaseAction):
    """Detach user-managed tags from IBM Cloud resources via GlobalTaggingV1.

    Example policy:

    .. code-block:: yaml

        policies:
          - name: remove-obsolete-tags
            resource: ibm.vpc-instance
            actions:
              - type: remove-tag
                tags:
                  - environment
                  - owner
    """

    type = "remove-tag"
    schema = type_schema(
        "remove-tag",
        tags={"type": "array", "items": {"type": "string"}},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        crn = resource.get("crn")
        if not crn:
            log.warning("Resource %s has no CRN; skipping remove-tag action", resource.get("id"))
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
        log.debug("Removed tags %s from %s (tag_type=%s)", tag_names, crn, tag_type)


class MarkForOpAction(IBMBaseAction):
    """Mark resources for a future operation by attaching a custodian status tag.

    The tag format is ``custodian_status_<op>:<YYYY-MM-DD>``.

    Example policy:

    .. code-block:: yaml

        policies:
          - name: mark-old-instances-for-stop
            resource: ibm.vpc-instance
            filters:
              - type: value
                key: status
                value: running
            actions:
              - type: mark-for-op
                op: stop
                days: 7
    """

    type = "mark-for-op"
    schema = type_schema(
        "mark-for-op",
        op={"type": "string"},
        days={"type": "integer", "minimum": 0},
        hours={"type": "integer", "minimum": 0},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        from datetime import datetime, timedelta

        op = self.data.get("op", "stop")
        days = self.data.get("days", 0)
        hours = self.data.get("hours", 0)
        delta = timedelta(days=days, hours=hours)
        target_date = (datetime.utcnow() + delta).strftime("%Y-%m-%d")
        tag_type = getattr(self.manager.resource_type, "tag_type", "user")
        tag_value = "custodian_status_%s:%s" % (op, target_date)

        crn = resource.get("crn")
        if not crn:
            log.warning("Resource %s has no CRN; skipping mark-for-op", resource.get("id"))
            return

        session = local_session(self.manager.session_factory)
        client = session.client("global-tagging")

        from ibm_platform_services.global_tagging_v1 import Resource

        tag_type = getattr(self.manager.resource_type, "tag_type", "user")
        if tag_type == "access":
            _ensure_access_tags(client, [tag_value])
        client.attach_tag(
            resources=[Resource(resource_id=crn)],
            tag_names=[tag_value],
            tag_type=tag_type,
        )
        log.debug("Marked %s with %s (tag_type=%s)", crn, tag_value, tag_type)


class DeleteAction(IBMBaseAction):
    """Generic delete action.

    Resource modules that support deletion should register this action
    and override ``perform_action`` to call the appropriate SDK delete method.

    This base class can be used directly by resource modules that register it
    and provide ``_delete_resource``.
    """

    type = "delete"
    schema = type_schema(
        "delete",
        force={"type": "boolean"},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        self._delete_resource(resource)

    def _delete_resource(self, resource):
        raise NotImplementedError(
            "%s must implement _delete_resource()" % self.__class__.__name__
        )

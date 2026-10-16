# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Cloud IAM resources.

Covers the following resource types:
- ibm.iam-user          — IAM users in the account
- ibm.iam-service-id    — Service IDs (machine identities)
- ibm.iam-api-key       — API keys (user and service-ID owned)
- ibm.iam-access-group  — Access groups
- ibm.iam-policy        — IAM authorization policies
- ibm.iam-trusted-profile — Trusted profiles (compute workload identities)

MFA augmentation
----------------
``UserManagementV1.list_users`` returns ``UserProfile`` objects which have no
MFA field.  MFA status lives in ``IamIdentityV1.get_mfa_status(account_id,
iam_id)`` which returns a ``UserMfaEnrollments`` object with an
``effective_mfa_type`` string (empty = no MFA enrolled) and per-method
enrollment details.

``IAMUser`` overrides ``augment()`` to fetch MFA status for every user and
inject ``c7n:mfa_enrolled`` (bool) and ``c7n:mfa_type`` (str) fields.
``MFADisabledFilter`` checks ``c7n:mfa_enrolled`` instead of the old
(non-existent) ``mfa_type`` field.

Actions without tagging support
---------------------------------
``ibm.iam-user`` and ``ibm.iam-access-group`` resources have no CRN field
returned by their respective list APIs, so GlobalTaggingV1 tagging is not
available.  The supported remediation actions are:

- **iam-user**: ``delete`` (remove from account) and ``add-to-review-group``
  (add the user to a named access group for manual review).
- **iam-api-key**: ``lock`` (prevent use) and ``delete``.
- **iam-access-group**: ``delete`` and ``append-description`` (append a
  custodian notice to the group description so reviewers are alerted).
- **iam-trusted-profile**: ``delete`` and ``append-description``.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from c7n.utils import local_session, type_schema

from c7n_ibmcloud.actions.base import IBMBaseAction, TagAction, RemoveTagAction, MarkForOpAction
from c7n_ibmcloud.filters.base import TagFilter, MarkedForOpFilter, MFADisabledFilter, AgeFilter
from c7n_ibmcloud.provider import resources
from c7n_ibmcloud.query import QueryResourceManager, TypeInfo, DescribeSource, sources

log = logging.getLogger("custodian.ibm.iam")

# Thread pool size for concurrent MFA status fetches
_MFA_WORKERS = 10


@sources.register("describe-iam-users")
class IAMUserDescribeSource(DescribeSource):
    """Describe source for IAM users that augments with MFA status."""

    def get_resources(self, query):
        """Enumerate users via UserManagementV1, then augment with MFA status.

        ``_fetch_resources`` on ``QueryResourceManager`` calls
        ``self.source.get_resources()`` and then ``self.augment()`` (the
        no-op on the manager).  It does NOT call ``self.source.augment()``,
        so MFA enrichment must happen here — inside ``get_resources`` — to
        guarantee users always leave this source with ``c7n:mfa_enrolled``
        set.
        """
        from c7n_ibmcloud.query import ResourceQuery
        rq = ResourceQuery(self.manager.session_factory)
        users = rq.filter(self.manager, query or {})
        return self.augment(users)

    def augment(self, resources):
        if not resources:
            return resources
        session = local_session(self.manager.session_factory)
        return _augment_mfa(resources, session)


def _mfa_enrolled_from_result(result):
    """Determine whether a user has any MFA method enrolled.

    Uses **enrollment-based** detection: a user is considered to have MFA
    disabled when they have not enrolled *any* MFA method, regardless of
    whether the account policy currently *requires* it.

    This matches the intent of the ``mfa-disabled`` filter — finding users
    who are running without MFA protection — even on accounts where MFA is
    not yet enforced at the policy level.

    Live API observation (``UserMfaEnrollments`` response):

    ``effective_mfa_type``: ``"id_based_mfa"`` (always present for IBMid users)

    ``id_based_mfa``:
      - ``trait_account_default``: account-level default (e.g. ``"NONE_NO_ROPC"``)
      - ``trait_user_specific``:   per-user override (e.g. ``"TOTP4ALL"``)
      - ``trait_effective``:       whichever trait governs this user
      - ``complies``: bool         whether they satisfy the *effective* requirement
      - ``comply_state``:          ``"CROSS_ACCOUNT"`` | ``"ACCOUNT"`` | ``"NO"``

    ``account_based_mfa``:
      - ``totp.enrolled``:              bool — TOTP authenticator app enrolled
      - ``totp.required``:              bool — TOTP required by account policy
      - ``security_questions.enrolled``:bool — security questions enrolled
      - ``verisign.enrolled``:          bool — Verisign identity enrolled

    Enrollment logic (in priority order):
    1. If ``id_based_mfa.trait_effective`` is a strong trait (TOTP, TOTP4ALL,
       LEVEL1–3) **and** ``complies=True`` → enrolled (satisfies requirement).
    2. If ``account_based_mfa`` shows ANY method with ``enrolled=True`` →
       enrolled (has MFA regardless of account policy).
    3. Otherwise → not enrolled.

    Returns ``(enrolled: bool, trait: str)`` where *trait* describes the
    detected MFA type for logging.
    """
    id_mfa   = result.get("id_based_mfa") or {}
    acct_mfa = result.get("account_based_mfa") or {}

    # ── 1. id_based_mfa: strong trait + complies ─────────────────────────────
    trait_effective = (id_mfa.get("trait_effective") or "").upper()
    _STRONG = {"TOTP", "TOTP4ALL", "LEVEL1", "LEVEL2", "LEVEL3"}
    if trait_effective in _STRONG and id_mfa.get("complies"):
        return True, id_mfa.get("trait_effective", trait_effective)

    # ── 2. account_based_mfa: any method physically enrolled ─────────────────
    for method in ("totp", "security_questions", "verisign"):
        m = acct_mfa.get(method) or {}
        if m.get("enrolled"):
            return True, method

    # ── 3. No MFA enrolled ────────────────────────────────────────────────────
    return False, trait_effective or ""


def _augment_mfa(resources, session):
    """Inject ``c7n:mfa_enrolled`` and ``c7n:mfa_type`` into each user dict.

    Fetches MFA status concurrently via ``IamIdentityV1.get_mfa_status``.

    ``c7n:mfa_enrolled`` is:
    - ``True``  — confirmed enrolled / compliant with MFA requirement
    - ``False`` — confirmed not compliant (has MFA requirement but does not satisfy it)
    - ``None``  — status unknown (API call failed or non-IBMid account);
                  user excluded from mfa-disabled filter to avoid false positives

    The IBM API response structure (``UserMfaEnrollments``):
    - ``effective_mfa_type``: ``"id_based_mfa"`` | ``"account_based_mfa"`` | absent
    - ``id_based_mfa.trait_effective``: ``"NONE"`` | ``"TOTP"`` | ``"LEVEL1"`` … etc.
    - ``id_based_mfa.complies``: bool — whether the user satisfies the requirement
    - ``account_based_mfa.complies``: bool — for account-level MFA requirements
    """
    account_id = session.account_id
    try:
        iam_id_client = session.client("iam-identity")
    except Exception as exc:
        log.warning("Could not create IamIdentityV1 client for MFA augment: %s", exc)
        return [dict(r, **{"c7n:mfa_enrolled": None, "c7n:mfa_type": ""})
                for r in resources]

    def _fetch(user):
        iam_id = user.get("iam_id", "")
        if not iam_id:
            # No iam_id — cannot determine MFA status; treat as unknown
            return dict(user, **{"c7n:mfa_enrolled": None, "c7n:mfa_type": ""})

        # get_mfa_status only works for IBMid-* users (human identities).
        # BSS-* accounts are IBM Cloud billing/service system accounts; the API
        # returns 400 "The user name cannot be found" for them — not an error,
        # just not applicable.  Exclude them silently.
        if not iam_id.startswith("IBMid-"):
            log.debug(
                "Skipping get_mfa_status for non-IBMid user %s (type: %s) — "
                "MFA status not applicable to service/system accounts",
                iam_id, iam_id.split("-")[0],
            )
            return dict(user, **{"c7n:mfa_enrolled": None, "c7n:mfa_type": ""})

        try:
            result = iam_id_client.get_mfa_status(
                account_id=account_id,
                iam_id=iam_id,
            ).get_result()
            enrolled, trait = _mfa_enrolled_from_result(result)
            log.debug(
                "MFA status for %s: effective_mfa_type=%r trait=%r enrolled=%r",
                iam_id, result.get("effective_mfa_type"), trait, enrolled,
            )
            return dict(user, **{"c7n:mfa_enrolled": enrolled, "c7n:mfa_type": trait})
        except Exception as exc:
            log.warning(
                "get_mfa_status failed for user %s — excluding from mfa-disabled filter "
                "to avoid false positives: %s", iam_id, exc
            )
            return dict(user, **{"c7n:mfa_enrolled": None, "c7n:mfa_type": ""})

    enriched = [None] * len(resources)
    with ThreadPoolExecutor(max_workers=_MFA_WORKERS) as pool:
        futures = {pool.submit(_fetch, r): i for i, r in enumerate(resources)}
        for future in as_completed(futures):
            idx = futures[future]
            try:
                enriched[idx] = future.result()
            except Exception as exc:
                log.warning("MFA augment future failed for user at index %d: %s", idx, exc)
                enriched[idx] = dict(
                    resources[idx], **{"c7n:mfa_enrolled": None, "c7n:mfa_type": ""}
                )

    return enriched


# ---------------------------------------------------------------------------
# ibm.iam-user
# ---------------------------------------------------------------------------

@resources.register("iam-user")
class IAMUser(QueryResourceManager):
    """IBM Cloud IAM users.

    :example:

    Find all IAM users without MFA enabled:

    .. code-block:: yaml

        policies:
          - name: ibm-iam-no-mfa
            resource: ibm.iam-user
            filters:
              - type: mfa-disabled
    """

    source_mapping = {"describe-iam-users": IAMUserDescribeSource}

    class resource_type(TypeInfo):
        service = "iam-users"   # UserManagementV1, not IamIdentityV1
        global_service = True
        # UserManagementV1.list_users returns UserList with key "resources"
        enum_spec = ("list_users", "resources", None)
        pagination = "cursor"
        required_params = {"account_id"}
        id = "iam_id"
        name = "email"
        default_report_fields = (
            "iam_id", "email", "firstname", "lastname", "state",
            "c7n:mfa_enrolled", "c7n:mfa_type",
        )
        permissions = ("iam-identity.user.list",)
        scope = "account"

    @property
    def source_type(self):
        return self.data.get("source", "describe-iam-users")


@IAMUser.filter_registry.register("mfa-disabled")
class IAMUserMFAFilter(MFADisabledFilter):
    pass


# NOTE: IAMUser has no CRN field — UserManagementV1.list_users returns UserProfile
# objects without a CRN.  Tag actions via GlobalTaggingV1 are not supported.


@IAMUser.action_registry.register("delete")
class IAMUserDeleteAction(IBMBaseAction):
    """Remove a user from the IBM Cloud account.

    Uses ``UserManagementV1.remove_user`` which requires the account_id and the
    user's ``iam_id`` (the ``IAM_ID`` field on the UserProfile object).

    .. code-block:: yaml

        policies:
          - name: remove-suspended-users
            resource: ibm.iam-user
            filters:
              - type: value
                key: state
                op: ne
                value: ACTIVE
            actions:
              - delete
    """

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("iam-users")
        account_id = session.account_id
        iam_id = resource.get("iam_id", "")
        if not iam_id:
            log.warning("iam-user resource has no iam_id; skipping delete")
            return
        client.remove_user(account_id=account_id, iam_id=iam_id)
        log.debug("Removed user %s from account %s", iam_id, account_id)


@IAMUser.action_registry.register("add-to-review-group")
class IAMUserAddToReviewGroupAction(IBMBaseAction):
    """Add a user to an IAM access group for manual review.

    The access group must already exist in the account.  This action is a
    non-destructive alternative to ``delete`` — it flags the user for review
    by placing them in a dedicated group while leaving their account access
    intact.

    Specify the group by **name** (recommended — human-readable, portable
    across environments) or by its ``AccessGroupId-<uuid>`` ID.  When
    ``group_name`` is used the ID is resolved once per policy run and cached.

    Parameters
    ----------
    group_name : str
        Human-readable name of the access group (e.g. ``custodian-review``).
        Looked up via ``list_access_groups(search=<name>)`` at run time.
    group_id : str
        The ``AccessGroupId-<uuid>`` of the access group.  Use this when you
        prefer an explicit stable reference.  Mutually exclusive with
        ``group_name``.

    .. code-block:: yaml

        policies:
          - name: flag-mfa-disabled-users-for-review
            resource: ibm.iam-user
            filters:
              - type: mfa-disabled
            actions:
              - type: add-to-review-group
                group_name: custodian-review
    """

    type = "add-to-review-group"
    schema = type_schema(
        "add-to-review-group",
        group_name={"type": "string"},
        group_id={"type": "string"},
        rinherit=IBMBaseAction.schema,
    )

    def validate(self):
        has_name = bool(self.data.get("group_name", "").strip())
        has_id   = bool(self.data.get("group_id",   "").strip())
        if not has_name and not has_id:
            raise ValueError(
                "add-to-review-group: specify either 'group_name' (e.g. "
                "group_name: custodian-review) or 'group_id' "
                "(e.g. group_id: AccessGroupId-<uuid>)."
            )
        if has_name and has_id:
            raise ValueError(
                "add-to-review-group: specify either 'group_name' or 'group_id', not both."
            )
        if has_id and not self.data["group_id"].startswith("AccessGroupId-"):
            raise ValueError(
                "add-to-review-group: group_id must start with 'AccessGroupId-'. "
                "Got %r. Use group_name to specify by name instead." % self.data["group_id"]
            )
        return self

    def _resolve_group_id(self, session):
        """Resolve group_name → AccessGroupId, cached for this action instance."""
        if hasattr(self, "_resolved_group_id"):
            return self._resolved_group_id

        group_name = self.data.get("group_name", "").strip()
        if not group_name:
            # group_id was specified directly — use it as-is
            self._resolved_group_id = self.data["group_id"]
            return self._resolved_group_id

        client = session.client("iam-groups")
        resp = client.list_access_groups(
            account_id=session.account_id,
            search="name:%s" % group_name,
        ).get_result()
        for group in resp.get("groups", []):
            if group.get("name") == group_name:
                self._resolved_group_id = group["id"]
                log.debug("Resolved access group %r → %s", group_name, self._resolved_group_id)
                return self._resolved_group_id

        raise ValueError(
            "add-to-review-group: no access group named %r found in this account. "
            "Create it first or check the spelling." % group_name
        )

    def perform_action(self, resource):
        iam_id = resource.get("iam_id", "")
        if not iam_id:
            log.warning("iam-user resource has no iam_id; skipping add-to-review-group")
            return
        session = local_session(self.manager.session_factory)
        group_id = self._resolve_group_id(session)
        from ibm_platform_services.iam_access_groups_v2 import AddGroupMembersRequestMembersItem
        client = session.client("iam-groups")
        client.add_members_to_access_group(
            access_group_id=group_id,
            members=[AddGroupMembersRequestMembersItem(iam_id=iam_id, type="user")],
        )
        log.debug("Added user %s to review group %s (%s)", iam_id,
                  self.data.get("group_name") or group_id, group_id)


# ---------------------------------------------------------------------------
# ibm.iam-service-id
# ---------------------------------------------------------------------------

@resources.register("iam-service-id")
class IAMServiceID(QueryResourceManager):
    """IBM Cloud IAM service IDs (machine identities).

    :example:

    Find old service IDs:

    .. code-block:: yaml

        policies:
          - name: ibm-old-service-ids
            resource: ibm.iam-service-id
            filters:
              - type: age
                days: 365
                op: gt
    """

    class resource_type(TypeInfo):
        service = "iam-identity"
        global_service = True
        enum_spec = ("list_service_ids", "serviceids", None)
        pagination = "iam-cursor"
        required_params = {"account_id"}
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "description", "crn", "created_at")
        permissions = ("iam-identity.serviceid.list",)
        scope = "account"
        tag_type = "access"


@IAMServiceID.filter_registry.register("age")
class IAMServiceIDAgeFilter(AgeFilter):
    date_attribute = "created_at"


@IAMServiceID.filter_registry.register("tag")
class IAMServiceIDTagFilter(TagFilter):
    pass


@IAMServiceID.filter_registry.register("marked-for-op")
class IAMServiceIDMarkedFilter(MarkedForOpFilter):
    pass


@IAMServiceID.action_registry.register("tag")
class IAMServiceIDTagAction(TagAction):
    pass


@IAMServiceID.action_registry.register("remove-tag")
class IAMServiceIDRemoveTagAction(RemoveTagAction):
    pass


@IAMServiceID.action_registry.register("mark-for-op")
class IAMServiceIDMarkForOpAction(MarkForOpAction):
    pass


@IAMServiceID.action_registry.register("delete")
class IAMServiceIDDeleteAction(IBMBaseAction):
    """Delete an IAM service ID.

    .. code-block:: yaml

        policies:
          - name: delete-old-service-ids
            resource: ibm.iam-service-id
            filters:
              - type: age
                days: 365
                op: gt
            actions:
              - delete
    """

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("iam-identity")
        client.delete_service_id(id=resource["id"])
        log.debug("Deleted service ID %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.iam-api-key
# ---------------------------------------------------------------------------

@resources.register("iam-api-key")
class IAMApiKey(QueryResourceManager):
    """IBM Cloud IAM API keys.

    :example:

    Find user-owned API keys older than 90 days and tag them:

    .. code-block:: yaml

        policies:
          - name: ibm-old-api-keys
            resource: ibm.iam-api-key
            filters:
              - type: age
                days: 90
                op: gt
            actions:
              - type: tag
                tags:
                  rotation-needed: "true"
    """

    class resource_type(TypeInfo):
        service = "iam-identity"
        global_service = True
        enum_spec = ("list_api_keys", "apikeys", None)
        pagination = "iam-cursor"
        required_params = {"account_id"}
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "crn", "iam_id", "created_at", "locked")
        permissions = ("iam-identity.apikey.list",)
        scope = "account"
        tag_type = "access"


@IAMApiKey.filter_registry.register("age")
class IAMApiKeyAgeFilter(AgeFilter):
    date_attribute = "created_at"


# NOTE: IAMApiKey resources do not support GlobalTaggingV1 tagging because the
# IamIdentityV1.list_api_keys response does not include a CRN field.
# Use lock, delete, or append-description for remediation actions on API keys.


@IAMApiKey.action_registry.register("append-description")
class IAMApiKeyAppendDescriptionAction(IBMBaseAction):
    """Append a custodian notice to an IAM API key's description.

    Concatenates *notice* to the current description via
    ``IamIdentityV1.update_api_key`` so that operators can identify API keys
    flagged by Cloud Custodian without locking or deleting them immediately.

    Parameters
    ----------
    notice : str
        Text to append.  Defaults to
        ``"[custodian] This API key requires review."``.

    .. code-block:: yaml

        policies:
          - name: flag-undescribed-api-keys
            resource: ibm.iam-api-key
            filters:
              - type: value
                key: description
                op: eq
                value: ""
            actions:
              - type: append-description
                notice: "[custodian] No description — identify and rotate this key."
    """

    type = "append-description"
    _DEFAULT_NOTICE = "[custodian] This API key requires review."
    schema = type_schema(
        "append-description",
        notice={"type": "string"},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        notice = self.data.get("notice", self._DEFAULT_NOTICE)
        current_desc = resource.get("description") or ""
        if notice in current_desc:
            log.debug("Notice already present on API key %s; skipping", resource["id"])
            return
        new_desc = (current_desc + " " + notice).strip()
        session = local_session(self.manager.session_factory)
        client = session.client("iam-identity")
        # Attempt update; if the key is locked (400 "The API Key is locked."),
        # unlock it first, update description, then re-lock it.
        try:
            client.update_api_key(
                id=resource["id"],
                if_match="*",
                description=new_desc,
            )
            log.debug(
                "Appended description notice to API key %s: %r", resource["id"], notice
            )
        except Exception as exc:
            if "locked" in str(exc).lower():
                log.info(
                    "API key %s is locked; temporarily unlocking to update description",
                    resource["id"],
                )
                try:
                    client.unlock_api_key(id=resource["id"])
                except Exception as unlock_exc:
                    log.warning(
                        "Could not unlock API key %s: %s", resource["id"], unlock_exc
                    )
                    raise
                try:
                    client.update_api_key(
                        id=resource["id"],
                        if_match="*",
                        description=new_desc,
                    )
                    log.debug(
                        "Appended description notice to API key %s: %r",
                        resource["id"],
                        notice,
                    )
                finally:
                    try:
                        client.lock_api_key(id=resource["id"])
                        log.debug("Re-locked API key %s", resource["id"])
                    except Exception as lock_exc:
                        log.warning(
                            "Could not re-lock API key %s: %s", resource["id"], lock_exc
                        )
            else:
                raise


@IAMApiKey.action_registry.register("lock")
class LockApiKeyAction(IBMBaseAction):
    """Lock an IAM API key to prevent its use.

    .. code-block:: yaml

        policies:
          - name: lock-old-api-keys
            resource: ibm.iam-api-key
            filters:
              - type: age
                days: 180
            actions:
              - lock
    """

    type = "lock"
    schema = type_schema("lock", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("iam-identity")
        client.lock_api_key(id=resource["id"])
        log.debug("Locked API key %s", resource["id"])


@IAMApiKey.action_registry.register("unlock")
class UnlockApiKeyAction(IBMBaseAction):
    """Unlock an IAM API key."""

    type = "unlock"
    schema = type_schema("unlock", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("iam-identity")
        client.unlock_api_key(id=resource["id"])
        log.debug("Unlocked API key %s", resource["id"])


@IAMApiKey.action_registry.register("delete")
class IAMApiKeyDeleteAction(IBMBaseAction):
    """Delete an IAM API key."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("iam-identity")
        client.delete_api_key(id=resource["id"])
        log.debug("Deleted API key %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.iam-access-group
# ---------------------------------------------------------------------------

@resources.register("iam-access-group")
class IAMAccessGroup(QueryResourceManager):
    """IBM Cloud IAM access groups.

    :example:

    Find empty access groups (no members):

    .. code-block:: yaml

        policies:
          - name: ibm-empty-access-groups
            resource: ibm.iam-access-group
            filters:
              - type: value
                key: member_count
                value: 0
    """

    class resource_type(TypeInfo):
        service = "iam-groups"
        global_service = True
        enum_spec = ("list_access_groups", "groups", None)
        pagination = "cursor"
        required_params = {"account_id"}
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "description", "created_at")
        permissions = ("iam-groups.groups.list",)
        scope = "account"
        # NOTE: IamAccessGroupsV2.list_access_groups does not return a CRN field.
        # GlobalTaggingV1 tagging is therefore not supported for access groups.


@IAMAccessGroup.action_registry.register("delete")
class IAMAccessGroupDeleteAction(IBMBaseAction):
    """Delete an IAM access group."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("iam-groups")
        client.delete_access_group(access_group_id=resource["id"])
        log.debug("Deleted access group %s", resource["id"])


@IAMAccessGroup.action_registry.register("append-description")
class IAMAccessGroupAppendDescriptionAction(IBMBaseAction):
    """Append a custodian notice to an IAM access group's description.

    Concatenates *notice* to the current description (separated by a space)
    so that operators can identify groups flagged by Cloud Custodian without
    deleting them immediately.

    Parameters
    ----------
    notice : str
        Text to append.  Defaults to
        ``"[custodian] This group requires review."``.

    .. code-block:: yaml

        policies:
          - name: flag-empty-access-groups
            resource: ibm.iam-access-group
            filters:
              - type: value
                key: member_count
                value: 0
            actions:
              - type: append-description
                notice: "[custodian] Empty group — review or delete."
    """

    type = "append-description"
    _DEFAULT_NOTICE = "[custodian] This group requires review."
    schema = type_schema(
        "append-description",
        notice={"type": "string"},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        notice = self.data.get("notice", self._DEFAULT_NOTICE)
        current_desc = resource.get("description") or ""
        # Avoid duplicating the same notice on repeated runs
        if notice in current_desc:
            log.debug("Notice already present on access group %s; skipping", resource["id"])
            return
        new_desc = (current_desc + " " + notice).strip()
        session = local_session(self.manager.session_factory)
        client = session.client("iam-groups")
        # update_access_group requires the real ETag — "if_match='*'" is rejected (412).
        # Fetch the group to get the current ETag from the response headers.
        get_resp = client.get_access_group(access_group_id=resource["id"])
        etag = get_resp.get_headers().get("ETag", "*")
        client.update_access_group(
            access_group_id=resource["id"],
            if_match=etag,
            description=new_desc,
        )
        log.debug(
            "Appended description notice to access group %s: %r", resource["id"], notice
        )


# ---------------------------------------------------------------------------
# ibm.iam-custom-role
# ---------------------------------------------------------------------------

@resources.register("iam-custom-role")
class IAMCustomRole(QueryResourceManager):
    """IBM Cloud IAM custom roles.

    Custom roles are account-specific roles that bundle service actions.
    Unlike system or service roles, they are created and managed by account
    administrators.  Common governance finding: roles with no description
    cannot be identified by purpose or owner.

    :example:

    Find custom roles with no description and append a custodian notice:

    .. code-block:: yaml

        policies:
          - name: iam-custom-role-no-description
            resource: ibm.iam-custom-role
            filters:
              - type: value
                key: description
                value: absent
            actions:
              - type: append-description
                notice: "[custodian] No description — document the purpose and owner."
    """

    class resource_type(TypeInfo):
        service = "iam-policy"
        global_service = True
        # list_roles returns a RoleCollection; custom_roles is the key for account-owned roles.
        enum_spec = ("list_roles", "custom_roles", None)
        pagination = None
        required_params = {"account_id"}
        id = "id"
        name = "display_name"
        default_report_fields = (
            "id", "name", "display_name", "description", "service_name", "created_at"
        )
        permissions = ("iam-access-management.customRole.list",)
        scope = "account"


@IAMCustomRole.action_registry.register("append-description")
class IAMCustomRoleAppendDescriptionAction(IBMBaseAction):
    """Append a custodian notice to a custom role's description.

    Fetches the current ETag via ``get_role`` before calling ``replace_role``
    (the IBM API requires a real ETag — ``"*"`` is rejected with 412).

    ``replace_role`` is a full-replace endpoint that requires ``display_name``
    and ``actions`` alongside ``description`` — both are read from the resource
    dict returned by ``list_roles`` and passed through unchanged.

    Parameters
    ----------
    notice : str
        Text to append.  Defaults to
        ``"[custodian] This custom role requires review."``.

    .. code-block:: yaml

        policies:
          - name: iam-custom-role-no-description
            resource: ibm.iam-custom-role
            filters:
              - type: value
                key: description
                value: absent
            actions:
              - type: append-description
                notice: "[custodian] No description — document purpose and owner."
    """

    type = "append-description"
    _DEFAULT_NOTICE = "[custodian] This custom role requires review."
    schema = type_schema(
        "append-description",
        notice={"type": "string"},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        notice = self.data.get("notice", self._DEFAULT_NOTICE)
        current_desc = resource.get("description") or ""
        if notice in current_desc:
            log.debug("Notice already present on custom role %s; skipping", resource["id"])
            return
        new_desc = (current_desc + " " + notice).strip()

        session = local_session(self.manager.session_factory)
        client = session.client("iam-policy")

        # replace_role requires the real ETag from a prior GET.
        get_resp = client.get_role(role_id=resource["id"])
        etag = get_resp.get_headers().get("ETag", "*")

        # replace_role is a full-replace — must pass display_name and actions unchanged.
        client.replace_role(
            role_id=resource["id"],
            if_match=etag,
            display_name=resource["display_name"],
            actions=resource.get("actions", []),
            description=new_desc,
        )
        log.debug(
            "Appended description notice to custom role %s: %r", resource["id"], notice
        )


# ---------------------------------------------------------------------------
# ibm.iam-policy
# ---------------------------------------------------------------------------

@resources.register("iam-policy")
class IAMPolicy(QueryResourceManager):
    """IBM Cloud IAM authorization policies.

    :example:

    Find policies with wildcard (*) resource access:

    .. code-block:: yaml

        policies:
          - name: ibm-wildcard-policies
            resource: ibm.iam-policy
            filters:
              - type: value
                key: "resources[0].attributes[0].value"
                value: "*"
    """

    class resource_type(TypeInfo):
        service = "iam-policy"
        global_service = True
        enum_spec = ("list_policies", "policies", None)
        pagination = None
        required_params = {"account_id"}
        id = "id"
        name = "id"
        default_report_fields = ("id", "type", "state", "created_at")
        permissions = ("iam-access-management.policy.list",)
        scope = "account"


@IAMPolicy.action_registry.register("delete")
class IAMPolicyDeleteAction(IBMBaseAction):
    """Delete an IAM policy.

    .. code-block:: yaml

        policies:
          - name: delete-wildcard-policies
            resource: ibm.iam-policy
            filters:
              - type: value
                key: "resources[0].attributes[0].value"
                value: "*"
            actions:
              - delete
    """

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("iam-policy")
        client.delete_policy(policy_id=resource["id"])
        log.debug("Deleted IAM policy %s", resource["id"])


# ---------------------------------------------------------------------------
# ibm.iam-trusted-profile
# ---------------------------------------------------------------------------

@resources.register("iam-trusted-profile")
class IAMTrustedProfile(QueryResourceManager):
    """IBM Cloud IAM trusted profiles (compute workload identities).

    :example:

    .. code-block:: yaml

        policies:
          - name: list-trusted-profiles
            resource: ibm.iam-trusted-profile
    """

    class resource_type(TypeInfo):
        service = "iam-identity"
        global_service = True
        enum_spec = ("list_profiles", "profiles", None)
        pagination = "iam-cursor"
        required_params = {"account_id"}
        id = "id"
        name = "name"
        default_report_fields = ("id", "name", "description", "crn", "created_at")
        permissions = ("iam-identity.profile.list",)
        scope = "account"
        tag_type = "access"


@IAMTrustedProfile.filter_registry.register("age")
class IAMTrustedProfileAgeFilter(AgeFilter):
    date_attribute = "created_at"


# NOTE: IAMTrustedProfile has a CRN field (tag_type="access") so GlobalTaggingV1
# tagging works in principle. However the IamIdentityV1 list_profiles response
# may not always include the CRN. Prefer append-description or delete for
# governance remediation to keep remediation self-contained without a tagging
# dependency.


@IAMTrustedProfile.action_registry.register("delete")
class IAMTrustedProfileDeleteAction(IBMBaseAction):
    """Delete an IAM trusted profile."""

    type = "delete"
    schema = type_schema("delete", rinherit=IBMBaseAction.schema)

    def perform_action(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("iam-identity")
        client.delete_profile(profile_id=resource["id"])
        log.debug("Deleted trusted profile %s", resource["id"])


@IAMTrustedProfile.action_registry.register("append-description")
class IAMTrustedProfileAppendDescriptionAction(IBMBaseAction):
    """Append a custodian notice to an IAM trusted profile's description.

    Concatenates *notice* to the current description so that operators can
    identify profiles flagged by Cloud Custodian.

    Parameters
    ----------
    notice : str
        Text to append.  Defaults to
        ``"[custodian] This profile requires review."``.

    .. code-block:: yaml

        policies:
          - name: flag-stale-trusted-profiles
            resource: ibm.iam-trusted-profile
            filters:
              - type: age
                days: 180
                op: gt
            actions:
              - type: append-description
                notice: "[custodian] Profile unused for 180+ days — review."
    """

    type = "append-description"
    _DEFAULT_NOTICE = "[custodian] This profile requires review."
    schema = type_schema(
        "append-description",
        notice={"type": "string"},
        rinherit=IBMBaseAction.schema,
    )

    def perform_action(self, resource):
        notice = self.data.get("notice", self._DEFAULT_NOTICE)
        current_desc = resource.get("description") or ""
        if notice in current_desc:
            log.debug(
                "Notice already present on trusted profile %s; skipping", resource["id"]
            )
            return
        new_desc = (current_desc + " " + notice).strip()
        session = local_session(self.manager.session_factory)
        client = session.client("iam-identity")
        try:
            # update_profile requires the real ETag — fetch it from get_profile first.
            get_resp = client.get_profile(profile_id=resource["id"])
            etag = get_resp.get_headers().get("ETag", "*")
            client.update_profile(
                profile_id=resource["id"],
                if_match=etag,
                description=new_desc,
            )
        except Exception as exc:
            # IBM Cloud Enterprise-managed trusted profiles cannot be modified
            # from a child account — this is a permanent platform restriction,
            # not an operator error. Demote to debug so it doesn't fill logs.
            if "managed by enterprise" in str(exc).lower():
                log.debug(
                    "Skipping trusted profile %s: managed by IBM Cloud Enterprise "
                    "(cannot be modified from this account).",
                    resource["id"],
                )
                return
            raise
        log.debug(
            "Appended description notice to trusted profile %s: %r",
            resource["id"], notice,
        )

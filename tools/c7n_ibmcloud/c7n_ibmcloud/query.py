# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Cloud query layer.

Provides the pluggable source / resource-manager infrastructure that all IBM
Cloud resource modules build on.  The design mirrors ``c7n_oci/query.py``.

Pagination notes
----------------
IBM Cloud APIs use two pagination patterns:

* **cursor / start-next** (VPC, IAM list_*):
  Each response includes a ``next`` dict with an ``href`` field containing
  a ``start=<token>`` query parameter.  Pass the token back as ``start=``
  on the next request until ``next`` is absent.

* **offset / limit** (Key Protect, ICD):
  Pass ``offset`` + ``limit``.  Increment offset by ``limit`` until the
  returned list is shorter than ``limit``.
"""

import logging

from c7n.actions import ActionRegistry
from c7n.filters import FilterRegistry
from c7n.manager import ResourceManager
from c7n.query import sources, MaxResourceLimit
from c7n.utils import local_session

log = logging.getLogger("custodian.ibm.query")

# Default page size for all IBM Cloud paginated calls.
IBM_DEFAULT_PAGE_SIZE = 50


def _extract_next_token(response):
    """Extract the cursor/start token for the next page from an IBM SDK response dict.

    IBM Cloud APIs use several different pagination shapes:

    * **VPC / IamIdentityV1 (ServiceId, ApiKey, TrustedProfile)**::

        {"next": {"href": "https://…?start=<token>"}}   # dict with href key
        {"next": "https://…?start=<token>"}              # plain string

    * **UserManagementV1** (list_users)::

        {"next_url": "https://…?start=<token>"}

    * **IamAccessGroupsV2** (list_access_groups) — uses HrefStruct::

        {"next": {"href": "https://…?offset=<n>&limit=<m>"}}

    Returns the ``start`` query parameter value, or ``None`` if there is no
    next page.  Does NOT handle ``pagetoken`` (used by IamIdentityV1 for
    service-ids/api-keys/profiles) — those use ``_extract_pagetoken()``.
    """
    # UserManagementV1: flat next_url string
    next_url = response.get("next_url")
    if next_url and isinstance(next_url, str):
        return _token_from_url(next_url, "start")

    next_val = response.get("next")
    if not next_val:
        return None

    # IamIdentityV1 plain-string next
    if isinstance(next_val, str):
        return _token_from_url(next_val, "start")

    # VPC / IamAccessGroupsV2: dict with href key
    if isinstance(next_val, dict):
        href = next_val.get("href", "")
        return _token_from_url(href, "start")

    return None


def _extract_pagetoken(response):
    """Extract the ``pagetoken`` value from an ``IamIdentityV1`` response.

    ``list_service_ids``, ``list_api_keys``, and ``list_profiles`` return::

        {"next": "https://…?pagetoken=<token>&pagesize=<n>"}
    """
    next_val = response.get("next")
    if not next_val:
        return None
    url = next_val if isinstance(next_val, str) else next_val.get("href", "")
    return _token_from_url(url, "pagetoken")


def _token_from_url(url, param):
    """Return the value of *param* from the query string of *url*, or ``None``."""
    if not url:
        return None
    for part in url.split("?", 1)[-1].split("&"):
        if part.startswith(param + "="):
            return part[len(param) + 1:]
    return None


class ResourceQuery:
    """Invoke an IBM Cloud SDK list method and collect all pages."""

    def __init__(self, session_factory):
        self.session_factory = session_factory

    def filter(self, resource_manager, query=None):
        m = resource_manager.resource_type
        session = local_session(self.session_factory)

        if m.global_service:
            client = session.client(m.service)
        else:
            client = session.client(m.service)

        extra_params = dict(m.extra_params or {})
        if query:
            extra_params.update(query)

        # Inject account_id if the resource type requires it
        if m.scope == "account" and "account_id" in m.required_params:
            extra_params.setdefault("account_id", session.account_id)

        method_name, result_path, _ = m.enum_spec
        method = getattr(client, method_name)

        if m.pagination == "cursor":
            return self._paginate_cursor(method, extra_params, result_path)
        elif m.pagination == "iam-cursor":
            return self._paginate_iam_cursor(method, extra_params, result_path)
        elif m.pagination == "offset":
            return self._paginate_offset(method, extra_params, result_path)
        else:
            # Single-call (no pagination)
            response = method(**extra_params).get_result()
            return _extract_path(response, result_path)

    # ------------------------------------------------------------------
    # Pagination strategies
    # ------------------------------------------------------------------

    def _paginate_cursor(self, method, params, result_path):
        """Collect all pages using the VPC / UserManagement start-cursor pattern.

        Passes ``limit`` + ``start`` on each call.  Used by VPC and
        ``UserManagementV1.list_users``.
        """
        results = []
        start = None
        while True:
            kw = dict(params)
            if start:
                kw["start"] = start
            kw.setdefault("limit", IBM_DEFAULT_PAGE_SIZE)
            response = method(**kw).get_result()
            page = _extract_path(response, result_path)
            if page:
                results.extend(page)
            start = _extract_next_token(response)
            if not start:
                break
        return results

    def _paginate_iam_cursor(self, method, params, result_path):
        """Collect all pages using the IamIdentityV1 pagesize/pagetoken pattern.

        ``list_service_ids``, ``list_api_keys``, and ``list_profiles`` accept
        ``pagesize`` and ``pagetoken`` — NOT ``limit``/``start``.
        """
        results = []
        pagetoken = None
        while True:
            kw = dict(params)
            if pagetoken:
                kw["pagetoken"] = pagetoken
            kw.setdefault("pagesize", IBM_DEFAULT_PAGE_SIZE)
            response = method(**kw).get_result()
            page = _extract_path(response, result_path)
            if page:
                results.extend(page)
            pagetoken = _extract_pagetoken(response)
            if not pagetoken:
                break
        return results

    def _paginate_offset(self, method, params, result_path):
        """Collect all pages using the offset/limit pattern (KMS, ICD)."""
        results = []
        offset = 0
        limit = IBM_DEFAULT_PAGE_SIZE
        while True:
            kw = dict(params)
            kw["limit"] = limit
            kw["offset"] = offset
            response = method(**kw).get_result()
            page = _extract_path(response, result_path)
            if not page:
                break
            results.extend(page)
            if len(page) < limit:
                break
            offset += limit
        return results


def _extract_path(data, path):
    """Walk a dotted *path* through nested dicts/lists and return the value."""
    if not path:
        return data
    for key in path.split("."):
        if data is None:
            return []
        if isinstance(data, list):
            # jmespath-lite: apply remaining path to each element
            return [_extract_path(item, key) for item in data]
        data = data.get(key, [])
    return data or []


# ---------------------------------------------------------------------------
# Describe source — registered on the global sources registry
# ---------------------------------------------------------------------------

@sources.register("describe-ibm")
class DescribeSource:
    """Default source for IBM Cloud resources (uses ResourceQuery)."""

    def __init__(self, manager):
        self.manager = manager
        self.query = ResourceQuery(manager.session_factory)

    def get_resources(self, query):
        return self.query.filter(self.manager, query or {})

    def augment(self, resources):
        return resources

    def get_permissions(self):
        m = self.manager.resource_type
        if m.permissions:
            return m.permissions
        method, _, _ = m.enum_spec
        return ("%s:%s" % (m.service, method),)


# ---------------------------------------------------------------------------
# QueryMeta / QueryResourceManager
# ---------------------------------------------------------------------------

class QueryMeta(type):
    """Metaclass providing per-class filter and action registries."""

    def __new__(cls, name, parents, attrs):
        if "filter_registry" not in attrs:
            attrs["filter_registry"] = FilterRegistry("%s.filters" % name.lower())
        if "action_registry" not in attrs:
            attrs["action_registry"] = ActionRegistry("%s.actions" % name.lower())
        return super().__new__(cls, name, parents, attrs)


class QueryResourceManager(ResourceManager, metaclass=QueryMeta):
    """Base resource manager for all IBM Cloud resource types."""

    type: str
    resource_type: "TypeInfo"

    def __init__(self, ctx, data):
        super().__init__(ctx, data)
        self.source = self.get_source(self.source_type)

    @property
    def source_type(self):
        return self.data.get("source", "describe-ibm")

    def get_source(self, source_type):
        return sources.get(source_type)(self)

    def get_client(self):
        session = local_session(self.session_factory)
        return session.client(self.resource_type.service)

    def get_session(self):
        return local_session(self.session_factory)

    def get_model(self):
        return self.resource_type

    def get_permissions(self):
        return self.source.get_permissions()

    def get_cache_key(self, query):
        session = local_session(self.session_factory)
        return {
            "source_type": self.source_type,
            "query": query,
            "account_id": session.account_id,
            "region": session.region,
            # Use the manager's registered type name (e.g. "vpc-floating-ip"), not
            # the inner class __name__ which is always "resource_type" for every
            # IBM resource and would cause all VPC types to share one cache slot.
            "resource_type": self.type,
        }

    def get_resource_query(self):
        if "query" in self.data:
            return self.data["query"]
        return None

    def resources(self, query=None):
        q = query or self.get_resource_query()
        cache_key = self.get_cache_key(q)

        self._cache.load()
        cached = self._cache.get(cache_key)
        if cached is not None:
            self.log.debug(
                "Using cached ibm.%s: %d", self.type, len(cached)
            )
            resources = cached
        else:
            with self.ctx.tracer.subsegment("resource-fetch"):
                resources = self._fetch_resources(q)
            self._cache.save(cache_key, resources)

        self._cache.close()
        resource_count = len(resources)

        with self.ctx.tracer.subsegment("filter"):
            resources = self.filter_resources(resources)

        if self.data == self.ctx.policy.data:
            self.check_resource_limit(len(resources), resource_count)

        return resources

    def check_resource_limit(self, selection_count, population_count):
        p = self.ctx.policy
        limits = MaxResourceLimit(p, selection_count, population_count)
        return limits.check_resource_limits()

    def _fetch_resources(self, query):
        resources = self.source.get_resources(query) or []
        return self.source.augment(resources)

    def augment(self, resources):
        return resources

    def _get_extra_params(self):
        return {}


# ---------------------------------------------------------------------------
# TypeInfo — resource type descriptor
# ---------------------------------------------------------------------------

class TypeInfo:
    """Metadata descriptor for an IBM Cloud resource type.

    Attributes
    ----------
    service:
        Logical service name from ``session.SERVICE_MAP``
        (e.g. ``"vpc"``, ``"iam-identity"``).
    global_service:
        ``True`` when the service is not region-scoped (IAM, GlobalSearch, …).
    enum_spec:
        3-tuple ``(method_name, result_path, extra_params)`` where:
        - *method_name* is the SDK list method,
        - *result_path* is a dot-separated path into the response dict
          (e.g. ``"instances"``),
        - *extra_params* is a dict of additional fixed keyword arguments.
    pagination:
        ``"cursor"`` (VPC/IAM start-token), ``"offset"`` (KMS/ICD),
        or ``None`` (single-page).
    required_params:
        Set of param names that the query layer must auto-fill
        (e.g. ``{"account_id"}``).
    id:
        Field name of the resource's primary identifier.
    name:
        Field name of the resource's human-readable name.
    default_report_fields:
        List of field names shown in tabular reports.
    permissions:
        Explicit list of required IAM permissions (optional).
    scope:
        ``"account"`` or ``"regional"`` — determines how account/region params
        are injected.
    """

    service = None
    global_service = False
    enum_spec = (None, None, None)
    pagination = "cursor"
    required_params = set()
    extra_params = None
    id = "id"
    name = "name"
    default_report_fields = ("id", "name")
    permissions = ()
    scope = "account"
    # Tag type used when attaching/detaching tags via GlobalTaggingV1.
    # VPC / COS / ICD / KMS resources use "user" tags (Resource Controller plane).
    # IAM Identity resources (service-id, api-key, trusted-profile, access-group)
    # are not RC-registered and require "access" tags instead.
    tag_type = "user"

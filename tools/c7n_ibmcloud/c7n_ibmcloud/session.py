# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Cloud session management.

Provides SessionFactory and Session that wrap the IBM Cloud Python SDKs.
Authentication is handled via IAMAuthenticator (API key), with a fallback path
for Trusted Profile / compute identity.  COS uses a separate credential branch
because ibm-cos-sdk requires HMAC keys rather than an IAMAuthenticator.
"""

import importlib
import logging
import os

log = logging.getLogger("custodian.ibm.session")

# ---------------------------------------------------------------------------
# IBM Cloud regions supported for VPC and regional services.
# IAM / GlobalSearch / GlobalTagging / ResourceController are global.
# ---------------------------------------------------------------------------
IBM_REGIONS = [
    "au-syd",
    "br-sao",
    "ca-tor",
    "eu-de",
    "eu-es",
    "eu-gb",
    "jp-osa",
    "jp-tok",
    "us-east",
    "us-south",
]

# Map logical service names used by resource modules to
# (dotted SDK class path, {extra constructor kwargs}) tuples.
# Services that need region-specific endpoints are handled in Session.client().
SERVICE_MAP = {
    # VPC Infrastructure — region-scoped (no service_name kwarg in VpcV1)
    "vpc": ("ibm_vpc.VpcV1", {}),
    # IAM — global
    "iam-identity": ("ibm_platform_services.IamIdentityV1", {}),
    "iam-users": ("ibm_platform_services.UserManagementV1", {}),
    "iam-policy": ("ibm_platform_services.IamPolicyManagementV1", {}),
    "iam-groups": ("ibm_platform_services.IamAccessGroupsV2", {}),
    # Resource Controller / Global Search / Global Tagging — global
    "resource-ctrl": ("ibm_platform_services.ResourceControllerV2", {}),
    "global-search": ("ibm_platform_services.GlobalSearchV2", {}),
    "global-tagging": ("ibm_platform_services.GlobalTaggingV1", {}),
    # Cloud Databases — global
    "databases": ("ibm_platform_services.CloudDatabasesV5", {}),
}

# VPC API regional endpoint template.
# Must include /v1 — VpcV1.set_service_url() does NOT append a path prefix,
# so omitting it yields URLs like https://us-south.iaas.cloud.ibm.com/instances
# instead of the correct https://us-south.iaas.cloud.ibm.com/v1/instances.
VPC_ENDPOINT_TEMPLATE = "https://{region}.iaas.cloud.ibm.com/v1"

# PowerVS (Power IaaS) regional endpoint template
POWERVS_ENDPOINT_TEMPLATE = "https://{region}.power-iaas.cloud.ibm.com"

# PowerVS datacenter → API region mapping
POWERVS_REGION_MAP = {
    "dal": "us-south",
    "us-south": "us-south",
    "us-east": "us-east",
    "wdc": "us-east",
    "eu-de": "eu-de",
    "lon": "eu-gb",
    "eu-gb": "eu-gb",
    "tok": "jp-tok",
    "jp-tok": "jp-tok",
    "osa": "jp-osa",
    "jp-osa": "jp-osa",
    "sao": "br-sao",
    "br-sao": "br-sao",
    "tor": "ca-tor",
    "ca-tor": "ca-tor",
    "syd": "au-syd",
    "au-syd": "au-syd",
    "mon": "ca-tor",
}


class SessionFactory:
    """Creates IBM Cloud Session objects.

    Credential resolution order:
    1. Explicit ``api_key`` argument.
    2. ``IBMCLOUD_API_KEY`` environment variable.
    3. ``~/.ibmcloud/credentials`` profile (future: ibmcloud CLI config).
    4. Trusted Profile / compute metadata endpoint (future).
    """

    def __init__(self, api_key=None, region=None, account_id=None, profile=None):
        self.api_key = api_key or os.environ.get("IBMCLOUD_API_KEY", "")
        self.region = region or os.environ.get("IBMCLOUD_REGION", "us-south")
        self.account_id = account_id or os.environ.get("IBMCLOUD_ACCOUNT_ID", "")
        self.profile = profile
        self._authenticator = None

    @property
    def authenticator(self):
        """Return a cached IAMAuthenticator instance."""
        if self._authenticator is None:
            from ibm_cloud_sdk_core.authenticators import IAMAuthenticator

            self._authenticator = IAMAuthenticator(self.api_key)
        return self._authenticator

    def __call__(self):
        return Session(
            authenticator=self.authenticator,
            region=self.region,
            account_id=self.account_id,
        )


class Session:
    """IBM Cloud API session.

    Wraps multiple IBM SDK clients under a single authenticated context.
    Clients are lazy-instantiated and cached per service name.
    """

    def __init__(self, authenticator, region, account_id):
        self._authenticator = authenticator
        self.region = region
        self.account_id = account_id
        self._clients = {}

    # ------------------------------------------------------------------
    # Generic SDK client factory
    # ------------------------------------------------------------------

    def client(self, service_name, **kwargs):
        """Return an authenticated IBM SDK client for *service_name*.

        Parameters
        ----------
        service_name:
            Logical name from SERVICE_MAP, or a dotted class path
            (e.g. ``"ibm_vpc.VpcV1"``).
        **kwargs:
            Override any constructor kwargs defined in SERVICE_MAP.
        """
        cache_key = (service_name, self.region, tuple(sorted(kwargs.items())))
        if cache_key in self._clients:
            return self._clients[cache_key]

        # Key Protect is handled by a dedicated thin REST client
        if service_name == "key-protect":
            instance = KeyProtectClient(
                authenticator=self._authenticator,
                region=self.region,
            )
            self._clients[cache_key] = instance
            return instance

        # Transit Gateway has no Python SDK — use thin REST client
        if service_name == "transit-gateway":
            instance = TransitGatewayClient(authenticator=self._authenticator)
            self._clients[cache_key] = instance
            return instance

        # Resolve class path + base kwargs
        if service_name in SERVICE_MAP:
            class_path, base_kwargs = SERVICE_MAP[service_name]
        elif "." in service_name:
            class_path = service_name
            base_kwargs = {}
        else:
            raise KeyError("Unknown IBM service: %s" % service_name)

        constructor_kwargs = dict(base_kwargs)
        constructor_kwargs.update(kwargs)

        # Inject authenticator
        constructor_kwargs["authenticator"] = self._authenticator

        # VpcV1.__init__ does NOT accept service_url — set it after construction
        # via set_service_url().  Remove it from constructor kwargs if present.
        vpc_endpoint = None
        if service_name == "vpc" or class_path.endswith("VpcV1"):
            vpc_endpoint = constructor_kwargs.pop(
                "service_url",
                VPC_ENDPOINT_TEMPLATE.format(region=self.region),
            )

        sdk_class = _import_class(class_path)
        instance = sdk_class(**constructor_kwargs)

        # Apply the regional endpoint now that the instance exists
        if vpc_endpoint and hasattr(instance, "set_service_url"):
            instance.set_service_url(vpc_endpoint)

        self._clients[cache_key] = instance
        return instance

    # ------------------------------------------------------------------
    # COS client (uses ibm-cos-sdk / boto3-compatible)
    # ------------------------------------------------------------------

    def cos_client(
        self,
        endpoint_url=None,
        hmac_access_key=None,
        hmac_secret_key=None,
        cos_instance_id=None,
    ):
        """Return an ibm-cos-sdk (boto3-compatible) client for Cloud Object Storage.

        Parameters
        ----------
        endpoint_url:
            Override the COS S3 endpoint (defaults to regional endpoint from
            ``IBMCLOUD_COS_ENDPOINT`` or the session region).
        hmac_access_key / hmac_secret_key:
            HMAC credentials; if provided (or set via env vars
            ``IBMCLOUD_COS_HMAC_ACCESS_KEY_ID`` / ``IBMCLOUD_COS_HMAC_SECRET_ACCESS_KEY``),
            HMAC signing is used.  HMAC mode supports ``list_buckets_extended()``.
        cos_instance_id:
            COS service instance GUID to use as ``ibm_service_instance_id``.
            Overrides ``IBMCLOUD_COS_RESOURCE_INSTANCE_ID`` env var.
            Required for ``list_buckets(IBMServiceInstanceId=...)`` with IAM auth.
        """
        cache_key = ("cos", endpoint_url, cos_instance_id)
        if cache_key in self._clients:
            return self._clients[cache_key]

        import ibm_boto3
        from ibm_botocore.client import Config

        hmac_key = hmac_access_key or os.environ.get("IBMCLOUD_COS_HMAC_ACCESS_KEY_ID")
        hmac_secret = hmac_secret_key or os.environ.get("IBMCLOUD_COS_HMAC_SECRET_ACCESS_KEY")
        endpoint = endpoint_url or os.environ.get(
            "IBMCLOUD_COS_ENDPOINT",
            "https://s3.{region}.cloud-object-storage.appdomain.cloud".format(
                region=self.region
            ),
        )
        instance_id = cos_instance_id or os.environ.get("IBMCLOUD_COS_RESOURCE_INSTANCE_ID", "")

        if hmac_key and hmac_secret:
            cos = ibm_boto3.client(
                "s3",
                aws_access_key_id=hmac_key,
                aws_secret_access_key=hmac_secret,
                config=Config(signature_version="hmac"),
                endpoint_url=endpoint,
            )
        else:
            # IAM token-based auth — apikey lives on token_manager, not authenticator
            cos = ibm_boto3.client(
                "s3",
                ibm_api_key_id=self._authenticator.token_manager.apikey,
                ibm_service_instance_id=instance_id,
                ibm_auth_endpoint="https://iam.cloud.ibm.com/identity/token",
                config=Config(signature_version="oauth"),
                endpoint_url=endpoint,
            )

        self._clients[cache_key] = cos
        return cos

    # ------------------------------------------------------------------
    # COS Resource Configuration REST client
    # ------------------------------------------------------------------

    def cos_resource_config_client(self):
        """Return a thin REST client for the IBM COS Resource Configuration API.

        The Resource Configuration API (``config.cloud-object-storage.cloud.ibm.com``)
        is separate from the S3-compatible data-plane API.  It exposes bucket metadata
        including the CRN, firewall settings, and public-access configuration that the
        S3 ``list_buckets`` / ``head_bucket`` calls do not return.

        There is no dedicated Python SDK for this API — we wrap it as a lightweight
        REST client that matches the ``.get_result()`` convention used by all other
        IBM SDK clients in this codebase.
        """
        cache_key = ("cos-resource-config",)
        if cache_key in self._clients:
            return self._clients[cache_key]
        client = COSResourceConfigClient(authenticator=self._authenticator)
        self._clients[cache_key] = client
        return client

    # ------------------------------------------------------------------
    # PowerVS REST client (no official Python SDK)
    # ------------------------------------------------------------------

    def powervs_client(self, workspace_id, region=None, workspace_crn=None):
        """Return a thin PowerVS REST wrapper for the given workspace GUID / CRN."""
        r = region or self.region
        return PowerVSClient(
            workspace_id=workspace_id,
            authenticator=self._authenticator,
            region=r,
            workspace_crn=workspace_crn,
        )

    def __repr__(self):
        return "<ibm-session region=%s account=%s>" % (self.region, self.account_id)


# ---------------------------------------------------------------------------
# Key Protect thin REST client
# ---------------------------------------------------------------------------

KMS_ENDPOINT_TEMPLATE = "https://{region}.kms.cloud.ibm.com"


class KeyProtectClient:
    """Minimal REST client for the IBM Key Protect API.

    Key Protect has no standalone Python SDK in ibm-platform-services;
    this wraps the REST API directly using an IAM bearer token.
    """

    def __init__(self, authenticator, region):
        self._authenticator = authenticator
        self.region = region

    def _token(self):
        return self._authenticator.token_manager.get_token()

    def _headers(self, instance_id=""):
        h = {
            "Authorization": "Bearer %s" % self._token(),
            "Accept": "application/vnd.ibm.kms.key+json",
        }
        if instance_id:
            h["bluemix-instance"] = instance_id
        return h

    def _base(self):
        return KMS_ENDPOINT_TEMPLATE.format(region=self.region)

    def get_keys(self, instance_id, limit=50, offset=0, **kwargs):
        """List keys in the given Key Protect instance (matches offset pagination)."""
        import requests
        url = "%s/api/v2/keys" % self._base()
        params = {"limit": limit, "offset": offset}
        resp = requests.get(url, headers=self._headers(instance_id), params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        # Wrap in get_result()-compatible object so query layer works uniformly
        return _DictResult(data)

    def get_key_rings_in_instance(self, instance_id, **kwargs):
        """List key rings in the given Key Protect instance."""
        import requests
        url = "%s/api/v2/key_rings" % self._base()
        resp = requests.get(url, headers=self._headers(instance_id), timeout=30)
        resp.raise_for_status()
        return _DictResult(resp.json())

    def get_key_policies(self, id, instance_id="", **kwargs):
        """Get policies for a single key."""
        import requests
        url = "%s/api/v2/keys/%s/policies" % (self._base(), id)
        resp = requests.get(url, headers=self._headers(instance_id), timeout=30)
        resp.raise_for_status()
        return _DictResult(resp.json())

    def action_on_key(self, id, action, instance_id="", **kwargs):
        """Perform an action (disable, enable, rotate) on a key.

        Each action requires its own Content-Type per the Key Protect API spec:
        https://cloud.ibm.com/apidocs/key-protect#action-on-key
        Without the correct Content-Type the API returns 409 Conflict.
        """
        import requests
        action_content_types = {
            "disable": "application/vnd.ibm.kms.key_action_disable+json",
            "enable":  "application/vnd.ibm.kms.key_action_enable+json",
            "rotate":  "application/vnd.ibm.kms.key_action_rotate+json",
        }
        headers = self._headers(instance_id)
        headers["Content-Type"] = action_content_types.get(
            action, "application/vnd.ibm.kms.key_action+json"
        )
        url = "%s/api/v2/keys/%s/actions/%s" % (self._base(), id, action)
        resp = requests.post(url, headers=headers, json={}, timeout=30)
        resp.raise_for_status()

    def set_key_for_deletion(self, id, instance_id="", **kwargs):
        """Authorise a key for deletion (dual-auth)."""
        import requests
        url = "%s/api/v2/keys/%s/actions/setKeyForDeletion" % (self._base(), id)
        resp = requests.post(url, headers=self._headers(instance_id), json={}, timeout=30)
        resp.raise_for_status()

    def delete_key(self, id, instance_id="", prefer="return=representation", **kwargs):
        """Delete a key."""
        import requests
        url = "%s/api/v2/keys/%s" % (self._base(), id)
        h = self._headers(instance_id)
        h["Prefer"] = prefer
        resp = requests.delete(url, headers=h, timeout=30)
        resp.raise_for_status()

    def delete_key_ring(self, key_ring_id, instance_id="", **kwargs):
        """Delete a key ring."""
        import requests
        url = "%s/api/v2/key_rings/%s" % (self._base(), key_ring_id)
        resp = requests.delete(url, headers=self._headers(instance_id), timeout=30)
        resp.raise_for_status()


class _DictResult:
    """Thin wrapper so KeyProtectClient responses match the .get_result() pattern."""
    def __init__(self, data):
        self._data = data

    def get_result(self):
        return self._data


# ---------------------------------------------------------------------------
# PowerVS thin REST client
# ---------------------------------------------------------------------------

class PowerVSClient:
    """Minimal REST client for the IBM Power IaaS API.

    The Power IaaS API has no official Python SDK; this wraps requests
    with an IAM bearer token obtained from the authenticator.
    """

    BASE_URL = POWERVS_ENDPOINT_TEMPLATE

    def __init__(self, workspace_id, authenticator, region, workspace_crn=None):
        self.workspace_id = workspace_id
        self.workspace_crn = workspace_crn or workspace_id
        self._authenticator = authenticator
        self.region = region
        self._session = None

    def _get_token(self, force_refresh=False):
        """Retrieve a current IAM bearer token, refreshing if requested."""
        token_manager = self._authenticator.token_manager
        if force_refresh:
            # Force SDK token manager to clear cached token and fetch fresh one
            token_manager.expire_time = 0
            token_manager.token_info = {}
        return token_manager.get_token()

    def _headers(self, with_crn=True, force_refresh=False):
        headers = {
            "Authorization": "Bearer %s" % self._get_token(force_refresh=force_refresh),
            "Content-Type": "application/json",
        }
        if with_crn and self.workspace_crn:
            headers["CRN"] = self.workspace_crn
        return headers

    def _url(self, path, v1=False):
        base = self.BASE_URL.format(region=self.region)
        if v1:
            return "%s/v1%s" % (base, path)
        return "%s/pcloud/v1/cloud-instances/%s%s" % (base, self.workspace_id, path)

    def _request(self, method, path, v1=False, **kwargs):
        """Perform request with automatic token refresh on 401.

        Both pcloud (``/pcloud/v1/cloud-instances/{ws}/...``) and workspace
        (``/v1/...``) endpoints require the ``CRN`` header to scope the request
        to the correct workspace.  The header is always sent when
        ``workspace_crn`` is set.
        """
        import requests

        url = self._url(path, v1=v1)
        headers = self._headers(with_crn=True)
        resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)

        # Retry once on 401 with a freshly fetched IAM token
        if resp.status_code == 401:
            headers = self._headers(with_crn=True, force_refresh=True)
            resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)

        return resp

    def list(self, path, result_key=None, v1=False):
        """GET *path* and return the list found under *result_key* or list body."""
        resp = self._request("GET", path, v1=v1)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            return data
        if result_key and isinstance(data, dict):
            return data.get(result_key, [])
        if isinstance(data, dict):
            # Try to find list under common keys
            if result_key in data:
                return data[result_key]
            for v in data.values():
                if isinstance(v, list):
                    return v
        return []

    def get(self, path, v1=False):
        """GET *path* and return the full response dict."""
        resp = self._request("GET", path, v1=v1)
        resp.raise_for_status()
        return resp.json()

    def post(self, path, body, v1=False):
        """POST *body* to *path* and return the response JSON."""
        resp = self._request("POST", path, v1=v1, json=body)
        resp.raise_for_status()
        return resp.json()

    def delete(self, path, v1=False):
        """DELETE *path*."""
        resp = self._request("DELETE", path, v1=v1)
        resp.raise_for_status()

    def put(self, path, body, v1=False):
        """PUT *body* to *path* and return the response JSON."""
        resp = self._request("PUT", path, v1=v1, json=body)
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# COS Resource Configuration thin REST client
# ---------------------------------------------------------------------------

COS_RC_ENDPOINT = "https://config.cloud-object-storage.cloud.ibm.com/v1"


class COSResourceConfigClient:
    """Thin REST client for the IBM COS Resource Configuration API.

    Endpoint: ``GET /v1/b/{bucket}``
    Documentation: https://cloud.ibm.com/apidocs/cos/cos-configuration

    Returns bucket metadata including ``crn``, ``firewall.allowed_ip``, and
    activity-tracking / metrics-monitoring settings that the S3-compatible
    data-plane API does not expose.

    Responses are wrapped in a ``_DictResult`` so callers can use the standard
    ``.get_result()`` convention that all other IBM SDK clients use.
    """

    def __init__(self, authenticator):
        self._authenticator = authenticator

    def _token(self):
        return self._authenticator.token_manager.get_token()

    def _headers(self):
        return {
            "Authorization": "Bearer %s" % self._token(),
            "Accept": "application/json",
        }

    def get_bucket_config(self, bucket):
        """GET /v1/b/{bucket} — return a _DictResult wrapping the response JSON."""
        import requests
        url = "%s/b/%s" % (COS_RC_ENDPOINT, bucket)
        resp = requests.get(url, headers=self._headers(), timeout=30)
        resp.raise_for_status()
        return _DictResult(resp.json())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _import_class(dotted_path):
    """Import and return a class from a dotted module path string."""
    module_path, class_name = dotted_path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


# ---------------------------------------------------------------------------
# Transit Gateway thin REST client
# ---------------------------------------------------------------------------

TGW_ENDPOINT = "https://transit.cloud.ibm.com/v1"
TGW_API_VERSION = "2024-01-01"


class TransitGatewayClient:
    """Minimal REST client for the IBM Transit Gateway API.

    The Transit Gateway API is not included in ibm-platform-services.
    This wraps the REST API directly using an IAM bearer token.

    API reference: https://cloud.ibm.com/apidocs/transit-gateway
    """

    def __init__(self, authenticator):
        self._authenticator = authenticator

    def _token(self):
        return self._authenticator.token_manager.get_token()

    def _headers(self):
        return {
            "Authorization": "Bearer %s" % self._token(),
            "Accept": "application/json",
        }

    def list_transit_gateways(self, limit=50, start=None):
        """List all transit gateways. Returns the raw response dict."""
        import requests
        params = {"version": TGW_API_VERSION, "limit": limit}
        if start:
            params["start"] = start
        resp = requests.get(
            "%s/transit_gateways" % TGW_ENDPOINT,
            headers=self._headers(),
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def delete_transit_gateway(self, gateway_id):
        """Delete a transit gateway by ID."""
        import requests
        params = {"version": TGW_API_VERSION}
        resp = requests.delete(
            "%s/transit_gateways/%s" % (TGW_ENDPOINT, gateway_id),
            headers=self._headers(),
            params=params,
            timeout=30,
        )
        resp.raise_for_status()

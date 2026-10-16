# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
Test fixtures and helpers for c7n_ibmcloud tests.

Tests use the ``responses`` library to intercept HTTP calls and return
pre-recorded (cassette) responses without hitting real IBM Cloud APIs.
"""

import json
import os

import pytest

# Ensure the IBM Cloud provider is registered before tests run
import c7n_ibmcloud.entry  # noqa
from c7n_ibmcloud.entry import initialize_ibm

initialize_ibm()


# ---------------------------------------------------------------------------
# Environment stubs — set required env vars for tests
# ---------------------------------------------------------------------------

os.environ.setdefault("IBMCLOUD_API_KEY", "test-api-key-placeholder")
os.environ.setdefault("IBMCLOUD_REGION", "us-south")
os.environ.setdefault("IBMCLOUD_ACCOUNT_ID", "test-account-id-123")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeResult:
    """Mimics the .get_result() interface of IBM SDK responses."""

    def __init__(self, data):
        self._data = data

    def get_result(self):
        return self._data


class FakeIAMAuthenticator:
    """Stub IAMAuthenticator that never calls the real IAM token endpoint."""

    def __init__(self, api_key="test-key"):
        self.iam_apikey = api_key

    class _token_manager:
        @staticmethod
        def get_token():
            return "Bearer fake-token"

    token_manager = _token_manager()

    def validate(self):
        pass


class FakeSession:
    """Minimal session stub used in policy tests."""

    def __init__(self, clients=None, region="us-south", account_id="test-account-id-123"):
        self._clients = clients or {}
        self.region = region
        self.account_id = account_id
        self._authenticator = FakeIAMAuthenticator()

    def client(self, service_name, **kwargs):
        if service_name in self._clients:
            return self._clients[service_name]
        raise KeyError("No fake client registered for service: %s" % service_name)

    def cos_client(self, endpoint_url=None, hmac_access_key=None,
                   hmac_secret_key=None, cos_instance_id=None, **kwargs):
        return self._clients.get("cos")

    def powervs_client(self, workspace_id, region=None, workspace_crn=None):
        return self._clients.get("powervs")


class FakeSessionFactory:
    """Session factory that always returns a FakeSession."""

    def __init__(self, session):
        self._session = session

    def __call__(self):
        return self._session


# ---------------------------------------------------------------------------
# Policy runner
# ---------------------------------------------------------------------------

def load_policy(data, session=None):
    """Build and return a minimal runnable c7n Policy from a raw dict.

    Parameters
    ----------
    data:
        Policy dict (same shape as YAML).
    session:
        Optional FakeSession; if provided it is wired as the session factory.
    """
    from c7n.config import Config
    from c7n.ctx import ExecutionContext
    from c7n.policy import Policy

    config = Config.empty(region="us-south", account_id="test-account-id-123")
    if session:
        factory = FakeSessionFactory(session)
    else:
        factory = None

    return Policy(data, config, session_factory=factory)


# ---------------------------------------------------------------------------
# pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_session():
    """Return a factory function to create FakeSessions with pre-loaded clients."""
    def _make(clients=None, region="us-south", account_id="test-account-id-123"):
        return FakeSession(clients=clients or {}, region=region, account_id=account_id)
    return _make


@pytest.fixture
def policy_runner():
    """Return the load_policy helper as a fixture."""
    return load_policy

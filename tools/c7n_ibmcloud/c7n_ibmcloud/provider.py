# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Cloud provider registration.

Registers the ``ibm`` cloud provider with Cloud Custodian's plugin system,
wires up the SessionFactory, and handles region expansion so that a single
policy can target multiple IBM Cloud regions.
"""

import copy
import logging
import os

from c7n.provider import Provider, clouds
from c7n.registry import PluginRegistry

from c7n_ibmcloud.resources.resource_map import ResourceMap
from c7n_ibmcloud.session import SessionFactory, IBM_REGIONS

log = logging.getLogger("custodian.ibm.provider")


@clouds.register("ibm")
class IBMCloud(Provider):
    """IBM Cloud provider for Cloud Custodian."""

    display_name = "IBM Cloud"
    resource_prefix = "ibm"
    resources = PluginRegistry("%s.resources" % resource_prefix)
    resource_map = ResourceMap

    def initialize(self, options):
        """Resolve account_id if not supplied and validate required credentials."""
        if not options.get("account_id"):
            account_id = os.environ.get("IBMCLOUD_ACCOUNT_ID", "")
            if account_id:
                options["account_id"] = account_id
            else:
                # Attempt to resolve via IAM API
                try:
                    options["account_id"] = self._resolve_account_id(options)
                except Exception as exc:
                    log.warning("Could not resolve IBM Cloud account ID: %s", exc)

        if not options.get("region"):
            options["region"] = os.environ.get("IBMCLOUD_REGION", "us-south")

        return options

    def _resolve_account_id(self, options):
        """Look up account_id from the IAM identity service."""
        factory = self.get_session_factory(options)
        session = factory()
        client = session.client("iam-identity")
        # get_api_keys_details can reveal the bound account
        result = client.get_api_keys_details(
            iam_apikey=os.environ.get("IBMCLOUD_API_KEY", "")
        ).get_result()
        return result.get("account_id", "")

    def initialize_policies(self, policy_collection, options):
        """Expand a policy collection to cover multiple regions if requested."""
        from c7n.policy import Policy, PolicyCollection

        if not options.get("regions"):
            return policy_collection

        requested = options["regions"]
        if "all" in requested:
            target_regions = IBM_REGIONS
        else:
            target_regions = [r for r in requested if r in IBM_REGIONS]
            unknown = set(requested) - set(IBM_REGIONS) - {"all"}
            if unknown:
                log.warning("Unknown IBM Cloud regions requested: %s", unknown)

        policies = []
        for p in policy_collection:
            for region in target_regions:
                opts_copy = copy.copy(options)
                opts_copy.region = region
                if len(target_regions) > 1 and getattr(opts_copy, "output_dir", None):
                    opts_copy.output_dir = "/".join([opts_copy.output_dir.rstrip("/"), region])
                policies.append(
                    Policy(
                        p.data,
                        opts_copy,
                        session_factory=self.get_session_factory(opts_copy),
                    )
                )
        return PolicyCollection(policies, options)

    def get_session_factory(self, options):
        """Build a SessionFactory from resolved options."""
        return SessionFactory(
            api_key=os.environ.get("IBMCLOUD_API_KEY", ""),
            region=getattr(options, "region", None) or options.get("region", "us-south"),
            account_id=getattr(options, "account_id", None) or options.get("account_id", ""),
        )


# Module-level shortcut used by resource modules:
#   from c7n_ibmcloud.provider import resources
resources = IBMCloud.resources

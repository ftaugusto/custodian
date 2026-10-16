# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Cloud provider entry point.

This module is referenced by the ``c7n.providers`` entry point in
``pyproject.toml``.  Cloud Custodian calls ``initialize_ibm()`` at startup
to register all resources, filters, and actions.
"""

import logging

# Register the IBM Cloud provider (must come first)
from c7n_ibmcloud.provider import IBMCloud  # noqa

logging.getLogger("ibm_cloud_sdk_core").setLevel(logging.WARNING)
logging.getLogger("ibm_platform_services").setLevel(logging.WARNING)
logging.getLogger("ibm_vpc").setLevel(logging.WARNING)


def initialize_ibm():
    """Load all IBM Cloud resource modules and shared components."""

    # Shared filters and actions
    import c7n_ibmcloud.filters  # noqa
    import c7n_ibmcloud.actions  # noqa

    # Output backend
    import c7n_ibmcloud.output  # noqa

    # Resource modules — each file registers its types on IBMCloud.resources
    import c7n_ibmcloud.resources.iam  # noqa
    import c7n_ibmcloud.resources.vpc  # noqa
    import c7n_ibmcloud.resources.cos  # noqa
    import c7n_ibmcloud.resources.kms  # noqa
    import c7n_ibmcloud.resources.kubernetes  # noqa
    import c7n_ibmcloud.resources.powervs  # noqa
    import c7n_ibmcloud.resources.dbaas  # noqa

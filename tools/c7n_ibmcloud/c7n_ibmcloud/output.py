# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
IBM Cloud output backend — writes custodian execution output to a COS bucket.

Usage in custodian config::

    custodian run --output-dir cos://my-bucket/custodian-output/ policy.yml
"""

import logging
import os

from c7n.output import BlobOutput, blob_outputs

log = logging.getLogger("custodian.ibm.output")


@blob_outputs.register("cos")
class COSOutput(BlobOutput):
    """Store custodian run output in an IBM Cloud Object Storage bucket.

    The output directory URI format is::

        cos://<bucket-name>/<key-prefix>/

    Authentication uses the same credentials as the session layer:
    HMAC keys (``IBMCLOUD_COS_HMAC_ACCESS_KEY_ID`` /
    ``IBMCLOUD_COS_HMAC_SECRET_ACCESS_KEY``) or IAM token fallback.
    """

    def __init__(self, ctx, config=None):
        super().__init__(ctx, config)
        self.s3 = None

    @staticmethod
    def join(*parts):
        return "/".join(p.strip("/") for p in parts if p)

    def get_s3_client(self):
        if self.s3 is None:
            from c7n.utils import local_session

            session = local_session(self.ctx.session_factory)
            self.s3 = session.cos_client()
        return self.s3

    def upload(self):
        """Upload local output files to COS after policy execution."""
        bucket, key_prefix = self._parse_uri()
        s3 = self.get_s3_client()
        for root, _dirs, files in os.walk(self.root_dir):
            for fname in files:
                local_path = os.path.join(root, fname)
                rel_path = os.path.relpath(local_path, self.root_dir)
                key = self.join(key_prefix, rel_path)
                log.debug("Uploading %s → cos://%s/%s", local_path, bucket, key)
                s3.upload_file(local_path, bucket, key)

    def _parse_uri(self):
        """Parse ``cos://bucket/prefix`` into ``(bucket, prefix)``."""
        uri = self.config.get("url", "")
        uri = uri.removeprefix("cos://")
        bucket, _, prefix = uri.partition("/")
        return bucket, prefix

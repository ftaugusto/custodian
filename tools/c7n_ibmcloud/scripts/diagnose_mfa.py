#!/usr/bin/env python3
# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
Diagnostic: print raw get_mfa_status response for every user in the account.

Run this FIRST before debugging the mfa-disabled filter.
The output shows the exact JSON the IBM API returns so the filter logic
can be verified against real data.

Usage:
    cd cloud-custodian/tools/c7n_ibmcloud
    python3 scripts/diagnose_mfa.py
"""
import json
import os
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR  = os.path.normpath(os.path.join(_SCRIPT_DIR, ".."))
_C7N_DIR    = os.path.normpath(os.path.join(_TOOLS_DIR, "..", ".."))
for _p in (_TOOLS_DIR, _C7N_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from c7n_ibmcloud.session import SessionFactory


def main():
    api_key    = os.environ.get("IBMCLOUD_API_KEY", "")
    account_id = os.environ.get("IBMCLOUD_ACCOUNT_ID", "")
    region     = os.environ.get("IBMCLOUD_REGION", "us-south")
    if not api_key or not account_id:
        print("ERROR: set IBMCLOUD_API_KEY and IBMCLOUD_ACCOUNT_ID")
        sys.exit(1)

    session    = SessionFactory(api_key=api_key, region=region, account_id=account_id)()
    iam_users  = session.client("iam-users")
    iam_id_cli = session.client("iam-identity")

    # ── List all users ────────────────────────────────────────────────────────
    users = []
    start = None
    while True:
        kw = {"account_id": account_id, "limit": 100}
        if start:
            kw["start"] = start
        resp = iam_users.list_users(**kw).get_result()
        users.extend(resp.get("resources", []))
        next_url = resp.get("next_url", "")
        if not next_url:
            break
        for part in next_url.split("?", 1)[-1].split("&"):
            if part.startswith("start="):
                start = part[len("start="):]
                break
        else:
            break

    print(f"Total users: {len(users)}\n")
    print("=" * 70)

    for u in users:
        uid   = u.get("iam_id", u.get("id", "?"))
        email = u.get("email", "?")
        state = u.get("state", "?")
        print(f"\nUser : {email}")
        print(f"  iam_id : {uid}")
        print(f"  state  : {state}")

        if not uid.startswith("IBMid-"):
            print(f"  SKIPPED: non-IBMid prefix ({uid.split('-')[0]}) — MFA not applicable")
            continue

        try:
            result = iam_id_cli.get_mfa_status(
                account_id=account_id,
                iam_id=uid,
            ).get_result()

            # ── Print the FULL raw JSON so there is no ambiguity ─────────────
            print(f"  RAW RESPONSE:")
            print("    " + json.dumps(result, indent=4).replace("\n", "\n    "))

            # ── Summarise what the filter will decide ─────────────────────────
            eff = result.get("effective_mfa_type") or ""
            id_mfa   = result.get("id_based_mfa") or {}
            acct_mfa = result.get("account_based_mfa") or {}

            if not eff:
                decision = "enrolled=True  (no MFA requirement on account)"
            elif eff == "id_based_mfa":
                trait    = id_mfa.get("trait_effective") or ""
                complies = id_mfa.get("complies")
                if trait.upper() in ("NONE", "NONE_NO_ROPC", ""):
                    decision = f"enrolled=True  (trait_effective={trait!r} — no per-user MFA)"
                else:
                    decision = f"enrolled={complies}  (trait_effective={trait!r}, complies={complies})"
            elif eff == "account_based_mfa":
                complies = acct_mfa.get("complies")
                decision = f"enrolled={complies}  (account_based_mfa.complies={complies})"
            else:
                decision = f"enrolled=True  (unknown effective_mfa_type={eff!r} — safe default)"

            print(f"  FILTER DECISION: {decision}")

        except Exception as exc:
            print(f"  ERROR: {exc}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()

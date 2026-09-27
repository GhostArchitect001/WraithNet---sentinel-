"""
Ghost Sentinel - Key Rotation Reminder
=========================================

Lightweight "reminder mechanism" for key rotation - deliberately just
a script you run by hand or from cron, not a notification service with
its own moving parts.

Usage:
    python3 scripts/list_expiring_keys.py
    python3 scripts/list_expiring_keys.py --within-days 30
    python3 scripts/list_expiring_keys.py --tenant-id my-bank
    python3 scripts/list_expiring_keys.py --db-path data/ghost_sentinel_keys.db

Exit code is 1 if any keys are expiring/expired within the window, 0
otherwise - so this can gate a cron job's alerting (e.g. mail the
output only on nonzero exit) without any extra plumbing.

To actually rotate a listed key, use ApiKeyStore.rotate_key(raw_key) -
you'll need the raw key on hand (from wherever the tenant/ops team
keeps it), since only its hash is stored here. This script only tells
you WHAT needs rotating, not the raw key value itself (which this
system never retains after creation, by design).
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.api_keys import ApiKeyStore


def main():
    parser = argparse.ArgumentParser(
        description="List Ghost Sentinel API keys that are expired or expiring soon"
    )
    parser.add_argument(
        "--within-days", type=int, default=14,
        help="Flag keys expiring within this many days (default: 14)",
    )
    parser.add_argument("--tenant-id", default=None, help="Limit to one tenant")
    parser.add_argument("--db-path", default="data/ghost_sentinel_keys.db")
    args = parser.parse_args()

    store = ApiKeyStore(args.db_path)
    expiring = store.list_expiring_keys(within_days=args.within_days, tenant_id=args.tenant_id)

    if not expiring:
        print(f"No active keys expiring within {args.within_days} days. Nothing to do.")
        return 0

    print(f"{len(expiring)} key(s) need attention (expiring within {args.within_days} days):\n")
    for info in expiring:
        status = "ALREADY EXPIRED" if info.is_expired else f"expires in {info.days_until_expiry} day(s)"
        print(f"  tenant: {info.tenant_id:20} type: {info.tenant_type.value:9} "
              f"key_id: {info.key_id}  [{status}]  (expires_at: {info.expires_at.isoformat()})")

    print(
        "\nTo rotate one of these, call ApiKeyStore.rotate_key(raw_key) with the "
        "tenant's current raw key - it creates a fresh key and revokes this one "
        "in a single step. This script only identifies which keys need rotating; "
        "it can't show you the raw key value, since that's never stored."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

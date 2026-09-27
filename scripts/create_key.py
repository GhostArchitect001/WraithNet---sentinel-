"""
Ghost Sentinel - API Key Provisioning Script
===============================================

Usage:
    python3 scripts/create_key.py --tenant-id my-bank --tenant-type b2b
    python3 scripts/create_key.py --tenant-id my-phone --tenant-type consumer
    python3 scripts/create_key.py --tenant-id my-bank --tenant-type b2b --ttl-days 30
    python3 scripts/create_key.py --tenant-id internal-service --tenant-type b2b --no-expiry

Prints the raw API key once. Save it immediately - it is not retrievable
again, only its hash is stored.

Keys expire after --ttl-days (default 90) unless --no-expiry is passed.
Expiry is the main defense against a forgotten or leaked key staying
valid forever - use --no-expiry sparingly, and only for credentials you
have another way of tracking and rotating.
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.api_keys import ApiKeyStore
from core.models import TenantType


def main():
    parser = argparse.ArgumentParser(description="Provision a new Ghost Sentinel API key")
    parser.add_argument("--tenant-id", required=True, help="Unique identifier for this tenant")
    parser.add_argument("--tenant-type", required=True, choices=["consumer", "b2b"])
    parser.add_argument("--db-path", default="data/ghost_sentinel_keys.db")
    parser.add_argument(
        "--ttl-days", type=int, default=90,
        help="Days until this key expires (default: 90)",
    )
    parser.add_argument(
        "--no-expiry", action="store_true",
        help="Create a key that never expires (use sparingly - see module docstring)",
    )
    args = parser.parse_args()

    store = ApiKeyStore(args.db_path)
    tenant_type = TenantType.CONSUMER if args.tenant_type == "consumer" else TenantType.B2B
    ttl_days = None if args.no_expiry else args.ttl_days
    raw_key = store.create_key(args.tenant_id, tenant_type, ttl_days=ttl_days)

    print(f"Tenant ID:   {args.tenant_id}")
    print(f"Tenant type: {tenant_type.value}")
    print(f"API key:     {raw_key}")
    print(f"Expires:     {'never' if ttl_days is None else f'in {ttl_days} days'}")
    print("")
    print("Save this key now. It is stored only as a salted hash and cannot be shown again.")


if __name__ == "__main__":
    main()

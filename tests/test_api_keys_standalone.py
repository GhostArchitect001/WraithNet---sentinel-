"""
Standalone test for ApiKeyStore. Run with:
    python3 tests/test_api_keys_standalone.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone

from core.api_keys import ApiKeyStore
from core.models import TenantType


def _force_expiry(db_path: str, key_hash_prefix: str, when: datetime) -> None:
    """Test-only helper: directly rewrites expires_at for a key so expiry
    behavior can be tested deterministically, without waiting real time
    or adding a 'backdate this key' method to production code."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE api_keys SET expires_at = ? WHERE key_hash LIKE ?",
        (when.isoformat(), key_hash_prefix + "%"),
    )
    conn.commit()
    conn.close()


def run():
    failures = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_keys.db")
        store = ApiKeyStore(db_path)

        print("=== Scenario 1: create and verify a valid key ===")
        raw_key = store.create_key("tenant-alpha", TenantType.B2B)
        result = store.verify_key(raw_key)
        if result is None or result[0] != "tenant-alpha" or result[1] != TenantType.B2B:
            print(f"  FAIL: expected ('tenant-alpha', B2B, <key_id>), got {result}")
            failures += 1
        elif not isinstance(result[2], str) or len(result[2]) != 12:
            print(f"  FAIL: expected a 12-char key_id as the third element, got {result[2]!r}")
            failures += 1
        else:
            print(f"  OK: verified correctly as {result}")

        print("\n=== Scenario 2: raw key is never stored in plaintext ===")
        with open(db_path, "rb") as f:
            raw_bytes = f.read()
        if raw_key.encode("utf-8") in raw_bytes:
            print("  FAIL: raw API key found in plaintext inside the database file")
            failures += 1
        else:
            print("  OK: raw key not present in database file")

        print("\n=== Scenario 3: invalid key is rejected ===")
        bad_result = store.verify_key("this-is-not-a-real-key")
        if bad_result is not None:
            print(f"  FAIL: expected None for invalid key, got {bad_result}")
            failures += 1
        else:
            print("  OK: invalid key correctly rejected")

        print("\n=== Scenario 4: revoked key stops working ===")
        raw_key2 = store.create_key("tenant-beta", TenantType.CONSUMER)
        pre_revoke = store.verify_key(raw_key2)
        revoked = store.revoke_key(raw_key2)
        post_revoke = store.verify_key(raw_key2)
        if pre_revoke is None:
            print("  FAIL: key should have verified before revocation")
            failures += 1
        elif not revoked:
            print("  FAIL: revoke_key should have returned True")
            failures += 1
        elif post_revoke is not None:
            print(f"  FAIL: revoked key should no longer verify, got {post_revoke}")
            failures += 1
        else:
            print("  OK: key worked before revocation, rejected after revocation")

        print("\n=== Scenario 5: two different tenants get independently valid keys ===")
        key_a = store.create_key("tenant-gamma", TenantType.CONSUMER)
        key_b = store.create_key("tenant-delta", TenantType.B2B)
        res_a = store.verify_key(key_a)
        res_b = store.verify_key(key_b)
        if (res_a is None or res_a[:2] != ("tenant-gamma", TenantType.CONSUMER)
                or res_b is None or res_b[:2] != ("tenant-delta", TenantType.B2B)):
            print(f"  FAIL: got res_a={res_a}, res_b={res_b}")
            failures += 1
        else:
            print("  OK: both tenants correctly and independently verified")

        print("\n=== Scenario 6: a new key defaults to a 90-day expiry ===")
        key_default_ttl = store.create_key("tenant-epsilon", TenantType.B2B)
        info_list = store.list_keys(tenant_id="tenant-epsilon")
        if len(info_list) != 1 or info_list[0].expires_at is None:
            print(f"  FAIL: expected exactly 1 key with a non-null expiry, got {info_list}")
            failures += 1
        else:
            days_left = info_list[0].days_until_expiry
            if days_left is None or not (85 <= days_left <= 90):
                print(f"  FAIL: expected ~90 days until expiry, got {days_left}")
                failures += 1
            else:
                print(f"  OK: default TTL applied, {days_left} days until expiry")

        print("\n=== Scenario 7: ttl_days=None creates a key that never expires ===")
        key_no_expiry = store.create_key("tenant-zeta", TenantType.B2B, ttl_days=None)
        info_list = store.list_keys(tenant_id="tenant-zeta")
        if len(info_list) != 1 or info_list[0].expires_at is not None:
            print(f"  FAIL: expected a key with no expiry, got {info_list}")
            failures += 1
        else:
            print("  OK: ttl_days=None correctly creates a non-expiring key")

        print("\n=== Scenario 8: expired key is rejected by verify_key, even though not revoked ===")
        key_expiring = store.create_key("tenant-eta", TenantType.CONSUMER)
        pre_expiry = store.verify_key(key_expiring)
        expiring_info = store.list_keys(tenant_id="tenant-eta")[0]
        _force_expiry(db_path, expiring_info.key_id, datetime.now(timezone.utc) - timedelta(days=1))
        post_expiry = store.verify_key(key_expiring)
        if pre_expiry is None:
            print("  FAIL: key should have verified before it expired")
            failures += 1
        elif post_expiry is not None:
            print(f"  FAIL: expired key should no longer verify, got {post_expiry}")
            failures += 1
        else:
            print("  OK: key worked before expiry, rejected after expiry (without being revoked)")

        print("\n=== Scenario 9: list_expiring_keys surfaces keys nearing expiry ===")
        key_soon = store.create_key("tenant-theta", TenantType.B2B)
        soon_info = store.list_keys(tenant_id="tenant-theta")[0]
        _force_expiry(db_path, soon_info.key_id, datetime.now(timezone.utc) + timedelta(days=5))
        expiring_soon = store.list_expiring_keys(within_days=14, tenant_id="tenant-theta")
        if len(expiring_soon) != 1 or expiring_soon[0].key_id != soon_info.key_id:
            print(f"  FAIL: expected tenant-theta's key to show up as expiring soon, got {expiring_soon}")
            failures += 1
        else:
            print(f"  OK: key expiring in 5 days correctly flagged within a 14-day window "
                  f"(days_until_expiry={expiring_soon[0].days_until_expiry})")

        print("\n=== Scenario 10: list_expiring_keys does not flag keys with distant expiry ===")
        store.create_key("tenant-iota", TenantType.B2B, ttl_days=365)
        expiring_far = store.list_expiring_keys(within_days=14, tenant_id="tenant-iota")
        if expiring_far:
            print(f"  FAIL: a key expiring in 365 days should not appear in a 14-day window, got {expiring_far}")
            failures += 1
        else:
            print("  OK: key with distant expiry correctly excluded from the reminder window")

        print("\n=== Scenario 11: rotate_key issues a new key and revokes the old one ===")
        old_key = store.create_key("tenant-kappa", TenantType.B2B)
        new_key = store.rotate_key(old_key)
        old_still_works = store.verify_key(old_key)
        new_works = store.verify_key(new_key)
        if new_key is None:
            print("  FAIL: rotate_key should have returned a new raw key")
            failures += 1
        elif old_still_works is not None:
            print(f"  FAIL: old key should be revoked after rotation, got {old_still_works}")
            failures += 1
        elif new_works is None or new_works[0] != "tenant-kappa":
            print(f"  FAIL: new key should verify for the same tenant, got {new_works}")
            failures += 1
        else:
            print("  OK: rotate_key revoked the old key and issued a working new one for the same tenant")

        print("\n=== Scenario 12: rotate_key on an invalid key does nothing and returns None ===")
        result = store.rotate_key("not-a-real-key-at-all")
        if result is not None:
            print(f"  FAIL: expected None for rotating a nonexistent key, got {result}")
            failures += 1
        else:
            print("  OK: rotating an invalid key correctly returns None with no side effects")

    print(f"\n=== Summary: {failures} failures ===")
    return failures


if __name__ == "__main__":
    failures = run()
    sys.exit(1 if failures else 0)

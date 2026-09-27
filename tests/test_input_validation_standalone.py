"""
Standalone test for the hardened SignalIn schema in api/main.py.
Run with:
    python3 tests/test_input_validation_standalone.py

Requires fastapi + pydantic to be installed (api/main.py imports them
at module level to build the app and register detectors/routes). If
they're not installed, this test reports that clearly and skips
rather than failing, matching the way test_rate_limiter_standalone.py
skips its Redis-dependent scenarios when Redis isn't reachable.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta, timezone

try:
    from api.main import SignalIn
    from pydantic import ValidationError
    _IMPORT_OK = True
    _IMPORT_ERROR = None
except Exception as exc:  # ImportError if fastapi/pydantic/uvicorn missing
    _IMPORT_OK = False
    _IMPORT_ERROR = exc


def _valid_base(**overrides) -> dict:
    base = {
        "signal_type": "login_attempt",
        "account_id": "acct-12345",
    }
    base.update(overrides)
    return base


def run():
    failures = 0

    if not _IMPORT_OK:
        print(
            "=== SKIPPED: could not import api.main (fastapi/pydantic not "
            f"installed in this environment): {_IMPORT_ERROR} ===\n"
            "This test needs `pip install fastapi uvicorn pydantic` to run.\n"
        )
        print("=== Summary: 0 failures (skipped) ===")
        return 0

    print("=== Scenario 1: a normal, valid signal is accepted ===")
    try:
        SignalIn(**_valid_base())
        print("  OK: valid minimal signal accepted")
    except ValidationError as e:
        print(f"  FAIL: valid signal was rejected: {e}")
        failures += 1

    print("\n=== Scenario 2: empty account_id is rejected ===")
    try:
        SignalIn(**_valid_base(account_id=""))
        print("  FAIL: empty account_id should have been rejected")
        failures += 1
    except ValidationError:
        print("  OK: empty account_id rejected")

    print("\n=== Scenario 3: account_id with control characters/whitespace is rejected ===")
    bad_ids_accepted = []
    for bad_id in ["acct 123", "acct\n123", "acct\t123", "acct;DROP TABLE x"]:
        try:
            SignalIn(**_valid_base(account_id=bad_id))
            bad_ids_accepted.append(bad_id)
        except ValidationError:
            pass
    if bad_ids_accepted:
        print(f"  FAIL: unsafe account_id values wrongly accepted: {bad_ids_accepted!r}")
        failures += 1
    else:
        print("  OK: all unsafe account_id values rejected")

    print("\n=== Scenario 4: account_id over max length is rejected ===")
    try:
        SignalIn(**_valid_base(account_id="a" * 500))
        print("  FAIL: 500-char account_id should have been rejected")
        failures += 1
    except ValidationError:
        print("  OK: oversized account_id rejected")

    print("\n=== Scenario 5: oversized payload is rejected ===")
    try:
        SignalIn(**_valid_base(payload={"blob": "x" * 20000}))
        print("  FAIL: oversized payload should have been rejected")
        failures += 1
    except ValidationError:
        print("  OK: oversized payload rejected")

    print("\n=== Scenario 6: small payload is accepted ===")
    try:
        SignalIn(**_valid_base(payload={"ip": "203.0.113.5", "result": "success"}))
        print("  OK: normal-sized payload accepted")
    except ValidationError as e:
        print(f"  FAIL: normal payload was rejected: {e}")
        failures += 1

    print("\n=== Scenario 7: out-of-range geo coordinates are rejected ===")
    bad_geos_accepted = []
    for bad_geo in [(999.0, 0.0), (0.0, -999.0), (91.0, 0.0), (0.0, 181.0)]:
        try:
            SignalIn(**_valid_base(geo=bad_geo))
            bad_geos_accepted.append(bad_geo)
        except ValidationError:
            pass
    if bad_geos_accepted:
        print(f"  FAIL: out-of-range geo values wrongly accepted: {bad_geos_accepted}")
        failures += 1
    else:
        print("  OK: all out-of-range geo values rejected")

    print("\n=== Scenario 8: non-finite geo coordinates (NaN/inf) are rejected ===")
    bad_finite_geos_accepted = []
    for bad_geo in [(float("nan"), 0.0), (0.0, float("inf")), (float("-inf"), 0.0)]:
        try:
            SignalIn(**_valid_base(geo=bad_geo))
            bad_finite_geos_accepted.append(bad_geo)
        except ValidationError:
            pass
    if bad_finite_geos_accepted:
        print(f"  FAIL: non-finite geo values wrongly accepted: {bad_finite_geos_accepted}")
        failures += 1
    else:
        print("  OK: all non-finite geo values rejected")

    print("\n=== Scenario 9: valid geo coordinates are accepted ===")
    try:
        SignalIn(**_valid_base(geo=(6.5244, 3.3792)))  # Lagos, Nigeria
        print("  OK: valid geo coordinates accepted")
    except ValidationError as e:
        print(f"  FAIL: valid geo was rejected: {e}")
        failures += 1

    print("\n=== Scenario 10: far-future timestamp is rejected ===")
    try:
        far_future = datetime.now(timezone.utc) + timedelta(days=30)
        SignalIn(**_valid_base(timestamp=far_future))
        print("  FAIL: far-future timestamp should have been rejected")
        failures += 1
    except ValidationError:
        print("  OK: far-future timestamp rejected")

    print("\n=== Scenario 11: implausibly old timestamp is rejected ===")
    try:
        ancient = datetime(1970, 1, 1, tzinfo=timezone.utc)
        SignalIn(**_valid_base(timestamp=ancient))
        print("  FAIL: implausibly old timestamp should have been rejected")
        failures += 1
    except ValidationError:
        print("  OK: implausibly old timestamp rejected")

    print("\n=== Scenario 12: small clock skew is tolerated ===")
    try:
        slight_skew = datetime.now(timezone.utc) + timedelta(seconds=30)
        SignalIn(**_valid_base(timestamp=slight_skew))
        print("  OK: small forward clock skew accepted")
    except ValidationError as e:
        print(f"  FAIL: small clock skew should have been tolerated: {e}")
        failures += 1

    print("\n=== Scenario 13: recent, ordinary timestamp is accepted ===")
    try:
        SignalIn(**_valid_base(timestamp=datetime.now(timezone.utc) - timedelta(hours=1)))
        print("  OK: ordinary recent timestamp accepted")
    except ValidationError as e:
        print(f"  FAIL: ordinary timestamp was rejected: {e}")
        failures += 1

    print("\n=== Scenario 14: unsafe device_id is rejected the same way as account_id ===")
    try:
        SignalIn(**_valid_base(device_id="device\x00null"))
        print("  FAIL: device_id with a null byte should have been rejected")
        failures += 1
    except ValidationError:
        print("  OK: unsafe device_id rejected")

    print("\n=== Scenario 15: missing required account_id is rejected ===")
    try:
        SignalIn(signal_type="login_attempt")
        print("  FAIL: missing account_id should have been rejected")
        failures += 1
    except ValidationError:
        print("  OK: missing account_id rejected")

    print(f"\n=== Summary: {failures} failures ===")
    return failures


if __name__ == "__main__":
    failures = run()
    sys.exit(1 if failures else 0)

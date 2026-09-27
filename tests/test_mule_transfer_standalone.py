"""
Standalone smoke test for MuleTransferDetector. Run with:
    python3 tests/test_mule_transfer_standalone.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta

from core.engine import DetectionEngine
from core.models import Signal, SignalType
from detectors.mule_transfer import MuleTransferDetector


def make_signal(account_id, ts, **payload_kwargs):
    return Signal(
        signal_type=SignalType.TRANSACTION,
        tenant_id="test-tenant",
        account_id=account_id,
        timestamp=ts,
        payload=payload_kwargs,
    )


def run():
    engine = DetectionEngine()
    engine.register(MuleTransferDetector())
    failures = 0
    base_time = datetime(2026, 7, 17, 9, 0, 0)

    print("=== Scenario 1: inflow immediately followed by near-total outflow (pass-through) ===")
    acct = "acct-001"
    inflow = make_signal(acct, base_time, direction="in", amount=10000)
    engine.process(inflow)
    outflow = make_signal(
        acct, base_time + timedelta(minutes=5),
        direction="out", amount=9000, beneficiary_id="ben-new-1",
    )
    events = engine.process(outflow)
    if not events:
        print("  FAIL: expected inflow-then-rapid-outflow to trigger a risk event")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 2: inflow followed by slow, partial outflow should NOT trigger pass-through ===")
    acct2 = "acct-002"
    inflow = make_signal(acct2, base_time, direction="in", amount=10000)
    engine.process(inflow)
    # Build a normal outflow history first, all to the SAME familiar
    # beneficiary, spread well outside the churn window - so this setup
    # doesn't itself look like beneficiary churn (see Scenario 5/6 for
    # churn-specific tests).
    for i in range(4):
        engine.process(make_signal(
            acct2, base_time - timedelta(days=30 - i),
            direction="out", amount=200, beneficiary_id="ben-regular",
        ))
    small_outflow = make_signal(
        acct2, base_time + timedelta(hours=3),
        direction="out", amount=500, beneficiary_id="ben-regular",
    )
    events = engine.process(small_outflow)
    if events:
        print(f"  FAIL: small, delayed, familiar-beneficiary outflow should not trigger, got {events}")
        failures += 1
    else:
        print("  OK: no false positive on ordinary delayed partial spending")

    print("\n=== Scenario 3: new beneficiary + high value relative to account history ===")
    acct3 = "acct-003"
    for i in range(5):
        engine.process(make_signal(
            acct3, base_time + timedelta(days=i),
            direction="out", amount=100, beneficiary_id=f"ben-{i}",
        ))
    big_new_transfer = make_signal(
        acct3, base_time + timedelta(days=6),
        direction="out", amount=2000, beneficiary_id="ben-unfamiliar",
    )
    events = engine.process(big_new_transfer)
    if not events:
        print("  FAIL: expected large transfer to a new beneficiary (20x average) to trigger")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 4: new beneficiary but value in line with history should NOT trigger ===")
    acct4 = "acct-004"
    for i in range(5):
        engine.process(make_signal(
            acct4, base_time + timedelta(days=i),
            direction="out", amount=100, beneficiary_id=f"ben-{i}",
        ))
    normal_new_transfer = make_signal(
        acct4, base_time + timedelta(days=6),
        direction="out", amount=110, beneficiary_id="ben-new-but-normal",
    )
    events = engine.process(normal_new_transfer)
    if events:
        print(f"  FAIL: new beneficiary at normal value should not trigger, got {events}")
        failures += 1
    else:
        print("  OK: no false positive for a new beneficiary at an ordinary transfer size")

    print("\n=== Scenario 5: beneficiary churn - several new beneficiaries paid within 24h ===")
    acct5 = "acct-005"
    events = []
    for i in range(4):
        events = engine.process(make_signal(
            acct5, base_time + timedelta(hours=i * 2),
            direction="out", amount=50, beneficiary_id=f"ben-churn-{i}",
        ))
    if not events:
        print("  FAIL: expected beneficiary churn (4 new beneficiaries in 24h) to trigger by the 4th")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 6: same beneficiaries repeated should NOT count as churn ===")
    acct6 = "acct-006"
    events = []
    for i in range(6):
        events = engine.process(make_signal(
            acct6, base_time + timedelta(hours=i),
            direction="out", amount=50, beneficiary_id="ben-repeat",
        ))
    if events:
        print(f"  FAIL: repeated payments to the same beneficiary should not count as churn, got {events}")
        failures += 1
    else:
        print("  OK: no false positive for repeat payments to one familiar beneficiary")

    print("\n=== Scenario 7: round-trip timing tightness stacks with pass-through severity ===")
    acct7 = "acct-007"
    engine.process(make_signal(acct7, base_time, direction="in", amount=5000))
    fast_outflow = make_signal(
        acct7, base_time + timedelta(minutes=2),
        direction="out", amount=4800, beneficiary_id="ben-fast",
    )
    events = engine.process(fast_outflow)
    if not events or events[0].severity.value not in ("high", "critical"):
        print(f"  FAIL: expected a tight round-trip to escalate severity, got {events}")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 8: inflow alone (no matching outflow) should NOT trigger ===")
    acct8 = "acct-008"
    events = engine.process(make_signal(acct8, base_time, direction="in", amount=8000))
    if events:
        print(f"  FAIL: an inflow with no outflow should not trigger anything, got {events}")
        failures += 1
    else:
        print("  OK: inflow alone produces no risk event (risk only shows up on the outflow)")

    print("\n=== Scenario 9: transaction missing amount is handled without crashing ===")
    acct9 = "acct-009"
    try:
        events = engine.process(make_signal(acct9, base_time, direction="out", beneficiary_id="ben-x"))
        if events:
            print(f"  FAIL: missing amount should not produce a risk event, got {events}")
            failures += 1
        else:
            print("  OK: missing amount handled gracefully, no crash, no false positive")
    except Exception as exc:
        print(f"  FAIL: missing amount crashed the detector: {exc}")
        failures += 1

    print("\n=== Scenario 10: transaction missing direction is handled without crashing ===")
    acct10 = "acct-010"
    try:
        events = engine.process(make_signal(acct10, base_time, amount=500, beneficiary_id="ben-y"))
        if events:
            print(f"  FAIL: missing direction should not produce a risk event, got {events}")
            failures += 1
        else:
            print("  OK: missing direction handled gracefully, no crash, no false positive")
    except Exception as exc:
        print(f"  FAIL: missing direction crashed the detector: {exc}")
        failures += 1

    print(f"\n=== Summary: {failures} failures ===")
    return failures


if __name__ == "__main__":
    failures = run()
    sys.exit(1 if failures else 0)

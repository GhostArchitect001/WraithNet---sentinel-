"""
Standalone smoke test - exercises DetectionEngine + BehavioralAnomalyDetector
without needing FastAPI installed. Run with:
    python3 tests/test_engine_standalone.py

This mirrors the spirit of your run_full_stack_simulation.py from
energy_mesh_v2 - a scripted scenario that should catch real bugs, not
just confirm imports work.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta

from core.engine import DetectionEngine
from core.models import Signal, SignalType
from detectors.behavioral_anomaly import BehavioralAnomalyDetector


def make_signal(signal_type, account_id, ts, **payload_kwargs):
    return Signal(
        signal_type=signal_type,
        tenant_id="test-tenant",
        account_id=account_id,
        timestamp=ts,
        payload=payload_kwargs,
    )


def run():
    engine = DetectionEngine()
    engine.register(BehavioralAnomalyDetector())

    account = "acct-harry-001"
    base_time = datetime(2026, 7, 16, 10, 0, 0)
    failures = 0
    total_events = 0

    print("=== Scenario 1: normal transaction history, then an outlier ===")
    normal_amounts = [5000, 4800, 5200, 5100, 4900, 5000]  # naira, tight range
    for i, amt in enumerate(normal_amounts):
        sig = make_signal(SignalType.TRANSACTION, account, base_time + timedelta(minutes=i), amount=amt)
        events = engine.process(sig)
        if events:
            print(f"  UNEXPECTED risk event on normal txn #{i}: {events}")
            failures += 1

    outlier_sig = make_signal(
        SignalType.TRANSACTION, account, base_time + timedelta(minutes=10), amount=500000
    )
    events = engine.process(outlier_sig)
    total_events += len(events)
    if not events:
        print("  FAIL: expected outlier transaction to trigger a risk event, got none")
        failures += 1
    else:
        for e in events:
            print(f"  OK: {e.severity.value} risk={e.risk_score} reasons={e.reasons}")

    print("\n=== Scenario 2: rapid OTP failures then success (ATO pattern) ===")
    account2 = "acct-test-002"
    t0 = base_time + timedelta(hours=1)
    for i in range(4):
        sig = make_signal(SignalType.OTP_REQUEST, account2, t0 + timedelta(seconds=i * 10), result="failure")
        engine.process(sig)

    success_sig = make_signal(SignalType.OTP_VERIFIED, account2, t0 + timedelta(seconds=45))
    events = engine.process(success_sig)
    total_events += len(events)
    if not events:
        print("  FAIL: expected rapid-retry pattern to trigger a risk event, got none")
        failures += 1
    else:
        for e in events:
            print(f"  OK: {e.severity.value} risk={e.risk_score} reasons={e.reasons}")

    print("\n=== Scenario 3: known device change should NOT trigger on first-ever device ===")
    account3 = "acct-test-003"
    sig = make_signal(SignalType.DEVICE_CHANGE, account3, base_time, device_id="device-A")
    events = engine.process(sig)
    if events:
        print(f"  FAIL: first-ever device for a fresh account should not be flagged, got {events}")
        failures += 1
    else:
        print("  OK: no false positive on first device for new account")

    print("\n=== Scenario 4: new device AFTER an established device history ===")
    sig2 = make_signal(SignalType.DEVICE_CHANGE, account3, base_time + timedelta(days=1), device_id="device-B")
    events = engine.process(sig2)
    total_events += len(events)
    if not events:
        print("  FAIL: expected a flag for a second, different device on established account")
        failures += 1
    else:
        for e in events:
            print(f"  OK: {e.severity.value} risk={e.risk_score} reasons={e.reasons}")

    print(f"\n=== Summary: {total_events} risk events generated, {failures} failures ===")
    return failures


if __name__ == "__main__":
    failures = run()
    sys.exit(1 if failures else 0)

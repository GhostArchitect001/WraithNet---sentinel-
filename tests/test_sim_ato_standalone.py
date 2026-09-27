"""
Standalone smoke test for SimAtoDetector. Run with:
    python3 tests/test_sim_ato_standalone.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta

from core.engine import DetectionEngine
from core.models import Signal, SignalType
from detectors.sim_ato import SimAtoDetector


def make_signal(signal_type, account_id, ts, device_id=None, geo=None, **payload_kwargs):
    return Signal(
        signal_type=signal_type,
        tenant_id="test-tenant",
        account_id=account_id,
        timestamp=ts,
        payload=payload_kwargs,
        device_id=device_id,
        geo=geo,
    )


def run():
    engine = DetectionEngine()
    engine.register(SimAtoDetector())
    failures = 0
    base_time = datetime(2026, 7, 16, 9, 0, 0)

    print("=== Scenario 1: SIM status change followed by login within risk window ===")
    acct = "acct-001"
    sig1 = make_signal(SignalType.SIM_STATUS_CHANGE, acct, base_time, carrier_status="recently_swapped")
    events = engine.process(sig1)
    if not events:
        print("  FAIL: expected carrier_status enrichment alone to trigger a risk event")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    sig2 = make_signal(SignalType.LOGIN_ATTEMPT, acct, base_time + timedelta(minutes=20))
    events = engine.process(sig2)
    if not events:
        print("  FAIL: expected login shortly after SIM status change to trigger a risk event")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 2: login long after SIM status change should NOT trigger window check ===")
    acct2 = "acct-002"
    sig = make_signal(SignalType.SIM_STATUS_CHANGE, acct2, base_time)
    engine.process(sig)  # no carrier_status this time, just a timestamp marker
    late_login = make_signal(SignalType.LOGIN_ATTEMPT, acct2, base_time + timedelta(hours=5))
    events = engine.process(late_login)
    if events:
        print(f"  FAIL: login 5 hours after SIM event should be outside the risk window, got {events}")
        failures += 1
    else:
        print("  OK: no false positive outside the risk window")

    print("\n=== Scenario 3: device-binding mismatch ===")
    acct3 = "acct-003"
    bind_sig = make_signal(SignalType.DEVICE_CHANGE, acct3, base_time, device_id="device-alpha")
    engine.process(bind_sig)
    mismatch_sig = make_signal(SignalType.LOGIN_ATTEMPT, acct3, base_time + timedelta(hours=1), device_id="device-beta")
    events = engine.process(mismatch_sig)
    if not events:
        print("  FAIL: expected device mismatch to trigger a risk event")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 4: geographically implausible activity ===")
    acct4 = "acct-004"
    lagos = (6.5244, 3.3792)
    london = (51.5072, -0.1276)
    sig_a = make_signal(SignalType.LOGIN_ATTEMPT, acct4, base_time, geo=lagos)
    engine.process(sig_a)
    sig_b = make_signal(SignalType.LOGIN_ATTEMPT, acct4, base_time + timedelta(minutes=30), geo=london)
    events = engine.process(sig_b)
    if not events:
        print("  FAIL: expected Lagos-to-London in 30 minutes to be flagged as implausible")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 5: same-city activity should NOT trigger geo check ===")
    acct5 = "acct-005"
    point_a = (6.5244, 3.3792)
    point_b = (6.5300, 3.3800)  # a few km away, same city
    sig_a = make_signal(SignalType.LOGIN_ATTEMPT, acct5, base_time, geo=point_a)
    engine.process(sig_a)
    sig_b = make_signal(SignalType.LOGIN_ATTEMPT, acct5, base_time + timedelta(minutes=15), geo=point_b)
    events = engine.process(sig_b)
    if events:
        print(f"  FAIL: nearby same-city movement should not trigger geo implausibility, got {events}")
        failures += 1
    else:
        print("  OK: no false positive for plausible local movement")

    print(f"\n=== Summary: {failures} failures ===")
    return failures


if __name__ == "__main__":
    failures = run()
    sys.exit(1 if failures else 0)

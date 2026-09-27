"""
Standalone smoke test for SocialEngineeringSessionDetector. Run with:
    python3 tests/test_social_engineering_session_standalone.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta

from core.engine import DetectionEngine
from core.models import Signal, SignalType
from detectors.social_engineering_session import SocialEngineeringSessionDetector


def make_message(account_id, ts, text):
    return Signal(
        signal_type=SignalType.MESSAGE_RECEIVED,
        tenant_id="test-tenant",
        account_id=account_id,
        timestamp=ts,
        payload={"text": text},
    )


def make_transaction(account_id, ts, **payload_kwargs):
    return Signal(
        signal_type=SignalType.TRANSACTION,
        tenant_id="test-tenant",
        account_id=account_id,
        timestamp=ts,
        payload=payload_kwargs,
    )


def run():
    engine = DetectionEngine()
    engine.register(SocialEngineeringSessionDetector())
    failures = 0
    base_time = datetime(2026, 7, 17, 9, 0, 0)

    print("=== Scenario 1: support-impersonation message shortly before a transaction ===")
    acct = "acct-001"
    engine.process(make_message(
        acct, base_time,
        "URGENT: unusual activity detected on your account, verify immediately to avoid suspension.",
    ))
    events = engine.process(make_transaction(acct, base_time + timedelta(minutes=10), amount=500))
    if not events:
        print("  FAIL: expected pressure message followed by transaction to trigger")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 2: ordinary message followed by transaction should NOT trigger ===")
    acct2 = "acct-002"
    engine.process(make_message(acct2, base_time, "Your package has been delivered, thanks for shopping with us."))
    events = engine.process(make_transaction(acct2, base_time + timedelta(minutes=10), amount=500))
    if events:
        print(f"  FAIL: ordinary message should not trigger, got {events}")
        failures += 1
    else:
        print("  OK: no false positive on a non-pressure message")

    print("\n=== Scenario 3: pressure message followed by a transaction outside the time window ===")
    acct3 = "acct-003"
    engine.process(make_message(acct3, base_time, "Your account will be suspended, act now."))
    events = engine.process(make_transaction(acct3, base_time + timedelta(hours=5), amount=500))
    if events:
        print(f"  FAIL: transaction well outside the pressure window should not trigger this check, got {events}")
        failures += 1
    else:
        print("  OK: no false positive once the pressure-message window has elapsed")

    print("\n=== Scenario 4: on_active_call enrichment alone triggers ===")
    acct4 = "acct-004"
    events = engine.process(make_transaction(acct4, base_time, amount=500, on_active_call=True))
    if not events:
        print("  FAIL: expected on_active_call=True to trigger on its own")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 5: on_active_call absent/False should NOT trigger by itself ===")
    acct5 = "acct-005"
    events = engine.process(make_transaction(acct5, base_time, amount=500, on_active_call=False))
    if events:
        print(f"  FAIL: on_active_call=False should not trigger, got {events}")
        failures += 1
    else:
        print("  OK: no false positive when explicitly not on a call")
    events = engine.process(make_transaction(acct5, base_time + timedelta(minutes=1), amount=500))
    if events:
        print(f"  FAIL: missing on_active_call field should not trigger, got {events}")
        failures += 1
    else:
        print("  OK: no false positive when the field is simply absent")

    print("\n=== Scenario 6: idle-then-burst session timing triggers ===")
    acct6 = "acct-006"
    idle_start = base_time
    burst_start = idle_start + timedelta(minutes=25)  # > IDLE_THRESHOLD_SECONDS (20 min)
    session_events = [
        idle_start.isoformat(),
        (burst_start + timedelta(seconds=10)).isoformat(),
        (burst_start + timedelta(seconds=30)).isoformat(),
        (burst_start + timedelta(seconds=55)).isoformat(),
    ]
    events = engine.process(make_transaction(
        acct6, burst_start + timedelta(seconds=60), amount=500, session_events=session_events,
    ))
    if not events:
        print("  FAIL: expected idle-then-burst session timing to trigger")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 7: steady, non-bursty session activity should NOT trigger ===")
    acct7 = "acct-007"
    start = base_time
    session_events = [
        (start + timedelta(minutes=i * 5)).isoformat() for i in range(6)
    ]
    events = engine.process(make_transaction(
        acct7, start + timedelta(minutes=35), amount=500, session_events=session_events,
    ))
    if events:
        print(f"  FAIL: steady browsing pattern should not trigger, got {events}")
        failures += 1
    else:
        print("  OK: no false positive for a user browsing steadily at their own pace")

    print("\n=== Scenario 8: all three signals stack to escalate severity ===")
    acct8 = "acct-008"
    engine.process(make_message(acct8, base_time, "Confirm your identity immediately, act now."))
    idle_start = base_time + timedelta(minutes=1)
    burst_start = idle_start + timedelta(minutes=25)
    session_events = [
        idle_start.isoformat(),
        (burst_start + timedelta(seconds=10)).isoformat(),
        (burst_start + timedelta(seconds=30)).isoformat(),
        (burst_start + timedelta(seconds=50)).isoformat(),
    ]
    events = engine.process(make_transaction(
        acct8, burst_start + timedelta(seconds=60),
        amount=500, on_active_call=True, session_events=session_events,
    ))
    if not events or events[0].severity.value != "critical":
        print(f"  FAIL: expected all three signals stacking to reach CRITICAL, got {events}")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 9: malformed session_events is handled without crashing ===")
    acct9 = "acct-009"
    try:
        events = engine.process(make_transaction(
            acct9, base_time, amount=500, session_events=["not-a-timestamp", 12345],
        ))
        print("  OK: malformed session_events handled gracefully, no crash")
    except Exception as exc:
        print(f"  FAIL: malformed session_events crashed the detector: {exc}")
        failures += 1

    print("\n=== Scenario 10: transaction with no message history and no enrichment fields ===")
    acct10 = "acct-010"
    events = engine.process(make_transaction(acct10, base_time, amount=500))
    if events:
        print(f"  FAIL: a plain transaction with no context should not trigger, got {events}")
        failures += 1
    else:
        print("  OK: no false positive for an ordinary, context-free transaction")

    print(f"\n=== Summary: {failures} failures ===")
    return failures


if __name__ == "__main__":
    failures = run()
    sys.exit(1 if failures else 0)

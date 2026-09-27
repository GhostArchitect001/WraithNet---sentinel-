"""
Standalone smoke test for PhishingDetector. Run with:
    python3 tests/test_phishing_standalone.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime

from core.engine import DetectionEngine
from core.models import Signal, SignalType
from detectors.phishing import PhishingDetector


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
    engine.register(PhishingDetector())
    failures = 0
    base_time = datetime(2026, 7, 16, 9, 0, 0)

    print("=== Scenario 1: urgent message + lookalike domain triggers high risk ===")
    sig = make_signal(
        SignalType.MESSAGE_RECEIVED, "acct-001", base_time,
        text="URGENT: Your account will be suspended. Verify immediately to avoid loss of access.",
        url="https://secure-paypal-verify.com/login",
    )
    events = engine.process(sig)
    if not events:
        print("  FAIL: expected urgency language + lookalike domain to trigger a risk event")
        failures += 1
    else:
        e = events[0]
        print(f"  OK: {e.severity.value} risk={e.risk_score} reasons={e.reasons}")

    print("\n=== Scenario 2: benign transactional message should NOT trigger ===")
    sig = make_signal(
        SignalType.MESSAGE_RECEIVED, "acct-002", base_time,
        text="Hey, are we still on for lunch tomorrow?",
    )
    events = engine.process(sig)
    if events:
        print(f"  FAIL: benign message should not trigger phishing detector, got {events}")
        failures += 1
    else:
        print("  OK: no false positive on ordinary conversational message")

    print("\n=== Scenario 3: legitimate brand's own domain is NOT flagged as lookalike ===")
    sig = make_signal(
        SignalType.URL_CLICKED, "acct-003", base_time,
        url="https://www.paypal.com/signin",
    )
    events = engine.process(sig)
    if events:
        print(f"  FAIL: paypal.com itself should not be flagged as a lookalike of paypal, got {events}")
        failures += 1
    else:
        print("  OK: brand's real domain correctly excluded from lookalike detection")

    print("\n=== Scenario 4: leetspeak lookalike domain (paypa1.com) is flagged ===")
    sig = make_signal(
        SignalType.URL_CLICKED, "acct-004", base_time,
        url="http://paypa1.com/account/confirm",
    )
    events = engine.process(sig)
    if not events:
        print("  FAIL: expected paypa1.com to be flagged as a paypal lookalike")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 5: brand name smuggled into unrelated domain is flagged ===")
    sig = make_signal(
        SignalType.URL_CLICKED, "acct-005", base_time,
        url="https://paypal.com.login-alert.ru/verify",
    )
    events = engine.process(sig)
    if not events:
        print("  FAIL: expected brand name in subdomain of an unrelated domain to be flagged")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 6: mismatched display text vs actual link ===")
    sig = make_signal(
        SignalType.MESSAGE_RECEIVED, "acct-006", base_time,
        text="Please review your statement.",
        display_text="www.chase.com",
        url="http://chase-secure-login.xyz/statement",
    )
    events = engine.process(sig)
    if not events:
        print("  FAIL: expected display-text/actual-link mismatch to be flagged")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 7: URL shortener alone is a mild signal, not high severity ===")
    sig = make_signal(
        SignalType.URL_CLICKED, "acct-007", base_time,
        url="https://bit.ly/3xyzABC",
    )
    events = engine.process(sig)
    if not events:
        print("  FAIL: expected shortener usage to register at least a low-level signal")
        failures += 1
    elif events[0].severity.value not in ("low", "medium"):
        print(f"  FAIL: shortener alone should not reach high/critical, got {events[0].severity.value}")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 8: QR-scanned lookalike URL is flagged the same as a clicked link ===")
    sig = make_signal(
        SignalType.QR_SCANNED, "acct-008", base_time,
        url="https://amaz0n.com/gift-card",
    )
    events = engine.process(sig)
    if not events:
        print("  FAIL: expected QR-scanned lookalike domain to be flagged")
        failures += 1
    else:
        print(f"  OK: {events[0].severity.value} risk={events[0].risk_score} reasons={events[0].reasons}")

    print("\n=== Scenario 9: missing url in payload is handled gracefully (no crash, no event) ===")
    sig = make_signal(SignalType.URL_CLICKED, "acct-009", base_time)
    events = engine.process(sig)
    if events:
        print(f"  FAIL: expected no event when url is absent from payload, got {events}")
        failures += 1
    else:
        print("  OK: absent url handled without error or false positive")

    print("\n=== Scenario 10: legitimate domain with no red flags produces no event ===")
    sig = make_signal(
        SignalType.URL_CLICKED, "acct-010", base_time,
        url="https://www.wikipedia.org/wiki/Phishing",
    )
    events = engine.process(sig)
    if events:
        print(f"  FAIL: ordinary legitimate domain should not trigger, got {events}")
        failures += 1
    else:
        print("  OK: no false positive on unrelated legitimate domain")

    print(f"\n=== Summary: {failures} failures ===")
    return failures


if __name__ == "__main__":
    failures = run()
    sys.exit(1 if failures else 0)

"""
Standalone test for SqliteAuditLogStore (core/audit_log.py). Run with:
    python3 tests/test_audit_log_standalone.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tempfile
from datetime import datetime, timedelta

from core.audit_log import SqliteAuditLogStore, _summarize_payload
from core.models import Signal, SignalType, RiskEvent, Severity


def _make_signal(payload=None, tenant_id="tenant-a", account_id="acct-1"):
    return Signal(
        signal_type=SignalType.LOGIN_ATTEMPT,
        tenant_id=tenant_id,
        account_id=account_id,
        timestamp=datetime(2026, 7, 16, 12, 0, 0),
        payload=payload or {"ip": "203.0.113.5"},
    )


def _make_event(account_id="acct-1", risk_score=0.82, severity=Severity.HIGH):
    return RiskEvent(
        account_id=account_id,
        tenant_id="tenant-a",
        detector_name="behavioral_anomaly",
        risk_score=risk_score,
        severity=severity,
        reasons=["Login from a device never seen on this account before."],
        triggered_signals=["sig-1"],
        recommended_action="Require step-up verification",
    )


def run():
    failures = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_audit.db")
        store = SqliteAuditLogStore(db_path)

        print("=== Scenario 1: recording a decision writes a retrievable row ===")
        signal = _make_signal()
        event = _make_event()
        record = store.record(
            signal=signal, event=event,
            requesting_tenant_id="tenant-a", api_key_id="abc123def456",
        )
        rows = store.query(event_id=event.event_id)
        if len(rows) != 1:
            print(f"  FAIL: expected 1 row for event_id, got {len(rows)}")
            failures += 1
        else:
            r = rows[0]
            checks = [
                (r.requesting_tenant_id == "tenant-a", "requesting_tenant_id"),
                (r.api_key_id == "abc123def456", "api_key_id"),
                (r.account_id == "acct-1", "account_id"),
                (r.signal_id == signal.signal_id, "signal_id"),
                (r.signal_type == "login_attempt", "signal_type"),
                (r.detector_name == "behavioral_anomaly", "detector_name"),
                (abs(r.risk_score - 0.82) < 1e-9, "risk_score"),
                (r.severity == "high", "severity"),
                (r.recommended_action == "Require step-up verification", "recommended_action"),
            ]
            bad = [name for ok, name in checks if not ok]
            if bad:
                print(f"  FAIL: mismatched fields: {bad}")
                failures += 1
            else:
                print(f"  OK: all fields round-tripped correctly, audit_id={record.audit_id}")

        print("\n=== Scenario 2: sensitive payload fields are redacted ===")
        sensitive_signal = _make_signal(payload={"otp": "123456", "ip": "203.0.113.5"})
        sensitive_event = _make_event(account_id="acct-2")
        store.record(
            signal=sensitive_signal, event=sensitive_event,
            requesting_tenant_id="tenant-a", api_key_id="abc123def456",
        )
        rows = store.query(event_id=sensitive_event.event_id)
        if not rows:
            print("  FAIL: expected a row for the sensitive-payload event")
            failures += 1
        elif "123456" in rows[0].payload_summary:
            print(f"  FAIL: raw OTP value leaked into payload_summary: {rows[0].payload_summary}")
            failures += 1
        elif "<redacted>" not in rows[0].payload_summary or "203.0.113.5" not in rows[0].payload_summary:
            print(f"  FAIL: expected redaction marker + non-sensitive field preserved, got {rows[0].payload_summary}")
            failures += 1
        else:
            print(f"  OK: sensitive field redacted, other fields preserved: {rows[0].payload_summary}")

        print("\n=== Scenario 3: query filters by requesting_tenant_id ===")
        store.record(
            signal=_make_signal(tenant_id="tenant-b", account_id="acct-3"),
            event=_make_event(account_id="acct-3"),
            requesting_tenant_id="tenant-b", api_key_id="other-key-id",
        )
        tenant_a_rows = store.query(requesting_tenant_id="tenant-a")
        tenant_b_rows = store.query(requesting_tenant_id="tenant-b")
        if len(tenant_a_rows) != 2 or len(tenant_b_rows) != 1:
            print(f"  FAIL: expected 2 rows for tenant-a and 1 for tenant-b, "
                  f"got {len(tenant_a_rows)} and {len(tenant_b_rows)}")
            failures += 1
        else:
            print("  OK: tenant filter correctly isolates rows")

        print("\n=== Scenario 4: query filters by min_severity ===")
        store.record(
            signal=_make_signal(account_id="acct-4"),
            event=_make_event(account_id="acct-4", risk_score=0.1, severity=Severity.INFO),
            requesting_tenant_id="tenant-a", api_key_id="abc123def456",
        )
        high_plus = store.query(requesting_tenant_id="tenant-a", min_severity="high")
        if not all(r.severity in ("high", "critical") for r in high_plus):
            print(f"  FAIL: min_severity='high' returned rows below that floor: "
                  f"{[r.severity for r in high_plus]}")
            failures += 1
        elif len(high_plus) != 2:  # the two 'high' events recorded for tenant-a
            print(f"  FAIL: expected 2 high-severity rows for tenant-a, got {len(high_plus)}")
            failures += 1
        else:
            print("  OK: min_severity floor filter works correctly")

        print("\n=== Scenario 5: audit rows survive a fresh store instance (restart) ===")
        store2 = SqliteAuditLogStore(db_path)
        reloaded = store2.query(event_id=event.event_id)
        if len(reloaded) != 1:
            print(f"  FAIL: expected the original event to still be queryable after 'restart', got {len(reloaded)} rows")
            failures += 1
        else:
            print("  OK: audit record persisted and readable from a new store instance")

        print("\n=== Scenario 6: multiple detectors on one signal each get their own row ===")
        shared_signal = _make_signal(account_id="acct-shared")
        event_x = _make_event(account_id="acct-shared")
        event_x.detector_name = "behavioral_anomaly"
        event_y = _make_event(account_id="acct-shared")
        event_y.detector_name = "sim_ato"
        store.record(signal=shared_signal, event=event_x, requesting_tenant_id="tenant-a", api_key_id="abc123def456")
        store.record(signal=shared_signal, event=event_y, requesting_tenant_id="tenant-a", api_key_id="abc123def456")
        rows = store.query(account_id="acct-shared")
        detector_names = sorted(r.detector_name for r in rows)
        if detector_names != ["behavioral_anomaly", "sim_ato"]:
            print(f"  FAIL: expected one row per detector, got {detector_names}")
            failures += 1
        else:
            print("  OK: one signal triggering two detectors produced two independent audit rows")

    print("\n=== Scenario 7: payload summary truncates oversized payloads ===")
    huge_payload = {"blob": "x" * 5000}
    summary = _summarize_payload(huge_payload)
    if len(summary) > 2050:
        print(f"  FAIL: expected summary to be truncated, got length {len(summary)}")
        failures += 1
    elif "truncated" not in summary:
        print(f"  FAIL: expected truncation marker in oversized summary")
        failures += 1
    else:
        print(f"  OK: oversized payload truncated to {len(summary)} chars")

    print("\n=== Scenario 8: client_ip is recorded and queryable ===")
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_audit_ip.db")
        store = SqliteAuditLogStore(db_path)
        sig = _make_signal(account_id="acct-ip-1")
        evt = _make_event(account_id="acct-ip-1")
        store.record(
            signal=sig, event=evt, requesting_tenant_id="tenant-a",
            api_key_id="key-1", client_ip="203.0.113.9",
        )
        rows = store.query(client_ip="203.0.113.9")
        if len(rows) != 1 or rows[0].client_ip != "203.0.113.9":
            print(f"  FAIL: expected exactly 1 row with client_ip=203.0.113.9, got {rows}")
            failures += 1
        else:
            print("  OK: client_ip round-trips and is queryable")

        print("\n=== Scenario 9: rows with no client_ip default to None, don't break queries ===")
        sig2 = _make_signal(account_id="acct-ip-2")
        evt2 = _make_event(account_id="acct-ip-2")
        store.record(signal=sig2, event=evt2, requesting_tenant_id="tenant-a", api_key_id="key-1")
        rows_no_ip = store.query(account_id="acct-ip-2")
        if len(rows_no_ip) != 1 or rows_no_ip[0].client_ip is not None:
            print(f"  FAIL: expected client_ip=None when not supplied, got {rows_no_ip}")
            failures += 1
        else:
            print("  OK: omitted client_ip is stored/read back as None, not a crash")

        print("\n=== Scenario 10: list_flagged_ips surfaces high-severity repeat offenders ===")
        # Same IP, three separate high-severity events on different accounts.
        for i in range(3):
            store.record(
                signal=_make_signal(account_id=f"acct-flag-{i}"),
                event=_make_event(account_id=f"acct-flag-{i}", risk_score=0.9, severity=Severity.CRITICAL),
                requesting_tenant_id="tenant-a", api_key_id="key-1", client_ip="198.51.100.7",
            )
        # A different IP with just one high-severity event.
        store.record(
            signal=_make_signal(account_id="acct-flag-once"),
            event=_make_event(account_id="acct-flag-once", risk_score=0.6, severity=Severity.HIGH),
            requesting_tenant_id="tenant-a", api_key_id="key-1", client_ip="198.51.100.8",
        )
        # A low-severity event from a third IP should never appear.
        store.record(
            signal=_make_signal(account_id="acct-flag-low"),
            event=_make_event(account_id="acct-flag-low", risk_score=0.1, severity=Severity.LOW),
            requesting_tenant_id="tenant-a", api_key_id="key-1", client_ip="198.51.100.9",
        )
        flagged = store.list_flagged_ips(min_severity="high")
        flagged_ips = {f.client_ip: f for f in flagged}
        if "198.51.100.9" in flagged_ips:
            print("  FAIL: low-severity-only IP should not appear in flagged list")
            failures += 1
        elif "198.51.100.7" not in flagged_ips or "198.51.100.8" not in flagged_ips:
            print(f"  FAIL: expected both high-severity IPs flagged, got {list(flagged_ips)}")
            failures += 1
        elif flagged_ips["198.51.100.7"].event_count != 3:
            print(f"  FAIL: expected event_count=3 for repeat-offender IP, got {flagged_ips['198.51.100.7'].event_count}")
            failures += 1
        elif flagged_ips["198.51.100.7"].distinct_accounts != 3:
            print(f"  FAIL: expected distinct_accounts=3, got {flagged_ips['198.51.100.7'].distinct_accounts}")
            failures += 1
        elif flagged_ips["198.51.100.7"].max_severity != "critical":
            print(f"  FAIL: expected max_severity=critical, got {flagged_ips['198.51.100.7'].max_severity}")
            failures += 1
        elif flagged[0].client_ip != "198.51.100.7":
            print(f"  FAIL: expected repeat offender first (ordered by event_count desc), got {flagged[0].client_ip}")
            failures += 1
        else:
            print(f"  OK: list_flagged_ips correctly surfaces and ranks repeat high-severity IPs: "
                  f"{[(f.client_ip, f.event_count, f.max_severity) for f in flagged]}")

        print("\n=== Scenario 11: list_flagged_ips respects min_event_count ===")
        strict = store.list_flagged_ips(min_severity="high", min_event_count=2)
        strict_ips = {f.client_ip for f in strict}
        if "198.51.100.8" in strict_ips:
            print("  FAIL: min_event_count=2 should exclude the single-event IP")
            failures += 1
        elif "198.51.100.7" not in strict_ips:
            print("  FAIL: min_event_count=2 should still include the 3-event IP")
            failures += 1
        else:
            print("  OK: min_event_count threshold correctly filters out single-offense IPs")

    print(f"\n=== Summary: {failures} failures ===")
    return failures


if __name__ == "__main__":
    failures = run()
    sys.exit(1 if failures else 0)

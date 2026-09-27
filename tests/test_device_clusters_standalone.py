"""
Standalone test for SqliteAuditLogStore.list_shared_device_ip_clusters()
(core/audit_log.py). Run with:
    python3 tests/test_device_clusters_standalone.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tempfile
from datetime import datetime, timedelta

from core.audit_log import SqliteAuditLogStore
from core.models import Signal, SignalType, RiskEvent, Severity


def _make_signal(account_id, device_id=None, tenant_id="tenant-a", payload=None, ts=None):
    return Signal(
        signal_type=SignalType.LOGIN_ATTEMPT,
        tenant_id=tenant_id,
        account_id=account_id,
        timestamp=ts or datetime(2026, 7, 16, 12, 0, 0),
        payload=payload or {},
        device_id=device_id,
    )


def _make_event(account_id, risk_score=0.7, severity=Severity.HIGH):
    return RiskEvent(
        account_id=account_id,
        tenant_id="tenant-a",
        detector_name="behavioral_anomaly",
        risk_score=risk_score,
        severity=severity,
        reasons=["Test reason."],
        triggered_signals=["sig-1"],
        recommended_action="Review manually.",
    )


def run():
    failures = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_audit.db")
        store = SqliteAuditLogStore(db_path)
        base_time = datetime(2026, 7, 17, 9, 0, 0)

        print("=== Scenario 1: device_id shared across 3+ accounts is surfaced ===")
        for i, acct in enumerate(["acct-1", "acct-2", "acct-3"]):
            store.record(
                signal=_make_signal(acct, device_id="device-shared-1", ts=base_time + timedelta(minutes=i)),
                event=_make_event(acct),
                requesting_tenant_id="tenant-a",
            )
        clusters = store.list_shared_device_ip_clusters(min_accounts=3)
        device_clusters = [c for c in clusters if c.cluster_type == "device_id"]
        if not device_clusters or device_clusters[0].cluster_key != "device-shared-1":
            print(f"  FAIL: expected device-shared-1 to surface as a cluster, got {clusters}")
            failures += 1
        elif set(device_clusters[0].account_ids) != {"acct-1", "acct-2", "acct-3"}:
            print(f"  FAIL: expected 3 distinct accounts, got {device_clusters[0].account_ids}")
            failures += 1
        else:
            print(f"  OK: device-shared-1 surfaced with accounts {device_clusters[0].account_ids}, "
                  f"max_severity={device_clusters[0].max_severity}")

        print("\n=== Scenario 2: device_id used by only one account is NOT surfaced ===")
        store2 = SqliteAuditLogStore(os.path.join(tmpdir, "test_audit2.db"))
        for i in range(5):
            store2.record(
                signal=_make_signal("acct-solo", device_id="device-solo", ts=base_time + timedelta(minutes=i)),
                event=_make_event("acct-solo"),
                requesting_tenant_id="tenant-a",
            )
        clusters = store2.list_shared_device_ip_clusters(min_accounts=3)
        if clusters:
            print(f"  FAIL: a device used by one account repeatedly should not cluster, got {clusters}")
            failures += 1
        else:
            print("  OK: no false positive for one account reusing its own device many times")

        print("\n=== Scenario 3: min_accounts threshold correctly filters below the bar ===")
        store3 = SqliteAuditLogStore(os.path.join(tmpdir, "test_audit3.db"))
        for i, acct in enumerate(["acct-a", "acct-b"]):
            store3.record(
                signal=_make_signal(acct, device_id="device-pair", ts=base_time + timedelta(minutes=i)),
                event=_make_event(acct),
                requesting_tenant_id="tenant-a",
            )
        clusters_min3 = store3.list_shared_device_ip_clusters(min_accounts=3)
        clusters_min2 = store3.list_shared_device_ip_clusters(min_accounts=2)
        if clusters_min3:
            print(f"  FAIL: 2 accounts sharing a device should not clear min_accounts=3, got {clusters_min3}")
            failures += 1
        elif not clusters_min2 or set(clusters_min2[0].account_ids) != {"acct-a", "acct-b"}:
            print(f"  FAIL: 2 accounts sharing a device should clear min_accounts=2, got {clusters_min2}")
            failures += 1
        else:
            print("  OK: min_accounts threshold correctly gates the two-account cluster")

        print("\n=== Scenario 4: client_ip clustering works the same way as device_id ===")
        store4 = SqliteAuditLogStore(os.path.join(tmpdir, "test_audit4.db"))
        for i, acct in enumerate(["acct-x", "acct-y", "acct-z"]):
            store4.record(
                signal=_make_signal(acct, ts=base_time + timedelta(minutes=i)),
                event=_make_event(acct),
                requesting_tenant_id="tenant-a",
                client_ip="203.0.113.9",
            )
        clusters = store4.list_shared_device_ip_clusters(min_accounts=3)
        ip_clusters = [c for c in clusters if c.cluster_type == "client_ip"]
        if not ip_clusters or ip_clusters[0].cluster_key != "203.0.113.9":
            print(f"  FAIL: expected 203.0.113.9 to surface as an IP cluster, got {clusters}")
            failures += 1
        else:
            print(f"  OK: client_ip clustering surfaced 203.0.113.9 with accounts {ip_clusters[0].account_ids}")

        print("\n=== Scenario 5: rows with NULL device_id/client_ip are excluded from clustering ===")
        store5 = SqliteAuditLogStore(os.path.join(tmpdir, "test_audit5.db"))
        for acct in ["acct-p", "acct-q", "acct-r"]:
            store5.record(
                signal=_make_signal(acct, device_id=None, ts=base_time),
                event=_make_event(acct),
                requesting_tenant_id="tenant-a",
                client_ip=None,
            )
        clusters = store5.list_shared_device_ip_clusters(min_accounts=3)
        if clusters:
            print(f"  FAIL: rows with no device_id/client_ip should never form a cluster, got {clusters}")
            failures += 1
        else:
            print("  OK: NULL device_id/client_ip rows correctly excluded, no crash, no false cluster")

        print("\n=== Scenario 6: max_severity correctly reflects the worst event in the cluster ===")
        store6 = SqliteAuditLogStore(os.path.join(tmpdir, "test_audit6.db"))
        store6.record(
            signal=_make_signal("acct-low", device_id="device-mixed", ts=base_time),
            event=_make_event("acct-low", severity=Severity.LOW, risk_score=0.2),
            requesting_tenant_id="tenant-a",
        )
        store6.record(
            signal=_make_signal("acct-crit", device_id="device-mixed", ts=base_time + timedelta(minutes=1)),
            event=_make_event("acct-crit", severity=Severity.CRITICAL, risk_score=0.95),
            requesting_tenant_id="tenant-a",
        )
        store6.record(
            signal=_make_signal("acct-med", device_id="device-mixed", ts=base_time + timedelta(minutes=2)),
            event=_make_event("acct-med", severity=Severity.MEDIUM, risk_score=0.4),
            requesting_tenant_id="tenant-a",
        )
        clusters = store6.list_shared_device_ip_clusters(min_accounts=3)
        if not clusters or clusters[0].max_severity != "critical":
            print(f"  FAIL: expected max_severity='critical' for the mixed-severity cluster, got {clusters}")
            failures += 1
        else:
            print(f"  OK: max_severity correctly computed as 'critical' across mixed-severity rows")

        print("\n=== Scenario 7: results are ranked by distinct account count descending ===")
        store7 = SqliteAuditLogStore(os.path.join(tmpdir, "test_audit7.db"))
        # device-big: 5 distinct accounts
        for i, acct in enumerate([f"acct-big-{i}" for i in range(5)]):
            store7.record(
                signal=_make_signal(acct, device_id="device-big", ts=base_time + timedelta(minutes=i)),
                event=_make_event(acct),
                requesting_tenant_id="tenant-a",
            )
        # device-small: 3 distinct accounts
        for i, acct in enumerate([f"acct-small-{i}" for i in range(3)]):
            store7.record(
                signal=_make_signal(acct, device_id="device-small", ts=base_time + timedelta(minutes=i)),
                event=_make_event(acct),
                requesting_tenant_id="tenant-a",
            )
        clusters = store7.list_shared_device_ip_clusters(min_accounts=3)
        device_clusters = [c for c in clusters if c.cluster_type == "device_id"]
        if len(device_clusters) < 2 or device_clusters[0].cluster_key != "device-big":
            print(f"  FAIL: expected device-big (5 accounts) ranked above device-small (3 accounts), got {clusters}")
            failures += 1
        else:
            print(f"  OK: ranked correctly, device-big first with {len(device_clusters[0].account_ids)} accounts")

        print("\n=== Scenario 8: time-range filtering (start_time/end_time) excludes out-of-range events ===")
        store8 = SqliteAuditLogStore(os.path.join(tmpdir, "test_audit8.db"))
        old_decided_at = base_time - timedelta(days=30)
        for i, acct in enumerate(["acct-old-1", "acct-old-2", "acct-old-3"]):
            store8.record(
                signal=_make_signal(acct, device_id="device-old", ts=old_decided_at + timedelta(minutes=i)),
                event=_make_event(acct),
                requesting_tenant_id="tenant-a",
            )
        # record() always stamps decided_at as "now" (it's an audit log of
        # when the decision was made, not the signal's own timestamp) - so
        # to actually test start_time/end_time filtering we backdate the
        # stored decided_at values directly, simulating rows written 30
        # days ago rather than trying to fake the wall clock.
        import sqlite3
        with sqlite3.connect(store8.db_path) as conn:
            conn.execute(
                "UPDATE audit_log SET decided_at = ? WHERE device_id = 'device-old'",
                (old_decided_at.isoformat(),),
            )
            conn.commit()
        clusters_no_filter = store8.list_shared_device_ip_clusters(min_accounts=3)
        clusters_filtered = store8.list_shared_device_ip_clusters(
            min_accounts=3, start_time=base_time - timedelta(days=1),
        )
        if not clusters_no_filter:
            print(f"  FAIL: expected device-old to surface without a time filter, got none")
            failures += 1
        elif clusters_filtered:
            print(f"  FAIL: expected device-old to be excluded once filtered to a recent window, got {clusters_filtered}")
            failures += 1
        else:
            print("  OK: start_time filtering correctly excludes an old cluster from a recent-window query")

        print("\n=== Scenario 9: limit correctly caps the number of clusters returned ===")
        store9 = SqliteAuditLogStore(os.path.join(tmpdir, "test_audit9.db"))
        for d in range(5):
            device = f"device-limit-{d}"
            for i, acct in enumerate([f"acct-{d}-{j}" for j in range(3)]):
                store9.record(
                    signal=_make_signal(acct, device_id=device, ts=base_time + timedelta(minutes=i)),
                    event=_make_event(acct),
                    requesting_tenant_id="tenant-a",
                )
        clusters = store9.list_shared_device_ip_clusters(min_accounts=3, limit=2)
        if len(clusters) != 2:
            print(f"  FAIL: expected limit=2 to cap results at 2, got {len(clusters)}")
            failures += 1
        else:
            print(f"  OK: limit correctly caps results at {len(clusters)}")

        print("\n=== Scenario 10: a device cluster and an IP cluster can coexist for different keys ===")
        store10 = SqliteAuditLogStore(os.path.join(tmpdir, "test_audit10.db"))
        for i, acct in enumerate(["acct-d1", "acct-d2", "acct-d3"]):
            store10.record(
                signal=_make_signal(acct, device_id="device-coexist", ts=base_time + timedelta(minutes=i)),
                event=_make_event(acct),
                requesting_tenant_id="tenant-a",
            )
        for i, acct in enumerate(["acct-i1", "acct-i2", "acct-i3"]):
            store10.record(
                signal=_make_signal(acct, ts=base_time + timedelta(minutes=i)),
                event=_make_event(acct),
                requesting_tenant_id="tenant-a",
                client_ip="198.51.100.7",
            )
        clusters = store10.list_shared_device_ip_clusters(min_accounts=3)
        types_seen = {c.cluster_type for c in clusters}
        if types_seen != {"device_id", "client_ip"}:
            print(f"  FAIL: expected both device_id and client_ip clusters present, got types {types_seen}")
            failures += 1
        else:
            print(f"  OK: both a device_id cluster and a client_ip cluster surfaced correctly, {len(clusters)} total")

        print(f"\n=== Summary: {failures} failures ===")
        return failures


if __name__ == "__main__":
    failures = run()
    sys.exit(1 if failures else 0)

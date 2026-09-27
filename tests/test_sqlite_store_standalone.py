"""
Standalone test for SqliteStateStore - specifically verifies that
detector_state containing datetime objects (as BehavioralAnomalyDetector
uses for OTP failure timestamps) survives a save-then-reload cycle,
simulating a server restart. Run with:
    python3 tests/test_sqlite_store_standalone.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tempfile
from datetime import datetime, timedelta

from core.sqlite_store import SqliteStateStore
from core.engine import DetectionEngine
from core.models import Signal, SignalType
from detectors.behavioral_anomaly import BehavioralAnomalyDetector


def run():
    failures = 0
    base_time = datetime(2026, 7, 16, 12, 0, 0)

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_state.db")

        print("=== Phase 1: process signals, save state, simulate restart ===")
        store1 = SqliteStateStore(db_path)
        engine1 = DetectionEngine(state_store=store1)
        engine1.register(BehavioralAnomalyDetector())

        acct = "acct-restart-test"
        # 3 OTP failures - not yet enough to trigger (threshold is 3, need the
        # verify to land within the window to fire)
        for i in range(3):
            sig = Signal(
                signal_type=SignalType.OTP_REQUEST,
                tenant_id="t1",
                account_id=acct,
                timestamp=base_time + timedelta(seconds=i * 10),
                payload={"result": "failure"},
            )
            engine1.process(sig)

        print("  Processed 3 OTP failures, state saved to disk.")

        print("\n=== Phase 2: new engine instance reads from same DB (restart simulation) ===")
        store2 = SqliteStateStore(db_path)
        engine2 = DetectionEngine(state_store=store2)
        engine2.register(BehavioralAnomalyDetector())

        verify_sig = Signal(
            signal_type=SignalType.OTP_VERIFIED,
            tenant_id="t1",
            account_id=acct,
            timestamp=base_time + timedelta(seconds=45),
        )
        events = engine2.process(verify_sig)

        if not events:
            print("  FAIL: expected rapid-retry pattern to be detected after reload from disk")
            print("  This means datetime objects are not surviving the save/reload cycle correctly.")
            failures += 1
        else:
            print(f"  OK: detected after reload - {events[0].severity.value} risk={events[0].risk_score}")
            print(f"       reasons={events[0].reasons}")

        print("\n=== Phase 3: confirm state file actually persisted to disk ===")
        if not os.path.exists(db_path):
            print("  FAIL: expected db file to exist on disk")
            failures += 1
        else:
            print(f"  OK: db file exists at {db_path}, size={os.path.getsize(db_path)} bytes")

    print(f"\n=== Summary: {failures} failures ===")
    return failures


if __name__ == "__main__":
    failures = run()
    sys.exit(1 if failures else 0)

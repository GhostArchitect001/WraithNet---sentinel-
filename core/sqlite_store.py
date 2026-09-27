"""
Ghost Sentinel - Persistent State Store
==========================================

SQLite-backed replacement for InMemoryStateStore. Same two-method
interface (get/save), so this is a drop-in swap in api/main.py.

SQLite is a reasonable default for early deployment (single-process,
moderate volume). For B2B scale with concurrent write load, replace
this with Postgres using the same interface - nothing else in the
system needs to change.

Account state is stored as serialized JSON in detector_state, so any
detector's evolving state schema does not require a migration here.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.models import AccountState


class SqliteStateStore:

    def __init__(self, db_path: str = "ghost_sentinel_state.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS account_state (
                    tenant_id TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    last_seen_device TEXT,
                    last_seen_geo TEXT,
                    sim_status TEXT,
                    detector_state TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, account_id)
                )
            """)
            conn.commit()

    def get(self, tenant_id: str, account_id: str) -> AccountState:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM account_state WHERE tenant_id = ? AND account_id = ?",
                (tenant_id, account_id),
            ).fetchone()

        if row is None:
            return AccountState(account_id=account_id, tenant_id=tenant_id)

        return AccountState(
            account_id=account_id,
            tenant_id=tenant_id,
            last_seen_device=row["last_seen_device"],
            last_seen_geo=self._deserialize_geo(row["last_seen_geo"]),
            sim_status=row["sim_status"],
            detector_state=json.loads(row["detector_state"], object_hook=self._json_object_hook),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def save(self, state: AccountState) -> None:
        state.updated_at = datetime.utcnow()
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO account_state
                    (tenant_id, account_id, last_seen_device, last_seen_geo,
                     sim_status, detector_state, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, account_id) DO UPDATE SET
                    last_seen_device = excluded.last_seen_device,
                    last_seen_geo = excluded.last_seen_geo,
                    sim_status = excluded.sim_status,
                    detector_state = excluded.detector_state,
                    updated_at = excluded.updated_at
            """, (
                state.tenant_id,
                state.account_id,
                state.last_seen_device,
                self._serialize_geo(state.last_seen_geo),
                state.sim_status,
                json.dumps(state.detector_state, default=self._json_default),
                state.updated_at.isoformat(),
            ))
            conn.commit()

    @staticmethod
    def _serialize_geo(geo: Optional[tuple]) -> Optional[str]:
        return json.dumps(geo) if geo is not None else None

    @staticmethod
    def _deserialize_geo(raw: Optional[str]) -> Optional[tuple]:
        if raw is None:
            return None
        val = json.loads(raw)
        return tuple(val) if val is not None else None

    @staticmethod
    def _json_default(obj):
        """Handles datetime objects inside detector_state dicts, since
        detectors like BehavioralAnomalyDetector store raw timestamps."""
        if isinstance(obj, datetime):
            return {"__datetime__": obj.isoformat()}
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    @staticmethod
    def _json_object_hook(d: dict):
        """Reverses _json_default: turns {"__datetime__": ...} markers back
        into real datetime objects when loading detector_state from disk."""
        if "__datetime__" in d and len(d) == 1:
            return datetime.fromisoformat(d["__datetime__"])
        return d

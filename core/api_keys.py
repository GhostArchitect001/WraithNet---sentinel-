"""
Ghost Sentinel - API Key Management
=====================================

Replaces the placeholder plaintext dict from the prototype gateway.
Keys are stored as salted hashes, never in plaintext, following the
same principle as password storage: if this table leaks, raw API keys
are not directly recoverable from it.

This is still a self-contained module with no external dependency
(SQLite-backed), so it runs the same in Termux as in a hosted deployment.
For very large B2B tenant counts, the same interface can be backed by
a managed database without changing calling code.

Key lifecycle
-------------
Keys now carry an expiry timestamp in addition to the existing active
flag - two different reasons a key can stop working:
  - revoked: someone explicitly turned it off (compromise, offboarding).
  - expired: it simply outlived its planned lifetime. Expiry exists so
    a leaked-but-not-yet-detected key doesn't stay valid forever, and
    so rotation becomes a routine calendar event instead of something
    that only happens after an incident.

Rotation is `rotate_key()`: create a replacement key for the same
tenant, revoke the old one, return the new raw key - one call instead
of manually wiring create_key + revoke_key together and hoping you
didn't forget the second half.

The "reminder mechanism" is deliberately lightweight for a project this
size: `list_expiring_keys()` is a plain query a solo dev can run by
hand or from a cron job (see scripts/list_expiring_keys.py) - not a
notification service with its own moving parts to maintain.
"""

import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from core.models import TenantType

# Default lifetime for a newly created key. 90 days is a common
# baseline rotation cadence for API credentials - long enough to not
# be a daily nuisance, short enough that a forgotten/leaked key has a
# bounded blast radius. Callers can override per-key via create_key's
# ttl_days argument.
_DEFAULT_KEY_TTL_DAYS = 90


@dataclass
class ApiKeyInfo:
    """Metadata about one key, returned by list_keys()/list_expiring_keys().
    Never includes the raw key or its hash - key_id is the same safe,
    non-reversible identifier verify_key() returns."""
    key_id: str
    tenant_id: str
    tenant_type: TenantType
    active: bool
    created_at: datetime
    expires_at: Optional[datetime]

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def days_until_expiry(self) -> Optional[int]:
        if self.expires_at is None:
            return None
        delta = self.expires_at - datetime.now(timezone.utc)
        return delta.days


class ApiKeyStore:

    def __init__(self, db_path: str = "ghost_sentinel_keys.db"):
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
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_hash TEXT PRIMARY KEY,
                    salt TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    tenant_type TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    expires_at TEXT
                )
            """)
            # Existing databases created before expiry support won't have
            # this column - add it if missing so upgrades don't require a
            # manual migration step.
            existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(api_keys)")}
            if "expires_at" not in existing_cols:
                conn.execute("ALTER TABLE api_keys ADD COLUMN expires_at TEXT")
            conn.commit()

    @staticmethod
    def _hash_key(raw_key: str, salt: str) -> str:
        return hashlib.sha256((salt + raw_key).encode("utf-8")).hexdigest()

    @staticmethod
    def _parse_ts(raw: Optional[str]) -> Optional[datetime]:
        if raw is None:
            return None
        dt = datetime.fromisoformat(raw)
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)

    def create_key(
        self,
        tenant_id: str,
        tenant_type: TenantType,
        ttl_days: Optional[int] = _DEFAULT_KEY_TTL_DAYS,
    ) -> str:
        """Generates a new raw API key, stores only its salted hash, and
        returns the raw key ONCE - callers must save it immediately, as
        it cannot be retrieved again.

        ttl_days sets how long the key is valid for before it expires
        on its own, independent of revocation. Pass ttl_days=None for a
        key that never expires (e.g. a long-lived internal service
        credential) - use sparingly, since expiry is the main defense
        against a forgotten key staying valid indefinitely."""
        raw_key = secrets.token_urlsafe(32)
        salt = secrets.token_hex(16)
        key_hash = self._hash_key(raw_key, salt)
        expires_at = (
            (datetime.now(timezone.utc) + timedelta(days=ttl_days)).isoformat()
            if ttl_days is not None
            else None
        )

        with self._connect() as conn:
            conn.execute(
                "INSERT INTO api_keys (key_hash, salt, tenant_id, tenant_type, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (key_hash, salt, tenant_id, tenant_type.value, expires_at),
            )
            conn.commit()

        return raw_key

    def verify_key(self, raw_key: str) -> Optional[tuple[str, TenantType, str]]:
        """Returns (tenant_id, tenant_type, key_id) if the key is valid,
        active, AND not expired - otherwise None. Uses constant-time
        comparison to avoid timing attacks during the final match check.

        key_id is a short, non-reversible identifier derived from the
        stored key_hash (first 12 hex chars) - safe to write into logs
        or the audit trail to distinguish which specific credential made
        a request, without exposing the hash itself or the raw key."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT key_hash, salt, tenant_id, tenant_type, expires_at "
                "FROM api_keys WHERE active = 1"
            ).fetchall()

        now = datetime.now(timezone.utc)
        for row in rows:
            candidate_hash = self._hash_key(raw_key, row["salt"])
            if hmac.compare_digest(candidate_hash, row["key_hash"]):
                expires_at = self._parse_ts(row["expires_at"])
                if expires_at is not None and now >= expires_at:
                    return None  # correct key, but it's expired - same as invalid
                return row["tenant_id"], TenantType(row["tenant_type"]), row["key_hash"][:12]

        return None

    def revoke_key(self, raw_key: str) -> bool:
        with self._connect() as conn:
            rows = conn.execute("SELECT key_hash, salt FROM api_keys WHERE active = 1").fetchall()
            for row in rows:
                if hmac.compare_digest(self._hash_key(raw_key, row["salt"]), row["key_hash"]):
                    conn.execute("UPDATE api_keys SET active = 0 WHERE key_hash = ?", (row["key_hash"],))
                    conn.commit()
                    return True
        return False

    def rotate_key(
        self,
        raw_key: str,
        ttl_days: Optional[int] = _DEFAULT_KEY_TTL_DAYS,
    ) -> Optional[str]:
        """Replaces an existing key with a brand new one for the same
        tenant: creates the new key, revokes the old one, returns the
        new raw key ONCE. Returns None if raw_key doesn't match any
        active key (nothing is created or revoked in that case).

        This is the single call a rotation reminder should lead to -
        no separate create_key/revoke_key bookkeeping to get right."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT key_hash, salt, tenant_id, tenant_type FROM api_keys WHERE active = 1"
            ).fetchall()

        for row in rows:
            if hmac.compare_digest(self._hash_key(raw_key, row["salt"]), row["key_hash"]):
                tenant_id = row["tenant_id"]
                tenant_type = TenantType(row["tenant_type"])
                new_raw_key = self.create_key(tenant_id, tenant_type, ttl_days=ttl_days)
                with self._connect() as conn:
                    conn.execute(
                        "UPDATE api_keys SET active = 0 WHERE key_hash = ?", (row["key_hash"],)
                    )
                    conn.commit()
                return new_raw_key

        return None

    def list_keys(self, tenant_id: Optional[str] = None, active_only: bool = True) -> list[ApiKeyInfo]:
        """Returns metadata (never raw keys or hashes) for keys in the
        store, optionally filtered to one tenant. Useful for an admin
        view of "what credentials exist and when do they expire"."""
        clauses = []
        params: list = []
        if active_only:
            clauses.append("active = 1")
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT key_hash, tenant_id, tenant_type, active, created_at, expires_at "
                f"FROM api_keys {where} ORDER BY created_at ASC",
                params,
            ).fetchall()

        return [self._row_to_info(row) for row in rows]

    def list_expiring_keys(self, within_days: int = 14, tenant_id: Optional[str] = None) -> list[ApiKeyInfo]:
        """Returns active keys whose expiry falls within the given
        window (default 14 days) - already-expired keys are included
        too, since those need even more urgent attention. This is the
        whole "reminder mechanism": call it by hand, or from a small
        cron job (scripts/list_expiring_keys.py), and rotate whatever
        it lists via rotate_key()."""
        cutoff = (datetime.now(timezone.utc) + timedelta(days=within_days)).isoformat()
        clauses = ["active = 1", "expires_at IS NOT NULL", "expires_at <= ?"]
        params: list = [cutoff]
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT key_hash, tenant_id, tenant_type, active, created_at, expires_at "
                f"FROM api_keys WHERE {' AND '.join(clauses)} ORDER BY expires_at ASC",
                params,
            ).fetchall()

        return [self._row_to_info(row) for row in rows]

    def _row_to_info(self, row: sqlite3.Row) -> ApiKeyInfo:
        return ApiKeyInfo(
            key_id=row["key_hash"][:12],
            tenant_id=row["tenant_id"],
            tenant_type=TenantType(row["tenant_type"]),
            active=bool(row["active"]),
            created_at=self._parse_ts(row["created_at"]) or datetime.now(timezone.utc),
            expires_at=self._parse_ts(row["expires_at"]),
        )

"""
Ghost Sentinel - Audit Log
=============================

Append-only, structured record of every risk decision the engine
makes. Built for two audiences:

1. Compliance review - "show me every high-severity decision made
   for tenant X in the last quarter."
2. Dispute resolution - "the customer says their account was flagged
   in error on <date> - what exactly did the system see, what score
   did it produce, and what action did it recommend?"

This is deliberately a separate table/concern from AccountState
(core/models.py / core/sqlite_store.py). AccountState is mutable
rolling state a detector reads/writes to do its job *now*. The audit
log is the immutable record of what happened, kept *forever* (or per
your retention policy) regardless of what current state looks like.
Never update or delete rows here in normal operation - only insert.

Each row answers the four questions compliance/legal will always ask:
  - WHO queried: the tenant/API key that made the request producing
    this decision (requesting_tenant_id), separate from the account
    the decision is *about* (account_id) - these differ whenever a
    B2B tenant is scoring one of their own customers. As of this
    delivery, "who queried" also includes the requester's IP address
    (client_ip) where the gateway was able to determine one - see
    api/main.py for how that's captured and why it can legitimately
    be None.
  - WHAT signal: signal_id, signal_type, and a redacted/sized summary
    of the payload that triggered the decision (not the raw payload -
    see _summarize_payload below).
  - WHAT score: risk_score, severity, reasons.
  - WHAT action: recommended_action.

IP flagging (list_flagged_ips)
-------------------------------
This module also exposes a read-only aggregate view over client_ip:
"which IPs have been associated with high-severity risk events
recently, and how many times." This is intentionally the same
advisory, human-in-the-loop shape as the rest of the system -
recommended_action on a RiskEvent is text for a human/calling system
to act on, not an autonomous freeze; list_flagged_ips is the same
idea applied to infrastructure-level response. It surfaces a
candidate list for a human to review and decide whether to block at
the WAF/firewall - it does not block anything itself, and it never
will from inside this module.

A few honesty notes on what this can and can't tell you:
  - client_ip is frequently None. IP capture depends on how the
    service is deployed (see api/main.py) - a self-reported
    X-Forwarded-For from an untrusted client is worthless as an
    identifier, so the gateway only records an IP it has some basis
    to trust. Don't assume every row has one.
  - An IP is not a person or even a stable device. NAT, shared
    corporate/mobile-carrier egress, VPNs, and dynamic residential
    IP reassignment all mean the same IP can represent many
    legitimate users over time, and one attacker can rotate through
    many IPs. Treat this list as a lead for a human to investigate,
    not a verdict.
  - Aggregating by IP says nothing about *why* those events fired -
    pull the underlying rows (query(...) filtered by IP, once you
    have one) before recommending a block.

Cross-account device/IP clustering (list_shared_device_ip_clusters)
---------------------------------------------------------------------
Extends the same aggregate-view idea one step further: instead of
"which single IPs show up on high-severity rows," this asks "which
device fingerprints or IPs are shared across *multiple distinct
accounts*" - a pattern consistent with a fraud ring operating several
mule/scam accounts from the same device or network, or a single
attacker who has taken over several accounts. Same advisory,
human-review shape as list_flagged_ips: it surfaces candidate clusters
for a human to investigate, and it does not link, merge, flag, or
block any account itself. Nothing in this module writes back to
AccountState or takes any action beyond returning a list.

Same honesty caveats as IP flagging apply, plus one specific to
clustering: a shared device_id or client_ip across accounts is not
proof of a fraud ring on its own. Shared household devices, shared
office/campus networks, family members using one phone, and NAT'd
corporate egress all produce genuinely-shared device_id/client_ip
values between entirely legitimate, unrelated accounts. This function
returns a candidate list ranked by how many distinct accounts and how
severe the associated activity was - it is a lead, not a verdict, and
the account count threshold (min_accounts) exists specifically so
callers can tune how much "shared-ness" is worth a human's time
before investigating.

Same get/write-only shape philosophy as SqliteStateStore, so it's a
familiar pattern to extend or swap for Postgres later (see README).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
import uuid

from core.models import RiskEvent, Signal

# Payload fields we never want to persist verbatim into an audit log
# that may be read by compliance staff, exported, or retained for
# years. Detectors can add device/geo/behavioral fields to a
# signal's payload; auditors need to know a field was present and
# roughly what it looked like, not necessarily its raw value.
_SENSITIVE_PAYLOAD_KEYS = {"otp", "otp_code", "password", "pin", "cvv", "ssn"}
_MAX_PAYLOAD_SUMMARY_CHARS = 2000


@dataclass
class AuditRecord:
    """One immutable row: the full context behind a single risk decision."""
    # who queried
    requesting_tenant_id: str
    api_key_id: Optional[str]
    client_ip: Optional[str]
    # what was evaluated
    account_id: str
    signal_id: str
    signal_type: str
    payload_summary: str
    # what the detector decided
    detector_name: str
    risk_score: float
    severity: str
    reasons: list[str]
    recommended_action: Optional[str]
    event_id: str
    # bookkeeping
    decided_at: datetime = field(default_factory=datetime.utcnow)
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    device_id: Optional[str] = None


@dataclass
class FlaggedIp:
    """One row of list_flagged_ips() output: an IP address and the
    high-severity activity associated with it, for a human to review.
    Deliberately has no `blocked` or `action_taken` field - this
    object is informational input to a human decision, not a record
    of an action the system took (the system doesn't take that
    action)."""
    client_ip: str
    event_count: int
    distinct_accounts: int
    max_severity: str
    first_seen: datetime
    last_seen: datetime


@dataclass
class SharedDeviceIpCluster:
    """One row of list_shared_device_ip_clusters() output: a device
    fingerprint or IP address that multiple distinct accounts have
    used, for a human to review. Same informational shape as
    FlaggedIp - no `linked` or `action_taken` field, because this
    object is input to a human decision, not a record of an action
    the system took (the system doesn't link or block accounts)."""
    cluster_key: str            # the shared device_id or client_ip value
    cluster_type: str           # "device_id" or "client_ip"
    account_ids: list[str]      # distinct accounts observed sharing this key
    event_count: int
    max_severity: str
    first_seen: datetime
    last_seen: datetime


def _summarize_payload(payload: dict[str, Any]) -> str:
    """Turns a signal payload into a compact, redacted string safe for
    long-term audit storage: sensitive keys are replaced with a
    redaction marker, everything else is kept so an auditor can still
    see what shape of evidence a detector was reacting to."""
    if not payload:
        return "{}"
    redacted = {
        k: ("<redacted>" if k.lower() in _SENSITIVE_PAYLOAD_KEYS else v)
        for k, v in payload.items()
    }
    try:
        summary = json.dumps(redacted, default=str, sort_keys=True)
    except TypeError:
        summary = str(redacted)
    if len(summary) > _MAX_PAYLOAD_SUMMARY_CHARS:
        summary = summary[:_MAX_PAYLOAD_SUMMARY_CHARS] + "...<truncated>"
    return summary


class SqliteAuditLogStore:
    """
    Append-only SQLite-backed audit log. Same db-per-file setup as
    SqliteStateStore, but intentionally kept in its own database file
    (default: data/ghost_sentinel_audit.db) so retention, backup, and
    access-control policy for audit data can differ from operational
    state - compliance data often needs longer retention and stricter
    read access than working state does.
    """

    def __init__(self, db_path: str = "ghost_sentinel_audit.db"):
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
                CREATE TABLE IF NOT EXISTS audit_log (
                    audit_id TEXT PRIMARY KEY,
                    decided_at TEXT NOT NULL,
                    requesting_tenant_id TEXT NOT NULL,
                    api_key_id TEXT,
                    client_ip TEXT,
                    account_id TEXT NOT NULL,
                    signal_id TEXT NOT NULL,
                    signal_type TEXT NOT NULL,
                    payload_summary TEXT NOT NULL,
                    detector_name TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    severity TEXT NOT NULL,
                    reasons TEXT NOT NULL,
                    recommended_action TEXT,
                    event_id TEXT NOT NULL
                )
            """)
            # Existing databases created before client_ip support won't
            # have this column - add it if missing so upgrades don't
            # require a manual migration step (same pattern as
            # ApiKeyStore._init_schema for expires_at).
            existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)")}
            if "client_ip" not in existing_cols:
                conn.execute("ALTER TABLE audit_log ADD COLUMN client_ip TEXT")
            if "device_id" not in existing_cols:
                conn.execute("ALTER TABLE audit_log ADD COLUMN device_id TEXT")

            # Compliance queries are almost always "for this tenant,
            # in this time range" or "for this account" or "find this
            # event_id to resolve a dispute" - index all three.
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_tenant_time "
                "ON audit_log (requesting_tenant_id, decided_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_account "
                "ON audit_log (account_id, decided_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_event "
                "ON audit_log (event_id)"
            )
            # Supports list_flagged_ips: "which IPs show up on
            # high-severity rows" is a client_ip + severity scan.
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_ip "
                "ON audit_log (client_ip, severity, decided_at)"
            )
            # Supports list_shared_device_ip_clusters: "which
            # device_ids show up across multiple accounts" needs a
            # device_id-keyed scan the same way idx_audit_ip supports
            # the client_ip-keyed one.
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_device "
                "ON audit_log (device_id, decided_at)"
            )
            conn.commit()

    def record(
        self,
        signal: Signal,
        event: RiskEvent,
        requesting_tenant_id: str,
        api_key_id: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> AuditRecord:
        """Write one immutable audit row for a single detector's
        decision about a single signal. Called once per RiskEvent -
        if one signal triggers three detectors, that's three audit
        rows, one per decision, matching how RiskEvents are already
        modeled (one event per detector verdict).

        client_ip is whatever the gateway determined the requester's
        IP to be (or None if it couldn't determine one it trusts - see
        api/main.py). This module makes no attempt to validate or
        second-guess it; that judgment call belongs at the layer that
        actually terminates the connection.

        device_id is read directly off the Signal (signal.device_id) -
        whatever device identifier the calling app supplied with this
        signal, or None if it didn't. Persisted so
        list_shared_device_ip_clusters() has something to cluster on
        beyond client_ip."""
        record = AuditRecord(
            requesting_tenant_id=requesting_tenant_id,
            api_key_id=api_key_id,
            client_ip=client_ip,
            account_id=event.account_id,
            signal_id=signal.signal_id,
            signal_type=signal.signal_type.value,
            payload_summary=_summarize_payload(signal.payload),
            detector_name=event.detector_name,
            risk_score=event.risk_score,
            severity=event.severity.value,
            reasons=list(event.reasons),
            recommended_action=event.recommended_action,
            event_id=event.event_id,
            device_id=signal.device_id,
        )
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO audit_log
                    (audit_id, decided_at, requesting_tenant_id, api_key_id,
                     client_ip, account_id, signal_id, signal_type,
                     payload_summary, detector_name, risk_score, severity,
                     reasons, recommended_action, event_id, device_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.audit_id,
                record.decided_at.isoformat(),
                record.requesting_tenant_id,
                record.api_key_id,
                record.client_ip,
                record.account_id,
                record.signal_id,
                record.signal_type,
                record.payload_summary,
                record.detector_name,
                record.risk_score,
                record.severity,
                json.dumps(record.reasons),
                record.recommended_action,
                record.event_id,
                record.device_id,
            ))
            conn.commit()
        return record

    def query(
        self,
        requesting_tenant_id: Optional[str] = None,
        account_id: Optional[str] = None,
        event_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        min_severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditRecord]:
        """
        Flexible read path for compliance review and dispute
        resolution. All filters are optional and combine with AND;
        pass event_id alone to pull up the full record behind one
        specific decision a customer is disputing. Pass client_ip to
        pull up everything a specific address has been associated
        with - the natural follow-up after list_flagged_ips() surfaces
        a candidate.
        """
        clauses = []
        params: list[Any] = []

        if requesting_tenant_id is not None:
            clauses.append("requesting_tenant_id = ?")
            params.append(requesting_tenant_id)
        if account_id is not None:
            clauses.append("account_id = ?")
            params.append(account_id)
        if event_id is not None:
            clauses.append("event_id = ?")
            params.append(event_id)
        if client_ip is not None:
            clauses.append("client_ip = ?")
            params.append(client_ip)
        if start_time is not None:
            clauses.append("decided_at >= ?")
            params.append(start_time.isoformat())
        if end_time is not None:
            clauses.append("decided_at <= ?")
            params.append(end_time.isoformat())
        if min_severity is not None:
            # Severity ranks low-to-high; filter to >= the requested floor.
            rank_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            floor = rank_map.get(min_severity, 0)
            allowed = [s for s, r in rank_map.items() if r >= floor]
            placeholders = ",".join("?" for _ in allowed)
            clauses.append(f"severity IN ({placeholders})")
            params.extend(allowed)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = (
            f"SELECT * FROM audit_log {where} "
            f"ORDER BY decided_at DESC LIMIT ?"
        )
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [self._row_to_record(row) for row in rows]

    def list_flagged_ips(
        self,
        min_severity: str = "high",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        min_event_count: int = 1,
        limit: int = 100,
    ) -> list["FlaggedIp"]:
        """
        Aggregate view: which client IPs have been associated with
        risk events at or above min_severity, how many times, for how
        many distinct accounts, and the severity/time range involved.
        Ordered by event_count descending so the most-implicated IPs
        surface first.

        This is a *recommendation feed for a human*, not a block list -
        see the module docstring's "IP flagging" section for why an IP
        alone is weak evidence (NAT, shared egress, VPNs) and why this
        function does not take any blocking action itself. Rows with a
        NULL client_ip are excluded, since "unknown" is not an
        actionable target.

        min_event_count lets a caller raise the bar above "flagged
        even once" - useful once you have enough volume that a single
        stray high-severity event from a shared/NAT'd IP is expected
        noise rather than a signal worth a human's time.
        """
        rank_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        floor = rank_map.get(min_severity, 0)
        allowed = [s for s, r in rank_map.items() if r >= floor]

        clauses = ["client_ip IS NOT NULL", f"severity IN ({','.join('?' for _ in allowed)})"]
        params: list[Any] = list(allowed)
        if start_time is not None:
            clauses.append("decided_at >= ?")
            params.append(start_time.isoformat())
        if end_time is not None:
            clauses.append("decided_at <= ?")
            params.append(end_time.isoformat())

        where = f"WHERE {' AND '.join(clauses)}"
        query = f"""
            SELECT
                client_ip,
                COUNT(*) AS event_count,
                COUNT(DISTINCT account_id) AS distinct_accounts,
                MAX(severity) AS max_severity_raw,
                MIN(decided_at) AS first_seen,
                MAX(decided_at) AS last_seen
            FROM audit_log
            {where}
            GROUP BY client_ip
            HAVING COUNT(*) >= ?
            ORDER BY event_count DESC
            LIMIT ?
        """
        params.append(min_event_count)
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        # SQL MAX() on the severity string sorts alphabetically, not by
        # our low-to-high rank, so recompute max severity in Python
        # rather than trusting max_severity_raw.
        results = []
        for row in rows:
            with self._connect() as conn:
                sev_rows = conn.execute(
                    "SELECT severity FROM audit_log WHERE client_ip = ? "
                    f"AND severity IN ({','.join('?' for _ in allowed)})",
                    [row["client_ip"], *allowed],
                ).fetchall()
            worst = max((r["severity"] for r in sev_rows), key=lambda s: rank_map.get(s, 0))
            results.append(FlaggedIp(
                client_ip=row["client_ip"],
                event_count=row["event_count"],
                distinct_accounts=row["distinct_accounts"],
                max_severity=worst,
                first_seen=datetime.fromisoformat(row["first_seen"]),
                last_seen=datetime.fromisoformat(row["last_seen"]),
            ))
        return results

    def list_shared_device_ip_clusters(
        self,
        min_accounts: int = 3,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list["SharedDeviceIpCluster"]:
        """
        Aggregate view: which device fingerprints or client IPs have
        been used by at least `min_accounts` distinct accounts, how
        many events involved that key, and the severity/time range
        associated with it. Runs the same query shape twice - once
        keyed on device_id, once on client_ip - and returns both kinds
        of cluster in one ranked list, since a fraud ring can show up
        on either axis depending on what the client app was able to
        report. Ordered by distinct account count descending so the
        most-shared keys surface first.

        This is a *recommendation feed for a human*, not an account
        linker - see the module docstring's "Cross-account device/IP
        clustering" section for why shared device/IP alone is weak
        evidence (shared households, offices, NAT) and why this
        function does not link, merge, flag, or block any account
        itself. Rows with a NULL device_id/client_ip are excluded from
        the respective scan, since "unknown" is not an actionable
        cluster key.

        min_accounts is the whole point of this function versus a
        plain per-IP or per-device count: one account reusing its own
        device/IP across many events is normal and not what this
        surfaces. Only keys touching multiple *distinct* accounts
        count, and min_accounts lets a caller raise that bar further
        once they know their own base rate of legitimate device/IP
        sharing (family devices, office networks, etc).
        """
        clusters: list[SharedDeviceIpCluster] = []
        for column, cluster_type in (("device_id", "device_id"), ("client_ip", "client_ip")):
            clusters.extend(
                self._cluster_by_column(
                    column=column,
                    cluster_type=cluster_type,
                    min_accounts=min_accounts,
                    start_time=start_time,
                    end_time=end_time,
                )
            )
        clusters.sort(key=lambda c: len(c.account_ids), reverse=True)
        return clusters[:limit]

    def _cluster_by_column(
        self,
        column: str,
        cluster_type: str,
        min_accounts: int,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> list["SharedDeviceIpCluster"]:
        """Shared implementation behind list_shared_device_ip_clusters -
        runs the "group by this column, keep only groups touching
        multiple distinct accounts" query against either device_id or
        client_ip. `column` is only ever one of those two hardcoded
        literals passed internally, never user input, so building the
        column name into the SQL text here is safe."""
        rank_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        clauses = [f"{column} IS NOT NULL"]
        params: list[Any] = []
        if start_time is not None:
            clauses.append("decided_at >= ?")
            params.append(start_time.isoformat())
        if end_time is not None:
            clauses.append("decided_at <= ?")
            params.append(end_time.isoformat())
        where = f"WHERE {' AND '.join(clauses)}"

        query = f"""
            SELECT
                {column} AS cluster_key,
                COUNT(*) AS event_count,
                COUNT(DISTINCT account_id) AS distinct_accounts,
                MIN(decided_at) AS first_seen,
                MAX(decided_at) AS last_seen
            FROM audit_log
            {where}
            GROUP BY {column}
            HAVING COUNT(DISTINCT account_id) >= ?
            ORDER BY distinct_accounts DESC
        """
        params.append(min_accounts)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        results = []
        for row in rows:
            with self._connect() as conn:
                detail_rows = conn.execute(
                    f"SELECT DISTINCT account_id, severity FROM audit_log "
                    f"WHERE {column} = ?",
                    [row["cluster_key"]],
                ).fetchall()
            account_ids = sorted({r["account_id"] for r in detail_rows})
            worst = max(
                (r["severity"] for r in detail_rows),
                key=lambda s: rank_map.get(s, 0),
                default="info",
            )
            results.append(SharedDeviceIpCluster(
                cluster_key=row["cluster_key"],
                cluster_type=cluster_type,
                account_ids=account_ids,
                event_count=row["event_count"],
                max_severity=worst,
                first_seen=datetime.fromisoformat(row["first_seen"]),
                last_seen=datetime.fromisoformat(row["last_seen"]),
            ))
        return results

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> AuditRecord:
        return AuditRecord(
            requesting_tenant_id=row["requesting_tenant_id"],
            api_key_id=row["api_key_id"],
            client_ip=row["client_ip"],
            account_id=row["account_id"],
            signal_id=row["signal_id"],
            signal_type=row["signal_type"],
            payload_summary=row["payload_summary"],
            detector_name=row["detector_name"],
            risk_score=row["risk_score"],
            severity=row["severity"],
            reasons=json.loads(row["reasons"]),
            recommended_action=row["recommended_action"],
            event_id=row["event_id"],
            decided_at=datetime.fromisoformat(row["decided_at"]),
            audit_id=row["audit_id"],
            device_id=row["device_id"] if "device_id" in row.keys() else None,
        )

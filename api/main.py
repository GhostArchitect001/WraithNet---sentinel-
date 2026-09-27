"""
Ghost Sentinel - Ingestion Gateway
====================================

FastAPI service exposing the Detection Engine to both consumer clients
and B2B API tenants. Same request/response shape for both - the only
difference is the auth/tenant tier, matching the estate/org/tenant
multi-tenancy pattern from energy_mesh_v2.

Run locally (in Termux this is the same uvicorn pattern you already use):
    uvicorn api.main:app --reload --port 8000

Auth uses ApiKeyStore (core/api_keys.py) - hashed key storage, not
plaintext. State persists via SqliteStateStore (core/sqlite_store.py)
so account history survives restarts.

To provision a new API key for a tenant, run:
    python3 -c "
    from core.api_keys import ApiKeyStore
    from core.models import TenantType
    store = ApiKeyStore('ghost_sentinel_keys.db')
    print(store.create_key('my-tenant-id', TenantType.B2B))
    "
The printed key is shown once only - save it immediately.
"""

import json
import math
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from starlette.responses import JSONResponse

from core.engine import DetectionEngine
from core.models import Signal, SignalType, TenantType
from core.api_keys import ApiKeyStore
from core.sqlite_store import SqliteStateStore
from core.audit_log import SqliteAuditLogStore
from core.rate_limiter import RateLimitExceeded, build_rate_limiter
from core.verification import (
    ChallengeMethod,
    ConsoleChallengeDelivery,
    VerificationStore,
    VerifyResult,
    maybe_request_challenge,
    verify_response,
)
from detectors.behavioral_anomaly import BehavioralAnomalyDetector
from detectors.sim_ato import SimAtoDetector
from detectors.phishing import PhishingDetector
from detectors.mule_transfer import MuleTransferDetector
from detectors.social_engineering_session import SocialEngineeringSessionDetector

app = FastAPI(title="Ghost Sentinel Detection Gateway", version="0.2.0")

# --- Request body size limit, enforced before any JSON/pydantic parsing ---
# Protects against a client (malicious or just buggy) sending a huge
# body to exhaust memory or CPU parsing it before validation even gets
# a chance to run. A single signal is a handful of small fields plus a
# free-form payload dict - 256 KB is generous headroom over any
# legitimate use while still being a hard ceiling.
_MAX_REQUEST_BODY_BYTES = 256 * 1024  # 256 KB


@app.middleware("http")
async def limit_request_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > _MAX_REQUEST_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Request body too large (max {_MAX_REQUEST_BODY_BYTES} bytes)"},
                )
        except ValueError:
            pass  # malformed header - fall through to the real-body check below

    # Content-Length can be absent (chunked transfer) or simply wrong, so
    # don't rely on it alone - read the actual body and re-inject it for
    # downstream handlers, enforcing the same ceiling either way.
    body = await request.body()
    if len(body) > _MAX_REQUEST_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={"detail": f"Request body too large (max {_MAX_REQUEST_BODY_BYTES} bytes)"},
        )

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    request._receive = receive
    return await call_next(request)

# --- Engine setup: register detectors here as they're built ---
state_store = SqliteStateStore("data/ghost_sentinel_state.db")
engine = DetectionEngine(state_store=state_store)
engine.register(BehavioralAnomalyDetector())
engine.register(SimAtoDetector())
engine.register(PhishingDetector())
engine.register(MuleTransferDetector())
engine.register(SocialEngineeringSessionDetector())

key_store = ApiKeyStore("data/ghost_sentinel_keys.db")

# --- Audit log: one immutable row per risk decision ---
# Separate database file from operational state (see core/audit_log.py)
# so retention/backup/access policy for compliance data can differ from
# working state. Every RiskEvent the engine produces gets logged here
# with who queried, what signal, what score, and what action was
# recommended - for compliance review and dispute resolution.
audit_store = SqliteAuditLogStore("data/ghost_sentinel_audit.db")

# --- Identity verification (Step 6) ---
# See core/verification.py for the full design writeup. In short:
# ChallengeDelivery is the pluggable seam Ghost Identity would
# implement later; ConsoleChallengeDelivery is a local/mock stand-in
# used here because no Ghost Identity spec exists yet for this
# delivery. Swapping in a real delivery implementation later is a
# one-line change at this registration point - nothing else in this
# file, or in core/verification.py, needs to change.
challenge_delivery = ConsoleChallengeDelivery(log_to_stdout=False)
verification_store = VerificationStore()



# --- Per-tenant rate limiting (sliding window) ---
# Backed by Redis when GHOST_SENTINEL_REDIS_URL is set, so limits hold
# across multiple API processes/servers and survive restarts. Falls
# back to an in-process limiter automatically if no URL is set or
# Redis can't be reached (see core/rate_limiter.py for details).
_RATE_LIMIT_WINDOW_SECONDS = 60
_RATE_LIMIT_MAX_REQUESTS = 120  # per tenant, per window

rate_limiter = build_rate_limiter(
    redis_url=os.environ.get("GHOST_SENTINEL_REDIS_URL"),
    window_seconds=_RATE_LIMIT_WINDOW_SECONDS,
    max_requests=_RATE_LIMIT_MAX_REQUESTS,
)


def check_rate_limit(tenant_id: str) -> None:
    try:
        rate_limiter.check(tenant_id)
    except RateLimitExceeded:
        raise HTTPException(status_code=429, detail="Rate limit exceeded, slow down")


def get_tenant(x_api_key: Optional[str] = Header(default=None)) -> tuple[str, TenantType, str]:
    if x_api_key is None:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    result = key_store.verify_key(x_api_key)
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    tenant_id, _tenant_type, _key_id = result
    check_rate_limit(tenant_id)
    return result


# --- Client IP capture ---
# request.client.host is the IP of whoever opened the TCP connection to
# this process. If Ghost Sentinel is deployed directly (no reverse
# proxy/load balancer in front of it), that's the real client IP and
# it's safe to trust.
#
# If it's deployed behind a reverse proxy/load balancer (the common
# case in production - nginx, an ALB, Cloudflare, etc.), request.client
# will be the *proxy's* IP, and the real client IP shows up in a header
# like X-Forwarded-For or X-Real-IP instead. The dishonest shortcut
# here would be to just trust whatever X-Forwarded-For says - but that
# header is entirely client-supplied. Anyone can set
# "X-Forwarded-For: 1.2.3.4" on a raw request and this service would
# have no way to tell that from a real proxy hop, which would make
# list_flagged_ips() (and any human decision downstream of it) trust
# attacker-controlled input.
#
# The honest middle ground: only trust X-Forwarded-For/X-Real-IP when
# GHOST_SENTINEL_TRUSTED_PROXY_COUNT is explicitly set to a positive
# integer by whoever is deploying this - i.e. "I know I'm running
# behind exactly N proxies I control, and I know the last N hops in
# the chain are mine." When it's unset (the default), we only ever
# record request.client.host - which, behind an unconfigured proxy,
# will just be the proxy's own IP for every request. That's a real
# limitation of running behind a proxy without configuring this, not
# a bug: recording "the proxy's IP for everyone" is honest and useless
# for flagging; recording an unverified client-supplied header would
# be dishonest and actively misleading. We choose useless over
# misleading here, since list_flagged_ips() output can lead to a real
# infrastructure block decision.
_TRUSTED_PROXY_COUNT = int(os.environ.get("GHOST_SENTINEL_TRUSTED_PROXY_COUNT", "0") or "0")


def get_client_ip(request: Request) -> Optional[str]:
    """Best-effort, spoof-aware client IP extraction. See the module
    comment above for the trust model. Returns None rather than a
    guess if we can't determine an IP we have grounds to trust -
    callers (audit_store.record) already treat client_ip as optional."""
    if _TRUSTED_PROXY_COUNT > 0:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # X-Forwarded-For is a comma-separated list appended to by
            # each proxy hop: "client, proxy1, proxy2, ...". With N
            # trusted proxies in front of us, the real client is N
            # entries from the right end of that list.
            hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
            index_from_right = _TRUSTED_PROXY_COUNT
            if len(hops) >= index_from_right:
                return hops[-index_from_right]
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()

    if request.client is not None:
        return request.client.host
    return None


# --- Request/response schemas ---

# Bounds chosen from what detectors and storage actually need, not
# arbitrary round numbers:
#   - account_id/device_id: real identifiers (UUIDs, customer IDs,
#     device fingerprints) are well under 128 chars; this also becomes
#     a SQLite primary-key component (core/sqlite_store.py) and a log
#     field (core/audit_log.py), so an unbounded string is a storage
#     and log-injection risk, not just a correctness one.
#   - payload: free-form per signal_type, but detectors only ever read
#     a handful of scalar fields out of it (see detectors/*.py) - 8 KB
#     is generous headroom for that while still bounding what flows
#     into audit_log's payload_summary and detector_state.
#   - geo: real latitude/longitude, not sentinel/placeholder floats -
#     out-of-range or non-finite values would silently corrupt the
#     haversine distance math in sim_ato.py.
_MAX_ID_LENGTH = 128
_MAX_PAYLOAD_BYTES = 8 * 1024
_MAX_FUTURE_SKEW = timedelta(minutes=5)   # allow small clock drift from clients
_MAX_PAST_AGE = timedelta(days=365 * 5)   # reject implausibly old backdated signals

_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:@-]+$")


class SignalIn(BaseModel):
    signal_type: SignalType
    account_id: str = Field(..., min_length=1, max_length=_MAX_ID_LENGTH)
    timestamp: Optional[datetime] = None
    payload: dict = Field(default_factory=dict)
    device_id: Optional[str] = Field(default=None, max_length=_MAX_ID_LENGTH)
    geo: Optional[tuple[float, float]] = None

    @field_validator("account_id", "device_id")
    @classmethod
    def _id_must_be_safe(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not v:
            raise ValueError("must not be blank")
        if not _SAFE_ID_PATTERN.match(v):
            raise ValueError(
                "must contain only letters, numbers, and . _ : @ - "
                "(no whitespace or control characters)"
            )
        return v

    @field_validator("payload")
    @classmethod
    def _payload_size_limit(cls, v: dict) -> dict:
        # Rough but cheap: serialize to measure actual encoded size
        # rather than trusting len(dict), since a handful of large
        # string values in a small dict can still be a large payload.
        try:
            encoded_size = len(json.dumps(v).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"payload must be JSON-serializable: {exc}")
        if encoded_size > _MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"payload too large ({encoded_size} bytes, max {_MAX_PAYLOAD_BYTES})"
            )
        return v

    @field_validator("geo")
    @classmethod
    def _geo_must_be_real_coordinates(cls, v: Optional[tuple[float, float]]):
        if v is None:
            return v
        lat, lon = v
        if not (math.isfinite(lat) and math.isfinite(lon)):
            raise ValueError("geo coordinates must be finite numbers")
        if not (-90.0 <= lat <= 90.0):
            raise ValueError("latitude must be between -90 and 90")
        if not (-180.0 <= lon <= 180.0):
            raise ValueError("longitude must be between -180 and 180")
        return v

    @field_validator("timestamp")
    @classmethod
    def _timestamp_must_be_plausible(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is None:
            return v
        now = datetime.now(timezone.utc)
        # Normalize naive datetimes to UTC for comparison; detectors and
        # storage elsewhere in this codebase also treat naive timestamps
        # as UTC (see AccountState.updated_at, Signal.timestamp usage).
        compare_v = v if v.tzinfo is not None else v.replace(tzinfo=timezone.utc)
        if compare_v > now + _MAX_FUTURE_SKEW:
            raise ValueError("timestamp is too far in the future")
        if compare_v < now - _MAX_PAST_AGE:
            raise ValueError("timestamp is implausibly old")
        return v


class RiskEventOut(BaseModel):
    event_id: str
    account_id: str
    detector_name: str
    risk_score: float
    severity: str
    reasons: list[str]
    recommended_action: Optional[str]
    verification_challenge_id: Optional[str] = None
    verification_method: Optional[str] = None



@app.post("/v1/signals", response_model=list[RiskEventOut])
def ingest_signal(
    signal_in: SignalIn,
    request: Request,
    tenant: tuple = Depends(get_tenant),
) -> list[RiskEventOut]:
    """
    Single ingestion endpoint for both consumer app and B2B clients.
    Accepts one signal, returns zero or more risk events produced by it.
    """
    tenant_id, _tenant_type, key_id = tenant
    client_ip = get_client_ip(request)

    signal = Signal(
        signal_type=signal_in.signal_type,
        tenant_id=tenant_id,
        account_id=signal_in.account_id,
        timestamp=signal_in.timestamp or datetime.utcnow(),
        payload=signal_in.payload,
        device_id=signal_in.device_id,
        geo=signal_in.geo,
    )

    events = engine.process(signal)

    # One immutable audit row per risk decision - who queried (tenant_id,
    # key_id), what signal, what score, what action. Logged even though
    # nothing here is a user-facing side effect, since compliance needs
    # this record regardless of whether the client ever looks at it.
    for e in events:
        audit_store.record(
            signal=signal,
            event=e,
            requesting_tenant_id=tenant_id,
            api_key_id=key_id,
            client_ip=client_ip,
        )

    # Advisory step-up verification: if any event crosses the HIGH/
    # CRITICAL bar and the account hasn't already cleared a challenge
    # recently, request one. This only ever results in a challenge
    # being issued for the calling application to present - it never
    # blocks this response or the signal that triggered it. See
    # core/verification.py for the full advisory-only rationale.
    account_state = engine.state_store.get(tenant_id, signal.account_id)
    challenges_by_event: dict[str, tuple[str, str]] = {}
    for e in events:
        challenge = maybe_request_challenge(
            event=e,
            state=account_state,
            delivery=challenge_delivery,
            store=verification_store,
        )
        if challenge is not None:
            challenges_by_event[e.event_id] = (challenge.challenge_id, challenge.method.value)
    if challenges_by_event:
        engine.state_store.save(account_state)

    return [
        RiskEventOut(
            event_id=e.event_id,
            account_id=e.account_id,
            detector_name=e.detector_name,
            risk_score=round(e.risk_score, 3),
            severity=e.severity.value,
            reasons=e.reasons,
            recommended_action=e.recommended_action,
            verification_challenge_id=challenges_by_event.get(e.event_id, (None, None))[0],
            verification_method=challenges_by_event.get(e.event_id, (None, None))[1],
        )
        for e in events
    ]


class FlaggedIpOut(BaseModel):
    client_ip: str
    event_count: int
    distinct_accounts: int
    max_severity: str
    first_seen: datetime
    last_seen: datetime


@app.get("/v1/admin/flagged-ips", response_model=list[FlaggedIpOut])
def flagged_ips(
    min_severity: str = "high",
    min_event_count: int = 1,
    limit: int = 100,
    tenant: tuple = Depends(get_tenant),
) -> list[FlaggedIpOut]:
    """
    Advisory list of client IPs associated with high-severity risk
    events, for a human to review and decide on infrastructure-level
    action (WAF/firewall block) - this endpoint does not block
    anything itself, matching the rest of the system's
    advisory/human-in-the-loop design (see recommended_action on
    RiskEvent). Authenticated the same as the ingestion endpoint;
    there's no separate admin credential tier in this delivery, so
    treat any key with access to this endpoint as privileged.
    """
    flagged = audit_store.list_flagged_ips(
        min_severity=min_severity,
        min_event_count=min_event_count,
        limit=limit,
    )
    return [
        FlaggedIpOut(
            client_ip=f.client_ip,
            event_count=f.event_count,
            distinct_accounts=f.distinct_accounts,
            max_severity=f.max_severity,
            first_seen=f.first_seen,
            last_seen=f.last_seen,
        )
        for f in flagged
    ]


class DeviceClusterOut(BaseModel):
    cluster_key: str
    cluster_type: str
    account_ids: list[str]
    event_count: int
    max_severity: str
    first_seen: datetime
    last_seen: datetime


@app.get("/v1/admin/device-clusters", response_model=list[DeviceClusterOut])
def device_clusters(
    min_accounts: int = 3,
    limit: int = 100,
    tenant: tuple = Depends(get_tenant),
) -> list[DeviceClusterOut]:
    """
    Advisory list of device fingerprints or client IPs shared across
    multiple distinct accounts, for a human to review as a possible
    fraud-ring/mule-network lead - this endpoint does not link, flag,
    or block any account itself, matching the rest of the system's
    advisory/human-in-the-loop design (see recommended_action on
    RiskEvent, and list_flagged_ips above). Authenticated and
    rate-limited the same as the flagged-ips endpoint; there's no
    separate admin credential tier in this delivery, so treat any key
    with access to this endpoint as privileged.
    """
    clusters = audit_store.list_shared_device_ip_clusters(
        min_accounts=min_accounts,
        limit=limit,
    )
    return [
        DeviceClusterOut(
            cluster_key=c.cluster_key,
            cluster_type=c.cluster_type,
            account_ids=c.account_ids,
            event_count=c.event_count,
            max_severity=c.max_severity,
            first_seen=c.first_seen,
            last_seen=c.last_seen,
        )
        for c in clusters
    ]


class VerifyIn(BaseModel):
    challenge_id: str = Field(..., min_length=1, max_length=64)
    code: str = Field(..., min_length=1, max_length=32)
    account_id: str = Field(..., min_length=1, max_length=_MAX_ID_LENGTH)

    @field_validator("account_id")
    @classmethod
    def _account_id_must_be_safe(cls, v: str) -> str:
        v = v.strip()
        if not v or not _SAFE_ID_PATTERN.match(v):
            raise ValueError(
                "must contain only letters, numbers, and . _ : @ - "
                "(no whitespace or control characters)"
            )
        return v


class VerifyOut(BaseModel):
    result: str
    verified: bool


_VERIFY_RESULT_HTTP_STATUS = {
    VerifyResult.NOT_FOUND: 404,
    VerifyResult.EXPIRED: 410,
    VerifyResult.TOO_MANY_ATTEMPTS: 429,
    VerifyResult.ALREADY_RESOLVED: 409,
    # INCORRECT_CODE and VERIFIED both return 200 - an incorrect code is
    # a normal, expected outcome of this endpoint (the user mistyped
    # it), not a client error. The response body's "verified" field is
    # what callers should branch on, not the HTTP status.
}


@app.post("/v1/verify", response_model=VerifyOut)
def submit_verification(
    verify_in: VerifyIn,
    tenant: tuple = Depends(get_tenant),
) -> VerifyOut:
    """
    Submits a response code for a pending step-up verification
    challenge (see core/verification.py). Authenticated and rate
    limited the same as signal ingestion.

    On success, marks the account's state so detectors/calling apps
    can see this session already cleared step-up verification (see
    has_cleared_verification in core/verification.py) and avoid
    re-triggering a challenge on the very next high-severity signal.

    This endpoint only ever confirms or denies a code - like the rest
    of this system, it takes no autonomous action on the account
    itself. What the calling application does with a VERIFIED result
    (e.g. release a held transaction) is entirely its own decision.
    """
    tenant_id, _tenant_type, _key_id = tenant

    challenge = verification_store.get(verify_in.challenge_id)
    if challenge is not None and challenge.tenant_id != tenant_id:
        # Cross-tenant challenge_id guess - treat identically to "not
        # found" rather than leaking whether the ID exists for another
        # tenant.
        raise HTTPException(status_code=404, detail="Challenge not found")
    if challenge is not None and challenge.account_id != verify_in.account_id:
        raise HTTPException(status_code=404, detail="Challenge not found")

    account_state = engine.state_store.get(tenant_id, verify_in.account_id)
    result = verify_response(
        challenge_id=verify_in.challenge_id,
        submitted_code=verify_in.code,
        store=verification_store,
        account_state=account_state,
    )
    if result == VerifyResult.VERIFIED:
        engine.state_store.save(account_state)

    status_code = _VERIFY_RESULT_HTTP_STATUS.get(result)
    if status_code is not None:
        raise HTTPException(status_code=status_code, detail=result.value)

    return VerifyOut(result=result.value, verified=result == VerifyResult.VERIFIED)


@app.get("/health")
def health():
    return {"status": "ok", "detectors_registered": len(engine._detectors)}

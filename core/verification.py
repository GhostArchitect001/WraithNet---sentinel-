"""
Ghost Sentinel - Identity Verification Workflow
==================================================

Step 6 (final item on the "Next build steps" list): when a detector
produces a RiskEvent whose severity crosses a threshold (HIGH/CRITICAL),
this module lets the calling application request an out-of-band
confirmation challenge - a step-up verification code sent to the
account holder through some channel outside the (possibly compromised)
session, and a way to record whether they cleared it.

Honest status of "Ghost Identity"
----------------------------------
The README references tying this into "Ghost Identity" as an external
system. No spec for it exists or was made available for this delivery,
so it is treated as not-yet-built - same honesty standard as the
phishing detector's "no fake domain-reputation feed" decision: better
to ship a real, working local implementation than to fake an
integration with a system that doesn't exist yet.

What's built instead is the seam Ghost Identity would plug into later:
  - ChallengeDelivery is an abstract interface (send(challenge) -> bool),
    the same shape as core/detector_base.py's Detector interface.
  - ConsoleChallengeDelivery is a working local/mock implementation
    (logs the challenge instead of sending it through a real channel)
    so the whole workflow is testable today with zero external
    dependencies.
  - When Ghost Identity (or any real SMS/email/push provider) exists,
    it becomes a new class implementing ChallengeDelivery - the trigger
    logic, storage, and API endpoint below do not change. This is the
    exact same "enrichment field, not a rewrite" pattern as
    carrier_status in detectors/sim_ato.py and domain_reputation in
    detectors/phishing.py, just applied to an entire interface instead
    of a payload field.

Advisory, not autonomous - same principle as everywhere else in this
system
------------------------------------------------------------------------
This module REQUESTS a challenge and RECORDS whether it was cleared. It
does not freeze, block, or lock anything itself. request_challenge()
returns a VerificationChallenge and RiskEvent.recommended_action stays
the text description of what the calling application should do -
exactly like list_flagged_ips() surfaces candidates for a human to
review rather than blocking IPs itself. The calling application (bank,
fintech, consumer app) decides what "pending verification" means for
its own UX (e.g. hold a transaction, show a banner) - this module never
reaches into that decision.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional
import hashlib
import hmac
import secrets
import uuid

from core.models import AccountState, RiskEvent, Severity

# Severities that warrant requesting step-up verification. Matches the
# same HIGH/CRITICAL bar SimAtoDetector and PhishingDetector already use
# in their _recommend() methods when they suggest step-up auth or an
# out-of-band identity check - this module is what actually generates
# the challenge those recommendations describe, it does not invent a
# new threshold.
VERIFICATION_TRIGGER_SEVERITIES = {Severity.HIGH, Severity.CRITICAL}

# Codes are short by design (out-of-band OTP UX, not a cryptographic
# secret on their own) - the real protection is the short expiry window
# and the attempt cap below, the same defense-in-depth shape as a bank
# card PIN: a small keyspace is fine when attempts are bounded and
# short-lived.
_DEFAULT_CODE_LENGTH = 6
_DEFAULT_EXPIRY_SECONDS = 600  # 10 minutes - long enough for a real
                                # out-of-band channel (SMS/push) to
                                # arrive and be read, short enough that
                                # a stale code is useless to an attacker
                                # who intercepts it later.
_MAX_VERIFY_ATTEMPTS = 5        # bounds brute-force guessing of a
                                 # 6-digit code within the expiry window


class ChallengeMethod(str, Enum):
    """Out-of-band channel the challenge is delivered through. Mirrors
    SignalType's role in models.py: the single source of truth for what
    delivery channels this system knows about, so detectors/API/tests
    all reference the same values instead of loose strings."""
    SMS = "sms"
    EMAIL = "email"
    PUSH = "push"
    CONSOLE = "console"  # local/mock delivery only, see ConsoleChallengeDelivery


class ChallengeStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    EXPIRED = "expired"
    FAILED = "failed"   # attempt cap exhausted without a correct code


@dataclass
class VerificationChallenge:
    """One step-up verification attempt for one account. Analogous to
    RiskEvent: a scored/typed record of one thing the system did, kept
    around so calling code (and audit review later) can see what
    happened and why.

    The plaintext code is deliberately NOT stored on this dataclass
    once issued - only its salted hash lives in VerificationStore,
    same principle as ApiKeyStore never storing raw keys. What the
    caller/detector layer sees is this object with `code` populated
    only at creation time (to hand to a ChallengeDelivery), never on
    subsequent reads.
    """
    account_id: str
    tenant_id: str
    method: ChallengeMethod
    triggering_event_id: Optional[str]   # RiskEvent.event_id that caused this, if any
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(seconds=_DEFAULT_EXPIRY_SECONDS))
    status: ChallengeStatus = ChallengeStatus.PENDING
    attempt_count: int = 0
    challenge_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    code: Optional[str] = None  # only populated on the object returned at creation time

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at


def _generate_code(length: int = _DEFAULT_CODE_LENGTH) -> str:
    """Cryptographically random numeric code, not a predictable
    sequence - uses secrets, not random, for the same reason
    ApiKeyStore uses secrets.token_urlsafe for API keys."""
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def _hash_code(code: str, salt: str) -> str:
    return hashlib.sha256((salt + code).encode("utf-8")).hexdigest()


class ChallengeDelivery(ABC):
    """The seam Ghost Identity (or any real SMS/email/push provider)
    implements later. Same shape as core/detector_base.py's Detector:
    the calling code (request_challenge below) doesn't know or care
    which implementation it's talking to, it just calls .send().

    A real implementation is expected to actually get the code to the
    user through a channel the (possibly compromised) session doesn't
    control - e.g. SMS to a verified phone number, push to a registered
    device, email to a verified address. This module has no way to
    verify any given implementation actually does that; it only defines
    the contract.
    """

    @abstractmethod
    def send(self, challenge: VerificationChallenge) -> bool:
        """Attempt to deliver `challenge.code` to the account holder
        through this channel. Returns True if delivery was accepted/
        dispatched (not necessarily confirmed read - that's what the
        verify step is for), False if delivery could not be attempted
        or failed outright (e.g. no known contact address on file)."""
        raise NotImplementedError


class ConsoleChallengeDelivery(ChallengeDelivery):
    """Local/mock delivery for testing and development. Logs the
    challenge to an in-memory list (and optionally stdout) instead of
    sending it anywhere real. This is what makes the whole verification
    workflow testable today, standalone, with zero external
    dependencies - the same role InMemoryStateStore plays for account
    state before SqliteStateStore existed.

    NOT SAFE for anything touching a real account: any code that can
    read this process's memory (or its stdout, if logged) can read
    every code ever issued. Use only for local dev/tests, and swap for
    a real ChallengeDelivery implementation before this ever reaches
    production traffic."""

    def __init__(self, log_to_stdout: bool = False):
        self.log_to_stdout = log_to_stdout
        self.sent: list[VerificationChallenge] = []

    def send(self, challenge: VerificationChallenge) -> bool:
        self.sent.append(challenge)
        if self.log_to_stdout:
            print(
                f"[ConsoleChallengeDelivery] account={challenge.account_id} "
                f"tenant={challenge.tenant_id} method={challenge.method.value} "
                f"code={challenge.code} expires_at={challenge.expires_at.isoformat()}"
            )
        return True

    def last_code_for(self, account_id: str) -> Optional[str]:
        """Test/dev convenience: retrieve the most recent code sent to
        an account, the way a human tester would read it off their own
        phone. Not part of the ChallengeDelivery interface - a real
        delivery implementation has no equivalent method, because a
        real implementation should not let the calling application
        read codes back out of band."""
        for c in reversed(self.sent):
            if c.account_id == account_id:
                return c.code
        return None


class VerificationStore:
    """In-memory store for issued challenges, keyed by challenge_id.
    Holds the salted code hash, not the plaintext - verify_response()
    hashes the submitted code with the stored salt and compares in
    constant time, the same pattern ApiKeyStore uses for API keys.

    In-memory only, matching InMemoryStateStore's prototype status: a
    server restart loses pending challenges, which just means the user
    re-requests one - acceptable for a short-lived (10 minute default)
    object. If persistence across restarts becomes a requirement, this
    can move to a SQLite-backed store following the exact same
    get/save-shaped pattern as core/sqlite_store.py without changing
    any caller."""

    def __init__(self):
        self._by_id: dict[str, VerificationChallenge] = {}
        self._hashes: dict[str, tuple[str, str]] = {}  # challenge_id -> (code_hash, salt)
        # cleared[(tenant_id, account_id)] = datetime the account last
        # cleared step-up verification. Detectors/calling apps read this
        # via AccountState.detector_state (see mark_verified_in_state
        # below) - this dict is VerificationStore's own bookkeeping to
        # answer "when did this account last clear a challenge", kept
        # separately from the per-challenge records above since a
        # cleared challenge and "is this account currently in a cleared
        # window" are different questions.

    def save(self, challenge: VerificationChallenge, code: str, salt: str) -> None:
        self._by_id[challenge.challenge_id] = challenge
        self._hashes[challenge.challenge_id] = (_hash_code(code, salt), salt)

    def get(self, challenge_id: str) -> Optional[VerificationChallenge]:
        return self._by_id.get(challenge_id)

    def check_code(self, challenge_id: str, submitted_code: str) -> bool:
        entry = self._hashes.get(challenge_id)
        if entry is None:
            return False
        stored_hash, salt = entry
        candidate_hash = _hash_code(submitted_code, salt)
        return hmac.compare_digest(candidate_hash, stored_hash)


def request_challenge(
    account_id: str,
    tenant_id: str,
    delivery: ChallengeDelivery,
    store: VerificationStore,
    method: ChallengeMethod = ChallengeMethod.CONSOLE,
    triggering_event_id: Optional[str] = None,
) -> Optional[VerificationChallenge]:
    """Issues a new challenge, hands it to `delivery` to send, and
    stores it (hashed) for later verification. Returns the challenge
    (with `code` populated) if delivery reported success, or None if
    delivery failed - e.g. no verified contact channel on file for this
    account, which the calling application should treat as "could not
    step up this account" rather than silently proceeding.

    This function does not decide WHETHER to challenge - that's
    should_trigger_challenge() below, called from the engine hook. This
    function only handles the mechanics of issuing one once that
    decision has already been made. Advisory framing applies here too:
    a failed or ignored challenge does not, on its own, cause this
    module to do anything to the account. What the calling application
    does with "verification requested but not yet cleared" is its call.
    """
    code = _generate_code()
    salt = secrets.token_hex(16)
    challenge = VerificationChallenge(
        account_id=account_id,
        tenant_id=tenant_id,
        method=method,
        triggering_event_id=triggering_event_id,
        code=code,
    )

    delivered = delivery.send(challenge)
    if not delivered:
        return None

    store.save(challenge, code, salt)
    return challenge


class VerifyResult(str, Enum):
    VERIFIED = "verified"
    INCORRECT_CODE = "incorrect_code"
    EXPIRED = "expired"
    TOO_MANY_ATTEMPTS = "too_many_attempts"
    NOT_FOUND = "not_found"
    ALREADY_RESOLVED = "already_resolved"  # already verified/expired/failed previously


def verify_response(
    challenge_id: str,
    submitted_code: str,
    store: VerificationStore,
    account_state: Optional[AccountState] = None,
) -> VerifyResult:
    """Checks a submitted code against the stored challenge and updates
    its status accordingly. If `account_state` is supplied and the
    result is VERIFIED, also marks the account's detector_state so
    detectors/calling apps can see "this session already cleared
    step-up verification" (see mark_verified_in_state /
    has_cleared_verification below) without needing to separately query
    VerificationStore.

    Mirrors ApiKeyStore.verify_key()'s shape: look up, check state
    (expired?), check attempt budget, compare in constant time, return
    an outcome rather than raising - callers (the API layer) map the
    outcome to an HTTP status.
    """
    challenge = store.get(challenge_id)
    if challenge is None:
        return VerifyResult.NOT_FOUND

    if challenge.status != ChallengeStatus.PENDING:
        return VerifyResult.ALREADY_RESOLVED

    if challenge.is_expired:
        challenge.status = ChallengeStatus.EXPIRED
        return VerifyResult.EXPIRED

    if challenge.attempt_count >= _MAX_VERIFY_ATTEMPTS:
        challenge.status = ChallengeStatus.FAILED
        return VerifyResult.TOO_MANY_ATTEMPTS

    challenge.attempt_count += 1

    if store.check_code(challenge_id, submitted_code):
        challenge.status = ChallengeStatus.VERIFIED
        if account_state is not None:
            mark_verified_in_state(account_state, challenge)
        return VerifyResult.VERIFIED

    if challenge.attempt_count >= _MAX_VERIFY_ATTEMPTS:
        challenge.status = ChallengeStatus.FAILED
        return VerifyResult.TOO_MANY_ATTEMPTS

    return VerifyResult.INCORRECT_CODE


# --- AccountState integration ---
#
# Detectors read/write their own slice of AccountState.detector_state
# (see core/detector_base.py's docstring). This module follows the same
# pattern under the "verification" key, storing only what a detector or
# calling app needs to answer "has this account recently cleared
# step-up verification" - not the full challenge history, which lives
# in VerificationStore instead.

_STATE_KEY = "verification"

# How long a cleared verification "counts" before a fresh HIGH/CRITICAL
# event should trigger a new challenge rather than being waved through
# on an old one. Deliberately much shorter than a login session - this
# is step-up verification for a specific risk spike, not a
# general-purpose session token.
CLEARED_VERIFICATION_VALIDITY_SECONDS = 900  # 15 minutes


def mark_verified_in_state(state: AccountState, challenge: VerificationChallenge) -> None:
    """Records that `state`'s account cleared a challenge, so
    should_trigger_challenge() can avoid re-challenging on the very
    next high-severity signal if one was just cleared moments ago."""
    st = state.detector_state.setdefault(_STATE_KEY, {})
    st["last_verified_at"] = datetime.now(timezone.utc)
    st["last_verified_challenge_id"] = challenge.challenge_id


def has_cleared_verification(state: AccountState) -> bool:
    """True if this account cleared a step-up challenge recently enough
    (within CLEARED_VERIFICATION_VALIDITY_SECONDS) that a calling
    detector/app may reasonably treat the current session as already
    stepped-up, rather than triggering another challenge immediately."""
    st = state.detector_state.get(_STATE_KEY)
    if not st or "last_verified_at" not in st:
        return False
    last_verified_at = st["last_verified_at"]
    if last_verified_at.tzinfo is None:
        last_verified_at = last_verified_at.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - last_verified_at).total_seconds()
    return age <= CLEARED_VERIFICATION_VALIDITY_SECONDS


# --- Trigger logic: the engine-facing hook ---


def should_trigger_challenge(event: RiskEvent, state: AccountState) -> bool:
    """Advisory decision function: does this RiskEvent warrant
    requesting a step-up challenge? True if severity crosses the
    HIGH/CRITICAL bar AND the account hasn't already cleared one
    recently (see has_cleared_verification).

    This function only answers the question - it does not call
    request_challenge() itself and does not touch delivery or storage.
    That separation mirrors Detector.evaluate() returning a RiskEvent
    rather than acting on it: the decision and the action are different
    steps, so either can be tested/swapped independently, and so the
    calling application always stays the one that actually initiates
    the challenge (see maybe_request_challenge below for the
    convenience wrapper that does both, which callers can use or
    bypass entirely)."""
    if event.severity not in VERIFICATION_TRIGGER_SEVERITIES:
        return False
    return not has_cleared_verification(state)


def maybe_request_challenge(
    event: RiskEvent,
    state: AccountState,
    delivery: ChallengeDelivery,
    store: VerificationStore,
    method: ChallengeMethod = ChallengeMethod.CONSOLE,
) -> Optional[VerificationChallenge]:
    """Convenience wrapper combining should_trigger_challenge() and
    request_challenge() for the common case (e.g. a hook called
    alongside core/engine.py's DetectionEngine.process()). Returns None
    both when no challenge was warranted and when one was warranted but
    delivery failed - callers that need to distinguish those cases
    should call should_trigger_challenge()/request_challenge()
    separately instead.

    This is advisory infrastructure, not an autonomous control: calling
    this function only ever results in a challenge being ISSUED
    (sent to the user for them to respond to). It never freezes,
    blocks, or otherwise acts on the account - same principle as
    RiskEvent.recommended_action and list_flagged_ips() elsewhere in
    this system. What the calling application does while a challenge is
    pending (e.g. hold a transaction in its own UX) is entirely up to
    that application."""
    if not should_trigger_challenge(event, state):
        return None
    return request_challenge(
        account_id=event.account_id,
        tenant_id=event.tenant_id,
        delivery=delivery,
        store=store,
        method=method,
        triggering_event_id=event.event_id,
    )

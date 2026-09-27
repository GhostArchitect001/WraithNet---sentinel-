"""
Ghost Sentinel - In-Session Pressure / Coercion Detector
===========================================================

Asks a different question than mule_transfer.py. That detector reasons
about *transaction shape* (pass-through, new-beneficiary velocity,
churn) with no awareness of what happened around the transaction in
the same session. This detector reasons about *session context*: was
this transaction preceded, in the same account's recent timeline, by
something that looks like an in-progress social-engineering attempt -
a support-impersonation message, an active call, or an interaction
rhythm consistent with someone being talked through a screen in real
time by an unseen third party.

The two are complementary, not overlapping. A transaction can trip
mule_transfer.py with zero social-engineering context (a mule who
signed up knowingly, no coercion involved). A transaction can also
happen inside an active coercion session while looking completely
ordinary in isolation (normal beneficiary, normal amount, normal
timing) - it's the *lead-up* that's the tell, not the transaction
shape itself. Running both gives coverage neither gets alone.

What this detector checks, in order of how much external support it
needs:

  1. Support-impersonation-style MESSAGE_RECEIVED shortly before a
     transaction on the same account. Reuses the exact same urgency/
     pressure-language matching phishing.py already does on message
     text - deliberately not reinvented here, imported directly, so
     the two detectors agree on what "pressure language" means rather
     than drifting into two slightly different definitions. This
     check needs nothing beyond what phishing.py already needs: no
     external feed, just the message text on the signal.

  2. on_active_call enrichment (optional). If the client app can tell
     us the account was on an active voice call when the transaction
     was initiated, that is scored heavily - a legitimate bank/app
     interaction rarely coincides with the customer being on a live
     call with someone else while executing a transfer, and this is
     exactly the "unknown caller walks the victim through the app in
     real time" pattern behind a large share of real-world
     authorized-push-payment scam calls. Ghost Sentinel has no way to
     detect an active call itself - this is the same enrichment-socket
     pattern as carrier_status in sim_ato.py: an optional payload
     field the calling application supplies if it has that
     visibility (e.g. it can see the OS is reporting an in-progress
     call), scored opportunistically when present, contributing
     nothing when absent. We do not attempt to infer "on a call" from
     any other signal - that would be exactly the kind of fabricated
     confidence phishing.py's domain-reputation section already
     explains why this project avoids.

  3. Idle-then-burst session timing (optional, needs client-supplied
     session telemetry). If the calling app can supply session
     activity timestamps in the TRANSACTION payload's
     "session_events" field (a list of ISO timestamps for taps/screens
     visited earlier in the same session), a long idle period
     immediately followed by a fast burst of screens leading straight
     to a transaction is consistent with someone who was not actively
     using the app, then was contacted and rapidly walked through a
     flow - as opposed to a user who was already browsing normally
     and gradually arrived at a transfer. Like on_active_call, this
     contributes nothing if the client doesn't supply session
     telemetry; we do not simulate or infer it.

This detector is advisory-only, same as every other module in this
system - it scores and explains, it never blocks a transaction or a
call itself.
"""

from datetime import datetime
from typing import Optional

from core.detector_base import Detector
from core.models import Signal, SignalType, RiskEvent, AccountState, Severity
from detectors.phishing import _count_urgency_matches


class SocialEngineeringSessionDetector(Detector):
    """
    Heuristic in-session pressure/coercion detector. See module
    docstring for exactly what's feasible from message text and
    transaction timing alone versus what needs client-supplied
    enrichment (on_active_call, session_events) - and what's not
    faked here (this project does not infer call state or session
    activity on its own).
    """

    name = "social_engineering_session"

    # --- Tunables. Same "start conservative" stance as mule_transfer.py -
    # these are reasonable starting points, not values validated against
    # real coercion-call losses at this project's current stage. ---

    # Check 1: support-impersonation message shortly before a transaction
    PRESSURE_MESSAGE_WINDOW_SECONDS = 1800   # 30 minutes

    # Check 3: idle-then-burst session timing
    IDLE_THRESHOLD_SECONDS = 1200            # 20+ minutes of prior inactivity counts as "idle"
    BURST_MAX_SECONDS = 120                  # then a burst of screens within 2 minutes counts as rushed
    BURST_MIN_EVENTS = 3                     # need at least this many screens in the burst to call it a burst

    def relevant_signal_types(self) -> list:
        return [SignalType.MESSAGE_RECEIVED, SignalType.TRANSACTION]

    def evaluate(self, signal: Signal, state: AccountState) -> Optional[RiskEvent]:
        st = state.detector_state.setdefault(self.name, {
            "recent_pressure_messages": [],  # list of (timestamp, matched_phrase)
        })

        if signal.signal_type == SignalType.MESSAGE_RECEIVED:
            self._record_pressure_message(signal, st)
            # A pressure-style message alone isn't the risk event - the
            # risk shows up when a transaction follows it, same
            # "record now, score on the later related signal" shape as
            # mule_transfer.py's inflow handling.
            return None

        if signal.signal_type != SignalType.TRANSACTION:
            return None

        reasons: list[str] = []
        score = 0.0

        # --- Check 1: support-impersonation message shortly before this transaction ---
        self._prune_old(st["recent_pressure_messages"], signal.timestamp, self.PRESSURE_MESSAGE_WINDOW_SECONDS)
        if st["recent_pressure_messages"]:
            _, phrase = st["recent_pressure_messages"][-1]
            score += 0.5
            reasons.append(
                f"Transaction initiated within {self.PRESSURE_MESSAGE_WINDOW_SECONDS // 60} minutes "
                f"of a message containing urgency/pressure language on this account "
                f"(e.g. '{phrase}') - consistent with a support-impersonation or "
                f"social-engineering lead-up to this transfer."
            )

        # --- Check 2: on_active_call enrichment (optional) ---
        if signal.payload.get("on_active_call") is True:
            score += 0.5
            reasons.append(
                "Account was reported to be on an active voice call when this transaction "
                "was initiated - a pattern strongly associated with real-time coercion, "
                "where an unseen caller walks the account holder through the transfer."
            )

        # --- Check 3: idle-then-burst session timing (optional) ---
        burst_reason = self._check_idle_then_burst(signal.payload.get("session_events"))
        if burst_reason:
            score += 0.3
            reasons.append(burst_reason)

        if score <= 0.0:
            return None

        severity = self._score_to_severity(score)
        return RiskEvent(
            account_id=signal.account_id,
            tenant_id=signal.tenant_id,
            detector_name=self.name,
            risk_score=min(score, 1.0),
            severity=severity,
            reasons=reasons,
            triggered_signals=[signal.signal_id],
            recommended_action=self._recommend(severity),
        )

    def _record_pressure_message(self, signal: Signal, st: dict) -> None:
        """Expected payload fields: text (str, optional) - the message
        body. Reuses phishing.py's urgency-pattern matcher directly
        rather than redefining a second notion of "pressure language" -
        see module docstring."""
        text = signal.payload.get("text", "")
        urgency_hits = _count_urgency_matches(text)
        if urgency_hits:
            st["recent_pressure_messages"].append((signal.timestamp, urgency_hits[0]))

    def _check_idle_then_burst(self, session_events: Optional[list]) -> Optional[str]:
        """session_events: optional list of ISO-8601 timestamp strings
        (or datetime objects) for prior activity in the same session,
        oldest first, ending just before this transaction. Flags a
        long idle gap immediately followed by a fast burst of screens
        leading straight into the transfer. Returns a reason string if
        the pattern is present, else None. Gracefully no-ops if the
        field is absent or malformed - we do not simulate this data,
        only reason about it when a client actually supplies it."""
        if not session_events or len(session_events) < self.BURST_MIN_EVENTS + 1:
            return None

        parsed: list[datetime] = []
        for e in session_events:
            if isinstance(e, datetime):
                parsed.append(e)
            elif isinstance(e, str):
                try:
                    parsed.append(datetime.fromisoformat(e))
                except ValueError:
                    return None  # malformed telemetry - don't guess, just skip the check
            else:
                return None
        parsed.sort()

        # Find the largest idle gap between consecutive events.
        gaps = [(parsed[i + 1] - parsed[i]).total_seconds() for i in range(len(parsed) - 1)]
        if not gaps:
            return None
        max_gap = max(gaps)
        gap_index = gaps.index(max_gap)

        if max_gap < self.IDLE_THRESHOLD_SECONDS:
            return None

        # Everything after the idle gap must be a tight burst.
        burst_events = parsed[gap_index + 1:]
        if len(burst_events) < self.BURST_MIN_EVENTS:
            return None
        burst_span = (burst_events[-1] - burst_events[0]).total_seconds()
        if burst_span > self.BURST_MAX_SECONDS:
            return None

        return (
            f"Session shows {int(max_gap // 60)} minutes of inactivity immediately followed by "
            f"{len(burst_events)} screens/actions within {int(burst_span)} seconds leading into "
            f"this transaction - a rushed pattern consistent with a user being actively walked "
            f"through the app rather than browsing at their own pace."
        )

    @staticmethod
    def _prune_old(entries: list[tuple[datetime, object]], now: datetime, window_seconds: int) -> None:
        """Same shape as mule_transfer.py's _prune_old - drops entries
        older than `window_seconds` relative to `now`, in place."""
        entries[:] = [e for e in entries if 0 <= (now - e[0]).total_seconds() <= window_seconds]

    @staticmethod
    def _score_to_severity(score: float) -> Severity:
        if score >= 0.8:
            return Severity.CRITICAL
        if score >= 0.55:
            return Severity.HIGH
        if score >= 0.3:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _recommend(severity: Severity) -> str:
        if severity == Severity.CRITICAL:
            return (
                "Interrupt the transaction flow with an in-app coercion/scam warning and "
                "require the account holder to confirm, away from any call, that they "
                "initiated this transfer themselves."
            )
        if severity == Severity.HIGH:
            return "Display an in-app scam-call warning and require explicit re-confirmation before this transfer proceeds."
        return "Log and monitor; consider a passive in-app notice about common phone-scam tactics."

"""
Ghost Sentinel - Behavioral Anomaly Detector
==============================================

Domain-agnostic statistical anomaly detection. Same core approach as
energy_mesh_v2's core/anomaly_detection.py (margin clustering, never-then-
suddenly signals, implausible-recovery checks) - just re-pointed at
account behavior instead of wattage.

This detector is deliberately generic: it doesn't know what "SIM swap"
or "phishing" means. It just tracks each account's normal rhythm
(login times, transaction sizes, device set) and flags statistically
surprising deviations. Both the SIM/ATO detector and B2B fraud clients
can feed off this same module - that's the point of the shared core.

Three checks, mirroring your existing pattern:
  1. Never-then-suddenly: an action type never seen for this account,
     appearing for the first time alongside other risk signals.
  2. Magnitude clustering: transaction/login values far outside the
     account's own historical distribution (z-score based).
  3. Implausible recovery: rapid alternation between failure and
     success states (e.g. many failed OTPs then immediate success)
     that's inconsistent with normal human retry behavior.
"""

from datetime import datetime
from statistics import mean, pstdev
from typing import Optional

from core.detector_base import Detector
from core.models import Signal, SignalType, RiskEvent, AccountState, Severity


class BehavioralAnomalyDetector(Detector):

    name = "behavioral_anomaly"

    # Tunables - start conservative, tighten once you have real data volume
    Z_SCORE_THRESHOLD = 2.5
    MIN_HISTORY_FOR_STATS = 5
    RAPID_RETRY_WINDOW_SECONDS = 120
    RAPID_RETRY_FAILURE_COUNT = 3

    def relevant_signal_types(self) -> list:
        return [
            SignalType.LOGIN_ATTEMPT,
            SignalType.OTP_REQUEST,
            SignalType.OTP_VERIFIED,
            SignalType.TRANSACTION,
            SignalType.DEVICE_CHANGE,
        ]

    def evaluate(self, signal: Signal, state: AccountState) -> Optional[RiskEvent]:
        st = state.detector_state.setdefault(self.name, {
            "transaction_amounts": [],
            "known_devices": [],
            "otp_failures": [],   # list of timestamps
            "seen_signal_types": [],
        })

        reasons: list[str] = []
        score = 0.0

        # --- Check 1: never-then-suddenly device ---
        if signal.signal_type == SignalType.DEVICE_CHANGE:
            device = signal.payload.get("device_id")
            if device and st["known_devices"] and device not in st["known_devices"]:
                score += 0.3
                reasons.append("Transaction/login from a device never seen on this account before.")
            if device and device not in st["known_devices"]:
                st["known_devices"].append(device)

        # --- Check 2: magnitude clustering on transactions ---
        if signal.signal_type == SignalType.TRANSACTION:
            amount = signal.payload.get("amount")
            history = st["transaction_amounts"]
            if amount is not None:
                if len(history) >= self.MIN_HISTORY_FOR_STATS:
                    mu = mean(history)
                    sigma = pstdev(history) or 1.0
                    z = abs(amount - mu) / sigma
                    if z > self.Z_SCORE_THRESHOLD:
                        score += min(0.5, 0.1 * z)
                        magnitude_desc = "far above" if amount > mu else "far below"
                        reasons.append(
                            f"Transaction amount is {magnitude_desc} this account's usual range "
                            f"(typical: ~{mu:,.0f}, this transaction: {amount:,.0f})."
                        )
                history.append(amount)
                if len(history) > 200:
                    history.pop(0)  # bounded rolling window

        # --- Check 3: implausible recovery (rapid OTP failure->success) ---
        if signal.signal_type == SignalType.OTP_REQUEST and signal.payload.get("result") == "failure":
            st["otp_failures"].append(signal.timestamp)
        if signal.signal_type == SignalType.OTP_VERIFIED:
            recent_failures = [
                t for t in st["otp_failures"]
                if (signal.timestamp - t).total_seconds() <= self.RAPID_RETRY_WINDOW_SECONDS
            ]
            if len(recent_failures) >= self.RAPID_RETRY_FAILURE_COUNT:
                score += 0.4
                reasons.append(
                    f"{len(recent_failures)} failed OTP attempts immediately followed by success - "
                    f"pattern consistent with brute-force or intercepted-code attacks rather than "
                    f"normal user retry behavior."
                )
            st["otp_failures"] = []  # reset window after a verified event

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

    @staticmethod
    def _score_to_severity(score: float) -> Severity:
        if score >= 0.8:
            return Severity.CRITICAL
        if score >= 0.6:
            return Severity.HIGH
        if score >= 0.35:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _recommend(severity: Severity) -> str:
        if severity in (Severity.HIGH, Severity.CRITICAL):
            return "Trigger out-of-band verification before allowing further action."
        return "Log and monitor; no user-facing interruption required yet."

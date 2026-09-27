"""
Ghost Sentinel - SIM / Account Takeover Detector
===================================================

Generalized account takeover detection. Not tied to any single country's
telecom infrastructure. The signal loss, device mismatch, and OTP
interception patterns behind SIM swap fraud show up worldwide;
this detector reasons about the pattern, not the local carrier system.

Where a market has a regulator-backed number status service, such as
Nigeria's TIRMS, that becomes an optional enrichment signal fed in via
the payload's "carrier_status" field. If it is absent, the detector
falls back to behavior-only reasoning. Nothing here assumes any specific
external system is available, so this same code runs unmodified in
markets with or without such infrastructure.

Checks:
  1. Signal-loss-then-recovery window: SIM/signal dropped, then quickly
     followed by high-risk activity (login, OTP request, transaction)
     from a device the account has never used before.
  2. Device-binding mismatch: a transaction or login occurs from a device
     inconsistent with the account's registered/bound device, especially
     shortly after a SIM status change.
  3. Geographic implausibility: two account activities occur close in
     time but far apart in distance, which is not physically possible
     for a single legitimate user.
  4. Carrier status enrichment (optional): if the client supplies a
     carrier-reported SIM status (e.g. "recently_swapped", "reassigned",
     "flagged"), this is weighted heavily since it is a direct signal
     rather than an inference.
"""

from datetime import datetime
from math import radians, sin, cos, sqrt, atan2
from typing import Optional

from core.detector_base import Detector
from core.models import Signal, SignalType, RiskEvent, AccountState, Severity


# Physically implausible speed threshold. Commercial flight is roughly
# 900 km/h; we use a generous 1000 km/h ceiling so we only flag things
# that could not be explained by any normal means of travel.
MAX_PLAUSIBLE_SPEED_KMH = 1000.0

HIGH_RISK_SIGNAL_TYPES = {
    SignalType.LOGIN_ATTEMPT,
    SignalType.OTP_REQUEST,
    SignalType.TRANSACTION,
}


def _haversine_km(p1: tuple[float, float], p2: tuple[float, float]) -> float:
    """Great-circle distance between two (lat, lon) points in kilometers."""
    lat1, lon1 = radians(p1[0]), radians(p1[1])
    lat2, lon2 = radians(p2[0]), radians(p2[1])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    earth_radius_km = 6371.0
    return earth_radius_km * c


class SimAtoDetector(Detector):

    name = "sim_ato"

    SIGNAL_LOSS_RISK_WINDOW_SECONDS = 3600  # 1 hour
    CARRIER_STATUS_RISK = {
        "recently_swapped": 0.7,
        "reassigned": 0.5,
        "flagged": 0.8,
        "inactive": 0.4,
    }

    def relevant_signal_types(self) -> list:
        return [
            SignalType.SIM_STATUS_CHANGE,
            SignalType.LOGIN_ATTEMPT,
            SignalType.OTP_REQUEST,
            SignalType.TRANSACTION,
            SignalType.DEVICE_CHANGE,
        ]

    def evaluate(self, signal: Signal, state: AccountState) -> Optional[RiskEvent]:
        st = state.detector_state.setdefault(self.name, {
            "last_sim_event_time": None,
            "bound_device": None,
            "last_activity_time": None,
            "last_activity_geo": None,
        })

        reasons: list[str] = []
        score = 0.0

        # --- Check 4: carrier status enrichment (used opportunistically) ---
        if signal.signal_type == SignalType.SIM_STATUS_CHANGE:
            status = signal.payload.get("carrier_status")
            st["last_sim_event_time"] = signal.timestamp
            if status in self.CARRIER_STATUS_RISK:
                score += self.CARRIER_STATUS_RISK[status]
                reasons.append(
                    f"Carrier-reported SIM status is '{status}', a direct indicator "
                    f"of recent number reassignment or flagged risk."
                )

        # --- Check 1: signal-loss-then-high-risk-activity window ---
        if signal.signal_type in HIGH_RISK_SIGNAL_TYPES and st["last_sim_event_time"] is not None:
            elapsed = (signal.timestamp - st["last_sim_event_time"]).total_seconds()
            if 0 <= elapsed <= self.SIGNAL_LOSS_RISK_WINDOW_SECONDS:
                score += 0.4
                reasons.append(
                    f"Sensitive activity occurred within {int(elapsed // 60)} minutes of a "
                    f"SIM/number status change - a hallmark of SIM-swap account takeover."
                )

        # --- Check 2: device-binding mismatch ---
        if signal.signal_type in HIGH_RISK_SIGNAL_TYPES:
            device = signal.device_id
            bound = st["bound_device"]
            if bound is not None and device is not None and device != bound:
                score += 0.3
                reasons.append(
                    "Activity originates from a device that does not match this "
                    "account's previously bound device."
                )
        if signal.signal_type == SignalType.DEVICE_CHANGE:
            new_device = signal.payload.get("device_id") or signal.device_id
            if new_device:
                st["bound_device"] = new_device

        # --- Check 3: geographic implausibility ---
        if signal.geo is not None:
            last_geo = st["last_activity_geo"]
            last_time = st["last_activity_time"]
            if last_geo is not None and last_time is not None:
                elapsed_hours = max((signal.timestamp - last_time).total_seconds() / 3600.0, 1e-6)
                distance_km = _haversine_km(last_geo, signal.geo)
                implied_speed = distance_km / elapsed_hours
                if implied_speed > MAX_PLAUSIBLE_SPEED_KMH:
                    score += 0.5
                    reasons.append(
                        f"Two account activities occurred {distance_km:.0f} km apart within "
                        f"{elapsed_hours:.2f} hours, which is not physically possible for a "
                        f"single legitimate user (implied speed {implied_speed:.0f} km/h)."
                    )
            st["last_activity_geo"] = signal.geo
            st["last_activity_time"] = signal.timestamp

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
        if score >= 0.55:
            return Severity.HIGH
        if score >= 0.3:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _recommend(severity: Severity) -> str:
        if severity == Severity.CRITICAL:
            return "Freeze sensitive actions immediately and require out-of-band identity verification."
        if severity == Severity.HIGH:
            return "Require step-up authentication before allowing this action to proceed."
        return "Log and monitor; consider a passive notification to the account holder."

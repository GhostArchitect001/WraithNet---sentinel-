"""
Ghost Sentinel - Money-Mule / Scam-Victim Transfer Pattern Detector
=====================================================================

Reasons about SignalType.TRANSACTION only, but asks a different
question than the other detectors already covering that signal type.
BehavioralAnomalyDetector asks "is this transaction statistically
surprising for this account." SimAtoDetector asks "does this look like
someone other than the account owner is acting." This detector asks a
third, distinct question: "is this account's own owner being used as a
conduit or manipulated into moving funds out - as a knowing or
unwitting money mule, or as a pig-butchering/romance-scam victim
authorizing their own transfer."

That distinction matters because none of the existing detectors catch
this case. SIM/ATO and behavioral anomaly are built around the
attacker acting as (or impersonating) the account owner. Money-mule and
scam-victim transfers are usually authorized by the real, legitimate
account owner, from their own device, in their normal geography -
every signal the other two detectors look at can be completely clean.
Real losses concentrate here: authorized push payment fraud and
pig-butchering-style scams routinely clear every identity/device check
because the *identity* was never compromised - it's the *decision*
that was manipulated. See the industry pattern this mirrors: mule
accounts behave normally by design, so detection needs a different
signal than "does this look like account takeover."

What this detector checks, all derivable from TRANSACTION signals and
account history alone - no external mule-registry, no cross-institution
data sharing, no device/network graph correlation (that's a distinct,
larger piece of infrastructure, out of scope here, see README):

  1. Inflow-then-rapid-outflow ("pass-through"): a large inflow
     followed by one or more outflows that drain most of the account's
     recent balance within a short window. This is the core mule
     pattern - funds arrive and leave fast, with the account acting as
     a conduit rather than a destination.
  2. New-beneficiary + high-value + velocity: a transfer to a
     beneficiary this account has never paid before, at a value that's
     large relative to the account's own history, especially when
     paired with other first-time-beneficiary transfers in a short
     window. One new beneficiary is normal life (a new landlord, a
     one-off purchase). Several new beneficiaries paid out in a tight
     window is not.
  3. Beneficiary churn: a high rate of distinct new beneficiaries added
     and paid in a short period - consistent with either mule
     layering (moving funds through several different downstream
     accounts to obscure the trail) or a scam victim being walked
     through paying several "fees," "taxes," or "verification"
     transfers.
  4. Round-trip timing tightness: the time between an inflow and the
     matching outflow is short enough that no real deliberation could
     plausibly have happened - a legitimate large inflow (salary,
     property sale, inheritance) is not usually spent down to near-zero
     within minutes to a first-time beneficiary.

What this detector deliberately does NOT do: it does not query any
mule-registry, consortium data-sharing feed, or cross-institution
signal-sharing platform. Real production mule-detection systems
increasingly rely on exactly that (pre-transaction intelligence about
the destination account, gathered before funds ever move, since
transaction-history analysis alone is often too late once the mule
account already has the money) - but this project has no partnership
or feed providing that, and faking one would repeat the exact mistake
already avoided in detectors/phishing.py's domain-reputation decision.
If a real mule-intelligence feed is integrated later, the natural seam
is a new optional payload field on the TRANSACTION signal (e.g.
"beneficiary_risk_score") - enrichment, not a rewrite, same pattern as
carrier_status in sim_ato.py.

This detector is also advisory-only, same as every other module in
this system: it scores and explains, it recommends a review or hold to
the calling application, it never freezes or blocks a transfer itself.
"""

from datetime import datetime
from typing import Optional

from core.detector_base import Detector
from core.models import Signal, SignalType, RiskEvent, AccountState, Severity


class MuleTransferDetector(Detector):
    """
    Heuristic mule/scam-victim transfer pattern detector. See module
    docstring for exactly what's feasible from transaction history
    alone versus what would need a real mule-intelligence feed (and
    isn't faked here).
    """

    name = "mule_transfer"

    # --- Tunables. Start conservative, per README's "confidence
    # calibration needs real labeled data" note - these are reasonable
    # starting points, not values validated against real mule/scam
    # losses at this project's current stage. ---

    # Check 1: inflow-then-rapid-outflow
    PASS_THROUGH_WINDOW_SECONDS = 3600         # 1 hour
    PASS_THROUGH_OUTFLOW_FRACTION = 0.8         # outflow >= 80% of the recent inflow

    # Check 2: new-beneficiary + high-value + velocity
    NEW_BENEFICIARY_VALUE_MULTIPLE = 3.0        # transfer >= 3x the account's average outflow
    MIN_HISTORY_FOR_AVERAGE = 3                 # need at least this many prior outflows to have a baseline

    # Check 3: beneficiary churn
    CHURN_WINDOW_SECONDS = 86400                # 24 hours
    CHURN_NEW_BENEFICIARY_COUNT = 3             # 3+ distinct new beneficiaries paid within the window

    # Check 4: round-trip timing tightness
    ROUND_TRIP_MAX_SECONDS = 900                # 15 minutes - too fast for real deliberation on a
                                                  # large, unfamiliar-destination transfer

    def relevant_signal_types(self) -> list:
        return [SignalType.TRANSACTION]

    def evaluate(self, signal: Signal, state: AccountState) -> Optional[RiskEvent]:
        st = state.detector_state.setdefault(self.name, {
            "recent_inflows": [],       # list of (timestamp, amount)
            "outflow_amounts": [],      # bounded rolling window, for the account's own average
            "known_beneficiaries": [],  # beneficiary_ids ever paid before
            "recent_new_beneficiary_payouts": [],  # list of (timestamp, beneficiary_id) within churn window
        })

        direction = signal.payload.get("direction")  # "in" or "out", both optional-safe
        amount = signal.payload.get("amount")
        beneficiary_id = signal.payload.get("beneficiary_id")

        if amount is None:
            return None  # nothing to reason about without a transaction amount

        reasons: list[str] = []
        score = 0.0

        if direction == "in":
            st["recent_inflows"].append((signal.timestamp, amount))
            self._prune_old(st["recent_inflows"], signal.timestamp, self.PASS_THROUGH_WINDOW_SECONDS)
            # An inflow alone is not risky - the risk shows up on the
            # matching outflow (Check 1), so no scoring happens here.
            return None

        if direction != "out":
            return None  # payload didn't specify a direction we can reason about

        # --- Check 1: inflow-then-rapid-outflow ("pass-through") ---
        self._prune_old(st["recent_inflows"], signal.timestamp, self.PASS_THROUGH_WINDOW_SECONDS)
        recent_inflow_total = sum(a for _, a in st["recent_inflows"])
        if recent_inflow_total > 0 and amount >= self.PASS_THROUGH_OUTFLOW_FRACTION * recent_inflow_total:
            score += 0.5
            reasons.append(
                f"Outflow of {amount:,.0f} closely matches a recent inflow total of "
                f"{recent_inflow_total:,.0f} within the last "
                f"{self.PASS_THROUGH_WINDOW_SECONDS // 60} minutes - a pass-through pattern "
                f"consistent with the account being used as a conduit rather than a destination."
            )
            # Check 4 only makes sense in the context of a pass-through -
            # find the earliest still-relevant inflow to measure round-trip tightness.
            if st["recent_inflows"]:
                earliest_inflow_time = min(t for t, _ in st["recent_inflows"])
                round_trip_seconds = (signal.timestamp - earliest_inflow_time).total_seconds()
                if 0 <= round_trip_seconds <= self.ROUND_TRIP_MAX_SECONDS:
                    score += 0.3
                    reasons.append(
                        f"Funds moved back out within {int(round_trip_seconds // 60)} minutes of "
                        f"arriving - too fast for the deliberation a legitimate large transfer "
                        f"decision would normally involve."
                    )

        # --- Check 2: new-beneficiary + high-value + velocity ---
        is_new_beneficiary = (
            beneficiary_id is not None and beneficiary_id not in st["known_beneficiaries"]
        )
        if is_new_beneficiary:
            history = st["outflow_amounts"]
            if len(history) >= self.MIN_HISTORY_FOR_AVERAGE:
                avg = sum(history) / len(history)
                if avg > 0 and amount >= self.NEW_BENEFICIARY_VALUE_MULTIPLE * avg:
                    score += 0.4
                    reasons.append(
                        f"Transfer of {amount:,.0f} to a beneficiary never paid before is "
                        f"{amount / avg:.1f}x this account's average outflow ({avg:,.0f}) - "
                        f"large, unfamiliar-destination transfers are a common early signal in "
                        f"both mule and scam-victim activity."
                    )

        # --- Check 3: beneficiary churn ---
        if is_new_beneficiary:
            st["recent_new_beneficiary_payouts"].append((signal.timestamp, beneficiary_id))
        self._prune_old(st["recent_new_beneficiary_payouts"], signal.timestamp, self.CHURN_WINDOW_SECONDS)
        distinct_recent_new = {b for _, b in st["recent_new_beneficiary_payouts"]}
        if len(distinct_recent_new) >= self.CHURN_NEW_BENEFICIARY_COUNT:
            score += 0.4
            reasons.append(
                f"{len(distinct_recent_new)} distinct new beneficiaries paid within the last "
                f"{self.CHURN_WINDOW_SECONDS // 3600} hours - a churn pattern consistent with "
                f"either mule layering or a scam victim being walked through multiple "
                f"successive transfers."
            )

        # --- Update rolling state ---
        if beneficiary_id is not None and beneficiary_id not in st["known_beneficiaries"]:
            st["known_beneficiaries"].append(beneficiary_id)
        st["outflow_amounts"].append(amount)
        if len(st["outflow_amounts"]) > 200:
            st["outflow_amounts"].pop(0)  # bounded rolling window, same cap as behavioral_anomaly.py

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
    def _prune_old(entries: list[tuple[datetime, object]], now: datetime, window_seconds: int) -> None:
        """Drops entries older than `window_seconds` relative to `now`,
        in place. Small helper shared by the inflow and beneficiary-churn
        rolling windows above - both need the same "keep only what's
        still relevant" trimming, just against different clocks/keys."""
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
                "Hold this transfer for manual review before it settles and require "
                "out-of-band confirmation from the account holder that they authorized it "
                "and understand the destination."
            )
        if severity == Severity.HIGH:
            return "Flag for manual review and require step-up confirmation before this transfer proceeds."
        return "Log and monitor; consider a passive in-app confirmation prompt."

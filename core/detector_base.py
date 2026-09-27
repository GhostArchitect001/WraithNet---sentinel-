"""
Ghost Sentinel - Detector Base Interface
==========================================

Every scam-detection module (SIM/ATO, phishing, behavioral anomaly,
identity verification) implements this same interface. This is the
seam that lets the Detection Core stay one engine: the gateway doesn't
know or care which detector it's calling, it just calls `.evaluate()`.

Adding a new scam type later = write a new class implementing this
interface + register it. Nothing else in the system changes.
"""

from abc import ABC, abstractmethod
from typing import Optional

from core.models import Signal, RiskEvent, AccountState


class Detector(ABC):
    """Base class for all detection modules."""

    name: str = "base_detector"

    @abstractmethod
    def relevant_signal_types(self) -> list:
        """Which SignalTypes this detector wants to see. The gateway uses
        this to route signals without every detector inspecting every event."""
        raise NotImplementedError

    @abstractmethod
    def evaluate(
        self, signal: Signal, state: AccountState
    ) -> Optional[RiskEvent]:
        """
        Process one incoming signal against the account's rolling state.
        Return a RiskEvent if this signal (combined with history) crosses
        a risk threshold, otherwise return None.

        Detectors should be side-effect-light: they read/update their own
        slice of `state.detector_state` and return a verdict. They should
        NOT reach out to other detectors or the network directly - that
        keeps them independently testable, which matters a lot once you
        have 4+ of these running against live traffic.
        """
        raise NotImplementedError

    def explain(self, event: RiskEvent) -> str:
        """Human-readable explanation for consumer app / B2B webhook.
        Override for custom phrasing; default just joins reasons."""
        return " ".join(event.reasons)

"""
Ghost Sentinel - Detection Engine
====================================

This is the "one brain" both the consumer app and the B2B API talk to.
It owns account state and routes each incoming Signal to whichever
registered detectors care about that signal type.

Swap `InMemoryStateStore` for a real DB-backed store when moving past
prototype - the interface is intentionally tiny so that's a drop-in change.
"""

from typing import Optional

from core.detector_base import Detector
from core.models import Signal, RiskEvent, AccountState


class InMemoryStateStore:
    """Prototype-only state store. Replace with Postgres/SQLite-backed
    version before anything touches real user data - this does not persist
    across restarts and is not safe for concurrent multi-process use."""

    def __init__(self):
        self._states: dict[str, AccountState] = {}

    def get(self, tenant_id: str, account_id: str) -> AccountState:
        key = f"{tenant_id}:{account_id}"
        if key not in self._states:
            self._states[key] = AccountState(account_id=account_id, tenant_id=tenant_id)
        return self._states[key]

    def save(self, state: AccountState) -> None:
        key = f"{state.tenant_id}:{state.account_id}"
        self._states[key] = state


class DetectionEngine:
    """Registers detectors and routes signals to the ones that care."""

    def __init__(self, state_store: Optional[InMemoryStateStore] = None):
        self._detectors: list[Detector] = []
        self._routing: dict[str, list[Detector]] = {}
        self.state_store = state_store or InMemoryStateStore()

    def register(self, detector: Detector) -> None:
        self._detectors.append(detector)
        for signal_type in detector.relevant_signal_types():
            self._routing.setdefault(signal_type.value, []).append(detector)

    def process(self, signal: Signal) -> list[RiskEvent]:
        """Run one signal through every detector that cares about it.
        A single signal can legitimately trigger multiple detectors
        (e.g. a device change might matter to both behavioral anomaly
        and SIM/ATO) - we return all resulting events, not just the first."""
        state = self.state_store.get(signal.tenant_id, signal.account_id)
        events: list[RiskEvent] = []

        for detector in self._routing.get(signal.signal_type.value, []):
            event = detector.evaluate(signal, state)
            if event is not None:
                events.append(event)

        self.state_store.save(state)
        return events

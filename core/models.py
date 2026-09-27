"""
Ghost Sentinel - Core Data Models
==================================

These are the shared contracts every detector, adapter, and API route
speaks. Keeping this single and small is what lets us have ONE scoring
engine behind TWO faces (consumer app + B2B API) instead of duplicating
logic per client type.

Design note: a "Signal" is a raw observation (a login, an OTP request,
an SMS received). A "RiskEvent" is what a Detector produces after
evaluating one or more Signals. RiskEvents feed the Alerting layer.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import uuid


class TenantType(str, Enum):
    """Who owns this account in our system - mirrors the estate/org/tenant
    pattern from energy_mesh_v2. A CONSUMER tenant is a single person's
    phone. A B2B tenant is a bank/fintech sending us their customers' events."""
    CONSUMER = "consumer"
    B2B = "b2b"


class SignalType(str, Enum):
    """Every kind of raw event the system can ingest. Add new types here
    as new detectors need new inputs - keep this the single source of truth."""
    SIM_STATUS_CHANGE = "sim_status_change"       # signal lost/regained, carrier-reported swap
    LOGIN_ATTEMPT = "login_attempt"
    OTP_REQUEST = "otp_request"
    OTP_VERIFIED = "otp_verified"
    DEVICE_CHANGE = "device_change"
    TRANSACTION = "transaction"
    MESSAGE_RECEIVED = "message_received"         # SMS/WhatsApp text, for phishing detector
    URL_CLICKED = "url_clicked"
    QR_SCANNED = "qr_scanned"
    VOICE_AUTH_ATTEMPT = "voice_auth_attempt"      # voice-channel auth/verification attempt.
                                                     # Optional "deepfake_confidence" payload
                                                     # field, populated by an external voice-auth/
                                                     # deepfake-detection service if the deploying
                                                     # org has one - Ghost Sentinel does not attempt
                                                     # deepfake detection itself. Same honesty stance
                                                     # as phishing.py's "no fake domain-reputation
                                                     # feed" decision. See detectors/
                                                     # social_engineering_session.py for the detector
                                                     # that consumes this.


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Signal:
    """A single raw observation ingested from a client or B2B feed."""
    signal_type: SignalType
    tenant_id: str
    account_id: str                       # the end-user/customer this signal is about
    timestamp: datetime
    payload: dict[str, Any] = field(default_factory=dict)
    signal_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    device_id: Optional[str] = None
    geo: Optional[tuple[float, float]] = None  # (lat, lon) - coarse only, matches
                                                 # your existing privacy-preserving pin pattern


@dataclass
class RiskEvent:
    """Output of a detector: a scored, explained verdict on one account's
    recent behavior. This is what gets shown in the consumer app and sent
    as a webhook to B2B clients - same object, two renderers."""
    account_id: str
    tenant_id: str
    detector_name: str
    risk_score: float              # 0.0 - 1.0
    severity: Severity
    reasons: list[str]             # human-readable explanations, NOT raw feature dumps
    triggered_signals: list[str]   # signal_ids that caused this event
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    recommended_action: Optional[str] = None


@dataclass
class AccountState:
    """Rolling state we keep per account so detectors don't need to
    re-scan full history on every signal. Each detector reads/writes
    its own slice of `detector_state`."""
    account_id: str
    tenant_id: str
    last_seen_device: Optional[str] = None
    last_seen_geo: Optional[tuple[float, float]] = None
    sim_status: Optional[str] = None
    detector_state: dict[str, Any] = field(default_factory=dict)
    updated_at: datetime = field(default_factory=datetime.utcnow)

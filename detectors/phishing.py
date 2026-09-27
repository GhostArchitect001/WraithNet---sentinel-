"""
Ghost Sentinel - Phishing / Suspicious-Link Detector
=======================================================

Reasons about SignalType.MESSAGE_RECEIVED, URL_CLICKED, and QR_SCANNED -
the three signal types that existed as reserved enum values with no
detector behind them until now.

What this detector honestly can and can't do
-----------------------------------------------
A *real* domain-reputation check ("is this domain known-bad") needs a
real external data source: a threat-intel feed, a Safe Browsing-style
API, a blocklist subscription, something with actual ground truth
that gets updated as new phishing infrastructure comes online. This
project has no such feed wired up, and fabricating one - a hardcoded
"bad domains" list dressed up to look like live threat intel - would
be worse than having nothing, because it would create false
confidence in a signal that's actually just a handful of stale
examples. So: no domain-reputation check here. If you later integrate
a real feed (Google Safe Browsing, a commercial threat-intel API,
your own abuse-report pipeline), that becomes a new enrichment field
on the payload (domain_reputation=...) the same way carrier_status
enriches SimAtoDetector - this detector is written so that's a
straightforward add later, not a rewrite.

What IS feasible without any external feed is *structural* and
*linguistic* heuristics - things you can determine from the
URL/message text alone, no lookup required:
  1. URL-shortener usage: shortened links (bit.ly, tinyurl, etc.) hide
     the real destination, which is exactly the property phishing
     campaigns rely on. Flagging shortener usage isn't proof of
     phishing - plenty of legitimate messages use them - but it's a
     real structural signal that combines with others.
  2. Lookalike-domain detection: domains that visually or
     structurally resemble a small set of commonly-impersonated brand
     names via character substitution, extra subdomains, or added
     words (e.g. "paypa1.com", "secure-paypal-verify.com",
     "paypal.com.login-alert.ru"). This is pattern-matching against a
     short, clearly-labeled list of well-known, heavily-impersonated
     brands - not a claim of comprehensive brand coverage.
  3. Urgency / social-engineering language: phishing messages
     disproportionately use urgency, threat, and action-now framing
     ("your account will be suspended", "verify immediately",
     "unusual activity detected", "act now or lose access"). Legit
     transactional messages use some of this language too, so this is
     scored as one input among several, not a standalone trigger.
  4. Mismatched display-vs-actual link text: when a message claims to
     link to one domain in its visible text but the actual href points
     somewhere else (e.g. text says "paypal.com" but the real link
     goes to a different domain) - a classic phishing trick, and one
     that's fully verifiable from the message content alone.
  5. QR code destination checks: QR_SCANNED signals carry a decoded
     URL like any other link, so the same shortener/lookalike/mismatch
     checks apply. QR phishing ("quishing") is otherwise identical to
     link phishing once the code is decoded - the only special case is
     that the "display text" a user saw (the physical sticker/poster)
     is often unverifiable, so we can't run the mismatch check on QR
     signals unless the payload also supplies what the code claimed
     to be.

None of these checks alone are proof of phishing - they're the same
"reason about the pattern, explain the reasons" approach as the other
two detectors, combined into a score.
"""

import re
from typing import Optional
from urllib.parse import urlparse

from core.detector_base import Detector
from core.models import Signal, SignalType, RiskEvent, AccountState, Severity


# Known URL-shortener domains. Not exhaustive - new shorteners appear
# regularly - but covers the large majority of shortener traffic seen
# in practice. A shortener not on this list simply won't get this
# particular signal; it can still get caught by the other checks.
_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "s.id", "v.gd",
}

# A short, explicitly-labeled list of heavily-impersonated brand names
# for lookalike-domain matching. This is NOT a claim of comprehensive
# brand coverage - it's the common targets seen across phishing
# campaigns globally (banks, payment processors, major platforms).
# Extend as needed; the detection logic doesn't change shape as this
# list grows.
_COMMONLY_IMPERSONATED_BRANDS = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "chase", "wellsfargo",
    "bankofamerica", "citibank", "hsbc", "dhl", "fedex", "usps",
    "irs", "coinbase", "binance",
}

# Character substitutions phishing domains commonly use to visually
# mimic a brand name while being a technically different string
# (leetspeak-style homoglyphs reachable on a standard keyboard - true
# Unicode homoglyph detection would need IDN-aware normalization,
# which is a reasonable future enhancement but out of scope here).
_LOOKALIKE_SUBSTITUTIONS = {
    "0": ["o"], "1": ["l", "i"], "3": ["e"], "5": ["s"], "4": ["a"], "7": ["t"],
}

# Phrases/patterns associated with urgency and social-engineering
# pressure tactics. Grouped loosely by tactic for readability; scored
# as a set, not individually, since real phishing messages usually
# stack several of these together.
_URGENCY_PATTERNS = [
    r"\bact now\b", r"\bact immediately\b", r"\bimmediate action\b",
    r"\burgent\b", r"\bexpires? (today|soon|in \d+ (hour|minute))s?\b",
    r"\baccount (will be|has been) (suspended|locked|closed|terminated)\b",
    r"\bverify (your|now|immediately)\b",
    r"\bconfirm your (identity|account|password|details)\b",
    r"\bunusual activity\b", r"\bsuspicious (activity|login|sign-?in)\b",
    r"\byour account (is|has been) (compromised|limited|restricted)\b",
    r"\bclick (here|below|this link) (now|immediately)?\b",
    r"\byou('ve| have) won\b", r"\bclaim your\b",
    r"\bfailure to (respond|verify|act)\b",
    r"\blast (chance|warning)\b",
]
_URGENCY_RE = [re.compile(p, re.IGNORECASE) for p in _URGENCY_PATTERNS]


def _extract_registrable_domain(url_or_domain: str) -> Optional[str]:
    """Best-effort extraction of a bare domain from a URL or raw
    domain string. Deliberately simple (no public-suffix-list lookup)
    since this project has no external dependency for that - good
    enough to compare "paypal.com" vs "paypa1.com", not a substitute
    for a real PSL-aware parser if that precision is ever needed."""
    if not url_or_domain:
        return None
    candidate = url_or_domain.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        netloc = urlparse(candidate).netloc
    except ValueError:
        return None
    if not netloc:
        return None
    # Strip userinfo and port if present.
    netloc = netloc.split("@")[-1].split(":")[0]
    return netloc.lower() or None


def _is_shortener(domain: str) -> bool:
    return domain in _SHORTENER_DOMAINS


def _normalize_candidates_for_lookalike(label: str) -> set[str]:
    """Generates every plausible de-leetspeaked reading of `label` by
    substituting each digit with each of its candidate letters (e.g.
    '1' -> 'l' or 'i'). Returns a set of candidate strings so callers
    can check "does any reading of this label match a brand name" -
    a single fixed substitution per digit would miss brands where the
    intended letter differs (paypa1 -> paypal needs '1'->'l', but a
    domain like 'faceb00k' needs '0'->'o' twice, and some domains use
    '1' for 'i' instead)."""
    candidates = {label}
    for digit, letters in _LOOKALIKE_SUBSTITUTIONS.items():
        if digit not in label:
            continue
        next_candidates = set()
        for candidate in candidates:
            for letter in letters:
                next_candidates.add(candidate.replace(digit, letter))
        candidates |= next_candidates
    return candidates


def _lookalike_brand(domain: str) -> Optional[str]:
    """Returns the brand name a domain appears to be impersonating, or
    None. Flags:
      - exact brand name present as a substring but NOT as the actual
        registrable domain (e.g. "paypal.com.login-alert.ru" or
        "secure-paypal-verify.com" contain "paypal" but the real
        domain is login-alert.ru / secure-paypal-verify.com, neither
        of which is paypal.com).
      - leetspeak/character-substitution near-matches to a brand name
        as the core label (e.g. "paypa1.com" normalizes to
        "paypal.com" but isn't it).
    Does NOT flag the brand's own real domain (paypal.com itself)."""
    if not domain:
        return None

    labels = domain.split(".")
    # The registrable "core" label is usually the second-to-last part
    # for a standard domain.tld shape; good enough without a PSL.
    core_label = labels[-2] if len(labels) >= 2 else labels[0]

    for brand in _COMMONLY_IMPERSONATED_BRANDS:
        exact_domain_forms = {f"{brand}.com", brand}
        if domain in exact_domain_forms or core_label == brand:
            continue  # this IS the brand's own domain - not a lookalike

        # Case A: brand name appears somewhere in the domain string,
        # but the domain isn't actually the brand's own domain -
        # e.g. extra subdomains/words smuggling the brand name in.
        if brand in domain:
            return brand

        # Case B: leetspeak/substitution near-match on the core label.
        if core_label != brand and brand in _normalize_candidates_for_lookalike(core_label):
            return brand

    return None


def _count_urgency_matches(text: str) -> list[str]:
    if not text:
        return []
    matches = []
    for pattern in _URGENCY_RE:
        m = pattern.search(text)
        if m:
            matches.append(m.group(0).lower())
    return matches


class PhishingDetector(Detector):
    """
    Heuristic phishing/social-engineering detector. See module
    docstring for exactly what's feasible without an external
    threat-intel feed versus what would need one (and isn't faked
    here).
    """

    name = "phishing"

    def relevant_signal_types(self) -> list:
        return [
            SignalType.MESSAGE_RECEIVED,
            SignalType.URL_CLICKED,
            SignalType.QR_SCANNED,
        ]

    def evaluate(self, signal: Signal, state: AccountState) -> Optional[RiskEvent]:
        reasons: list[str] = []
        score = 0.0

        if signal.signal_type == SignalType.MESSAGE_RECEIVED:
            score, reasons = self._evaluate_message(signal.payload)
        elif signal.signal_type == SignalType.URL_CLICKED:
            score, reasons = self._evaluate_url_click(signal.payload)
        elif signal.signal_type == SignalType.QR_SCANNED:
            score, reasons = self._evaluate_qr_scan(signal.payload)

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

    # --- Per-signal-type evaluation ---

    def _evaluate_message(self, payload: dict) -> tuple[float, list[str]]:
        """Expected payload fields (all optional, checks skip gracefully
        if absent): text (str) - the message body; url (str) - a link
        included in the message, if any; display_text (str) - the
        visible link text shown to the user, if it differs from the
        actual url (e.g. HTML email where the anchor text says one
        thing and href points elsewhere)."""
        score = 0.0
        reasons: list[str] = []

        text = payload.get("text", "")
        urgency_hits = _count_urgency_matches(text)
        if urgency_hits:
            # More stacked urgency phrases = more confidence this is
            # engineered pressure rather than one incidental phrase.
            bump = min(0.4, 0.15 * len(urgency_hits))
            score += bump
            reasons.append(
                f"Message text uses urgency/social-engineering language "
                f"({len(urgency_hits)} pattern(s) matched, e.g. "
                f"'{urgency_hits[0]}') - a common phishing pressure tactic."
            )

        url = payload.get("url")
        if url:
            url_score, url_reasons = self._evaluate_link(
                url, display_text=payload.get("display_text")
            )
            score += url_score
            reasons.extend(url_reasons)

        return score, reasons

    def _evaluate_url_click(self, payload: dict) -> tuple[float, list[str]]:
        """Expected payload fields: url (str, required for any check),
        display_text (str, optional) - what the user was shown before
        clicking, if the calling app can supply it (e.g. link text in
        an email/SMS client vs. the actual target)."""
        url = payload.get("url")
        if not url:
            return 0.0, []
        return self._evaluate_link(url, display_text=payload.get("display_text"))

    def _evaluate_qr_scan(self, payload: dict) -> tuple[float, list[str]]:
        """Expected payload fields: url (str, required) - the decoded
        destination; claimed_text (str, optional) - what the physical
        code/poster/sticker claimed to point to, if the scanning app
        captured that (e.g. OCR'd caption next to the code). Most QR
        codes in the wild carry no independently-verifiable display
        text, so the mismatch check only runs when claimed_text is
        actually supplied - we don't assume its absence means anything."""
        url = payload.get("url")
        if not url:
            return 0.0, []
        score, reasons = self._evaluate_link(url, display_text=payload.get("claimed_text"))
        if score > 0.0:
            reasons = [r.replace("message", "QR code") for r in reasons]
        return score, reasons

    def _evaluate_link(self, url: str, display_text: Optional[str]) -> tuple[float, list[str]]:
        score = 0.0
        reasons: list[str] = []

        actual_domain = _extract_registrable_domain(url)
        if actual_domain is None:
            return 0.0, []

        if _is_shortener(actual_domain):
            score += 0.2
            reasons.append(
                f"Link uses a URL-shortening service ({actual_domain}), which "
                f"hides the real destination until clicked - commonly used to "
                f"disguise phishing links, though also used legitimately."
            )

        lookalike = _lookalike_brand(actual_domain)
        if lookalike:
            score += 0.5
            reasons.append(
                f"Domain '{actual_domain}' resembles a lookalike for "
                f"'{lookalike}' without being that brand's actual domain - "
                f"a common phishing/brand-impersonation technique."
            )

        if display_text:
            displayed_domain = _extract_registrable_domain(display_text)
            if displayed_domain and displayed_domain != actual_domain:
                score += 0.4
                reasons.append(
                    f"Displayed link text suggests destination "
                    f"'{displayed_domain}' but the actual link goes to "
                    f"'{actual_domain}' - a classic mismatched-link phishing "
                    f"technique."
                )

        return score, reasons

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
                "Warn the user before allowing further interaction with this "
                "link/message and recommend they do not enter credentials."
            )
        if severity == Severity.HIGH:
            return "Display an in-app phishing warning and require explicit user confirmation to proceed."
        return "Log and monitor; consider a passive in-app notice."

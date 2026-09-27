# Ghost Sentinel

Scam and fraud detection engine. Part of WraithNet. Serves both a
consumer app and a B2B API off one shared detection core, built for
global deployment rather than any single country.

## Scope of this project

This is civilian and commercial fraud/scam detection software: account
takeover, SIM swap patterns, phishing, and transaction anomaly detection,
aimed at protecting individual users, banks, telecoms, and fintechs.

This is not military or offensive security software, and the design
intentionally stays out of that territory. What follows is the
legitimate, buildable version of "serious, global-grade security
software": real authentication, real persistence, real testing, and
an architecture that scales to any market, not just one country.

## What is built so far

### Step 1: Detection Core

- core/models.py - shared data contracts (Signal, RiskEvent, AccountState)
- core/detector_base.py - interface every detector implements
- core/engine.py - routes signals to registered detectors
- detectors/behavioral_anomaly.py - statistical baseline-deviation detector
  (transaction outliers, rapid OTP failure-then-success, new-device flags)

### Step 2: SIM / Account Takeover Detector

- detectors/sim_ato.py - generalized account takeover detection:
  - signal-loss-then-high-risk-activity timing window
  - device-binding mismatch
  - geographic implausibility (haversine distance / implied travel speed)
  - optional carrier-status enrichment for markets with a regulator-backed
    number status service (see the TIRMS note below)

This detector makes no assumption about any single country's telecom
infrastructure. It reasons about the underlying behavior pattern, so the
same code runs unmodified whether or not a market has something like
Nigeria's TIRMS available.

### Step 5: Phishing / Suspicious-Link Detector, and IP capture/flagging

These were built as net-new feature work, not part of the earlier
hardening list - the plumbing for both had to be built from scratch.

- detectors/phishing.py - PhishingDetector, handling the three signal
  types that existed as reserved SignalType enum values with no
  detector behind them (MESSAGE_RECEIVED, URL_CLICKED, QR_SCANNED).
  Registered in api/main.py (previously commented out).

  What it checks, all feasible without any external threat-intel feed:
    - URL-shortener usage (bit.ly, tinyurl, etc. - hides the real
      destination, a mild standalone signal)
    - Lookalike-domain detection against a short, explicitly-labeled
      list of commonly-impersonated brands (paypal, apple, banks,
      etc.), catching both leetspeak substitution ("paypa1.com") and
      brand names smuggled into an unrelated domain
      ("paypal.com.login-alert.ru") - while correctly NOT flagging
      the brand's own real domain
    - Urgency / social-engineering language patterns in message text
      ("verify immediately", "account will be suspended", etc.)
    - Mismatched display-vs-actual link text (message/QR claims one
      destination, the real link goes somewhere else)

  What it deliberately does NOT do: real domain-reputation checking.
  That needs a live external data source (a threat-intel feed, a Safe
  Browsing-style API) - this project doesn't have one wired up, and a
  hardcoded "known-bad domains" list dressed up as reputation data
  would create false confidence rather than real protection. If you
  add a real feed later, it plugs in as a `domain_reputation` payload
  enrichment field the same way `carrier_status` enriches SimAtoDetector
  - no rewrite needed.

- core/audit_log.py - added client_ip capture: every audit row now
  optionally records the requester's IP address alongside tenant_id
  and api_key_id in the "who queried" fields. Existing audit
  databases migrate automatically (ALTER TABLE ADD COLUMN, same
  pattern as api_keys.py's expiry migration) - no manual migration
  step. Also added `list_flagged_ips(min_severity=..., min_event_count=...)`:
  a read-only aggregate over the audit log surfacing which IPs have
  been associated with high-severity risk events, how many times, and
  across how many distinct accounts - a candidate list for a human to
  review and decide whether to block at the WAF/infrastructure level.
  This follows the same advisory, human-in-the-loop principle as
  `recommended_action` elsewhere in the system: it recommends, it does
  not block anything itself, and no code path in this module ever will.
- api/main.py - captures client IP at the FastAPI layer via
  `get_client_ip()`, honestly handling the fact that X-Forwarded-For /
  X-Real-IP are entirely client-suppliable and therefore spoofable
  unless the deployment explicitly says otherwise. By default
  (GHOST_SENTINEL_TRUSTED_PROXY_COUNT unset or 0), only
  `request.client.host` - the actual TCP peer - is trusted. Only when
  an operator sets GHOST_SENTINEL_TRUSTED_PROXY_COUNT to the number of
  trusted proxy hops in front of the service does the gateway read the
  real client IP out of X-Forwarded-For/X-Real-IP. Behind an
  unconfigured proxy this means every request records the proxy's own
  IP, which is a known, honest limitation rather than a silent
  correctness bug - the alternative (trusting an unverified header by
  default) would let anyone spoof the IP that ends up feeding
  list_flagged_ips() and, downstream, a human's block decision. New
  endpoint GET /v1/admin/flagged-ips exposes list_flagged_ips() over
  the API, authenticated the same way as signal ingestion (no separate
  admin credential tier exists yet in this delivery).

### Institutional hardening (this delivery)

- core/api_keys.py - real API key management: keys are generated with
  secrets.token_urlsafe, stored only as salted SHA-256 hashes (never
  plaintext), verified with constant-time comparison, and individually
  revocable. Keys now also carry an expiry (90 days by default,
  configurable per key, or none for long-lived service credentials
  used sparingly) - an expired key stops working the same as a revoked
  one, even without anyone acting on it. rotate_key() issues a
  replacement and revokes the old key in one call. list_keys() and
  list_expiring_keys() give a lightweight admin view of what exists
  and what needs rotating soon; scripts/list_expiring_keys.py wraps
  the latter as a script you can run by hand or from cron (nonzero
  exit code when something needs attention, for easy alerting). This
  replaces the placeholder dictionary from the earlier prototype.
- core/sqlite_store.py - persistent account state storage. Account
  history now survives a server restart, which the original in-memory
  store did not support. Interface is two methods (get/save), so this
  can be swapped for Postgres later without touching any detector code.
- core/audit_log.py - append-only structured audit log. Every risk
  decision the engine produces gets one immutable row: who queried
  (tenant_id + a non-reversible key_id derived from the API key hash),
  what signal triggered it (with sensitive payload fields redacted),
  what score/severity/reasons the detector produced, and what action
  was recommended. Queryable by tenant, account, event_id, time range,
  or severity floor - built for compliance review and dispute
  resolution ("what did the system see and decide on this date?").
  Kept in its own SQLite file (data/ghost_sentinel_audit.db) since
  audit retention/access policy will likely differ from operational
  state.
- api/main.py - gateway now uses real auth and persistent state, adds
  per-tenant sliding-window rate limiting (Redis-backed in production),
  logs a structured audit record for every risk decision, enforces a
  256 KB request body ceiling before any JSON parsing happens, and
  validates every SignalIn field before it reaches a detector:
  account_id/device_id are bounded in length and restricted to a safe
  character set (blocks injection-style or control-character IDs from
  ever reaching SQL keys or log lines), payload is capped at 8 KB of
  encoded JSON, geo must be real finite lat/lon coordinates (not
  sentinel floats that would silently corrupt the SIM/ATO detector's
  haversine distance math), and timestamp must fall within a plausible
  window (small future clock skew tolerated, far-future or
  implausibly-old values rejected). Both detectors are registered.
- scripts/create_key.py - command-line tool to provision new API keys
  for tenants without hand-writing Python each time. Supports
  --ttl-days and --no-expiry to control key lifetime at creation.
- scripts/list_expiring_keys.py - lightweight rotation reminder: lists
  keys that are expired or expiring soon, runnable by hand or from
  cron. Exits nonzero when something needs attention.

### Step 6: Identity Verification Workflow

- core/verification.py - out-of-band step-up verification, triggered
  advisorily when a detector's RiskEvent crosses the HIGH/CRITICAL
  severity bar:
  - `VerificationChallenge` - a scored/typed record of one challenge,
    analogous to RiskEvent: challenge_id, account_id, tenant_id,
    method, expiry, status (pending/verified/expired/failed),
    attempt_count. The plaintext code only lives on the object
    returned at issuance time - only its salted hash is stored, same
    principle as core/api_keys.py never storing raw API keys.
  - `ChallengeDelivery` - an abstract interface (`send(challenge) ->
    bool`), the same shape as core/detector_base.py's `Detector`. This
    is the seam Ghost Identity is meant to implement later.
  - `ConsoleChallengeDelivery` - a working local/mock implementation
    (in-memory, optional stdout logging) so the whole workflow is
    testable today with zero external dependencies. **Not safe for
    real accounts** - see the module docstring for why.
  - `should_trigger_challenge()` / `maybe_request_challenge()` - the
    trigger logic. Advisory only, matching `recommended_action` and
    `list_flagged_ips()` elsewhere in this system: it requests a
    challenge for the calling application to present, it does not
    freeze, block, or lock anything itself, and no code path in this
    module ever will.
  - `verify_response()` - checks a submitted code (constant-time
    comparison, bounded attempts, expiry-checked) and, on success,
    writes into `AccountState.detector_state["verification"]` so
    detectors/calling apps can see "this account already cleared
    step-up verification recently" and avoid re-triggering on the very
    next high-severity signal (15-minute validity window, distinct
    from a login session).
- api/main.py - wires this into signal ingestion: after `POST
  /v1/signals` produces risk events, any that cross the HIGH/CRITICAL
  bar (and haven't recently been cleared) get a challenge requested
  automatically via the registered `ChallengeDelivery`, surfaced back
  to the caller as `verification_challenge_id` /
  `verification_method` on the response. New endpoint `POST /v1/verify`
  lets a client submit a challenge response, authenticated and rate
  limited the same as signal ingestion; returns 200 with
  `verified: true/false` for a normal wrong-code/right-code outcome,
  and the appropriate 404/409/410/429 for not-found/already-resolved/
  expired/attempt-cap-exhausted.

**Honest status of "Ghost Identity":** no spec for Ghost Identity
existed or was made available for this delivery, so it is genuinely
not built. What's built is the pluggable interface it would implement
(`ChallengeDelivery`) plus a real, working local/mock implementation
(`ConsoleChallengeDelivery`) so the workflow is fully testable today.
This is the same honesty standard as the phishing detector's decision
not to fake a domain-reputation feed: a real local implementation you
can actually test beats a fake integration with a system that doesn't
exist. When Ghost Identity (or any real SMS/email/push provider) is
ready, it becomes one new class implementing `ChallengeDelivery`,
registered in api/main.py in place of `ConsoleChallengeDelivery` - no
change needed to the trigger logic, storage, verification logic, or
API endpoints.

Also genuinely mocked/limited in this delivery:
- `VerificationStore` is in-memory only (like the original
  `InMemoryStateStore` before `SqliteStateStore` existed) - a server
  restart loses pending challenges, which just means the user
  re-requests one. If persistence across restarts becomes a
  requirement, it can move to SQLite behind the same interface,
  following the same pattern as `core/sqlite_store.py`.
- Codes are short (6 digits) by OTP-UX design, not a cryptographic
  secret on their own - protection comes from the 10-minute expiry and
  5-attempt cap, not code length. This is a standard OTP threat model,
  not a shortcut specific to this project.

### Step 7: Money-Mule / Scam-Victim Transfer Pattern Detector

Net-new feature work, not part of the original hardening list - added
after reviewing 2026 fraud-industry reporting on where real losses
concentrate. Authorised push payment fraud, money-mule networks, and
pig-butchering/romance-investment scams routinely clear every
identity/device check the existing detectors run, because the account
owner's identity was never compromised - the *decision* to send money
was manipulated instead. SimAtoDetector and BehavioralAnomalyDetector
are both built around "does this look like someone other than the
account owner." This detector asks a distinct third question: "is this
account's own legitimate owner being used as a conduit, or being
walked through paying out funds."

- detectors/mule_transfer.py - MuleTransferDetector, registered in
  api/main.py. Reasons about SignalType.TRANSACTION only (no new
  signal type needed), using two new optional payload fields
  (`direction`: "in"/"out", `beneficiary_id`) alongside the existing
  `amount` field. Checks:
    - Inflow-then-rapid-outflow ("pass-through"): a large inflow
      followed by an outflow draining most of it within an hour - the
      account acting as a conduit rather than a destination.
    - New-beneficiary + high-value + velocity: a transfer to a
      never-before-paid beneficiary at a value far above the account's
      own historical average.
    - Beneficiary churn: several distinct new beneficiaries paid out
      within a 24-hour window - consistent with mule layering or a
      scam victim being walked through successive "fee"/"tax"/
      "verification" transfers.
    - Round-trip timing tightness: funds arriving and leaving within
      15 minutes, too fast for real deliberation on an unfamiliar,
      high-value destination - this stacks with and escalates the
      pass-through check rather than standing alone.

  What this deliberately does NOT do: query any mule-registry,
  cross-institution signal-sharing consortium, or device/network graph
  correlating accounts across a fraud ring. Production mule-detection
  increasingly depends on exactly that kind of pre-transaction
  intelligence about the destination account (gathered before funds
  ever move, since transaction-history analysis alone is often too
  late once a mule account already has the money) - but this project
  has no such feed or partnership, and faking one would repeat the
  same mistake already avoided in detectors/phishing.py's
  domain-reputation decision. If a real mule-intelligence feed is
  integrated later, it plugs in as a new `beneficiary_risk_score`
  payload enrichment field the same way `carrier_status` enriches
  SimAtoDetector - no rewrite needed.

  Also out of scope for the same honesty reasons: real-time voice
  deepfake / synthetic-voice detection for phone-based social
  engineering (the "grandparent scam" pattern). That needs an audio ML
  model this project has no access to. The correct-scope move, if this
  becomes a priority, is a new `SignalType.VOICE_AUTH_ATTEMPT` with an
  optional `deepfake_confidence` enrichment field populated by an
  external voice-auth service - a socket, not a fake detector - which
  has not been built yet either.

  Advisory only, same principle as everywhere else in this system:
  scores and explains, recommends a hold/review via
  `recommended_action`, never freezes or blocks a transfer itself.

### Step 8: In-Session Pressure/Coercion Detector, and `VOICE_AUTH_ATTEMPT` signal type

Also net-new, picked up from the "Planned next" list in the previous
delivery. Complements MuleTransferDetector rather than overlapping it:
that detector reasons about transaction *shape* with no session
context; this one reasons about what happened *around* the transaction
in the same account's recent timeline - a lead-up that can make an
otherwise ordinary-looking transfer suspicious, or that can co-occur
with a mule_transfer.py trigger and stack additional confidence onto it.

- `core/models.py` - added `SignalType.VOICE_AUTH_ATTEMPT`, a reserved
  signal type for voice-channel auth/verification attempts, with an
  optional `deepfake_confidence` payload field. Same honesty stance as
  everything else in this project: Ghost Sentinel does not attempt
  deepfake/voice-clone detection itself (no audio ML model available
  here) - this is a socket for an external voice-auth/deepfake service
  to populate if the deploying org has one, mirroring how
  `carrier_status` enriches SimAtoDetector. No detector consumes this
  field yet; it's reserved so the seam exists when a real deepfake
  signal becomes available, rather than bolting on a new signal type
  and a fake detector at the same time.
- `detectors/social_engineering_session.py` -
  SocialEngineeringSessionDetector, registered in api/main.py. Reasons
  about `SignalType.MESSAGE_RECEIVED` and `SignalType.TRANSACTION`.
  Checks:
    - Support-impersonation-style message shortly (within 30 minutes)
      before a transaction on the same account. Reuses phishing.py's
      existing urgency/pressure-language matcher directly rather than
      redefining a second notion of "pressure language" - the two
      detectors agree on what counts.
    - `on_active_call` enrichment (optional): if the client app can
      report the account was on an active voice call when the
      transaction was initiated, scored heavily on its own - the
      real-time "unseen caller walks the victim through the app"
      pattern behind a large share of authorized-push-payment scam
      calls. Same enrichment-socket pattern as `carrier_status`:
      contributes nothing when the client doesn't supply it, and this
      project does not attempt to infer call state any other way.
    - Idle-then-burst session timing (optional, needs client-supplied
      `session_events` timestamps in the TRANSACTION payload): a long
      idle gap immediately followed by a fast burst of screens leading
      into the transaction, consistent with a user being actively
      walked through a flow rather than browsing at their own pace.
      Contributes nothing if the client doesn't supply session
      telemetry - this project does not simulate or infer it.

  What this deliberately does NOT do: detect deepfakes or synthetic
  voices itself, or infer "on a call" / session activity from any
  signal other than what the client explicitly supplies. Both are
  documented sockets (`VOICE_AUTH_ATTEMPT.deepfake_confidence`,
  `on_active_call`, `session_events`), not fabricated detection.

  Advisory only, same principle as everywhere else in this system:
  scores and explains, recommends re-confirmation or a warning via
  `recommended_action`, never interrupts a call or blocks a transfer
  itself.

### Step 9: Cross-Account Device/IP Clustering

Extends the existing audit log rather than adding a new subsystem -
the same relationship `list_flagged_ips()` already has to the audit
log, one level up: instead of "which single IPs show up on
high-severity rows," this asks "which device fingerprints or IPs are
shared across multiple distinct accounts," a pattern consistent with
a fraud ring running several mule/scam accounts from one device or
network.

- `core/audit_log.py` - `AuditRecord` gained a `device_id` field
  (read straight off `Signal.device_id`, the field detectors already
  populate), with the same "add the column if missing" migration
  pattern already used for `client_ip` so existing audit databases
  upgrade without a manual step. New
  `list_shared_device_ip_clusters(min_accounts=3, start_time=None,
  end_time=None, limit=100)` runs the same aggregate-view shape as
  `list_flagged_ips()` twice - once keyed on `device_id`, once on
  `client_ip` - and returns both kinds of cluster in one list ranked
  by distinct-account count, since a fraud ring can show up on either
  axis depending on what the client app was able to report.
  `min_accounts` is the key difference from a plain per-device/per-IP
  count: one account reusing its own device or IP across many events
  is normal and is not what this surfaces - only keys touching
  multiple *distinct* accounts count.
- `api/main.py` - new `GET /v1/admin/device-clusters` endpoint
  exposing `list_shared_device_ip_clusters()` over the API,
  authenticated and rate-limited exactly the same way as the existing
  `GET /v1/admin/flagged-ips` endpoint (`Depends(get_tenant)`, which
  bakes in rate limiting - no separate admin credential tier exists
  yet in this delivery, same caveat as flagged-ips).

  Same advisory, human-review shape as `list_flagged_ips()`: this
  surfaces candidate clusters for a human to investigate. It does not
  link, merge, flag, or block any account itself, and nothing in this
  module writes back to `AccountState`.

  Same honesty caveats as IP flagging apply, plus one specific to
  clustering: a shared `device_id` or `client_ip` across accounts is
  not proof of a fraud ring on its own. Shared household devices,
  office/campus networks, family members on one phone, and NAT'd
  corporate egress all produce genuinely-shared values between
  entirely legitimate, unrelated accounts - this is a lead for a
  human, not a verdict, and `min_accounts` exists specifically so
  callers can tune how much "shared-ness" is worth investigating.

## Running in Termux or any Linux environment

```
pip install -r requirements.txt --break-system-packages

# Run all tests first - no server needed for these:
python3 tests/test_engine_standalone.py
python3 tests/test_sim_ato_standalone.py
python3 tests/test_phishing_standalone.py
python3 tests/test_sqlite_store_standalone.py
python3 tests/test_api_keys_standalone.py
python3 tests/test_audit_log_standalone.py
python3 tests/test_verification_standalone.py
python3 tests/test_mule_transfer_standalone.py
python3 tests/test_social_engineering_session_standalone.py
python3 tests/test_device_clusters_standalone.py

# Provision an API key for yourself:
python3 scripts/create_key.py --tenant-id my-test-tenant --tenant-type consumer

# Start the API:
uvicorn api.main:app --reload --port 8000
```

Test the running API (replace YOUR_KEY with the key printed above):

```
curl -X POST http://localhost:8000/v1/signals \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"signal_type": "transaction", "account_id": "acct-1", "payload": {"amount": 50000}}'
```

Check for accounts sharing a device/IP (advisory, human-review only):

```
curl "http://localhost:8000/v1/admin/device-clusters?min_accounts=3" \
  -H "X-API-Key: YOUR_KEY"
```

## Verified test coverage

All standalone test suites pass with zero failures as of this
delivery:
- Behavioral anomaly detector: 4 scenarios (outlier detection, ATO OTP
  pattern, no false positive on first device, correct flag on device change)
- SIM/ATO detector: 5 scenarios (carrier status enrichment, signal-loss
  window timing, no false positive outside window, device mismatch,
  geographic implausibility, no false positive on local movement)
- Phishing detector: 10 scenarios (urgency + lookalike domain combined,
  no false positive on ordinary conversation, brand's own domain
  correctly excluded, leetspeak lookalike caught, brand name smuggled
  into unrelated domain caught, mismatched display/actual link caught,
  shortener-only stays low severity, QR-scanned link checked the same
  as a clicked link, missing url handled without crashing, ordinary
  legitimate domain produces no false positive)
- SQLite persistence: verifies detector state including embedded
  timestamps correctly survives a save-then-reload cycle simulating
  a server restart
- API key store: verifies key creation, that raw keys are never present
  in the database file, rejection of invalid keys, revocation actually
  stopping a key from working, default/custom/no-expiry TTL behavior,
  an expired-but-not-revoked key being rejected, rotate_key() replacing
  a key in one step, and list_expiring_keys() correctly surfacing (or
  excluding) keys based on their expiry window
- Audit log: 11 scenarios covering the original round-trip/redaction/
  filtering/persistence behavior plus (new) client_ip round-tripping,
  rows with no client_ip staying queryable, list_flagged_ips() ranking
  repeat high-severity offenders above one-off single events and
  excluding low-severity-only IPs entirely, and min_event_count
  correctly raising the bar above "flagged even once"
- Identity verification: 12 scenarios covering HIGH/CRITICAL severity
  correctly triggering a challenge (LOW does not), mock delivery
  issuing and recording a code, correct-code verification, incorrect
  codes staying pending without exhausting immediately, the 5-attempt
  cap tripping to FAILED, expired challenges rejected even with the
  correct code, unknown challenge_id handling, a resolved challenge
  rejecting re-verification, a VERIFIED result correctly feeding back
  into AccountState.detector_state, a recently-cleared account not
  being re-challenged on a subsequent high-severity event, delivery
  failure correctly returning None with nothing stored, and a
  structural check that the module exposes no autonomous
  freeze/block/lock functions
- Money-mule / scam-victim transfer detector: 10 scenarios covering
  inflow-then-rapid-outflow triggering correctly, slow/partial/
  familiar-beneficiary spending correctly NOT triggering, a large
  transfer to a new beneficiary relative to account history triggering,
  a new beneficiary at an ordinary value correctly NOT triggering,
  beneficiary churn (4 new beneficiaries in 24h) triggering, repeat
  payments to one familiar beneficiary correctly NOT counted as churn,
  round-trip timing tightness escalating severity on top of a
  pass-through match, an inflow alone (no outflow) producing no event,
  and missing amount/direction payload fields handled without crashing
- In-session pressure/coercion detector: 10 scenarios covering a
  support-impersonation-style message followed by a transaction
  triggering, an ordinary message correctly NOT triggering, a pressure
  message outside the 30-minute window correctly NOT triggering,
  `on_active_call=True` triggering on its own, `on_active_call=False`/
  absent correctly NOT triggering, idle-then-burst session timing
  triggering, steady non-bursty session activity correctly NOT
  triggering, all three signals stacking to reach CRITICAL severity,
  malformed session_events handled without crashing, and a plain
  context-free transaction producing no event
- Cross-account device/IP clustering: 10 scenarios covering a
  device_id shared across 3+ accounts correctly surfacing, a device_id
  reused repeatedly by one account correctly NOT surfacing,
  min_accounts correctly gating a 2-account cluster below a 3-account
  threshold but allowing it at 2, client_ip clustering working the
  same way as device_id, rows with NULL device_id/client_ip correctly
  excluded, max_severity correctly computed as the worst severity
  across a mixed-severity cluster, results ranked by distinct-account
  count descending, start_time filtering correctly excluding an old
  cluster from a recent-window query, limit correctly capping result
  count, and a device_id cluster and a client_ip cluster correctly
  coexisting for different keys in one result set

## Important notes before deploying with real user data

1. Rate limiting is now Redis-backed (core/rate_limiter.py), so limits
   hold correctly across multiple API processes/servers and survive
   restarts. Set GHOST_SENTINEL_REDIS_URL (e.g.
   redis://localhost:6379/0) in production. If it's unset, or Redis
   is unreachable at startup, the service automatically falls back to
   the old in-process limiter (fine for local/dev, not for
   multi-server prod) and logs a warning - it won't crash on import.
   If Redis becomes unreachable mid-flight, the limiter fails open
   (allows the request through) by default; flip
   FAIL_OPEN_ON_REDIS_ERROR in core/rate_limiter.py if you'd rather
   fail closed for a stricter deployment.
2. SQLite is fine for early-stage or moderate load. For high B2B
   transaction volume with concurrent writes, move to Postgres using
   the same two-method store interface.
3. TIRMS (Nigeria's telecom identity risk platform) is confirmed to be
   restricted to licensed financial institutions querying it directly -
   there is no public API for third-party integration. The SIM/ATO
   detector does not depend on TIRMS access; it works from
   client-reported signals alone. If you later partner with a bank that
   has TIRMS access, their reported carrier_status can be passed into
   the existing enrichment field without any code changes.
4. This system detects and scores risk. It does not take autonomous
   action against a user's account (freeze, block, etc.) - the
   recommended_action field is advisory text for the calling
   application to act on, by design, so a human or the client system
   stays in the loop on consequential decisions. list_flagged_ips()
   (core/audit_log.py) and GET /v1/admin/flagged-ips follow the same
   principle for IP-level response: advisory candidates for a human
   to review, never an autonomous block. core/verification.py's step-up
   challenge workflow follows the same principle: it requests
   confirmation, it never freezes or blocks an account itself.
5. Identity verification (core/verification.py) uses
   ConsoleChallengeDelivery, a local/mock delivery channel, because no
   Ghost Identity integration exists yet. Codes are logged in-process
   only (optionally to stdout if enabled) - this is fine for local
   dev/testing but is NOT a real out-of-band channel. Do not deploy
   this to production with real accounts until it's swapped for a
   ChallengeDelivery implementation that actually reaches the user
   through SMS/email/push/Ghost Identity.
6. MuleTransferDetector (core/detectors/mule_transfer.py) reasons from
   this account's own transaction history alone - it has no
   cross-institution mule-registry feed, no device/network graph
   correlating accounts across a fraud ring, and no real-time voice
   deepfake detection for phone-based social engineering. Real
   production mule-detection increasingly depends on pre-transaction
   intelligence about the destination account; this project doesn't
   have that data source, and the detector is honest about reasoning
   from transaction patterns alone rather than faking one.
7. SocialEngineeringSessionDetector (core/detectors/
   social_engineering_session.py) does not detect deepfakes, does not
   listen to or transcribe calls, and does not infer whether an
   account is "on a call" or how a session is progressing on its own.
   `on_active_call` and `session_events` are enrichment fields the
   calling application must explicitly supply from its own visibility
   (OS-level call state, client-side session telemetry); absent those,
   this detector falls back to the message-timing check alone.
   `SignalType.VOICE_AUTH_ATTEMPT.deepfake_confidence` (core/models.py)
   is a reserved socket for an external voice-auth/deepfake service -
   no detector consumes it yet, and none should be added that fakes
   that analysis in-house.
8. Client IP capture only trusts X-Forwarded-For/X-Real-IP if you
   explicitly set GHOST_SENTINEL_TRUSTED_PROXY_COUNT to the number of
   trusted proxy hops in front of the service. Left unset, only the
   raw TCP peer address is recorded - which, behind an unconfigured
   proxy, means every request records the proxy's own IP. See
   api/main.py's get_client_ip() comment for why this default is the
   honest choice over trusting a client-spoofable header. Since
   `list_shared_device_ip_clusters()` clusters on client_ip as well as
   device_id, this same caveat applies to it: an unconfigured proxy
   means every client_ip-based cluster in a deployment behind that
   proxy is really just "the proxy," not distinct end users.
9. `list_shared_device_ip_clusters()` (core/audit_log.py) and
   `GET /v1/admin/device-clusters` are advisory candidate lists for a
   human to investigate, same as `list_flagged_ips()` and
   `GET /v1/admin/flagged-ips`. Neither this function nor this
   endpoint links, merges, flags, or blocks accounts - see item 4
   above; that principle applies here too.

## Next build steps, in order

1. Detection Core skeleton + Behavioral Anomaly - complete
2. SIM/ATO detector - complete
3. Institutional hardening (auth, persistence, rate limiting) - complete
4. Consumer client - thin Termux/Android agent hitting this same gateway
5. Phishing/social-engineering detector - message text, URL, and QR
   checks - complete (see "Step 5" above). IP capture/flagging was
   built alongside this as net-new infrastructure, not originally
   scoped in the hardening list.
6. Identity verification workflow - complete (see "Step 6" above).
   Generates out-of-band confirmation challenges when a RiskEvent
   crosses the HIGH/CRITICAL threshold, via a pluggable
   ChallengeDelivery interface. Ghost Identity itself is not built (no
   spec exists yet) - ConsoleChallengeDelivery is the local/mock
   implementation used for testing today; a real Ghost Identity
   integration plugs in later as one new class, no rewrite needed.
7. Money-mule / scam-victim transfer detector - complete (see "Step 7"
   above). Net-new feature work, added after reviewing current
   fraud-industry reporting on where real losses concentrate (mule
   accounts, pig-butchering/romance-investment scams, authorized push
   payment fraud) - none of which the earlier identity/device-focused
   detectors catch, since the account owner's identity isn't
   compromised in these cases.
8. In-session pressure/coercion detector, and `VOICE_AUTH_ATTEMPT`
   signal type - complete (see "Step 8" above). Complements the
   mule-transfer detector by reasoning about session context (a
   support-impersonation message or an active-call enrichment shortly
   before a transaction) rather than transaction shape.
9. Cross-account device/IP clustering - complete (see "Step 9" above).
   `list_shared_device_ip_clusters()` in core/audit_log.py plus
   `GET /v1/admin/device-clusters`, extending the existing audit log
   rather than adding a new subsystem, same advisory human-review
   shape as `list_flagged_ips()`.

## Planned next (not yet built)

Identified from current fraud-industry research (2026 reporting on AI
deepfakes, mule networks, and scam patterns), scoped but intentionally
not started yet - listed here so scope stays explicit rather than
implied:

- Consumer client (thin Termux/Android agent hitting this same
  gateway) - the one item from the original "Next build steps" list
  that predates this feature work and is still open.

Explicitly out of scope, documented rather than silently skipped:
real-time deepfake/voice-clone detection (needs an audio ML model this
project has no access to), autonomous mule-account freezing or
cross-account blocking (stays advisory only throughout this system),
and cross-institution mule-graph data sharing (needs a live consortium
this project isn't part of).

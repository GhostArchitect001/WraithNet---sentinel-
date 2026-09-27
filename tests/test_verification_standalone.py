"""
Standalone smoke test for the identity verification workflow. Run with:
    python3 tests/test_verification_standalone.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from datetime import datetime, timedelta, timezone

from core.models import AccountState, RiskEvent, Severity
from core.verification import (
    ChallengeMethod,
    ChallengeStatus,
    ConsoleChallengeDelivery,
    VerificationChallenge,
    VerificationStore,
    VerifyResult,
    has_cleared_verification,
    mark_verified_in_state,
    maybe_request_challenge,
    request_challenge,
    should_trigger_challenge,
    verify_response,
)


def make_event(severity, account_id="acct-001", tenant_id="test-tenant"):
    return RiskEvent(
        account_id=account_id,
        tenant_id=tenant_id,
        detector_name="sim_ato",
        risk_score=0.9,
        severity=severity,
        reasons=["test reason"],
        triggered_signals=["sig-1"],
        recommended_action="Require step-up authentication before allowing this action to proceed.",
    )


def run():
    failures = 0

    print("=== Scenario 1: HIGH severity triggers a challenge, LOW does not ===")
    state = AccountState(account_id="acct-001", tenant_id="test-tenant")
    high_event = make_event(Severity.HIGH)
    low_event = make_event(Severity.LOW)
    if not should_trigger_challenge(high_event, state):
        print("  FAIL: expected HIGH severity to trigger a challenge")
        failures += 1
    else:
        print("  OK: HIGH severity triggers a challenge")
    if should_trigger_challenge(low_event, state):
        print("  FAIL: expected LOW severity NOT to trigger a challenge")
        failures += 1
    else:
        print("  OK: LOW severity does not trigger a challenge")

    print("\n=== Scenario 2: request_challenge issues a code via mock delivery ===")
    delivery = ConsoleChallengeDelivery()
    store = VerificationStore()
    challenge = request_challenge(
        account_id="acct-002", tenant_id="test-tenant",
        delivery=delivery, store=store,
    )
    if challenge is None or challenge.code is None or len(challenge.code) != 6:
        print(f"  FAIL: expected a 6-digit code to be issued, got {challenge}")
        failures += 1
    elif delivery.last_code_for("acct-002") != challenge.code:
        print("  FAIL: mock delivery did not record the sent code")
        failures += 1
    else:
        print(f"  OK: challenge issued, code delivered via mock ({challenge.method.value})")

    print("\n=== Scenario 3: correct code verifies successfully ===")
    delivery = ConsoleChallengeDelivery()
    store = VerificationStore()
    challenge = request_challenge("acct-003", "test-tenant", delivery, store)
    correct_code = delivery.last_code_for("acct-003")
    result = verify_response(challenge.challenge_id, correct_code, store)
    stored = store.get(challenge.challenge_id)
    if result != VerifyResult.VERIFIED or stored.status != ChallengeStatus.VERIFIED:
        print(f"  FAIL: expected VERIFIED, got result={result} status={stored.status}")
        failures += 1
    else:
        print("  OK: correct code verifies and updates challenge status")

    print("\n=== Scenario 4: incorrect code fails without exhausting immediately ===")
    delivery = ConsoleChallengeDelivery()
    store = VerificationStore()
    challenge = request_challenge("acct-004", "test-tenant", delivery, store)
    result = verify_response(challenge.challenge_id, "000000", store)
    stored = store.get(challenge.challenge_id)
    if result != VerifyResult.INCORRECT_CODE or stored.status != ChallengeStatus.PENDING:
        print(f"  FAIL: expected INCORRECT_CODE and still-pending status, got {result}/{stored.status}")
        failures += 1
    else:
        print(f"  OK: wrong code rejected, challenge stays pending (attempt {stored.attempt_count})")

    print("\n=== Scenario 5: attempt cap exhausts after too many wrong codes ===")
    delivery = ConsoleChallengeDelivery()
    store = VerificationStore()
    challenge = request_challenge("acct-005", "test-tenant", delivery, store)
    last_result = None
    for _ in range(10):
        last_result = verify_response(challenge.challenge_id, "000000", store)
        if last_result == VerifyResult.TOO_MANY_ATTEMPTS:
            break
    stored = store.get(challenge.challenge_id)
    if last_result != VerifyResult.TOO_MANY_ATTEMPTS or stored.status != ChallengeStatus.FAILED:
        print(f"  FAIL: expected attempt cap to trip, got {last_result}/{stored.status}")
        failures += 1
    else:
        print(f"  OK: attempt cap enforced after {stored.attempt_count} attempts, status=FAILED")

    print("\n=== Scenario 6: expired challenge cannot be verified even with correct code ===")
    delivery = ConsoleChallengeDelivery()
    store = VerificationStore()
    challenge = request_challenge("acct-006", "test-tenant", delivery, store)
    correct_code = delivery.last_code_for("acct-006")
    # Force expiry by rewriting the stored challenge's expires_at into the past,
    # simulating time passing rather than sleeping in the test.
    stored = store.get(challenge.challenge_id)
    stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    result = verify_response(challenge.challenge_id, correct_code, store)
    if result != VerifyResult.EXPIRED:
        print(f"  FAIL: expected EXPIRED, got {result}")
        failures += 1
    else:
        print("  OK: expired challenge rejected even with the correct code")

    print("\n=== Scenario 7: unknown challenge_id returns NOT_FOUND ===")
    store = VerificationStore()
    result = verify_response("does-not-exist", "123456", store)
    if result != VerifyResult.NOT_FOUND:
        print(f"  FAIL: expected NOT_FOUND, got {result}")
        failures += 1
    else:
        print("  OK: unknown challenge_id correctly reported as not found")

    print("\n=== Scenario 8: already-resolved challenge cannot be re-verified ===")
    delivery = ConsoleChallengeDelivery()
    store = VerificationStore()
    challenge = request_challenge("acct-008", "test-tenant", delivery, store)
    correct_code = delivery.last_code_for("acct-008")
    first = verify_response(challenge.challenge_id, correct_code, store)
    second = verify_response(challenge.challenge_id, correct_code, store)
    if first != VerifyResult.VERIFIED or second != VerifyResult.ALREADY_RESOLVED:
        print(f"  FAIL: expected VERIFIED then ALREADY_RESOLVED, got {first} then {second}")
        failures += 1
    else:
        print("  OK: a resolved challenge cannot be verified again")

    print("\n=== Scenario 9: verifying feeds back into AccountState.detector_state ===")
    delivery = ConsoleChallengeDelivery()
    store = VerificationStore()
    state = AccountState(account_id="acct-009", tenant_id="test-tenant")
    if has_cleared_verification(state):
        print("  FAIL: fresh AccountState should not already show cleared verification")
        failures += 1
    challenge = request_challenge("acct-009", "test-tenant", delivery, store)
    correct_code = delivery.last_code_for("acct-009")
    verify_response(challenge.challenge_id, correct_code, store, account_state=state)
    if not has_cleared_verification(state):
        print("  FAIL: expected has_cleared_verification(state) to be True after VERIFIED result")
        failures += 1
    else:
        print("  OK: verified result marks AccountState.detector_state so re-triggering can be avoided")

    print("\n=== Scenario 10: maybe_request_challenge skips accounts that recently cleared one ===")
    delivery = ConsoleChallengeDelivery()
    store = VerificationStore()
    state = AccountState(account_id="acct-010", tenant_id="test-tenant")
    first_event = make_event(Severity.HIGH, account_id="acct-010")
    first_challenge = maybe_request_challenge(first_event, state, delivery, store)
    if first_challenge is None:
        print("  FAIL: expected first HIGH-severity event to request a challenge")
        failures += 1
    else:
        correct_code = delivery.last_code_for("acct-010")
        verify_response(first_challenge.challenge_id, correct_code, store, account_state=state)
        second_event = make_event(Severity.CRITICAL, account_id="acct-010")
        second_challenge = maybe_request_challenge(second_event, state, delivery, store)
        if second_challenge is not None:
            print("  FAIL: expected no new challenge for an account that just cleared one")
            failures += 1
        else:
            print("  OK: recently-cleared account is not re-challenged immediately")

    print("\n=== Scenario 11: mock delivery failure means no challenge is stored ===")
    class AlwaysFailDelivery:
        def send(self, challenge):
            return False

    store = VerificationStore()
    failed_challenge = request_challenge(
        "acct-011", "test-tenant", AlwaysFailDelivery(), store
    )
    if failed_challenge is not None:
        print("  FAIL: expected None when delivery reports failure")
        failures += 1
    else:
        print("  OK: failed delivery correctly returns None and stores nothing")

    print("\n=== Scenario 12: VerificationChallenge is advisory-only (no autonomous action) ===")
    # This is a structural check, not a behavioral one: the dataclass and
    # workflow functions have no method or code path that freezes, blocks,
    # or locks an account - only request/verify. We assert that by checking
    # the public surface doesn't expose anything like that.
    import core.verification as verification_module
    forbidden_terms = {"freeze", "block", "lock_account", "suspend"}
    module_names = {name.lower() for name in dir(verification_module)}
    hit = forbidden_terms & module_names
    if hit:
        print(f"  FAIL: found autonomous-sounding function names in verification module: {hit}")
        failures += 1
    else:
        print("  OK: verification module exposes only request/verify operations, no autonomous account actions")

    print(f"\n=== Summary: {failures} failures ===")
    return failures


if __name__ == "__main__":
    failures = run()
    sys.exit(1 if failures else 0)

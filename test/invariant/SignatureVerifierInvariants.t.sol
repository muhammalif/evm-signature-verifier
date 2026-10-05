// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SignatureVerifier} from "../../src/SignatureVerifier.sol";
import {SignatureVerifierHandler} from "./SignatureVerifierHandler.sol";

/**
 * @title SignatureVerifierInvariants
 * @notice Stateful (sequence-aware) invariant suite for `SignatureVerifier`.
 *
 * These tests complement the stateless fuzz tests: instead of exercising a
 * single call, they drive the contract through long, fuzz-chosen sequences of
 * valid, replayed, forged, expired and malleable authorizations, then assert
 * global properties over the accumulated state.
 *
 * Invariants proven
 * -----------------
 * 1. `executedHashIsWriteOnce` — no authorization digest can ever register a
 *    second successful execution (replay protection is unbreakable), no matter
 *    how many times it is replayed.
 * 2. `everyRecordedDigestIsMarkedExecuted` — every digest the contract accepted
 *    is permanently recorded in `executedHashes` (no "silent success").
 * 3. `nonceMatchesSuccessfulExecutions` — the signer's nonce advances by exactly
 *    one per accepted authorization and is never advanced by a rejected one.
 * 4. `failedAttemptsNeverAdvanceNonce` — adversarial attempts leave no state.
 * 5. `eip2LowSAlwaysEnforced` — every accepted signature used a canonical
 *    low-`s` value (the malleability guard is unbreakable).
 * 6. `deadlineAlwaysRespected` — no authorization ever executed at a timestamp
 *    past its deadline (the expiration guard is unbreakable).
 */
contract SignatureVerifierInvariants is Test {
    SignatureVerifier internal verifier;
    SignatureVerifierHandler internal handler;

    /// @dev secp256k1 n / 2 — the EIP-2 canonical `s` upper bound.
    uint256 internal constant SECP256K1_HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    function setUp() public {
        verifier = new SignatureVerifier();
        handler = new SignatureVerifierHandler(verifier);

        // Only mutate the handler; it is the single point of contact with the
        // verifier and keeps ghost state in sync.
        targetContract(address(handler));

        // Restrict fuzzing to the handler's adversarial action set so the
        // sequence space is meaningful and reproducible.
        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = SignatureVerifierHandler.executeFresh.selector;
        selectors[1] = SignatureVerifierHandler.replaySuccessful.selector;
        selectors[2] = SignatureVerifierHandler.executeForged.selector;
        selectors[3] = SignatureVerifierHandler.executeExpired.selector;
        selectors[4] = SignatureVerifierHandler.executeMalleable.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// @notice No digest may ever be executed more than once, even after it is
    ///         replayed arbitrarily many times across a long call sequence.
    function invariant_executedHashIsWriteOnce() public view {
        assertLe(handler.maxExecutionsPerDigest(), 1, "a digest was executed more than once");

        uint256 n = handler.trackedCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 digest = handler.executedDigests(i);
            assertLe(handler.executionsByDigest(digest), 1, "digest observed executing twice");
        }
    }

    /// @notice Anything the contract accepted must be permanently consumed.
    function invariant_everyRecordedDigestIsMarkedExecuted() public view {
        uint256 n = handler.trackedCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 digest = handler.executedDigests(i);
            assertTrue(verifier.executedHashes(digest), "accepted digest was not recorded");
        }
    }

    /// @notice The nonce advances exactly once per accepted authorization.
    function invariant_nonceMatchesSuccessfulExecutions() public view {
        assertEq(
            verifier.userNonces(handler.signer()),
            handler.successfulExecutions(),
            "nonce drifted from the number of successful executions"
        );
    }

    /// @notice Rejected (adversarial) attempts never move state — the nonce only
    ///         tracks accepted authorizations, never attempts.
    function invariant_failedAttemptsNeverAdvanceNonce() public view {
        assertEq(
            verifier.userNonces(handler.signer()),
            handler.successfulExecutions(),
            "nonce advanced for a rejected attempt"
        );
    }

    /// @notice No acceptance may ever have used a high (malleable) `s` value.
    function invariant_eip2LowSAlwaysEnforced() public view {
        assertLe(handler.maxAcceptedS(), SECP256K1_HALF_N, "a high-s (malleable) signature executed");
    }

    /// @notice No acceptance may ever have occurred after its deadline.
    function invariant_deadlineAlwaysRespected() public view {
        assertLe(handler.lastAcceptedAt(), handler.lastAcceptedDeadline(), "expired authorization executed");
    }
}

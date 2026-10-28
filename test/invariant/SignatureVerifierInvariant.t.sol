// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../../src/SignatureVerifier.sol";
import "./SignatureVerifierHandler.sol";

contract SignatureVerifierInvariantTest is Test {
    SignatureVerifier public verifier;
    SignatureVerifierHandler public handler;

    function setUp() public {
        verifier = new SignatureVerifier();
        handler = new SignatureVerifierHandler(verifier);

        targetContract(address(handler));

        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = SignatureVerifierHandler.executeValid.selector;
        selectors[1] = SignatureVerifierHandler.executeReplay.selector;
        selectors[2] = SignatureVerifierHandler.executeExpired.selector;
        selectors[3] = SignatureVerifierHandler.executeMalleatedHighS.selector;
        selectors[4] = SignatureVerifierHandler.executeForgedSigner.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// @notice Invariant: userNonces monotonically equals the number of successful executions
    function invariant_nonceMatchesSuccessfulExecutions() public view {
        assertEq(
            verifier.userNonces(handler.signer()),
            handler.ghost_successfulExecutions(),
            "Nonce drift detected: userNonces must match successful executions"
        );
    }

    /// @notice Invariant: Every accepted authorization digest must be permanently recorded in executedHashes
    function invariant_everyRecordedDigestIsMarkedExecuted() public view {
        uint256 count = handler.getGhostDigestsCount();
        for (uint256 i = 0; i < count; i++) {
            bytes32 digest = handler.ghost_digests(i);
            assertTrue(
                verifier.executedHashes(digest),
                "Digest execution record missing in executedHashes mapping"
            );
        }
    }

    /// @notice Invariant: Zero replayed authorizations can ever succeed
    function invariant_zeroSuccessfulReplays() public view {
        assertEq(
            handler.ghost_successfulReplays(),
            0,
            "Critical invariant violation: replay attack succeeded"
        );
    }

    /// @notice Invariant: Zero malleated high-s signatures can ever succeed
    function invariant_zeroSuccessfulMalleations() public view {
        assertEq(
            handler.ghost_successfulMalleations(),
            0,
            "Critical invariant violation: malleable high-s signature accepted"
        );
    }

    /// @notice Invariant: Zero expired authorizations can ever succeed
    function invariant_zeroSuccessfulExpired() public view {
        assertEq(
            handler.ghost_successfulExpired(),
            0,
            "Critical invariant violation: expired authorization accepted"
        );
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../src/SignatureVerifier.sol";

contract SignatureVerifierTest is Test {
    // secp256k1 curve order n and n/2 (EIP-2 canonical s upper bound)
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant HALF_SECP256K1_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    SignatureVerifier public verifier;

    uint256 internal signerPrivateKey = 0xA11CE;
    address internal signer;
    address internal recipient = address(0xB0B);

    uint256 internal signerBPrivateKey = 0xB0B0B0B;
    address internal signerB;

    function setUp() public {
        verifier = new SignatureVerifier();
        signer = vm.addr(signerPrivateKey);
        signerB = vm.addr(signerBPrivateKey);
    }

    /* -------------------------------------------------------------------------- */
    /*                         ORIGINAL TEST SUITE (PRESERVED)                    */
    /* -------------------------------------------------------------------------- */

    function test_VerifyAndExecute_Success() public {
        uint256 amount = 100 ether;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool success = verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
        assertTrue(success);
        assertEq(verifier.userNonces(signer), nonce + 1);
    }

    function test_RevertOnReplayAttack() public {
        uint256 amount = 50 ether;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First execution succeeds
        verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);

        // Second execution with same parameters fails due to nonce increment or digest replay
        vm.expectRevert();
        verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
    }

    function test_RevertOnExpiredSignature() public {
        uint256 amount = 25 ether;
        uint256 deadline = block.timestamp - 1; // Expired
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(SignatureVerifier.SignatureExpired.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
    }

    function test_RevertOnInvalidSigner() public {
        uint256 amount = 10 ether;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        uint256 wrongKey = 0xBAD;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(SignatureVerifier.InvalidSigner.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
    }

    /* -------------------------------------------------------------------------- */
    /*                         ADDITIONAL SECURITY UNIT TESTS                     */
    /* -------------------------------------------------------------------------- */

    function test_RevertOnInvalidSignatureLength() public {
        bytes32 digest = keccak256("test_digest");
        bytes memory shortSig = new bytes(64);
        bytes memory longSig = new bytes(66);

        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.recoverSigner(digest, shortSig);

        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.recoverSigner(digest, longSig);
    }

    function test_RevertOnInvalidVValue() public {
        bytes32 digest = keccak256("test_digest");
        (, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);

        // v must be 27 or 28
        bytes memory sigBadV0 = abi.encodePacked(r, s, uint8(0));
        bytes memory sigBadV26 = abi.encodePacked(r, s, uint8(26));
        bytes memory sigBadV29 = abi.encodePacked(r, s, uint8(29));

        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.recoverSigner(digest, sigBadV0);

        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.recoverSigner(digest, sigBadV26);

        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.recoverSigner(digest, sigBadV29);
    }

    function test_RevertOnZeroSValue() public {
        bytes32 digest = keccak256("test_digest");
        bytes32 r = bytes32(uint256(1));
        bytes32 sZero = bytes32(0);
        bytes memory sig = abi.encodePacked(r, sZero, uint8(27));

        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.recoverSigner(digest, sig);
    }

    function test_RevertOnZeroDeadline() public {
        uint256 amount = 1 ether;
        uint256 deadline = 0;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(SignatureVerifier.SignatureExpired.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
    }

    function test_RevertOnZeroAddressExpectedSigner() public {
        uint256 amount = 1 ether;
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory dummySig = new bytes(65);

        vm.expectRevert(SignatureVerifier.InvalidSigner.selector);
        verifier.verifyAndExecute(address(0), recipient, amount, deadline, dummySig);
    }

    function test_RevertOnMalleableSignature_EIP2() public {
        uint256 amount = 100 ether;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);

        // Standard signature has s <= HALF_SECP256K1_N
        assertLe(uint256(s), HALF_SECP256K1_N);

        // Construct inverted malleable s: s_high = n - s > HALF_SECP256K1_N
        bytes32 malleableS = bytes32(SECP256K1_N - uint256(s));
        uint8 malleableV = v == 27 ? 28 : 27;
        bytes memory malleableSig = abi.encodePacked(r, malleableS, malleableV);

        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, malleableSig);
    }

    function test_ReplayProtection_ExplicitHashedTracking() public {
        uint256 amount = 75 ether;
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        assertFalse(verifier.executedHashes(digest));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute authorization
        bool success = verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
        assertTrue(success);

        // Verify digest is permanently tracked in executedHashes
        assertTrue(verifier.executedHashes(digest));
    }

    function test_DeadlineExactBoundary() public {
        uint256 amount = 10 ether;
        uint256 deadline = block.timestamp; // Exactly current timestamp
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Exact boundary (block.timestamp == deadline) is valid
        assertTrue(verifier.verifyAndExecute(signer, recipient, amount, deadline, signature));

        // Advancing block timestamp by 1 makes subsequent attempt with deadline expired
        vm.warp(block.timestamp + 1);
        nonce = verifier.userNonces(signer);
        digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (v, r, s) = vm.sign(signerPrivateKey, digest);
        signature = abi.encodePacked(r, s, v);

        vm.expectRevert(SignatureVerifier.SignatureExpired.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
    }

    /* -------------------------------------------------------------------------- */
    /*                         STATELESS FUZZ TEST SUITE                          */
    /* -------------------------------------------------------------------------- */

    function testFuzz_VerifyAndExecute(uint256 amount, uint32 duration) public {
        duration = uint32(bound(duration, 1, 365 days));
        uint256 deadline = block.timestamp + duration;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool success = verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
        assertTrue(success);
        assertEq(verifier.userNonces(signer), nonce + 1);
        assertTrue(verifier.executedHashes(digest));
    }

    function testFuzz_SignatureMalleability_EIP2_Invariant(uint256 amount, uint32 duration) public {
        duration = uint32(bound(duration, 1, 365 days));
        uint256 deadline = block.timestamp + duration;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);

        // Malleate s to upper half of the curve
        bytes32 highS = bytes32(SECP256K1_N - uint256(s));
        bytes memory malleableSig = abi.encodePacked(r, highS, v);

        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, malleableSig);
    }

    function testFuzz_RevertOnExpiredDeadline(uint256 amount, uint32 pastOffset) public {
        vm.warp(1_700_000_000);
        pastOffset = uint32(bound(pastOffset, 1, 1_000_000));
        uint256 deadline = block.timestamp - pastOffset;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(SignatureVerifier.SignatureExpired.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
    }

    function testFuzz_RevertOnInvalidVValue(uint8 badV) public {
        vm.assume(badV != 27 && badV != 28);
        bytes32 digest = keccak256("fuzz_digest");
        (, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, badV);

        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.recoverSigner(digest, signature);
    }

    function testFuzz_PerUserNonceIsolation(uint8 countA, uint8 countB) public {
        countA = uint8(bound(countA, 1, 10));
        countB = uint8(bound(countB, 1, 10));

        uint256 deadline = block.timestamp + 1 days;

        for (uint256 i = 0; i < countA; i++) {
            uint256 nonceA = verifier.userNonces(signer);
            bytes32 digestA = verifier.hashAuthorization(signer, recipient, 1 ether, nonceA, deadline);
            (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(signerPrivateKey, digestA);
            bytes memory sigA = abi.encodePacked(rA, sA, vA);
            assertTrue(verifier.verifyAndExecute(signer, recipient, 1 ether, deadline, sigA));
        }

        for (uint256 j = 0; j < countB; j++) {
            uint256 nonceB = verifier.userNonces(signerB);
            bytes32 digestB = verifier.hashAuthorization(signerB, recipient, 2 ether, nonceB, deadline);
            (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(signerBPrivateKey, digestB);
            bytes memory sigB = abi.encodePacked(rB, sB, vB);
            assertTrue(verifier.verifyAndExecute(signerB, recipient, 2 ether, deadline, sigB));
        }

        assertEq(verifier.userNonces(signer), countA);
        assertEq(verifier.userNonces(signerB), countB);
    }
}

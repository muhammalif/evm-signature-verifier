// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../src/SignatureVerifier.sol";

contract SignatureVerifierTest is Test {
    SignatureVerifier public verifier;

    uint256 internal signerPrivateKey = 0xA11CE;
    address internal signer;
    address internal recipient = address(0xB0B);

    function setUp() public {
        verifier = new SignatureVerifier();
        signer = vm.addr(signerPrivateKey);
    }

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

    function test_RevertOnInvalidSignatureLength() public {
        bytes32 digest = keccak256("test_digest");
        bytes memory shortSig = new bytes(64);
        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.recoverSigner(digest, shortSig);

        bytes memory longSig = new bytes(66);
        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.recoverSigner(digest, longSig);
    }

    function test_RevertOnInvalidVValue() public {
        bytes32 digest = keccak256("test_digest");
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(uint256(1));
        bytes memory invalidVSig = abi.encodePacked(r, s, uint8(29));

        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.recoverSigner(digest, invalidVSig);
    }

    function test_RevertOnZeroSValue() public {
        bytes32 digest = keccak256("test_digest");
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(0);
        bytes memory zeroSSig = abi.encodePacked(r, s, uint8(27));

        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.recoverSigner(digest, zeroSSig);
    }

    function test_RevertOnMalleableSignature_EIP2() public {
        uint256 amount = 10 ether;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);

        // Compute secp256k1 malleable s: s' = secp256k1n - s
        uint256 secp256k1n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 malleableS = bytes32(secp256k1n - uint256(s));
        uint8 malleableV = v == 27 ? 28 : 27;
        bytes memory malleableSignature = abi.encodePacked(r, malleableS, malleableV);

        // Malleable s must strictly revert conforming to EIP-2
        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.recoverSigner(digest, malleableSignature);

        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, malleableSignature);
    }

    function test_RevertOnZeroDeadline() public {
        uint256 amount = 10 ether;
        uint256 deadline = 0;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(SignatureVerifier.SignatureExpired.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
    }

    function test_ReplayProtection_ExplicitHashedTracking() public {
        uint256 amount = 75 ether;
        uint256 deadline = block.timestamp + 2 hours;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute authorization
        bool success = verifier.verifyAndExecute(signer, recipient, amount, nonce, deadline, signature);
        assertTrue(success);
        assertTrue(verifier.executedHashes(digest));

        // Replay attempt with same nonce and digest must revert with SignatureAlreadyExecuted
        vm.expectRevert(SignatureVerifier.SignatureAlreadyExecuted.selector);
        verifier.verifyAndExecute(signer, recipient, amount, nonce, deadline, signature);
    }

    // --- Fuzz Tests ---

    function testFuzz_VerifyAndExecute(uint256 amount, uint32 duration) public {
        vm.assume(duration > 0 && duration < 365 days);
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

    function testFuzz_RevertOnExpiredDeadline(uint256 amount, uint32 pastOffset) public {
        vm.warp(1000 days);
        pastOffset = uint32(bound(pastOffset, 1, 500 days));
        uint256 deadline = block.timestamp - pastOffset;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(SignatureVerifier.SignatureExpired.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
    }

    function testFuzz_SignatureMalleability_EIP2_Invariant(uint256 amount, uint32 duration) public {
        vm.assume(duration > 0 && duration < 365 days);
        uint256 deadline = block.timestamp + duration;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);

        uint256 secp256k1n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 malleableS = bytes32(secp256k1n - uint256(s));
        uint8 malleableV = v == 27 ? 28 : 27;
        bytes memory malleableSignature = abi.encodePacked(r, malleableS, malleableV);

        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.recoverSigner(digest, malleableSignature);
    }
}

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
        assertTrue(verifier.executedHashes(digest));
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

        // Second execution with same parameters fails due to digest replay & nonce increment
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

    function test_RevertOnMalleableSignatureHighS() public {
        uint256 amount = 10 ether;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);

        // Flip s to high half of curve order n
        uint256 secp256k1n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 malleableS = bytes32(secp256k1n - uint256(s));
        uint8 malleableV = v == 27 ? 28 : 27;
        bytes memory malleableSig = abi.encodePacked(r, malleableS, malleableV);

        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.recoverSigner(digest, malleableSig);
    }

    function test_RevertOnInvalidSignatureLength() public {
        bytes32 digest = keccak256("test");
        bytes memory shortSig = hex"123456";

        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.recoverSigner(digest, shortSig);
    }

    function test_RevertOnInvalidVValue() public {
        bytes32 digest = keccak256("test");
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(uint256(1));
        uint8 invalidV = 29;
        bytes memory invalidSig = abi.encodePacked(r, s, invalidV);

        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.recoverSigner(digest, invalidSig);
    }

    function testFuzz_VerifyAndExecute(uint256 amount, uint256 duration) public {
        vm.assume(duration > 0 && duration < 365 days);
        uint256 deadline = block.timestamp + duration;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool success = verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
        assertTrue(success);
    }
}

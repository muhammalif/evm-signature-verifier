// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SignatureVerifier} from "../src/SignatureVerifier.sol";

contract SignatureVerifierTest is Test {
    SignatureVerifier public verifier;

    uint256 internal signerPrivateKey = 0xA11CE;
    address internal signer;
    address internal recipient = address(0xB0B);

    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant SECP256K1_HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    event SignatureExecuted(bytes32 indexed digest, address indexed signer);

    function setUp() public {
        verifier = new SignatureVerifier();
        signer = vm.addr(signerPrivateKey);
    }

    // =========================================================================
    // EXISTING TESTS (Preserved strictly intact)
    // =========================================================================

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

    // =========================================================================
    // FUZZ TESTS: Valid amounts, deadlines and recipients
    // =========================================================================

    function testFuzz_VerifyAndExecute_ValidAmountAndDeadline(uint256 amount, uint256 deadline) public {
        deadline = bound(deadline, block.timestamp, type(uint256).max);
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, false, true);
        emit SignatureExecuted(digest, signer);

        bool success = verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
        assertTrue(success);
        assertEq(verifier.userNonces(signer), nonce + 1);
        assertTrue(verifier.executedHashes(digest));
    }

    function testFuzz_VerifyAndExecute_FuzzedRecipient(address to, uint256 amount, uint256 deadline) public {
        deadline = bound(deadline, block.timestamp, type(uint256).max);
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, to, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool success = verifier.verifyAndExecute(signer, to, amount, deadline, signature);
        assertTrue(success);
        assertEq(verifier.userNonces(signer), nonce + 1);
        assertTrue(verifier.executedHashes(digest));
    }

    // =========================================================================
    // FUZZ TESTS: Malleability rejection (s > N / 2, malleableS = N - s)
    // =========================================================================

    function testFuzz_RevertOnMalleableS(uint256 amount, uint256 deadline, bool flipV) public {
        deadline = bound(deadline, block.timestamp, type(uint256).max);
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);

        // Standard vm.sign returns canonical s <= N/2
        assertTrue(uint256(s) <= SECP256K1_HALF_N);

        // Calculate mathematical malleable counterpart: malleableS = SECP256K1_N - s
        uint256 malleableSNum = SECP256K1_N - uint256(s);
        bytes32 malleableS = bytes32(malleableSNum);

        // Ensure mathematically that malleableS falls in the upper half of curve order
        assertTrue(malleableSNum > SECP256K1_HALF_N);

        // With standard ECDSA, flipping v to opposite parity recovers the same signer if not guarded
        uint8 testV = flipV ? (v == 27 ? uint8(28) : uint8(27)) : v;
        bytes memory malleableSignature = abi.encodePacked(r, malleableS, testV);

        // Calling recoverSigner must revert immediately with InvalidSignatureSValue
        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.recoverSigner(digest, malleableSignature);

        // Calling verifyAndExecute must also revert immediately with InvalidSignatureSValue
        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, malleableSignature);

        // Ensure state remains intact
        assertFalse(verifier.executedHashes(digest));
        assertEq(verifier.userNonces(signer), nonce);
    }

    function testFuzz_RecoverSigner_RevertOnHighS(bytes32 digest, bytes32 r, uint256 highS, uint8 v) public {
        highS = bound(highS, SECP256K1_HALF_N + 1, type(uint256).max);
        v = (v % 2 == 0) ? 27 : 28;
        bytes memory badSig = abi.encodePacked(r, bytes32(highS), v);

        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.recoverSigner(digest, badSig);
    }

    // =========================================================================
    // FUZZ TESTS: Deadline expiration
    // =========================================================================

    function testFuzz_RevertOnExpiredDeadline(uint256 warpTime, uint256 deadline, uint256 amount) public {
        warpTime = bound(warpTime, 1, type(uint256).max);
        deadline = bound(deadline, 0, warpTime - 1);

        vm.warp(warpTime);

        uint256 nonce = verifier.userNonces(signer);
        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(SignatureVerifier.SignatureExpired.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);

        assertEq(verifier.userNonces(signer), nonce);
        assertFalse(verifier.executedHashes(digest));
    }

    // =========================================================================
    // FUZZ TESTS: Invalid signer / wrong private key / mismatched expected signer
    // =========================================================================

    function testFuzz_RevertOnInvalidSigner_WrongPrivateKey(uint256 wrongKey, uint256 amount, uint256 deadline) public {
        wrongKey = bound(wrongKey, 1, SECP256K1_N - 1);
        vm.assume(wrongKey != signerPrivateKey);
        deadline = bound(deadline, block.timestamp, type(uint256).max);

        uint256 nonce = verifier.userNonces(signer);
        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(SignatureVerifier.InvalidSigner.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);

        assertEq(verifier.userNonces(signer), nonce);
        assertFalse(verifier.executedHashes(digest));
    }

    function testFuzz_RevertOnMismatchedExpectedSigner(address wrongExpectedSigner, uint256 amount, uint256 deadline) public {
        vm.assume(wrongExpectedSigner != signer && wrongExpectedSigner != address(0));
        deadline = bound(deadline, block.timestamp, type(uint256).max);

        uint256 nonce = verifier.userNonces(wrongExpectedSigner);
        // Authorization hash is computed with wrongExpectedSigner, but signed by signerPrivateKey
        bytes32 digest = verifier.hashAuthorization(wrongExpectedSigner, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(SignatureVerifier.InvalidSigner.selector);
        verifier.verifyAndExecute(wrongExpectedSigner, recipient, amount, deadline, signature);

        assertEq(verifier.userNonces(wrongExpectedSigner), nonce);
        assertFalse(verifier.executedHashes(digest));
    }

    // =========================================================================
    // UNIT TESTS: Edge cases
    // =========================================================================

    // Case: Signature length != 65
    function test_RevertOnInvalidSignatureLength_Short64() public {
        bytes memory shortSig = new bytes(64);
        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.recoverSigner(bytes32(0), shortSig);

        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.verifyAndExecute(signer, recipient, 10 ether, block.timestamp + 1 hours, shortSig);
    }

    function test_RevertOnInvalidSignatureLength_Long66() public {
        bytes memory longSig = new bytes(66);
        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.recoverSigner(bytes32(0), longSig);

        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.verifyAndExecute(signer, recipient, 10 ether, block.timestamp + 1 hours, longSig);
    }

    function test_RevertOnInvalidSignatureLength_Empty() public {
        bytes memory emptySig = new bytes(0);
        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.recoverSigner(bytes32(0), emptySig);

        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.verifyAndExecute(signer, recipient, 10 ether, block.timestamp + 1 hours, emptySig);
    }

    function testFuzz_RevertOnInvalidSignatureLength(uint256 len, bytes32 digest) public {
        len = bound(len, 0, 256);
        vm.assume(len != 65);
        bytes memory badSig = new bytes(len);

        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.recoverSigner(digest, badSig);

        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.verifyAndExecute(signer, recipient, 1 ether, block.timestamp + 1 hours, badSig);
    }

    // Case: Invalid v value (v != 27 && v != 28)
    function test_RevertOnInvalidVValue_Zero() public {
        bytes memory sig = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), uint8(0));
        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.recoverSigner(bytes32(uint256(1)), sig);

        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.verifyAndExecute(signer, recipient, 10 ether, block.timestamp + 1 hours, sig);
    }

    function test_RevertOnInvalidVValue_One() public {
        bytes memory sig = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), uint8(1));
        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.recoverSigner(bytes32(uint256(1)), sig);

        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.verifyAndExecute(signer, recipient, 10 ether, block.timestamp + 1 hours, sig);
    }

    function test_RevertOnInvalidVValue_26() public {
        bytes memory sig = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), uint8(26));
        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.recoverSigner(bytes32(uint256(1)), sig);

        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.verifyAndExecute(signer, recipient, 10 ether, block.timestamp + 1 hours, sig);
    }

    function test_RevertOnInvalidVValue_29() public {
        bytes memory sig = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), uint8(29));
        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.recoverSigner(bytes32(uint256(1)), sig);

        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.verifyAndExecute(signer, recipient, 10 ether, block.timestamp + 1 hours, sig);
    }

    function test_RevertOnInvalidVValue_255() public {
        bytes memory sig = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), uint8(255));
        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.recoverSigner(bytes32(uint256(1)), sig);

        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.verifyAndExecute(signer, recipient, 10 ether, block.timestamp + 1 hours, sig);
    }

    function testFuzz_RevertOnInvalidVValue(uint8 v, bytes32 digest) public {
        vm.assume(v != 27 && v != 28);
        bytes memory sig = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), v);

        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.recoverSigner(digest, sig);

        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.verifyAndExecute(signer, recipient, 1 ether, block.timestamp + 1 hours, sig);
    }

    // Case: s == 0
    function test_RevertWhenSIsZero_RecoverSigner() public {
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(0);
        uint8 v = 27;
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.recoverSigner(bytes32(uint256(1)), sig);
    }

    function test_RevertWhenSIsZero_VerifyAndExecute() public {
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(0);
        uint8 v = 28;
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.verifyAndExecute(signer, recipient, 10 ether, block.timestamp + 1 hours, sig);
    }

    // Case: r == 0
    function test_RevertWhenRIsZero() public {
        bytes32 r = bytes32(0);
        bytes32 s = bytes32(uint256(1));
        uint8 v = 27;
        bytes memory sig = abi.encodePacked(r, s, v);

        // r == 0 causes ecrecover to return address(0)
        vm.expectRevert(SignatureVerifier.InvalidSigner.selector);
        verifier.recoverSigner(bytes32(uint256(1)), sig);

        vm.expectRevert(SignatureVerifier.InvalidSigner.selector);
        verifier.verifyAndExecute(signer, recipient, 10 ether, block.timestamp + 1 hours, sig);
    }

    // Case: expectedSigner == address(0)
    function test_RevertWhenExpectedSignerIsZeroAddress() public {
        bytes memory dummySig = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), uint8(27));
        vm.expectRevert(SignatureVerifier.InvalidSigner.selector);
        verifier.verifyAndExecute(address(0), recipient, 10 ether, block.timestamp + 1 hours, dummySig);
    }

    function test_RevertWhenExpectedSignerIsZeroAddress_WithValidDigestSignature() public {
        uint256 amount = 100 ether;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = verifier.userNonces(address(0));

        bytes32 digest = verifier.hashAuthorization(address(0), recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(SignatureVerifier.InvalidSigner.selector);
        verifier.verifyAndExecute(address(0), recipient, amount, deadline, signature);

        // Ensure nonce of address(0) was not incremented
        assertEq(verifier.userNonces(address(0)), nonce);
    }

    function testFuzz_RevertWhenExpectedSignerIsZeroAddress(
        address to,
        uint256 amount,
        uint256 deadline,
        bytes32 r,
        uint256 sRaw,
        uint8 vRaw
    ) public {
        deadline = bound(deadline, block.timestamp, type(uint256).max);
        uint256 sBounded = bound(sRaw, 1, SECP256K1_HALF_N);
        uint8 v = (vRaw % 2 == 0) ? 27 : 28;
        bytes memory sig = abi.encodePacked(r, bytes32(sBounded), v);

        vm.expectRevert(SignatureVerifier.InvalidSigner.selector);
        verifier.verifyAndExecute(address(0), to, amount, deadline, sig);
    }

    // =========================================================================
    // INVARIANT / STATE INTEGRITY TESTS
    // =========================================================================

    function invariant_DomainSeparatorMatchesCalculation() public view {
        bytes32 expectedDomainSeparator = keccak256(
            abi.encode(
                verifier.DOMAIN_TYPEHASH(),
                keccak256(bytes("EIP712SignatureVerifier")),
                keccak256(bytes("1")),
                block.chainid,
                address(verifier)
            )
        );
        assertEq(verifier.DOMAIN_SEPARATOR(), expectedDomainSeparator);
    }

    function invariant_OwnerNeverChanges() public view {
        assertEq(verifier.owner(), address(this));
    }
}

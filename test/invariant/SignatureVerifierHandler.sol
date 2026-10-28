// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../../src/SignatureVerifier.sol";

contract SignatureVerifierHandler is Test {
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant HALF_SECP256K1_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    SignatureVerifier public immutable verifier;

    uint256 internal immutable signerPrivateKey = 0xA11CE;
    address public immutable signer;
    address public immutable recipient = address(0xB0B);

    // Ghost state tracking
    uint256 public ghost_successfulExecutions;
    uint256 public ghost_rejectedReplays;
    uint256 public ghost_rejectedExpired;
    uint256 public ghost_rejectedHighS;
    uint256 public ghost_rejectedForged;

    uint256 public ghost_successfulReplays;
    uint256 public ghost_successfulExpired;
    uint256 public ghost_successfulMalleations;

    bytes32[] public ghost_digests;
    bytes[] public ghost_signatures;

    constructor(SignatureVerifier _verifier) {
        verifier = _verifier;
        signer = vm.addr(signerPrivateKey);
    }

    function getGhostDigestsCount() external view returns (uint256) {
        return ghost_digests.length;
    }

    function executeValid(uint256 amount, uint32 duration) external {
        duration = uint32(bound(duration, 1, 365 days));
        uint256 deadline = block.timestamp + duration;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool success = verifier.verifyAndExecute(signer, recipient, amount, deadline, signature);
        if (success) {
            ghost_successfulExecutions++;
            ghost_digests.push(digest);
            ghost_signatures.push(signature);
        }
    }

    function executeReplay(uint256 indexSeed) external {
        if (ghost_signatures.length == 0) return;

        uint256 idx = indexSeed % ghost_signatures.length;
        bytes memory staleSig = ghost_signatures[idx];
        uint256 deadline = block.timestamp + 1 hours;

        try verifier.verifyAndExecute(signer, recipient, 10 ether, deadline, staleSig) returns (bool) {
            ghost_successfulReplays++;
        } catch {
            ghost_rejectedReplays++;
        }
    }

    function executeExpired(uint256 amount, uint32 pastOffset) external {
        pastOffset = uint32(bound(pastOffset, 1, 100 days));
        if (block.timestamp <= pastOffset) {
            vm.warp(block.timestamp + pastOffset + 100);
        }
        uint256 deadline = block.timestamp - pastOffset;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        try verifier.verifyAndExecute(signer, recipient, amount, deadline, signature) returns (bool) {
            ghost_successfulExpired++;
        } catch {
            ghost_rejectedExpired++;
        }
    }

    function executeMalleatedHighS(uint256 amount, uint32 duration) external {
        duration = uint32(bound(duration, 1, 365 days));
        uint256 deadline = block.timestamp + duration;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);

        // Malleate s to upper half: s_high = n - s
        bytes32 highS = bytes32(SECP256K1_N - uint256(s));
        bytes memory malleableSig = abi.encodePacked(r, highS, v);

        try verifier.verifyAndExecute(signer, recipient, amount, deadline, malleableSig) returns (bool) {
            ghost_successfulMalleations++;
        } catch {
            ghost_rejectedHighS++;
        }
    }

    function executeForgedSigner(uint256 amount, uint32 duration, uint256 badKeySeed) external {
        duration = uint32(bound(duration, 1, 365 days));
        badKeySeed = bound(badKeySeed, 1, 0xFFFFFF);
        if (badKeySeed == signerPrivateKey) badKeySeed += 1;

        uint256 deadline = block.timestamp + duration;
        uint256 nonce = verifier.userNonces(signer);

        bytes32 digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(badKeySeed, digest);
        bytes memory badSig = abi.encodePacked(r, s, v);

        try verifier.verifyAndExecute(signer, recipient, amount, deadline, badSig) returns (bool) {
            // Forged signer accepted (critical vulnerability)
            revert("ForgedSignatureAccepted");
        } catch {
            ghost_rejectedForged++;
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SignatureVerifier} from "../../src/SignatureVerifier.sol";

/**
 * @title SignatureVerifierHandler
 * @notice Stateful-invariant handler. It drives `SignatureVerifier` through a
 *         fuzz-chosen sequence of valid executions, verbatim replays, forged
 *         signatures, expired authorizations and EIP-2 malleable (high-s)
 *         signatures, while maintaining the ghost state consumed by the
 *         invariant assertions.
 *
 * @dev Each action swallows reverts (the expected outcome for every adversarial
 *      case) and only records a success when the contract actually accepted the
 *      authorization. If an adversarial path ever succeeds, the ghost counters
 *      move in lock-step with the contract state and the invariants fail.
 */
contract SignatureVerifierHandler is Test {
    SignatureVerifier public immutable verifier;

    uint256 internal constant SIGNER_KEY = 0xA11CE;
    uint256 internal constant WRONG_KEY = 0xB0B;

    /// @dev secp256k1 group order (n).
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @dev secp256k1 n / 2 — the EIP-2 canonical `s` upper bound.
    uint256 internal constant SECP256K1_HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @dev Upper bound on tracked digests so the invariant loops stay bounded.
    uint256 internal constant MAX_TRACKED = 256;

    address public immutable signer;
    address public constant RECIPIENT = address(0xBEEF);

    struct Attempt {
        bytes32 digest;
        address to;
        uint256 amount;
        uint256 deadline;
        uint256 sUsed;
        bytes sig;
    }

    Attempt[] internal _successful;
    bytes32[] public executedDigests;

    /// @notice Number of times each digest has been observed to execute.
    mapping(bytes32 => uint256) public executionsByDigest;

    /// @notice Maximum observed execution count for any single digest.
    uint256 public maxExecutionsPerDigest;

    /// @notice Highest `s` value the contract ever accepted.
    uint256 public maxAcceptedS;

    /// @notice Block timestamp of the last accepted authorization.
    uint256 public lastAcceptedAt;

    /// @notice Deadline of the last accepted authorization.
    uint256 public lastAcceptedDeadline;

    /// @notice Total successful executions recorded by the handler.
    uint256 public successfulExecutions;

    /// @notice Total adversarial/execution attempts made.
    uint256 public attempts;

    /// @notice Total attempts that reverted (expected for adversarial paths).
    uint256 public reverts;

    constructor(SignatureVerifier _verifier) {
        verifier = _verifier;
        signer = vm.addr(SIGNER_KEY);
    }

    function trackedCount() external view returns (uint256) {
        return executedDigests.length;
    }

    // ---------------------------------------------------------------------
    // Actions fuzzed by the stateful invariant runner
    // ---------------------------------------------------------------------

    /// @notice Produce and execute a fresh, valid authorization for `signer`.
    function executeFresh(uint256 amount, uint256 deadlineSeed) external {
        attempts++;
        uint256 deadline = block.timestamp + 1 + (deadlineSeed % 3650 days);
        uint256 nonce = verifier.userNonces(signer);
        bytes32 digest = verifier.hashAuthorization(signer, RECIPIENT, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        try verifier.verifyAndExecute(signer, RECIPIENT, amount, deadline, sig) returns (bool ok) {
            if (ok) {
                _recordSuccess(digest, RECIPIENT, amount, deadline, uint256(s), sig);
            } else {
                reverts++;
            }
        } catch {
            reverts++;
        }
    }

    /// @notice Replay a previously successful authorization verbatim.
    ///         A replay must never execute a second time.
    function replaySuccessful(uint256 idx) external {
        if (_successful.length == 0) {
            return;
        }
        attempts++;
        Attempt memory a = _successful[idx % _successful.length];
        try verifier.verifyAndExecute(signer, a.to, a.amount, a.deadline, a.sig) returns (bool ok) {
            if (ok) {
                _recordSuccess(a.digest, a.to, a.amount, a.deadline, a.sUsed, a.sig);
            } else {
                reverts++;
            }
        } catch {
            reverts++;
        }
    }

    /// @notice Attempt to execute an authorization signed by an unauthorized key.
    function executeForged(uint256 amount, uint256 deadlineSeed) external {
        attempts++;
        uint256 deadline = block.timestamp + 1 + (deadlineSeed % 3650 days);
        uint256 nonce = verifier.userNonces(signer);
        bytes32 digest = verifier.hashAuthorization(signer, RECIPIENT, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(WRONG_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        try verifier.verifyAndExecute(signer, RECIPIENT, amount, deadline, sig) {
            _recordSuccess(digest, RECIPIENT, amount, deadline, uint256(s), sig);
        } catch {
            reverts++;
        }
    }

    /// @notice Attempt to execute with an already-expired deadline.
    function executeExpired(uint256 amount) external {
        attempts++;
        if (block.timestamp == 0) {
            return;
        }
        uint256 deadline = block.timestamp - 1;
        uint256 nonce = verifier.userNonces(signer);
        bytes32 digest = verifier.hashAuthorization(signer, RECIPIENT, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        try verifier.verifyAndExecute(signer, RECIPIENT, amount, deadline, sig) {
            _recordSuccess(digest, RECIPIENT, amount, deadline, uint256(s), sig);
        } catch {
            reverts++;
        }
    }

    /// @notice Attempt an EIP-2 malleable (high-s) variant of a valid signature.
    ///         The malleable variant must be rejected by the `s`-value guard.
    function executeMalleable(uint256 amount, uint256 deadlineSeed) external {
        attempts++;
        uint256 deadline = block.timestamp + 1 + (deadlineSeed % 3650 days);
        uint256 nonce = verifier.userNonces(signer);
        bytes32 digest = verifier.hashAuthorization(signer, RECIPIENT, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);
        // Mathematically valid but EIP-2 non-canonical counterpart.
        bytes32 malleableS = bytes32(SECP256K1_N - uint256(s));
        uint8 flippedV = (v == 27) ? 28 : 27;
        bytes memory sig = abi.encodePacked(r, malleableS, flippedV);
        try verifier.verifyAndExecute(signer, RECIPIENT, amount, deadline, sig) {
            _recordSuccess(digest, RECIPIENT, amount, deadline, uint256(malleableS), sig);
        } catch {
            reverts++;
        }
    }

    // ---------------------------------------------------------------------
    // Ghost bookkeeping
    // ---------------------------------------------------------------------

    function _recordSuccess(
        bytes32 digest,
        address to,
        uint256 amount,
        uint256 deadline,
        uint256 sUsed,
        bytes memory sig
    ) internal {
        uint256 n = ++executionsByDigest[digest];
        if (n > maxExecutionsPerDigest) {
            maxExecutionsPerDigest = n;
        }
        if (sUsed > maxAcceptedS) {
            maxAcceptedS = sUsed;
        }
        lastAcceptedAt = block.timestamp;
        lastAcceptedDeadline = deadline;
        successfulExecutions++;
        if (executedDigests.length < MAX_TRACKED) {
            executedDigests.push(digest);
        }
        _successful.push(Attempt(digest, to, amount, deadline, sUsed, sig));
    }
}

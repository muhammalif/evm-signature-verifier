// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @title SignatureVerifier
 * @notice Standardized EVM cryptographic signature verification engine.
 * @dev Provides EIP-712 typed hashing, ECDSA signature recovery,
 *      strict malleability guards, and on-chain replay protection.
 */
contract SignatureVerifier {
    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 public constant AUTHORIZATION_TYPEHASH =
        keccak256("Authorization(address sender,address recipient,uint256 amount,uint256 nonce,uint256 deadline)");

    bytes32 public immutable DOMAIN_SEPARATOR;
    address public immutable owner;

    mapping(bytes32 => bool) public executedHashes;
    mapping(address => uint256) public userNonces;

    error InvalidSignatureLength();
    error InvalidSignatureSValue();
    error InvalidSignatureVValue();
    error SignatureExpired();
    error SignatureAlreadyExecuted();
    error InvalidSigner();
    error InvalidRecipient();

    event SignatureExecuted(bytes32 indexed digest, address indexed signer);

    constructor() {
        owner = msg.sender;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("EIP712SignatureVerifier")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @notice Computes EIP-712 typed data digest for an authorization.
     */
    function hashAuthorization(
        address sender,
        address recipient,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(AUTHORIZATION_TYPEHASH, sender, recipient, amount, nonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    /**
     * @notice Verifies an ECDSA signature with strict anti-malleability guarantees.
     */
    function recoverSigner(bytes32 digest, bytes memory signature) public pure returns (address) {
        if (signature.length != 65) {
            revert InvalidSignatureLength();
        }

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        // EIP-2 strict anti-malleability check: secp256k1 curve order / 2
        // Lower s-value constraint: s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidSignatureSValue();
        }

        // Standard v-value validation (27 or 28 for legacy/EIP-155 uncompressed ECDSA)
        if (v != 27 && v != 28) {
            revert InvalidSignatureVValue();
        }

        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) {
            revert InvalidSigner();
        }

        return signer;
    }

    /**
     * @notice Verifies and consumes a signed authorization with multi-layered security guards.
     * @dev Enforces:
     *      1. Non-zero recipient address check
     *      2. Strict timestamp deadline validation (anti-stale)
     *      3. Per-signer monotonic nonce increment
     *      4. Unique digest replay prevention via executedHashes registry
     *      5. Cryptographic EIP-712 / EIP-2 low-s signature recovery
     */
    function verifyAndExecute(
        address expectedSigner,
        address recipient,
        uint256 amount,
        uint256 deadline,
        bytes memory signature
    ) external returns (bool) {
        if (expectedSigner == address(0)) {
            revert InvalidSigner();
        }

        if (recipient == address(0)) {
            revert InvalidRecipient();
        }

        // Deadline expiration check
        if (block.timestamp > deadline) {
            revert SignatureExpired();
        }

        // Monotonic per-user nonce tracking for sequential replay protection
        uint256 currentNonce = userNonces[expectedSigner]++;
        bytes32 digest = hashAuthorization(expectedSigner, recipient, amount, currentNonce, deadline);

        // Digest-level on-chain execution guard
        if (executedHashes[digest]) {
            revert SignatureAlreadyExecuted();
        }

        address recovered = recoverSigner(digest, signature);
        if (recovered != expectedSigner) {
            revert InvalidSigner();
        }

        executedHashes[digest] = true;
        emit SignatureExecuted(digest, expectedSigner);

        return true;
    }
}

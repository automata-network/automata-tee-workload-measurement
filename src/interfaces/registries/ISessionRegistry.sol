// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {CVMSession, PublicIdentity} from "../../types/Common.sol";
import {AttestationEvidence, TpmReport, SessionRotationEvidence} from "../../types/Evidence.sol";

struct CVMSessionStorage {
    bool exists;
    bool isRevoked;
    bytes32 owner;
    CVMSession session;
}

interface ISessionRegistry {
    // ============================================================================
    // Events
    // ============================================================================

    /// @notice Emitted when a new CVM session is successfully registered after attestation verification
    /// @param sessionId Unique identifier for the registered session
    /// @param owner Owner fingerprint (bytes32 encoding of PublicIdentity fingerprint)
    /// @param workloadId Associated workload identifier
    /// @param baseImageId Associated base image identifier
    /// @param akPubKeyFingerprint Fingerprint of the Attestation Key (root of trust)
    /// @param tpmSigningKeyFingerprint Fingerprint of the TPM signing key (from TPM Certify)
    /// @param sessionKeyFingerprint Fingerprint of the session key (operational key)
    event SessionRegistered(
        bytes32 indexed sessionId,
        bytes32 indexed owner,
        bytes32 indexed workloadId,
        bytes32 baseImageId,
        bytes32 akPubKeyFingerprint,
        bytes32 tpmSigningKeyFingerprint,
        bytes32 sessionKeyFingerprint
    );

    /// @notice Emitted when full public keys are revealed (always emitted, keys never stored)
    /// @param sessionId The session identifier
    /// @param akPub Full Attestation Key public key
    /// @param tpmSigningKey Full TPM signing key public key
    /// @param sessionKey Full session key public key
    event AttestationKeysRevealed(
        bytes32 indexed sessionId, PublicIdentity akPub, PublicIdentity tpmSigningKey, PublicIdentity sessionKey
    );

    /// @notice Emitted when a session is revoked by its owner
    /// @param sessionId The revoked session identifier
    /// @param revoker Owner fingerprint that revoked the session
    event SessionRevoked(bytes32 indexed sessionId, bytes32 indexed revoker);

    /// @notice Emitted when a session is rotated
    /// @param oldSessionId The session being rotated
    /// @param newSessionId The newly created session
    /// @param owner Owner fingerprint that authorized the rotation
    /// @param newTpmSigningKeyFingerprint Fingerprint of the new TPM signing key
    /// @param newSessionKeyFingerprint Fingerprint of the new session key
    event SessionRotated(
        bytes32 indexed oldSessionId,
        bytes32 indexed newSessionId,
        bytes32 indexed owner,
        bytes32 newTpmSigningKeyFingerprint,
        bytes32 newSessionKeyFingerprint
    );

    // ============================================================================
    // Functions
    // ============================================================================

    /// @notice Register a new CVM session after attestation verification
    /// @param evidence The attestation evidence bundle (contains TEE type and backend type)
    /// @param workloadId The workload identifier
    /// @param baseImageId The base image identifier
    /// @param platformProfileId The platform profile identifier
    /// @param variantId The measurement variant identifier
    /// @param expireAt Signature expiration timestamp (must be >= block.timestamp)
    /// @param ownerIdentity The public key identity of the session owner
    /// @param ownerSignature Signature over the session registration data by ownerIdentity
    /// @return sessionId The unique identifier for the registered session
    function registerSession(
        AttestationEvidence calldata evidence,
        bytes32 workloadId,
        bytes32 baseImageId,
        bytes32 platformProfileId,
        bytes32 variantId,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 sessionId);

    /// @notice Get session data
    /// @param sessionId The session identifier
    /// @return session The complete session data
    function getSession(bytes32 sessionId) external view returns (CVMSession memory session);

    function getSessionId(bytes32 sessionFingerprint) external view returns (bytes32 sessionId);

    /// @notice Revoke a session (only by owner)
    /// @param sessionId The session identifier
    /// @param expireAt Signature expiration timestamp (must be >= block.timestamp)
    /// @param ownerIdentity The public key identity of the session owner
    /// @param ownerSignature Signature over the revocation request by ownerIdentity
    function revokeSession(
        bytes32 sessionId,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external;

    /// @notice Check if a session is active (not revoked and not expired)
    /// @param sessionId The session identifier
    /// @return True if the session is active
    function isSessionActive(bytes32 sessionId) external view returns (bool);

    /// @notice Check if a session is expired
    /// @param sessionId The session identifier
    /// @return True if the session is expired
    function isSessionExpired(bytes32 sessionId) external view returns (bool);

    /// @notice Get all session IDs for an owner
    /// @param ownerFingerprint The owner fingerprint
    /// @return Array of session IDs
    function getOwnerSessions(bytes32 ownerFingerprint) external view returns (bytes32[] memory);

    /// @notice Get the current nonce for an owner (for replay protection)
    /// @param ownerFingerprint The owner fingerprint
    /// @return nonce The current nonce value
    function getNonce(bytes32 ownerFingerprint) external view returns (uint256 nonce);

    /// @notice Rotate a session's TPM signing key and session key
    /// @param oldSessionId The session to rotate
    /// @param teeReportBytesHash keccak256(teeReport.data) from the original attestation
    /// @param rotationEvidence The rotation evidence bundle (TPM reports, signatures, keys)
    /// @param expireAt Signature expiration timestamp (must be >= block.timestamp)
    /// @param ownerIdentity The session owner's public key
    /// @param ownerSignature Signature over the rotation message by the owner
    /// @return newSessionId The derived identifier for the new rotated session
    function rotateSession(
        bytes32 oldSessionId,
        bytes32 teeReportBytesHash,
        SessionRotationEvidence calldata rotationEvidence,
        uint64 expireAt,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 newSessionId);

    /// @notice Verify a signature was made by an active session's sessionKey
    /// @dev Caller must provide the sessionKey (obtainable from AttestationKeysRevealed event)
    /// @param sessionId The session to verify against
    /// @param sessionKey The session's public key
    /// @param message The message that was signed (typically a hash)
    /// @param signature The signature to verify
    /// @return valid True if signature is valid and session is active
    function verifySessionSignature(
        bytes32 sessionId,
        PublicIdentity calldata sessionKey,
        bytes32 message,
        bytes calldata signature
    ) external view returns (bool valid);
}

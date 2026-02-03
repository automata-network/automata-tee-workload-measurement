// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {CVMSession, PublicIdentity} from "../../types/Common.sol";
import {AttestationEvidence, TEEType} from "../../types/Evidence.sol";

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

    // ============================================================================
    // Functions
    // ============================================================================

    /// @notice Register a new CVM session after attestation verification
    /// @param evidence The attestation evidence bundle (contains TEE type and backend type)
    /// @param workloadId The workload identifier
    /// @param baseImageId The base image identifier
    /// @param platformProfileId The platform profile identifier
    /// @param variantId The measurement variant identifier
    /// @param ownerIdentity The public key identity of the session owner
    /// @param ownerSignature Signature over the session registration data by ownerIdentity
    /// @return sessionId The unique identifier for the registered session
    function registerSession(
        AttestationEvidence calldata evidence,
        bytes32 workloadId,
        bytes32 baseImageId,
        bytes32 platformProfileId,
        bytes32 variantId,
        PublicIdentity calldata ownerIdentity,
        bytes calldata ownerSignature
    ) external returns (bytes32 sessionId);

    /// @notice Get session data
    /// @param sessionId The session identifier
    /// @return session The complete session data
    function getSession(bytes32 sessionId) external view returns (CVMSession memory session);

    /// @notice Revoke a session (only by owner)
    /// @param sessionId The session identifier
    /// @param ownerIdentity The public key identity of the session owner
    /// @param ownerSignature Signature over the revocation request by ownerIdentity
    function revokeSession(bytes32 sessionId, PublicIdentity calldata ownerIdentity, bytes calldata ownerSignature)
        external;

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
}

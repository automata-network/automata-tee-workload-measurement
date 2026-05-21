// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";

/// @title TpmBase
/// @notice Base contract for TPM attestation verification with shared immutable reference
/// @dev Shared by contracts that need access to the Automata TPM attestation verifier.
abstract contract TpmBase {
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Immutables - TPM Attestation Contract
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice TPM attestation verifier contract from automata-tpm-attestation library
    ITpmAttestation public immutable tpmAttestation;

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // Constructor
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @notice Initializes the TpmBase with the TPM attestation contract
    /// @param _tpmAttestation Address of the TPM attestation verifier contract
    constructor(ITpmAttestation _tpmAttestation) {
        tpmAttestation = _tpmAttestation;
    }
}

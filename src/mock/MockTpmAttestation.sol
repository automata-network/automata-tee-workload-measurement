// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {ITpmAttestation, PcrValue} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {ICertChainRegistry} from "@automata-network/automata-tpm-attestation/interfaces/ICertChainRegistry.sol";
import {CertPubkey, LibX509} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {LibTpm} from "@automata-network/automata-tpm-attestation/lib/LibTpm.sol";

/// @title MockTpmAttestation
/// @notice Mock TPM attestation verifier for development/testing without real TPM hardware
/// @dev Skips cryptographic signature verification but still parses TPM structures correctly.
///      This allows the full SessionRegistry registration flow to work with mock-generated
///      TPM data that has valid structure but fake signatures.
contract MockTpmAttestation is ITpmAttestation {
    // ═══════════════════════════════════════════════════════════════════════════════════════
    // ITpmAttestation Implementation
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @inheritdoc ITpmAttestation
    function verifyTpmQuote(bytes calldata tpmQuote, bytes calldata, bytes[] calldata akCertchain)
        external
        returns (bool success, bytes memory akPubkey, bytes memory extraData)
    {
        // Skip signature verification, just parse the quote to extract extraData
        extraData = LibTpm.extractExtraData(tpmQuote);

        // Extract public key from leaf certificate if provided
        CertPubkey memory leafPubkey;
        if (akCertchain.length > 0) {
            leafPubkey = LibX509.getPubkey(akCertchain[0]);
        }

        return (true, abi.encode(leafPubkey), extraData);
    }

    /// @inheritdoc ITpmAttestation
    function verifyTpmQuoteWithTrustedAkPub(
        bytes calldata tpmQuote,
        bytes calldata,
        CertPubkey calldata
    ) external returns (bool success, bytes memory extraData) {
        // Skip signature verification, just extract extraData
        extraData = LibTpm.extractExtraData(tpmQuote);
        emit TpmSignatureVerified(keccak256(tpmQuote));
        return (true, extraData);
    }

    /// @inheritdoc ITpmAttestation
    function verifyTpmKeyCertification(
        bytes calldata certifyInfo,
        bytes calldata,
        bytes calldata tpmtPublic,
        CertPubkey calldata,
        uint32
    ) external pure returns (CertPubkey memory certifiedPubkey, bytes memory extraData) {
        // Skip signature verification but still extract certified key from tpmtPublic
        extraData = LibTpm.extractExtraData(certifyInfo);
        certifiedPubkey = LibTpm.extractCertPubkey(tpmtPublic);
    }

    /// @inheritdoc ITpmAttestation
    function extractExtraData(bytes calldata tpmQuote) external pure returns (bool success, bytes memory extraData) {
        extraData = LibTpm.extractExtraData(tpmQuote);
        success = true;
    }

    /// @inheritdoc ITpmAttestation
    function checkPcrMeasurements(bytes calldata tpmQuote, PcrValue[] calldata)
        external
        returns (bool success, bytes memory extraData)
    {
        // Skip actual PCR validation, just extract extraData
        extraData = LibTpm.extractExtraData(tpmQuote);
        emit TpmMeasurementChecked(keccak256(tpmQuote), bytes32(0), extraData);
        return (true, extraData);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // ICertChainRegistry Implementation (no-ops for mock)
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// @inheritdoc ICertChainRegistry
    function p256() external pure returns (address) {
        return address(0x100);
    }

    /// @inheritdoc ICertChainRegistry
    function addCA(bytes calldata) external {}

    /// @inheritdoc ICertChainRegistry
    function removeCA(bytes calldata) external {}

    /// @inheritdoc ICertChainRegistry
    function isCertificateRevoked(bytes calldata) external pure returns (bool) {
        return false;
    }

    /// @inheritdoc ICertChainRegistry
    function removeIntermediateCerts(bytes32[] calldata) external {}

    /// @inheritdoc ICertChainRegistry
    function updateCRL(bytes calldata, bytes calldata) external {}

    /// @inheritdoc ICertChainRegistry
    function verifyCertSignature(bytes calldata, CertPubkey memory) external pure returns (bool) {
        return true;
    }

    /// @inheritdoc ICertChainRegistry
    function verifyCertChain(bytes[] calldata certs) external returns (CertPubkey memory) {
        // Extract public key from leaf certificate
        if (certs.length > 0) {
            return LibX509.getPubkey(certs[0]);
        }
        return CertPubkey({algo: 0, params: 0, data: ""});
    }

    /// @inheritdoc ICertChainRegistry
    function verifiedCA(bytes32) external pure returns (bool) {
        return true;
    }
}

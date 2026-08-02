// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {
    PcrBankSelection,
    PcrBinding256,
    PcrBinding384,
    PcrSetEntry256,
    PcrSetEntry384,
    PcrSpec256,
    PcrSpec384,
    PcrVerifyType,
    ProviderPcrRequirements,
    PublicIdentity,
    ResolvedPcrPolicy
} from "../types/Common.sol";
import {
    PcrValue256,
    PcrValue384,
    TpmCertifyEvidence,
    TpmQuoteEvidence,
    TpmReport,
    TpmReportType,
    VerificationBackendType
} from "../types/Evidence.sol";
import {
    PCR_BINDING_SHA256_COMMITMENT_DOMAIN,
    PCR_BINDING_SHA384_COMMITMENT_DOMAIN,
    PCR_POLICY_SHA256_COMMITMENT_DOMAIN,
    PCR_POLICY_SHA384_COMMITMENT_DOMAIN,
    PCR_SET_SHA256_COMMITMENT_DOMAIN,
    PCR_SET_SHA384_COMMITMENT_DOMAIN
} from "../types/Constants.sol";
import {ProgramBoundZkProof, TpmQuoteJournalV1, ZkProofType} from "../types/Zk.sol";
import {IZkVerifierRegistry} from "../interfaces/registries/IZkVerifierRegistry.sol";
import {ITpmQuoteZkVerifierAdapter} from "../interfaces/zk/IZkVerifierAdapters.sol";
import {Bytes48, LibBytes} from "../lib/LibBytes.sol";
import {LibKey} from "../lib/LibKey.sol";
import {Sha2Ext} from "../lib/Sha2Ext.sol";
import {TpmBase} from "./TpmBase.sol";

struct TpmQuoteVerificationResult {
    bytes32 akPubFingerprint;
    bytes32 qualifyingData;
    bytes32 tpmSignatureHash;
    bytes32 sha256PolicyCommitment;
    bytes32 sha384PolicyCommitment;
    bytes32 sha256PcrBindingCommitment;
    bytes32 sha384PcrBindingCommitment;
    bytes32 sha256PcrSetCommitment;
    bytes32 sha384PcrSetCommitment;
}

struct TpmCertifyVerificationResult {
    bool valid;
    PublicIdentity certifiedKey;
    bytes32 certifiedKeyFingerprint;
}

struct QuoteSelection {
    bool sha256Present;
    bool sha384Present;
    uint32 sha256Mask;
    uint32 sha384Mask;
    bytes32 pcrDigest;
}

contract TpmVerifier is TpmBase {
    uint32 internal constant TPMA_OBJECT_REQUIRED_SET = 0x40072;
    uint32 internal constant TPMA_OBJECT_REQUIRED_CLEAR = 0xFFFBFB8D;

    uint16 private constant TPM_ALG_SHA256 = 0x000B;
    uint16 private constant TPM_ALG_SHA384 = 0x000C;
    uint32 private constant SUPPORTED_PCR_MASK = 0x0081FFFF;
    uint8 private constant NO_STARTUP_LOCALITY = 0xFF;

    IZkVerifierRegistry public immutable zkVerifierRegistry;

    error UnexpectedTpmReportType(TpmReportType actual, TpmReportType expected);
    error TpmReportBackendNotConfigured(TpmReportType tpmReportType, VerificationBackendType verificationBackendType);
    error TpmQuoteLibraryFailed();
    error TpmQuoteMalformed(uint256 offset, uint256 requiredLength, uint256 actualLength);
    error TpmQuoteTrailingBytes(uint256 parsedLength, uint256 actualLength);
    error TpmQuoteExtraDataLength(uint256 actualLength);
    error TpmQuoteExtraDataMismatch(bytes32 measured, bytes32 expected);
    error InvalidPcrSelectionCount(uint32 count);
    error InvalidPcrSelectionSize(uint8 size);
    error InvalidPcrBank(uint16 algorithm);
    error InvalidPcrBankOrder();
    error EmptyPcrSelection(uint16 algorithm);
    error UnsupportedPcrSelection(uint16 algorithm, uint32 mask);
    error PcrEvidenceCountMismatch(uint16 algorithm, uint256 actual, uint256 expected);
    error PcrEvidenceIndexMismatch(uint16 algorithm, uint256 position, uint8 actual, uint8 expected);
    error PcrDigestSizeMismatch(uint16 actual);
    error PcrDigestMismatch(bytes32 measured, bytes32 expected);
    error PcrEvaluationTargetNotSelected(uint16 algorithm, uint8 pcrIndex);
    error PcrValueNotFound(uint16 algorithm, uint8 pcrIndex);
    error InvalidPcrRule(uint16 algorithm, uint8 pcrIndex);
    error DynamicSha384PolicyRequiresZk(uint8 pcrIndex, PcrVerifyType verifyType);
    error InvalidPcr0StartupLocality(uint8 locality);
    error PcrReplayMismatch256(uint8 pcrIndex, bytes32 measured, bytes32 replayed);
    error PcrStaticMismatch256(uint8 pcrIndex, bytes32 measured, bytes32 expected);
    error PcrStaticMismatch384(uint8 pcrIndex, Bytes48 measured, Bytes48 expected);
    error PcrEventLogEmpty(uint16 algorithm, uint8 pcrIndex, PcrVerifyType verifyType);
    error PcrSubsetLandmarkMissing(uint16 algorithm, uint8 pcrIndex, uint256 landmarkIndex);
    error PcrSubsequenceLandmarkMissing(uint16 algorithm, uint8 pcrIndex, uint256 matched, uint256 required);
    error PcrRequirementsNotSorted(uint16 algorithm, uint8 previousIndex, uint8 currentIndex);
    error PcrRequirementOverlap(uint16 algorithm, uint8 pcrIndex);
    error PcrBindingMismatch256(uint8 pcrIndex, bytes32 measured, bytes32 expected);
    error PcrBindingMismatch384(uint8 pcrIndex, Bytes48 measured, Bytes48 expected);
    error AttestationKeyFingerprintMismatch(bytes32 measured, bytes32 expected);
    error QualifyingDataMismatch(bytes32 measured, bytes32 expected);
    error PcrPolicyCommitmentMismatch(uint16 algorithm, bytes32 measured, bytes32 expected);
    error PcrBindingCommitmentMismatch(uint16 algorithm, bytes32 measured, bytes32 expected);
    error PcrSetCommitmentMissing(uint16 algorithm);
    error UnexpectedPcrSetCommitment(uint16 algorithm, bytes32 measured);
    error TpmQuoteBackendDoesNotSatisfyPolicy(VerificationBackendType backend);
    error TpmaObjectForbiddenBitsSet(uint32 actualAttrs, uint32 forbiddenBitsSet);
    error TpmtPublicTooShort(uint256 length);

    constructor(ITpmAttestation tpmAttestation_, IZkVerifierRegistry zkVerifierRegistry_) TpmBase(tpmAttestation_) {
        zkVerifierRegistry = zkVerifierRegistry_;
    }

    function verifyTpmQuote(
        TpmReport memory tpmReport,
        PublicIdentity memory akPub,
        bytes32 expectedQualifyingData,
        ResolvedPcrPolicy memory policy,
        ProviderPcrRequirements memory providerRequirements
    ) public returns (TpmQuoteVerificationResult memory result) {
        if (tpmReport.tpmReportType != TpmReportType.TpmQuote) {
            revert UnexpectedTpmReportType(tpmReport.tpmReportType, TpmReportType.TpmQuote);
        }
        _requireQuoteBackendForPolicy(tpmReport.verificationBackendType, policy);

        if (tpmReport.verificationBackendType == VerificationBackendType.Solidity) {
            result = _verifyRawTpmQuote(tpmReport.data, akPub, expectedQualifyingData, policy, providerRequirements);
        } else if (tpmReport.verificationBackendType == VerificationBackendType.ZkSuccinct) {
            ProgramBoundZkProof memory proof = abi.decode(tpmReport.data, (ProgramBoundZkProof));
            address adapter = zkVerifierRegistry.resolveVerifierAdapter(
                ZkProofType.TpmQuote, tpmReport.verificationBackendType, proof.programIdentifier
            );
            TpmQuoteJournalV1 memory journal = ITpmQuoteZkVerifierAdapter(adapter).verifyProof(proof);
            result = TpmQuoteVerificationResult({
                akPubFingerprint: journal.akPubFingerprint,
                qualifyingData: journal.qualifyingData,
                tpmSignatureHash: journal.tpmSignatureHash,
                sha256PolicyCommitment: journal.sha256PolicyCommitment,
                sha384PolicyCommitment: journal.sha384PolicyCommitment,
                sha256PcrBindingCommitment: journal.sha256PcrBindingCommitment,
                sha384PcrBindingCommitment: journal.sha384PcrBindingCommitment,
                sha256PcrSetCommitment: journal.sha256PcrSetCommitment,
                sha384PcrSetCommitment: journal.sha384PcrSetCommitment
            });
        } else {
            revert TpmReportBackendNotConfigured(tpmReport.tpmReportType, tpmReport.verificationBackendType);
        }
        _verifyCommonQuoteResult(
            result, LibKey.computeKeyFingerprint(akPub), expectedQualifyingData, policy, providerRequirements
        );
    }

    function verifyTpmCertify(TpmReport memory tpmReport, PublicIdentity memory akPub)
        public
        view
        returns (TpmCertifyVerificationResult memory result)
    {
        if (tpmReport.tpmReportType != TpmReportType.TpmCertify) {
            revert UnexpectedTpmReportType(tpmReport.tpmReportType, TpmReportType.TpmCertify);
        }
        if (tpmReport.verificationBackendType != VerificationBackendType.Solidity) {
            revert TpmReportBackendNotConfigured(tpmReport.tpmReportType, tpmReport.verificationBackendType);
        }

        TpmCertifyEvidence memory certifyEvidence = abi.decode(tpmReport.data, (TpmCertifyEvidence));
        _validateClearBits(certifyEvidence.tpmtPublic);

        CertPubkey memory akCertPubkey = LibKey.publicIdentityToCertPubkey(akPub);
        (CertPubkey memory certifiedPubkey,) = tpmAttestation.verifyTpmKeyCertification(
            certifyEvidence.tpmsAttest,
            certifyEvidence.tpmSignature,
            certifyEvidence.tpmtPublic,
            akCertPubkey,
            TPMA_OBJECT_REQUIRED_SET
        );
        PublicIdentity memory certifiedKey = LibKey.certPubkeyToPublicIdentity(certifiedPubkey);
        result = TpmCertifyVerificationResult({
            valid: true, certifiedKey: certifiedKey, certifiedKeyFingerprint: LibKey.computeKeyFingerprint(certifiedKey)
        });
    }

    function _verifyRawTpmQuote(
        bytes memory encodedEvidence,
        PublicIdentity memory akPub,
        bytes32 expectedQualifyingData,
        ResolvedPcrPolicy memory policy,
        ProviderPcrRequirements memory providerRequirements
    ) private returns (TpmQuoteVerificationResult memory result) {
        TpmQuoteEvidence memory evidence = abi.decode(encodedEvidence, (TpmQuoteEvidence));
        CertPubkey memory akCertPubkey = LibKey.publicIdentityToCertPubkey(akPub);
        (bool success, bytes memory extraData) =
            tpmAttestation.verifyTpmQuoteWithTrustedAkPub(evidence.tpmsAttest, evidence.tpmSignature, akCertPubkey);
        if (!success) revert TpmQuoteLibraryFailed();
        if (extraData.length != 32) revert TpmQuoteExtraDataLength(extraData.length);
        bytes32 qualifyingData = LibBytes.readBytes32(extraData, 0);
        if (qualifyingData != expectedQualifyingData) {
            revert TpmQuoteExtraDataMismatch(qualifyingData, expectedQualifyingData);
        }

        QuoteSelection memory selection = _parseQuoteSelection(evidence.tpmsAttest);
        _validateStartupLocality(evidence.pcr0StartupLocality);
        _validateEvidenceAndDigest(evidence, selection);

        (uint32 targetMask256, uint32 targetMask384) = _evaluationTargetMasks(policy, providerRequirements);
        _requireTargetsSelected(selection, targetMask256, targetMask384);
        _evaluateSelectedPolicy(evidence, policy);
        _evaluateProviderBindings(evidence, providerRequirements);

        result = TpmQuoteVerificationResult({
            akPubFingerprint: LibKey.computeKeyFingerprint(akPub),
            qualifyingData: qualifyingData,
            tpmSignatureHash: keccak256(evidence.tpmSignature),
            sha256PolicyCommitment: computeSha256PolicyCommitment(policy),
            sha384PolicyCommitment: computeSha384PolicyCommitment(policy),
            sha256PcrBindingCommitment: computeSha256PcrBindingCommitment(providerRequirements),
            sha384PcrBindingCommitment: computeSha384PcrBindingCommitment(providerRequirements),
            sha256PcrSetCommitment: _sha256PcrSetCommitment(evidence.pcrValues256, targetMask256),
            sha384PcrSetCommitment: _sha384PcrSetCommitment(evidence.pcrValues384, targetMask384)
        });
    }

    function computeSha256PolicyCommitment(ResolvedPcrPolicy memory policy) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                PCR_POLICY_SHA256_COMMITMENT_DOMAIN,
                policy.baseImageId,
                policy.platformProfileId,
                policy.measurementVariantId,
                policy.workloadId,
                policy.pcrBankSelection,
                policy.invariants256,
                policy.variantPcrs256,
                policy.workloadPcrs256
            )
        );
    }

    function computeSha384PolicyCommitment(ResolvedPcrPolicy memory policy) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                PCR_POLICY_SHA384_COMMITMENT_DOMAIN,
                policy.baseImageId,
                policy.platformProfileId,
                policy.measurementVariantId,
                policy.workloadId,
                policy.pcrBankSelection,
                policy.invariants384,
                policy.variantPcrs384,
                policy.workloadPcrs384
            )
        );
    }

    function computeSha256PcrBindingCommitment(ProviderPcrRequirements memory requirements)
        public
        pure
        returns (bytes32)
    {
        _validateRequirements256(requirements.pcrBindings256, requirements.pcrJoinIndexes256);
        return keccak256(
            abi.encode(
                PCR_BINDING_SHA256_COMMITMENT_DOMAIN, requirements.pcrBindings256, requirements.pcrJoinIndexes256
            )
        );
    }

    function computeSha384PcrBindingCommitment(ProviderPcrRequirements memory requirements)
        public
        pure
        returns (bytes32)
    {
        _validateRequirements384(requirements.pcrBindings384, requirements.pcrJoinIndexes384);
        return keccak256(
            abi.encode(
                PCR_BINDING_SHA384_COMMITMENT_DOMAIN, requirements.pcrBindings384, requirements.pcrJoinIndexes384
            )
        );
    }

    function _verifyCommonQuoteResult(
        TpmQuoteVerificationResult memory result,
        bytes32 akPubFingerprint,
        bytes32 expectedQualifyingData,
        ResolvedPcrPolicy memory policy,
        ProviderPcrRequirements memory requirements
    ) private pure {
        if (result.akPubFingerprint != akPubFingerprint) {
            revert AttestationKeyFingerprintMismatch(result.akPubFingerprint, akPubFingerprint);
        }
        if (result.qualifyingData != expectedQualifyingData) {
            revert QualifyingDataMismatch(result.qualifyingData, expectedQualifyingData);
        }
        bytes32 expected256Policy = computeSha256PolicyCommitment(policy);
        bytes32 expected384Policy = computeSha384PolicyCommitment(policy);
        if (result.sha256PolicyCommitment != expected256Policy) {
            revert PcrPolicyCommitmentMismatch(0x000B, result.sha256PolicyCommitment, expected256Policy);
        }
        if (result.sha384PolicyCommitment != expected384Policy) {
            revert PcrPolicyCommitmentMismatch(0x000C, result.sha384PolicyCommitment, expected384Policy);
        }
        bytes32 expected256Binding = computeSha256PcrBindingCommitment(requirements);
        bytes32 expected384Binding = computeSha384PcrBindingCommitment(requirements);
        if (result.sha256PcrBindingCommitment != expected256Binding) {
            revert PcrBindingCommitmentMismatch(0x000B, result.sha256PcrBindingCommitment, expected256Binding);
        }
        if (result.sha384PcrBindingCommitment != expected384Binding) {
            revert PcrBindingCommitmentMismatch(0x000C, result.sha384PcrBindingCommitment, expected384Binding);
        }

        (bool hasTargets256, bool hasTargets384) = _hasEvaluationTargets(policy, requirements);
        _requirePcrSetCommitmentState(0x000B, result.sha256PcrSetCommitment, hasTargets256);
        _requirePcrSetCommitmentState(0x000C, result.sha384PcrSetCommitment, hasTargets384);
    }

    function _requireQuoteBackendForPolicy(VerificationBackendType backend, ResolvedPcrPolicy memory policy)
        private
        pure
    {
        if (backend == VerificationBackendType.Solidity && _hasDynamicSha384Policy(policy)) {
            revert TpmQuoteBackendDoesNotSatisfyPolicy(backend);
        }
    }

    function _hasDynamicSha384Policy(ResolvedPcrPolicy memory policy) private pure returns (bool) {
        if (policy.pcrBankSelection == PcrBankSelection.Sha256) return false;
        for (uint256 i; i < policy.invariants384.length; ++i) {
            if (uint8(policy.invariants384[i].verifyType) != 0) return true;
        }
        for (uint256 i; i < policy.variantPcrs384.length; ++i) {
            if (uint8(policy.variantPcrs384[i].verifyType) != 0) return true;
        }
        for (uint256 i; i < policy.workloadPcrs384.length; ++i) {
            if (uint8(policy.workloadPcrs384[i].verifyType) != 0) return true;
        }
        return false;
    }

    function _hasEvaluationTargets(ResolvedPcrPolicy memory policy, ProviderPcrRequirements memory requirements)
        private
        pure
        returns (bool hasTargets256, bool hasTargets384)
    {
        hasTargets256 = requirements.pcrBindings256.length != 0 || requirements.pcrJoinIndexes256.length != 0;
        hasTargets384 = requirements.pcrBindings384.length != 0 || requirements.pcrJoinIndexes384.length != 0;
        if (policy.pcrBankSelection != PcrBankSelection.Sha384) {
            hasTargets256 = hasTargets256 || policy.invariants256.length != 0 || policy.variantPcrs256.length != 0
                || policy.workloadPcrs256.length != 0;
        }
        if (policy.pcrBankSelection != PcrBankSelection.Sha256) {
            hasTargets384 = hasTargets384 || policy.invariants384.length != 0 || policy.variantPcrs384.length != 0
                || policy.workloadPcrs384.length != 0;
        }
    }

    function _requirePcrSetCommitmentState(uint16 algorithm, bytes32 commitment, bool hasTargets) private pure {
        if (hasTargets && commitment == bytes32(0)) revert PcrSetCommitmentMissing(algorithm);
        if (!hasTargets && commitment != bytes32(0)) revert UnexpectedPcrSetCommitment(algorithm, commitment);
    }

    function _parseQuoteSelection(bytes memory quote) private pure returns (QuoteSelection memory selection) {
        _requireAvailable(quote, 0, 10);
        uint16 qualifiedSignerLength = uint16(LibBytes.readBytes2(quote, 6));
        _requireAvailable(quote, 8 + qualifiedSignerLength, 2);
        uint16 extraDataLength = uint16(LibBytes.readBytes2(quote, 8 + qualifiedSignerLength));
        uint256 offset = 35 + uint256(qualifiedSignerLength) + uint256(extraDataLength);
        _requireAvailable(quote, offset, 4);
        uint32 count = uint32(LibBytes.readBytes4(quote, offset));
        if (count == 0 || count > 2) revert InvalidPcrSelectionCount(count);
        offset += 4;

        for (uint256 i; i < count; ++i) {
            _requireAvailable(quote, offset, 3);
            uint16 algorithm = uint16(LibBytes.readBytes2(quote, offset));
            uint8 size = uint8(quote[offset + 2]);
            if (size != 3) revert InvalidPcrSelectionSize(size);
            _requireAvailable(quote, offset + 3, size);
            uint32 mask = uint32(uint8(quote[offset + 3])) | (uint32(uint8(quote[offset + 4])) << 8)
                | (uint32(uint8(quote[offset + 5])) << 16);
            if (mask == 0) revert EmptyPcrSelection(algorithm);
            if ((mask & ~SUPPORTED_PCR_MASK) != 0) revert UnsupportedPcrSelection(algorithm, mask);

            if (algorithm == TPM_ALG_SHA256) {
                if (selection.sha256Present || selection.sha384Present) revert InvalidPcrBankOrder();
                selection.sha256Present = true;
                selection.sha256Mask = mask;
            } else if (algorithm == TPM_ALG_SHA384) {
                if (selection.sha384Present) revert InvalidPcrBankOrder();
                selection.sha384Present = true;
                selection.sha384Mask = mask;
            } else {
                revert InvalidPcrBank(algorithm);
            }
            offset += 3 + size;
        }

        _requireAvailable(quote, offset, 2);
        uint16 digestLength = uint16(LibBytes.readBytes2(quote, offset));
        if (digestLength != 32) revert PcrDigestSizeMismatch(digestLength);
        offset += 2;
        _requireAvailable(quote, offset, digestLength);
        selection.pcrDigest = LibBytes.readBytes32(quote, offset);
        offset += digestLength;
        if (offset != quote.length) revert TpmQuoteTrailingBytes(offset, quote.length);
    }

    function _validateEvidenceAndDigest(TpmQuoteEvidence memory evidence, QuoteSelection memory selection)
        private
        pure
    {
        uint256 expected256 = _populationCount(selection.sha256Mask);
        uint256 expected384 = _populationCount(selection.sha384Mask);
        if (evidence.pcrValues256.length != expected256) {
            revert PcrEvidenceCountMismatch(TPM_ALG_SHA256, evidence.pcrValues256.length, expected256);
        }
        if (evidence.pcrValues384.length != expected384) {
            revert PcrEvidenceCountMismatch(TPM_ALG_SHA384, evidence.pcrValues384.length, expected384);
        }

        bytes memory concatenated;
        uint256 position;
        for (uint8 index; index < 24; ++index) {
            if ((selection.sha256Mask & (uint32(1) << index)) != 0) {
                uint8 actual = evidence.pcrValues256[position].pcrIndex;
                if (actual != index) revert PcrEvidenceIndexMismatch(TPM_ALG_SHA256, position, actual, index);
                concatenated = bytes.concat(concatenated, abi.encodePacked(evidence.pcrValues256[position].value));
                ++position;
            }
        }
        position = 0;
        for (uint8 index; index < 24; ++index) {
            if ((selection.sha384Mask & (uint32(1) << index)) != 0) {
                uint8 actual = evidence.pcrValues384[position].pcrIndex;
                if (actual != index) revert PcrEvidenceIndexMismatch(TPM_ALG_SHA384, position, actual, index);
                concatenated = bytes.concat(concatenated, LibBytes.toBytes(evidence.pcrValues384[position].value));
                ++position;
            }
        }

        bytes32 expectedDigest = sha256(concatenated);
        if (selection.pcrDigest != expectedDigest) revert PcrDigestMismatch(selection.pcrDigest, expectedDigest);
    }

    function _evaluationTargetMasks(ResolvedPcrPolicy memory policy, ProviderPcrRequirements memory requirements)
        private
        pure
        returns (uint32 mask256, uint32 mask384)
    {
        if (policy.pcrBankSelection != PcrBankSelection.Sha384) {
            mask256 = _addRuleIndexes256(mask256, policy.invariants256);
            mask256 = _addRuleIndexes256(mask256, policy.variantPcrs256);
            mask256 = _addRuleIndexes256(mask256, policy.workloadPcrs256);
        }
        if (policy.pcrBankSelection != PcrBankSelection.Sha256) {
            mask384 = _addRuleIndexes384(mask384, policy.invariants384);
            mask384 = _addRuleIndexes384(mask384, policy.variantPcrs384);
            mask384 = _addRuleIndexes384(mask384, policy.workloadPcrs384);
        }

        _validateRequirements256(requirements.pcrBindings256, requirements.pcrJoinIndexes256);
        _validateRequirements384(requirements.pcrBindings384, requirements.pcrJoinIndexes384);
        for (uint256 i; i < requirements.pcrBindings256.length; ++i) {
            mask256 |= uint32(1) << requirements.pcrBindings256[i].pcrIndex;
        }
        for (uint256 i; i < requirements.pcrJoinIndexes256.length; ++i) {
            mask256 |= uint32(1) << requirements.pcrJoinIndexes256[i];
        }
        for (uint256 i; i < requirements.pcrBindings384.length; ++i) {
            mask384 |= uint32(1) << requirements.pcrBindings384[i].pcrIndex;
        }
        for (uint256 i; i < requirements.pcrJoinIndexes384.length; ++i) {
            mask384 |= uint32(1) << requirements.pcrJoinIndexes384[i];
        }
    }

    function _requireTargetsSelected(QuoteSelection memory selection, uint32 mask256, uint32 mask384) private pure {
        uint32 missing256 = mask256 & ~selection.sha256Mask;
        uint32 missing384 = mask384 & ~selection.sha384Mask;
        if (missing256 != 0) revert PcrEvaluationTargetNotSelected(TPM_ALG_SHA256, _firstSetIndex(missing256));
        if (missing384 != 0) revert PcrEvaluationTargetNotSelected(TPM_ALG_SHA384, _firstSetIndex(missing384));
    }

    function _evaluateSelectedPolicy(TpmQuoteEvidence memory evidence, ResolvedPcrPolicy memory policy) private pure {
        if (policy.pcrBankSelection != PcrBankSelection.Sha384) {
            _evaluateRules256(evidence.pcrValues256, policy.invariants256, evidence.pcr0StartupLocality);
            _evaluateRules256(evidence.pcrValues256, policy.variantPcrs256, evidence.pcr0StartupLocality);
            _evaluateRules256(evidence.pcrValues256, policy.workloadPcrs256, evidence.pcr0StartupLocality);
        }
        if (policy.pcrBankSelection != PcrBankSelection.Sha256) {
            _evaluateRules384(evidence.pcrValues384, policy.invariants384);
            _evaluateRules384(evidence.pcrValues384, policy.variantPcrs384);
            _evaluateRules384(evidence.pcrValues384, policy.workloadPcrs384);
        }
    }

    function _evaluateRules256(PcrValue256[] memory values, PcrSpec256[] memory rules, uint8 locality) private pure {
        for (uint256 i; i < rules.length; ++i) {
            PcrSpec256 memory rule = rules[i];
            PcrValue256 memory measured = _findValue256(values, rule.pcrIndex);
            _evaluateSinglePcr256(rule, measured, locality);
        }
    }

    function _evaluateSinglePcr256(PcrSpec256 memory rule, PcrValue256 memory measured, uint8 locality) internal pure {
        if (rule.verifyType == PcrVerifyType.STATIC) {
            if (rule.matchData.length != 1) revert InvalidPcrRule(TPM_ALG_SHA256, rule.pcrIndex);
            if (measured.value != rule.matchData[0]) {
                revert PcrStaticMismatch256(rule.pcrIndex, measured.value, rule.matchData[0]);
            }
            return;
        }
        if (measured.eventLogHashes.length == 0) {
            revert PcrEventLogEmpty(TPM_ALG_SHA256, rule.pcrIndex, rule.verifyType);
        }
        bytes32 replayed =
            rule.pcrIndex == 0 && locality != NO_STARTUP_LOCALITY ? bytes32(uint256(locality)) : bytes32(0);
        for (uint256 j; j < measured.eventLogHashes.length; ++j) {
            replayed = sha256(abi.encodePacked(replayed, measured.eventLogHashes[j]));
        }
        if (replayed != measured.value) revert PcrReplayMismatch256(rule.pcrIndex, measured.value, replayed);
        _evaluateLandmarks256(rule, measured.eventLogHashes);
    }

    function _evaluateLandmarks256(PcrSpec256 memory rule, bytes32[] memory events) private pure {
        if (rule.matchData.length == 0) revert InvalidPcrRule(TPM_ALG_SHA256, rule.pcrIndex);
        if (rule.verifyType == PcrVerifyType.DYNAMIC_SUBSET) {
            for (uint256 i; i < rule.matchData.length; ++i) {
                bool found;
                for (uint256 j; j < events.length; ++j) {
                    if (rule.matchData[i] == events[j]) {
                        found = true;
                        break;
                    }
                }
                if (!found) revert PcrSubsetLandmarkMissing(TPM_ALG_SHA256, rule.pcrIndex, i);
            }
        } else if (rule.verifyType == PcrVerifyType.DYNAMIC_SUBSEQUENCE) {
            uint256 matched;
            for (uint256 i; i < events.length && matched < rule.matchData.length; ++i) {
                if (events[i] == rule.matchData[matched]) ++matched;
            }
            if (matched != rule.matchData.length) {
                revert PcrSubsequenceLandmarkMissing(TPM_ALG_SHA256, rule.pcrIndex, matched, rule.matchData.length);
            }
        } else {
            revert InvalidPcrRule(TPM_ALG_SHA256, rule.pcrIndex);
        }
    }

    function _evaluateRules384(PcrValue384[] memory values, PcrSpec384[] memory rules) private pure {
        for (uint256 i; i < rules.length; ++i) {
            PcrSpec384 memory rule = rules[i];
            if (rule.verifyType != PcrVerifyType.STATIC) {
                revert DynamicSha384PolicyRequiresZk(rule.pcrIndex, rule.verifyType);
            }
            if (rule.matchData.length != 1) revert InvalidPcrRule(TPM_ALG_SHA384, rule.pcrIndex);
            PcrValue384 memory measured = _findValue384(values, rule.pcrIndex);
            if (!LibBytes.equal(measured.value, rule.matchData[0])) {
                revert PcrStaticMismatch384(rule.pcrIndex, measured.value, rule.matchData[0]);
            }
        }
    }

    function _evaluateProviderBindings(TpmQuoteEvidence memory evidence, ProviderPcrRequirements memory requirements)
        private
        pure
    {
        for (uint256 i; i < requirements.pcrBindings256.length; ++i) {
            PcrBinding256 memory binding = requirements.pcrBindings256[i];
            bytes32 measured = _findValue256(evidence.pcrValues256, binding.pcrIndex).value;
            if (measured != binding.expectedValue) {
                revert PcrBindingMismatch256(binding.pcrIndex, measured, binding.expectedValue);
            }
        }
        for (uint256 i; i < requirements.pcrBindings384.length; ++i) {
            PcrBinding384 memory binding = requirements.pcrBindings384[i];
            Bytes48 memory measured = _findValue384(evidence.pcrValues384, binding.pcrIndex).value;
            if (!LibBytes.equal(measured, binding.expectedValue)) {
                revert PcrBindingMismatch384(binding.pcrIndex, measured, binding.expectedValue);
            }
        }
    }

    function _sha256PcrSetCommitment(PcrValue256[] memory values, uint32 targetMask) private pure returns (bytes32) {
        if (targetMask == 0) return bytes32(0);
        PcrSetEntry256[] memory entries = new PcrSetEntry256[](_populationCount(targetMask));
        uint256 position;
        for (uint8 index; index < 24; ++index) {
            if ((targetMask & (uint32(1) << index)) != 0) {
                entries[position] = PcrSetEntry256({pcrIndex: index, value: _findValue256(values, index).value});
                ++position;
            }
        }
        return keccak256(abi.encode(PCR_SET_SHA256_COMMITMENT_DOMAIN, entries));
    }

    function _sha384PcrSetCommitment(PcrValue384[] memory values, uint32 targetMask) private pure returns (bytes32) {
        if (targetMask == 0) return bytes32(0);
        PcrSetEntry384[] memory entries = new PcrSetEntry384[](_populationCount(targetMask));
        uint256 position;
        for (uint8 index; index < 24; ++index) {
            if ((targetMask & (uint32(1) << index)) != 0) {
                entries[position] = PcrSetEntry384({pcrIndex: index, value: _findValue384(values, index).value});
                ++position;
            }
        }
        return keccak256(abi.encode(PCR_SET_SHA384_COMMITMENT_DOMAIN, entries));
    }

    function _validateRequirements256(PcrBinding256[] memory bindings, uint8[] memory joins) private pure {
        uint32 bindingMask;
        for (uint256 i; i < bindings.length; ++i) {
            uint8 index = bindings[i].pcrIndex;
            _requireSupportedIndex(TPM_ALG_SHA256, index);
            if (i != 0 && index <= bindings[i - 1].pcrIndex) {
                revert PcrRequirementsNotSorted(TPM_ALG_SHA256, bindings[i - 1].pcrIndex, index);
            }
            bindingMask |= uint32(1) << index;
        }
        for (uint256 i; i < joins.length; ++i) {
            uint8 index = joins[i];
            _requireSupportedIndex(TPM_ALG_SHA256, index);
            if (i != 0 && index <= joins[i - 1]) {
                revert PcrRequirementsNotSorted(TPM_ALG_SHA256, joins[i - 1], index);
            }
            if ((bindingMask & (uint32(1) << index)) != 0) revert PcrRequirementOverlap(TPM_ALG_SHA256, index);
        }
    }

    function _validateRequirements384(PcrBinding384[] memory bindings, uint8[] memory joins) private pure {
        uint32 bindingMask;
        for (uint256 i; i < bindings.length; ++i) {
            uint8 index = bindings[i].pcrIndex;
            _requireSupportedIndex(TPM_ALG_SHA384, index);
            if (i != 0 && index <= bindings[i - 1].pcrIndex) {
                revert PcrRequirementsNotSorted(TPM_ALG_SHA384, bindings[i - 1].pcrIndex, index);
            }
            bindingMask |= uint32(1) << index;
        }
        for (uint256 i; i < joins.length; ++i) {
            uint8 index = joins[i];
            _requireSupportedIndex(TPM_ALG_SHA384, index);
            if (i != 0 && index <= joins[i - 1]) {
                revert PcrRequirementsNotSorted(TPM_ALG_SHA384, joins[i - 1], index);
            }
            if ((bindingMask & (uint32(1) << index)) != 0) revert PcrRequirementOverlap(TPM_ALG_SHA384, index);
        }
    }

    function _addRuleIndexes256(uint32 mask, PcrSpec256[] memory rules) private pure returns (uint32) {
        for (uint256 i; i < rules.length; ++i) {
            _requireSupportedIndex(TPM_ALG_SHA256, rules[i].pcrIndex);
            mask |= uint32(1) << rules[i].pcrIndex;
        }
        return mask;
    }

    function _addRuleIndexes384(uint32 mask, PcrSpec384[] memory rules) private pure returns (uint32) {
        for (uint256 i; i < rules.length; ++i) {
            _requireSupportedIndex(TPM_ALG_SHA384, rules[i].pcrIndex);
            mask |= uint32(1) << rules[i].pcrIndex;
        }
        return mask;
    }

    function _findValue256(PcrValue256[] memory values, uint8 index) private pure returns (PcrValue256 memory) {
        for (uint256 i; i < values.length; ++i) {
            if (values[i].pcrIndex == index) return values[i];
        }
        revert PcrValueNotFound(TPM_ALG_SHA256, index);
    }

    function _findValue384(PcrValue384[] memory values, uint8 index) private pure returns (PcrValue384 memory) {
        for (uint256 i; i < values.length; ++i) {
            if (values[i].pcrIndex == index) return values[i];
        }
        revert PcrValueNotFound(TPM_ALG_SHA384, index);
    }

    function _validateStartupLocality(uint8 locality) private pure {
        if (locality != NO_STARTUP_LOCALITY && locality > 4) revert InvalidPcr0StartupLocality(locality);
    }

    function _requireSupportedIndex(uint16 algorithm, uint8 index) private pure {
        if (index >= 24 || (SUPPORTED_PCR_MASK & (uint32(1) << index)) == 0) {
            revert UnsupportedPcrSelection(algorithm, uint32(1) << index);
        }
    }

    function _populationCount(uint32 mask) private pure returns (uint256 count) {
        while (mask != 0) {
            count += mask & 1;
            mask >>= 1;
        }
    }

    function _firstSetIndex(uint32 mask) private pure returns (uint8 index) {
        while ((mask & 1) == 0) {
            ++index;
            mask >>= 1;
        }
    }

    function _requireAvailable(bytes memory data, uint256 offset, uint256 length) private pure {
        if (offset > data.length || length > data.length - offset) {
            revert TpmQuoteMalformed(offset, length, data.length);
        }
    }

    function _validateClearBits(bytes memory tpmtPublic) private pure {
        if (tpmtPublic.length < 8) revert TpmtPublicTooShort(tpmtPublic.length);
        uint32 attributes = uint32(LibBytes.readBytes4(tpmtPublic, 4));
        uint32 forbidden = attributes & TPMA_OBJECT_REQUIRED_CLEAR;
        if (forbidden != 0) revert TpmaObjectForbiddenBitsSet(attributes, forbidden);
    }
}

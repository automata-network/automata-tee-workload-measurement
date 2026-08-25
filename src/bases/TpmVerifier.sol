// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {
    PcrBankSelection,
    PcrCommitment,
    PcrPolicyBlock,
    PcrSpec256,
    PcrSpec384,
    PublicIdentity,
    TpmVerificationRequest
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
import {ProgramBoundZkProof, TpmQuoteJournalV1, ZkProofType} from "../types/Zk.sol";
import {IZkVerifierRegistry} from "../interfaces/registries/IZkVerifierRegistry.sol";
import {ITpmQuoteZkVerifierAdapter} from "../interfaces/zk/IZkVerifierAdapters.sol";
import {Bytes48, LibBytes} from "../lib/LibBytes.sol";
import {PcrComparison} from "../lib/PcrComparison.sol";
import {PcrPolicy} from "../lib/PcrPolicy.sol";
import {LibKey} from "../lib/LibKey.sol";
import {TpmBase} from "./TpmBase.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

struct TpmQuoteVerificationResult {
    bytes32 akPubFingerprint;
    bytes32 qualifyingData;
    bytes32 tpmSignatureHash;
    PcrCommitment pcrCommitment;
    bytes32 policyCommitment;
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
    bytes3 sha256Bitmap;
    bytes3 sha384Bitmap;
    bytes32 pcrSelect;
    bytes32 pcrDigest;
}

contract TpmVerifier is TpmBase, OwnableUpgradeable, UUPSUpgradeable {
    uint32 internal constant TPMA_OBJECT_REQUIRED_SET = 0x40072;
    uint32 internal constant TPMA_OBJECT_REQUIRED_CLEAR = 0xFFFBFB8D;

    uint16 private constant TPM_ALG_SHA256 = 0x000B;
    uint16 private constant TPM_ALG_SHA384 = 0x000C;
    uint32 private constant SUPPORTED_PCR_MASK = 0x0081FFFF;
    uint8 private constant NO_STARTUP_LOCALITY = 0xFF;

    IZkVerifierRegistry public immutable zkVerifierRegistry;

    uint256[50] private __gap;

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
    error PcrSelectionMismatch(uint16 algorithm, uint32 actualMask, uint32 expectedMask);
    error PcrValueNotFound(uint16 algorithm, uint8 pcrIndex);
    error InvalidPcrRule(uint16 algorithm, uint8 pcrIndex);
    error InvalidPcrComparisonType(uint16 algorithm, uint8 pcrIndex, uint256 encodedType);
    error UnsupportedPcrComparison(uint16 algorithm, uint8 pcrIndex, uint16 comparisonType);
    error NonCanonicalPcrComparison(uint16 algorithm, uint8 pcrIndex);
    error DynamicSha384PolicyRequiresZk(uint8 pcrIndex, uint16 comparisonType);
    error InvalidPcr0StartupLocality(uint8 locality);
    error PcrReplayMismatch256(uint8 pcrIndex, bytes32 measured, bytes32 replayed);
    error PcrStaticMismatch256(uint8 pcrIndex, bytes32 measured, bytes32 expected);
    error PcrStaticMismatch384(uint8 pcrIndex, Bytes48 measured, Bytes48 expected);
    error PcrEventLogEmpty(uint16 algorithm, uint8 pcrIndex, uint16 comparisonType);
    error PcrSubsetLandmarkMissing(uint16 algorithm, uint8 pcrIndex, uint256 landmarkIndex);
    error PcrSubsequenceLandmarkMissing(uint16 algorithm, uint8 pcrIndex, uint256 matched, uint256 required);
    error PcrEventCountMismatch(uint16 algorithm, uint8 pcrIndex, uint256 actual, uint16 expected);
    error PcrCheckedEventsEmpty(uint16 algorithm, uint8 pcrIndex);
    error PcrCheckedEventIndexOutOfRange(uint16 algorithm, uint8 pcrIndex, uint16 eventIndex, uint16 eventCount);
    error PcrCheckedEventIndexesNotSorted(uint16 algorithm, uint8 pcrIndex, uint16 previous, uint16 current);
    error PcrAllowedValuesEmpty(uint16 algorithm, uint8 pcrIndex, uint16 eventIndex);
    error PcrAllowedValuesNotSorted(uint16 algorithm, uint8 pcrIndex, uint16 eventIndex, uint256 position);
    error PcrIndexedEventSetMismatch(uint16 algorithm, uint8 pcrIndex, uint16 eventIndex);
    error AttestationKeyFingerprintMismatch(bytes32 measured, bytes32 expected);
    error QualifyingDataMismatch(bytes32 measured, bytes32 expected);
    error PolicyCommitmentMismatch(bytes32 measured, bytes32 expected);
    error PcrSelectCommitmentMismatch(bytes32 measured, bytes32 expected);
    error TpmQuoteBackendDoesNotSatisfyPolicy(VerificationBackendType backend);
    error TpmaObjectForbiddenBitsSet(uint32 actualAttrs, uint32 forbiddenBitsSet);
    error TpmtPublicTooShort(uint256 length);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(ITpmAttestation tpmAttestation_, IZkVerifierRegistry zkVerifierRegistry_) TpmBase(tpmAttestation_) {
        zkVerifierRegistry = zkVerifierRegistry_;
        _disableInitializers();
    }

    function initialize(address initialOwner) external initializer {
        __Ownable_init(initialOwner);
    }

    function verifyTpmQuote(
        TpmReport memory tpmReport,
        PublicIdentity memory akPub,
        bytes32 expectedQualifyingData,
        TpmVerificationRequest memory request,
        bytes32 expectedPolicyCommitment,
        bytes32 expectedPcrSelect
    ) public returns (TpmQuoteVerificationResult memory result) {
        if (tpmReport.tpmReportType != TpmReportType.TpmQuote) {
            revert UnexpectedTpmReportType(tpmReport.tpmReportType, TpmReportType.TpmQuote);
        }
        _requireQuoteBackendForRequest(tpmReport.verificationBackendType, request);

        if (tpmReport.verificationBackendType == VerificationBackendType.Solidity) {
            result = _verifyRawTpmQuote(
                tpmReport.data, akPub, expectedQualifyingData, request, expectedPolicyCommitment, expectedPcrSelect
            );
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
                pcrCommitment: journal.pcrCommitment,
                policyCommitment: journal.policyCommitment
            });
        } else {
            revert TpmReportBackendNotConfigured(tpmReport.tpmReportType, tpmReport.verificationBackendType);
        }
        _verifyCommonQuoteResult(
            result,
            LibKey.computeKeyFingerprint(akPub),
            expectedQualifyingData,
            expectedPolicyCommitment,
            expectedPcrSelect
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
        TpmVerificationRequest memory request,
        bytes32 expectedPolicyCommitment,
        bytes32 expectedPcrSelect
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

        (uint32 targetMask256, uint32 targetMask384) = _evaluationTargetMasks(request);
        _requireExactSelection(selection, targetMask256, targetMask384);
        _evaluateRequest(evidence, request);

        result = TpmQuoteVerificationResult({
            akPubFingerprint: LibKey.computeKeyFingerprint(akPub),
            qualifyingData: qualifyingData,
            tpmSignatureHash: keccak256(evidence.tpmSignature),
            pcrCommitment: PcrCommitment({pcrSelect: selection.pcrSelect, pcrDigest: selection.pcrDigest}),
            policyCommitment: expectedPolicyCommitment
        });
        if (selection.pcrSelect != expectedPcrSelect) {
            revert PcrSelectCommitmentMismatch(selection.pcrSelect, expectedPcrSelect);
        }
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function computePolicyCommitment(
        bytes32 invariantBlockHash,
        bytes32 variantBlockHash,
        bytes32 workloadBlockHash,
        bytes32 providerBlockHash
    ) public pure returns (bytes32) {
        return PcrPolicy.policyCommitment(invariantBlockHash, variantBlockHash, workloadBlockHash, providerBlockHash);
    }

    function _verifyCommonQuoteResult(
        TpmQuoteVerificationResult memory result,
        bytes32 akPubFingerprint,
        bytes32 expectedQualifyingData,
        bytes32 expectedPolicyCommitment,
        bytes32 expectedPcrSelect
    ) private pure {
        if (result.akPubFingerprint != akPubFingerprint) {
            revert AttestationKeyFingerprintMismatch(result.akPubFingerprint, akPubFingerprint);
        }
        if (result.qualifyingData != expectedQualifyingData) {
            revert QualifyingDataMismatch(result.qualifyingData, expectedQualifyingData);
        }
        if (result.policyCommitment != expectedPolicyCommitment) {
            revert PolicyCommitmentMismatch(result.policyCommitment, expectedPolicyCommitment);
        }
        if (result.pcrCommitment.pcrSelect != expectedPcrSelect) {
            revert PcrSelectCommitmentMismatch(result.pcrCommitment.pcrSelect, expectedPcrSelect);
        }
    }

    function _requireQuoteBackendForRequest(VerificationBackendType backend, TpmVerificationRequest memory request)
        private
        pure
    {
        if (backend == VerificationBackendType.Solidity && _hasZkOnlySha384Rule(request)) {
            revert TpmQuoteBackendDoesNotSatisfyPolicy(backend);
        }
    }

    function _hasZkOnlySha384Rule(TpmVerificationRequest memory request) private pure returns (bool) {
        if (request.pcrBankSelection == PcrBankSelection.Sha256) return false;
        return _blockHasZkOnlySha384Rule(request.invariantPcrPolicy)
            || _blockHasZkOnlySha384Rule(request.variantPcrPolicy)
            || _blockHasZkOnlySha384Rule(request.workloadPcrPolicy)
            || _blockHasZkOnlySha384Rule(request.providerPcrPolicy);
    }

    function _blockHasZkOnlySha384Rule(PcrPolicyBlock memory policyBlock) private pure returns (bool) {
        for (uint256 i; i < policyBlock.pcrSpecs384.length; ++i) {
            PcrSpec384 memory pcrSpec = policyBlock.pcrSpecs384[i];
            if (_comparisonType(TPM_ALG_SHA384, pcrSpec.pcrIndex, pcrSpec.comparison) != PcrComparison.STATIC) {
                return true;
            }
        }
        return false;
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
            bytes3 bitmap = bytes3(
                (uint24(uint8(quote[offset + 3])) << 16) | (uint24(uint8(quote[offset + 4])) << 8)
                    | uint24(uint8(quote[offset + 5]))
            );
            if (mask == 0) revert EmptyPcrSelection(algorithm);
            if ((mask & ~SUPPORTED_PCR_MASK) != 0) revert UnsupportedPcrSelection(algorithm, mask);

            if (algorithm == TPM_ALG_SHA256) {
                if (selection.sha256Present || selection.sha384Present) revert InvalidPcrBankOrder();
                selection.sha256Present = true;
                selection.sha256Mask = mask;
                selection.sha256Bitmap = bitmap;
            } else if (algorithm == TPM_ALG_SHA384) {
                if (selection.sha384Present) revert InvalidPcrBankOrder();
                selection.sha384Present = true;
                selection.sha384Mask = mask;
                selection.sha384Bitmap = bitmap;
            } else {
                revert InvalidPcrBank(algorithm);
            }
            offset += 3 + size;
        }

        selection.pcrSelect = PcrPolicy.packPcrSelect(selection.sha256Bitmap, selection.sha384Bitmap);

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

    function _evaluationTargetMasks(TpmVerificationRequest memory request)
        private
        pure
        returns (uint32 mask256, uint32 mask384)
    {
        if (request.pcrBankSelection != PcrBankSelection.Sha384) {
            mask256 = _addBlockRuleIndexes256(mask256, request.invariantPcrPolicy);
            mask256 = _addBlockRuleIndexes256(mask256, request.variantPcrPolicy);
            mask256 = _addBlockRuleIndexes256(mask256, request.workloadPcrPolicy);
            mask256 = _addBlockRuleIndexes256(mask256, request.providerPcrPolicy);
        }
        if (request.pcrBankSelection != PcrBankSelection.Sha256) {
            mask384 = _addBlockRuleIndexes384(mask384, request.invariantPcrPolicy);
            mask384 = _addBlockRuleIndexes384(mask384, request.variantPcrPolicy);
            mask384 = _addBlockRuleIndexes384(mask384, request.workloadPcrPolicy);
            mask384 = _addBlockRuleIndexes384(mask384, request.providerPcrPolicy);
        }
    }

    function _requireExactSelection(QuoteSelection memory selection, uint32 mask256, uint32 mask384) private pure {
        if (selection.sha256Mask != mask256 || selection.sha256Present != (mask256 != 0)) {
            revert PcrSelectionMismatch(TPM_ALG_SHA256, selection.sha256Mask, mask256);
        }
        if (selection.sha384Mask != mask384 || selection.sha384Present != (mask384 != 0)) {
            revert PcrSelectionMismatch(TPM_ALG_SHA384, selection.sha384Mask, mask384);
        }
    }

    function _evaluateRequest(TpmQuoteEvidence memory evidence, TpmVerificationRequest memory request) private pure {
        if (request.pcrBankSelection != PcrBankSelection.Sha384) {
            _evaluateRules256(
                evidence.pcrValues256, request.invariantPcrPolicy.pcrSpecs256, evidence.pcr0StartupLocality
            );
            _evaluateRules256(evidence.pcrValues256, request.variantPcrPolicy.pcrSpecs256, evidence.pcr0StartupLocality);
            _evaluateRules256(
                evidence.pcrValues256, request.workloadPcrPolicy.pcrSpecs256, evidence.pcr0StartupLocality
            );
            _evaluateRules256(
                evidence.pcrValues256, request.providerPcrPolicy.pcrSpecs256, evidence.pcr0StartupLocality
            );
        }
        if (request.pcrBankSelection != PcrBankSelection.Sha256) {
            _evaluateRules384(evidence.pcrValues384, request.invariantPcrPolicy.pcrSpecs384);
            _evaluateRules384(evidence.pcrValues384, request.variantPcrPolicy.pcrSpecs384);
            _evaluateRules384(evidence.pcrValues384, request.workloadPcrPolicy.pcrSpecs384);
            _evaluateRules384(evidence.pcrValues384, request.providerPcrPolicy.pcrSpecs384);
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
        uint16 comparisonType = _comparisonType(TPM_ALG_SHA256, rule.pcrIndex, rule.comparison);
        if (comparisonType == PcrComparison.STATIC) {
            (uint16 decodedType, bytes32 expected) = abi.decode(rule.comparison, (uint16, bytes32));
            _requireCanonicalComparison(
                TPM_ALG_SHA256, rule.pcrIndex, rule.comparison, abi.encode(decodedType, expected)
            );
            if (measured.value != expected) revert PcrStaticMismatch256(rule.pcrIndex, measured.value, expected);
            return;
        }
        if (comparisonType == PcrComparison.EXTEND_FROM_ZERO) {
            (uint16 decodedType, bytes32 extendValue) = abi.decode(rule.comparison, (uint16, bytes32));
            _requireCanonicalComparison(
                TPM_ALG_SHA256, rule.pcrIndex, rule.comparison, abi.encode(decodedType, extendValue)
            );
            bytes32 expected = sha256(abi.encodePacked(bytes32(0), extendValue));
            if (measured.value != expected) revert PcrStaticMismatch256(rule.pcrIndex, measured.value, expected);
            return;
        }
        if (measured.eventLogHashes.length == 0) {
            revert PcrEventLogEmpty(TPM_ALG_SHA256, rule.pcrIndex, comparisonType);
        }
        bytes32 replayed =
            rule.pcrIndex == 0 && locality != NO_STARTUP_LOCALITY ? bytes32(uint256(locality)) : bytes32(0);
        for (uint256 j; j < measured.eventLogHashes.length; ++j) {
            replayed = sha256(abi.encodePacked(replayed, measured.eventLogHashes[j]));
        }
        if (replayed != measured.value) revert PcrReplayMismatch256(rule.pcrIndex, measured.value, replayed);
        _evaluateDynamicComparison256(rule, comparisonType, measured.eventLogHashes);
    }

    function _evaluateDynamicComparison256(PcrSpec256 memory rule, uint16 comparisonType, bytes32[] memory events)
        private
        pure
    {
        if (comparisonType == PcrComparison.DYNAMIC_SUBSET) {
            (uint16 decodedType, bytes32[] memory landmarks) = abi.decode(rule.comparison, (uint16, bytes32[]));
            _requireCanonicalComparison(
                TPM_ALG_SHA256, rule.pcrIndex, rule.comparison, abi.encode(decodedType, landmarks)
            );
            if (landmarks.length == 0) revert InvalidPcrRule(TPM_ALG_SHA256, rule.pcrIndex);
            for (uint256 i; i < landmarks.length; ++i) {
                bool found;
                for (uint256 j; j < events.length; ++j) {
                    if (landmarks[i] == events[j]) {
                        found = true;
                        break;
                    }
                }
                if (!found) revert PcrSubsetLandmarkMissing(TPM_ALG_SHA256, rule.pcrIndex, i);
            }
        } else if (comparisonType == PcrComparison.DYNAMIC_SUBSEQUENCE) {
            (uint16 decodedType, bytes32[] memory landmarks) = abi.decode(rule.comparison, (uint16, bytes32[]));
            _requireCanonicalComparison(
                TPM_ALG_SHA256, rule.pcrIndex, rule.comparison, abi.encode(decodedType, landmarks)
            );
            if (landmarks.length == 0) revert InvalidPcrRule(TPM_ALG_SHA256, rule.pcrIndex);
            uint256 matched;
            for (uint256 i; i < events.length && matched < landmarks.length; ++i) {
                if (events[i] == landmarks[matched]) ++matched;
            }
            if (matched != landmarks.length) {
                revert PcrSubsequenceLandmarkMissing(TPM_ALG_SHA256, rule.pcrIndex, matched, landmarks.length);
            }
        } else if (comparisonType == PcrComparison.DYNAMIC_INDEXED_EVENT_SETS) {
            (uint16 decodedType, PcrComparison.IndexedEventSets256 memory indexedRule) =
                abi.decode(rule.comparison, (uint16, PcrComparison.IndexedEventSets256));
            _requireCanonicalComparison(
                TPM_ALG_SHA256, rule.pcrIndex, rule.comparison, abi.encode(decodedType, indexedRule)
            );
            _evaluateIndexedEventSets256(rule.pcrIndex, events, indexedRule);
        } else {
            revert UnsupportedPcrComparison(TPM_ALG_SHA256, rule.pcrIndex, comparisonType);
        }
    }

    function _evaluateRules384(PcrValue384[] memory values, PcrSpec384[] memory rules) private pure {
        for (uint256 i; i < rules.length; ++i) {
            PcrSpec384 memory rule = rules[i];
            uint16 comparisonType = _comparisonType(TPM_ALG_SHA384, rule.pcrIndex, rule.comparison);
            if (comparisonType != PcrComparison.STATIC) {
                revert DynamicSha384PolicyRequiresZk(rule.pcrIndex, comparisonType);
            }
            (uint16 decodedType, Bytes48 memory expected) = abi.decode(rule.comparison, (uint16, Bytes48));
            _requireCanonicalComparison(
                TPM_ALG_SHA384, rule.pcrIndex, rule.comparison, abi.encode(decodedType, expected)
            );
            PcrValue384 memory measured = _findValue384(values, rule.pcrIndex);
            if (!LibBytes.equal(measured.value, expected)) {
                revert PcrStaticMismatch384(rule.pcrIndex, measured.value, expected);
            }
        }
    }

    function _evaluateIndexedEventSets256(
        uint8 pcrIndex,
        bytes32[] memory events,
        PcrComparison.IndexedEventSets256 memory rule
    ) private pure {
        if (events.length != rule.expectedEventCount) {
            revert PcrEventCountMismatch(TPM_ALG_SHA256, pcrIndex, events.length, rule.expectedEventCount);
        }
        if (rule.checkedEvents.length == 0) revert PcrCheckedEventsEmpty(TPM_ALG_SHA256, pcrIndex);

        uint16 previousIndex;
        for (uint256 i; i < rule.checkedEvents.length; ++i) {
            PcrComparison.IndexedEventSet256 memory checked = rule.checkedEvents[i];
            if (checked.eventIndex >= rule.expectedEventCount) {
                revert PcrCheckedEventIndexOutOfRange(
                    TPM_ALG_SHA256, pcrIndex, checked.eventIndex, rule.expectedEventCount
                );
            }
            if (i != 0 && checked.eventIndex <= previousIndex) {
                revert PcrCheckedEventIndexesNotSorted(TPM_ALG_SHA256, pcrIndex, previousIndex, checked.eventIndex);
            }
            if (checked.allowedValues.length == 0) {
                revert PcrAllowedValuesEmpty(TPM_ALG_SHA256, pcrIndex, checked.eventIndex);
            }

            bool matched;
            for (uint256 j; j < checked.allowedValues.length; ++j) {
                if (j != 0 && uint256(checked.allowedValues[j]) <= uint256(checked.allowedValues[j - 1])) {
                    revert PcrAllowedValuesNotSorted(TPM_ALG_SHA256, pcrIndex, checked.eventIndex, j);
                }
                if (events[checked.eventIndex] == checked.allowedValues[j]) matched = true;
            }
            if (!matched) revert PcrIndexedEventSetMismatch(TPM_ALG_SHA256, pcrIndex, checked.eventIndex);
            previousIndex = checked.eventIndex;
        }
    }

    function _comparisonType(uint16 algorithm, uint8 pcrIndex, bytes memory comparison)
        private
        pure
        returns (uint16 comparisonType)
    {
        if (comparison.length < 32) revert InvalidPcrRule(algorithm, pcrIndex);
        uint256 encodedType;
        assembly ("memory-safe") {
            encodedType := mload(add(comparison, 0x20))
        }
        if (encodedType > type(uint16).max) revert InvalidPcrComparisonType(algorithm, pcrIndex, encodedType);
        comparisonType = uint16(encodedType);
    }

    function _requireCanonicalComparison(
        uint16 algorithm,
        uint8 pcrIndex,
        bytes memory supplied,
        bytes memory canonical
    ) private pure {
        if (supplied.length != canonical.length || keccak256(supplied) != keccak256(canonical)) {
            revert NonCanonicalPcrComparison(algorithm, pcrIndex);
        }
    }

    function _addRuleIndexes256(uint32 mask, PcrSpec256[] memory rules) private pure returns (uint32) {
        for (uint256 i; i < rules.length; ++i) {
            _requireSupportedIndex(TPM_ALG_SHA256, rules[i].pcrIndex);
            mask |= uint32(1) << rules[i].pcrIndex;
        }
        return mask;
    }

    function _addBlockRuleIndexes256(uint32 mask, PcrPolicyBlock memory policyBlock) private pure returns (uint32) {
        return _addRuleIndexes256(mask, policyBlock.pcrSpecs256);
    }

    function _addRuleIndexes384(uint32 mask, PcrSpec384[] memory rules) private pure returns (uint32) {
        for (uint256 i; i < rules.length; ++i) {
            _requireSupportedIndex(TPM_ALG_SHA384, rules[i].pcrIndex);
            mask |= uint32(1) << rules[i].pcrIndex;
        }
        return mask;
    }

    function _addBlockRuleIndexes384(uint32 mask, PcrPolicyBlock memory policyBlock) private pure returns (uint32) {
        return _addRuleIndexes384(mask, policyBlock.pcrSpecs384);
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

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {ZkVerifierRegistry} from "../src/ZkVerifierRegistry.sol";
import {IZkVerifierRegistry} from "../src/interfaces/registries/IZkVerifierRegistry.sol";
import {ISp1Verifier} from "../src/interfaces/zk/IZkVerifierAdapters.sol";
import {VerificationBackendType} from "../src/types/Evidence.sol";
import {PcrCommitment} from "../src/types/Common.sol";
import {
    AwsNitroTpmJournalV1,
    ProgramBoundZkProof,
    TpmQuoteJournalV1,
    ZkProgramConfig,
    ZkProofType
} from "../src/types/Zk.sol";
import {
    AwsNitroTpmZkVerifierAdapter,
    CanonicalSp1VerifierAdapter,
    TpmQuoteZkVerifierAdapter
} from "../src/zk/ZkVerifierAdapters.sol";

contract MockSp1Verifier is ISp1Verifier {
    error UnexpectedProgramIdentifier(bytes32 actual);
    error UnexpectedOutput(bytes32 actual);
    error UnexpectedProof(bytes32 actual);

    bytes32 public expectedProgramIdentifier;
    bytes32 public expectedOutputHash;
    bytes32 public expectedProofHash;

    function expect(bytes32 programIdentifier, bytes memory output, bytes memory proofBytes) external {
        expectedProgramIdentifier = programIdentifier;
        expectedOutputHash = keccak256(output);
        expectedProofHash = keccak256(proofBytes);
    }

    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view {
        if (programVKey != expectedProgramIdentifier) revert UnexpectedProgramIdentifier(programVKey);
        if (keccak256(publicValues) != expectedOutputHash) revert UnexpectedOutput(keccak256(publicValues));
        if (keccak256(proofBytes) != expectedProofHash) revert UnexpectedProof(keccak256(proofBytes));
    }
}

contract ZkVerifierRegistryV2 is ZkVerifierRegistry {
    function implementationVersion() external pure returns (uint256) {
        return 2;
    }
}

contract ZkVerifierRegistryTest is Test {
    address internal constant OWNER = address(0xA11CE);
    address internal constant OTHER = address(0xB0B);
    bytes32 internal constant PROGRAM_IDENTIFIER = keccak256("tpm_quote.v1.sp1");
    address internal constant ADAPTER = address(0xAD47);

    ZkVerifierRegistry internal registry;

    function setUp() public {
        ZkVerifierRegistry implementation = new ZkVerifierRegistry();
        registry = ZkVerifierRegistry(
            address(new ERC1967Proxy(address(implementation), abi.encodeCall(ZkVerifierRegistry.initialize, (OWNER))))
        );
    }

    function test_owner_sets_and_resolves_exact_triplet() public {
        vm.expectEmit(true, true, true, true, address(registry));
        emit IZkVerifierRegistry.ZkProgramConfigUpdated(
            ZkProofType.TpmQuote,
            VerificationBackendType.ZkSuccinct,
            PROGRAM_IDENTIFIER,
            address(0),
            ADAPTER,
            false,
            true
        );

        vm.prank(OWNER);
        registry.setZkProgramConfig(
            ZkProofType.TpmQuote, VerificationBackendType.ZkSuccinct, PROGRAM_IDENTIFIER, ADAPTER, true
        );

        ZkProgramConfig memory config =
            registry.getZkProgramConfig(ZkProofType.TpmQuote, VerificationBackendType.ZkSuccinct, PROGRAM_IDENTIFIER);
        assertEq(config.verifierAdapter, ADAPTER);
        assertTrue(config.enabled);
        assertEq(
            registry.resolveVerifierAdapter(
                ZkProofType.TpmQuote, VerificationBackendType.ZkSuccinct, PROGRAM_IDENTIFIER
            ),
            ADAPTER
        );
    }

    function test_disabled_or_different_triplet_does_not_resolve() public {
        vm.prank(OWNER);
        registry.setZkProgramConfig(
            ZkProofType.TpmQuote, VerificationBackendType.ZkSuccinct, PROGRAM_IDENTIFIER, ADAPTER, false
        );

        vm.expectPartialRevert(ZkVerifierRegistry.ZkProgramNotEnabled.selector);
        registry.resolveVerifierAdapter(ZkProofType.TpmQuote, VerificationBackendType.ZkSuccinct, PROGRAM_IDENTIFIER);

        vm.expectPartialRevert(ZkVerifierRegistry.ZkProgramNotEnabled.selector);
        registry.resolveVerifierAdapter(ZkProofType.AwsNitroTpm, VerificationBackendType.ZkSuccinct, PROGRAM_IDENTIFIER);

        vm.expectPartialRevert(ZkVerifierRegistry.ZkProgramNotEnabled.selector);
        registry.resolveVerifierAdapter(ZkProofType.TpmQuote, VerificationBackendType.ZkRiscZero, PROGRAM_IDENTIFIER);
    }

    function test_non_owner_and_zero_adapter_are_rejected() public {
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, OTHER));
        vm.prank(OTHER);
        registry.setZkProgramConfig(
            ZkProofType.TpmQuote, VerificationBackendType.ZkSuccinct, PROGRAM_IDENTIFIER, ADAPTER, true
        );

        vm.expectRevert(ZkVerifierRegistry.ZeroVerifierAdapter.selector);
        vm.prank(OWNER);
        registry.setZkProgramConfig(
            ZkProofType.TpmQuote, VerificationBackendType.ZkSuccinct, PROGRAM_IDENTIFIER, address(0), true
        );
    }

    function test_only_owner_can_upgrade() public {
        ZkVerifierRegistryV2 nextImplementation = new ZkVerifierRegistryV2();

        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, OTHER));
        vm.prank(OTHER);
        registry.upgradeToAndCall(address(nextImplementation), bytes(""));

        vm.prank(OWNER);
        registry.upgradeToAndCall(address(nextImplementation), bytes(""));
        assertEq(ZkVerifierRegistryV2(address(registry)).implementationVersion(), 2);
    }
}

contract DirectSp1ZkVerifierAdapterTest is Test {
    bytes32 internal constant PROGRAM_IDENTIFIER = keccak256("program.v1.sp1");
    bytes internal constant PROOF = hex"01020304";

    MockSp1Verifier internal verifier;
    TpmQuoteZkVerifierAdapter internal tpmAdapter;
    AwsNitroTpmZkVerifierAdapter internal awsAdapter;

    function setUp() public {
        verifier = new MockSp1Verifier();
        tpmAdapter = new TpmQuoteZkVerifierAdapter(verifier);
        awsAdapter = new AwsNitroTpmZkVerifierAdapter(verifier);
    }

    function test_tpm_adapter_verifies_program_and_returns_exact_typed_journal() public {
        TpmQuoteJournalV1 memory expected = TpmQuoteJournalV1({
            akPubFingerprint: bytes32(uint256(1)),
            qualifyingData: bytes32(uint256(2)),
            tpmSignatureHash: bytes32(uint256(3)),
            pcrCommitment: PcrCommitment({pcrSelect: bytes32(uint256(4)), pcrDigest: bytes32(uint256(5))}),
            policyCommitment: bytes32(uint256(6))
        });
        bytes memory output = abi.encode(expected);
        verifier.expect(PROGRAM_IDENTIFIER, output, PROOF);

        TpmQuoteJournalV1 memory actual = tpmAdapter.verifyProof(_proof(output));
        assertEq(keccak256(abi.encode(actual)), keccak256(abi.encode(expected)));
    }

    function test_aws_adapter_verifies_program_and_returns_exact_typed_journal() public {
        AwsNitroTpmJournalV1 memory expected = AwsNitroTpmJournalV1({
            amdSevSnpReportHash: bytes32(uint256(1)),
            awsNitroRootCertHash: bytes32(uint256(2)),
            akPubFingerprint: bytes32(uint256(3)),
            qualifyingData: bytes32(uint256(4)),
            documentTimestampSeconds: 5,
            pcrCommitment: PcrCommitment({pcrSelect: bytes32(uint256(6)), pcrDigest: bytes32(uint256(7))})
        });
        bytes memory output = abi.encode(expected);
        verifier.expect(PROGRAM_IDENTIFIER, output, PROOF);

        AwsNitroTpmJournalV1 memory actual = awsAdapter.verifyProof(_proof(output));
        assertEq(keccak256(abi.encode(actual)), keccak256(abi.encode(expected)));
    }

    function test_adapter_rejects_trailing_output_after_proof_verification() public {
        TpmQuoteJournalV1 memory journal;
        bytes memory canonical = abi.encode(journal);
        bytes memory withTrailingBytes = bytes.concat(canonical, bytes32(uint256(1)));
        verifier.expect(PROGRAM_IDENTIFIER, withTrailingBytes, PROOF);

        vm.expectRevert(CanonicalSp1VerifierAdapter.NonCanonicalZkOutput.selector);
        tpmAdapter.verifyProof(_proof(withTrailingBytes));
    }

    function test_adapter_passes_program_identifier_to_sp1_verifier() public {
        TpmQuoteJournalV1 memory journal;
        bytes memory output = abi.encode(journal);
        verifier.expect(bytes32(uint256(99)), output, PROOF);

        vm.expectPartialRevert(MockSp1Verifier.UnexpectedProgramIdentifier.selector);
        tpmAdapter.verifyProof(_proof(output));
    }

    function _proof(bytes memory output) private pure returns (ProgramBoundZkProof memory) {
        return ProgramBoundZkProof({programIdentifier: PROGRAM_IDENTIFIER, output: output, proofBytes: PROOF});
    }
}

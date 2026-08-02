// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";

import {ITpmAttestation} from "@automata-network/automata-tpm-attestation/interfaces/ITpmAttestation.sol";
import {CertPubkey} from "@automata-network/automata-tpm-attestation/lib/LibX509.sol";
import {PcrValue} from "@automata-network/automata-tpm-attestation/types/Types.sol";

import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {TpmVerifier} from "../src/bases/TpmVerifier.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {AmdSnpSecurityPolicyRegistry} from "../src/AmdSnpSecurityPolicyRegistry.sol";
import {IAmdSnpSecurityPolicyRegistry} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";
import {IZkVerifierRegistry} from "../src/interfaces/registries/IZkVerifierRegistry.sol";
import {IAkCollateralVerifier, AkCollateralVerificationResult} from "../src/interfaces/IAkCollateralVerifier.sol";
import {IBaseImageRegistry} from "../src/interfaces/registries/IBaseImageRegistry.sol";
import {ISignatureVerifier} from "../src/interfaces/ISignatureVerifier.sol";
import {ITeeVerifier} from "../src/interfaces/ITeeVerifier.sol";
import {LibKey} from "../src/lib/LibKey.sol";
import {MockSignatureVerifier} from "./mocks/MockSignatureVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {
    AccessMode,
    Attribute,
    AttributeRequirement,
    BaseImageSpec,
    MeasurementVariant,
    PcrBankSelection,
    PcrSpec256,
    PcrSpec384,
    PcrVerifyType,
    PlatformProfile,
    PublicIdentity,
    WorkloadSpec
} from "../src/types/Common.sol";
import {
    AkPubCollateral,
    AkPubCollateralType,
    AttestationEvidence,
    SessionKeyRotationEvidence,
    TEEType,
    TeeReport,
    TeeVerificationResult,
    TpmCertifyEvidence,
    TpmQuoteEvidence,
    TpmReport,
    TpmReportType,
    VerificationBackendType
} from "../src/types/Evidence.sol";
import {
    ALGO_ID_ES256,
    ALGO_ID_ES256K,
    PLATFORM_PROFILE_DOMAIN,
    PLATFORM_VARIANT_DOMAIN,
    SESSION_NONCE_DOMAIN,
    TDX_TCB_STATUS_OK
} from "../src/types/Constants.sol";

/// @notice A platform profile invariant always holds. A measurement variant may only pin PCR
///         indices the profile leaves unpinned — it can never restate or relax an invariant.
///         Enforced at registration (BaseImageRegistry) and re-enforced at session evaluation
///         during session evaluation.
contract PcrInvariantPrecedenceTest is Test {
    address private constant TEE_VERIFIER = address(0x1001);
    address private constant TPM_ATTESTATION = address(0x1002);
    address private constant AK_COLLATERAL_VERIFIER = address(0x1003);

    bytes32 private constant GOLDEN_PCR4 = keccak256("golden-pcr4");
    bytes32 private constant ROGUE_PCR4 = keccak256("rogue-pcr4");

    MockSignatureVerifier private signatureVerifier;
    BaseImageRegistry private baseImageRegistry;
    WorkloadRegistry private workloadRegistry;
    TpmVerifier private tpmVerifier;
    SessionRegistry private sessionRegistry;

    PublicIdentity private imageOwner;
    PublicIdentity private sessionOwner;
    PublicIdentity private ak;
    PublicIdentity private tpmSigningKey;

    bytes32 private baseImageId;
    bytes32 private workloadId;
    bytes32 private profileId;

    function setUp() public {
        vm.warp(1_800_000_000);

        imageOwner = _identity(ALGO_ID_ES256K, 0x01);
        sessionOwner = _identity(ALGO_ID_ES256K, 0x0A);
        ak = _identity(ALGO_ID_ES256, 0x02);
        tpmSigningKey = _identity(ALGO_ID_ES256, 0x03);

        AmdSnpSecurityPolicyRegistry amdImpl = new AmdSnpSecurityPolicyRegistry();
        AmdSnpSecurityPolicyRegistry amdPolicy = AmdSnpSecurityPolicyRegistry(
            address(
                new ERC1967Proxy(
                    address(amdImpl), abi.encodeCall(AmdSnpSecurityPolicyRegistry.initialize, (address(this)))
                )
            )
        );

        signatureVerifier = new MockSignatureVerifier();
        baseImageRegistry = new BaseImageRegistry(signatureVerifier);
        workloadRegistry = new WorkloadRegistry(signatureVerifier);
        tpmVerifier = new TpmVerifier(ITpmAttestation(TPM_ATTESTATION), IZkVerifierRegistry(address(0)));
        sessionRegistry = new SessionRegistry(
            ITeeVerifier(TEE_VERIFIER),
            tpmVerifier,
            ISignatureVerifier(address(signatureVerifier)),
            IAkCollateralVerifier(AK_COLLATERAL_VERIFIER),
            baseImageRegistry,
            workloadRegistry,
            IAmdSnpSecurityPolicyRegistry(address(amdPolicy))
        );

        // Profile pins PCR4 as an invariant; the initial variant pins only PCR10 (disjoint).
        baseImageId = baseImageRegistry.registerBaseImage(
            BaseImageSpec({name: "invariant-base", version: "v1", uri: ""}),
            _profiles(_pcr(4, PcrVerifyType.STATIC, GOLDEN_PCR4)),
            _variants(_pcr(10, PcrVerifyType.STATIC, keccak256("pcr10"))),
            uint64(block.timestamp + 1 hours),
            imageOwner,
            hex"01"
        );
        profileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, "profile"));

        bytes32[] memory allowed = new bytes32[](1);
        allowed[0] = baseImageId;
        workloadId = workloadRegistry.registerWorkload(
            WorkloadSpec({
                name: "invariant-workload",
                version: "v1",
                sessionTtl: 1 days,
                baseImageMode: AccessMode.WHITELIST,
                baseImageIds: allowed,
                requirements: new AttributeRequirement[](0),
                workloadPcrs256: new PcrSpec256[](0),
                workloadPcrs384: new PcrSpec384[](0)
            }),
            uint64(block.timestamp + 1 hours),
            imageOwner,
            hex"01"
        );
    }

    /// @dev The scenario that previously let an image owner relax a profile invariant after
    ///      workloads had already whitelisted the image.
    function test_addPlatformVariants_rejects_variant_that_pins_an_invariant_pcr() public {
        bytes32[] memory anyEvent = new bytes32[](1);
        anyEvent[0] = keccak256("any-event");

        vm.expectRevert(
            abi.encodeWithSelector(BaseImageRegistry.VariantOverridesInvariantPcr.selector, profileId, uint8(4))
        );
        baseImageRegistry.addPlatformVariants(
            baseImageId,
            _profiles(_pcr(4, PcrVerifyType.STATIC, GOLDEN_PCR4)),
            _variantsNamed(
                "rogue", PcrSpec256({pcrIndex: 4, verifyType: PcrVerifyType.DYNAMIC_SUBSET, matchData: anyEvent})
            ),
            uint64(block.timestamp + 1 hours),
            imageOwner,
            hex"01"
        );
    }

    /// @dev Overlap is checked against the STORED invariants. Resubmitting the profile struct with
    ///      the invariant removed must not launder the check — submitted metadata is dropped for an
    ///      already-registered profile.
    function test_addPlatformVariants_rejects_changed_profile_metadata() public {
        PlatformProfile[] memory profilesWithoutInvariant = new PlatformProfile[](1);
        profilesWithoutInvariant[0] = PlatformProfile({
            name: "profile",
            pcrBankSelection: PcrBankSelection.Sha256,
            invariants256: new PcrSpec256[](0),
            invariants384: new PcrSpec384[](0),
            attributes: new Attribute[](0)
        });

        vm.expectRevert(abi.encodeWithSelector(BaseImageRegistry.PlatformProfileMetadataMismatch.selector, profileId));
        baseImageRegistry.addPlatformVariants(
            baseImageId,
            profilesWithoutInvariant,
            _variantsNamed("rogue", _pcr(4, PcrVerifyType.STATIC, ROGUE_PCR4)[0]),
            uint64(block.timestamp + 1 hours),
            imageOwner,
            hex"01"
        );
    }

    function test_registerBaseImage_rejects_variant_that_pins_an_invariant_pcr() public {
        bytes32 expectedProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, _otherBaseImageId(), "profile"));
        vm.expectRevert(
            abi.encodeWithSelector(BaseImageRegistry.VariantOverridesInvariantPcr.selector, expectedProfileId, uint8(4))
        );
        baseImageRegistry.registerBaseImage(
            BaseImageSpec({name: "invariant-base", version: "v2", uri: ""}),
            _profiles(_pcr(4, PcrVerifyType.STATIC, GOLDEN_PCR4)),
            _variants(_pcr(4, PcrVerifyType.STATIC, ROGUE_PCR4)),
            uint64(block.timestamp + 1 hours),
            imageOwner,
            hex"01"
        );
    }

    /// @dev A brand-new profile appended via addPlatformVariants is checked against its own
    ///      submitted invariants — the stored-profile lookup must not skip validation just
    ///      because the profile did not exist before this call.
    function test_addPlatformVariants_rejects_overlap_on_a_brand_new_profile() public {
        PlatformProfile[] memory profiles = new PlatformProfile[](1);
        profiles[0] = PlatformProfile({
            name: "second-profile",
            pcrBankSelection: PcrBankSelection.Sha256,
            invariants256: _pcr(7, PcrVerifyType.STATIC, GOLDEN_PCR4),
            invariants384: new PcrSpec384[](0),
            attributes: new Attribute[](0)
        });
        bytes32 newProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, "second-profile"));

        vm.expectRevert(
            abi.encodeWithSelector(BaseImageRegistry.VariantOverridesInvariantPcr.selector, newProfileId, uint8(7))
        );
        baseImageRegistry.addPlatformVariants(
            baseImageId,
            profiles,
            _variantsNamed("new-profile-variant", _pcr(7, PcrVerifyType.STATIC, ROGUE_PCR4)[0]),
            uint64(block.timestamp + 1 hours),
            imageOwner,
            hex"01"
        );
    }

    /// @dev A variant pinning an index the profile leaves unpinned is still accepted.
    function test_addPlatformVariants_accepts_disjoint_variant() public {
        baseImageRegistry.addPlatformVariants(
            baseImageId,
            _profiles(_pcr(4, PcrVerifyType.STATIC, GOLDEN_PCR4)),
            _variantsNamed("disjoint", _pcr(11, PcrVerifyType.STATIC, keccak256("pcr11"))[0]),
            uint64(block.timestamp + 1 hours),
            imageOwner,
            hex"01"
        );
        assertTrue(baseImageRegistry.hasVariant(keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, profileId, "disjoint"))));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────────────

    function _otherBaseImageId() private pure returns (bytes32) {
        return keccak256(abi.encode(keccak256("CVM_BASEIMAGE_V1"), "invariant-base", "v2"));
    }

    function _pcr(uint8 index, PcrVerifyType verifyType, bytes32 value)
        private
        pure
        returns (PcrSpec256[] memory specs)
    {
        bytes32[] memory matchData = new bytes32[](1);
        matchData[0] = value;
        specs = new PcrSpec256[](1);
        specs[0] = PcrSpec256({pcrIndex: index, verifyType: verifyType, matchData: matchData});
    }

    function _pcrSpecs(PcrSpec256 memory spec) private pure returns (PcrSpec256[] memory specs) {
        specs = new PcrSpec256[](1);
        specs[0] = spec;
    }

    function _profiles(PcrSpec256[] memory invariants) private pure returns (PlatformProfile[] memory profiles) {
        profiles = new PlatformProfile[](1);
        profiles[0] = PlatformProfile({
            name: "profile",
            pcrBankSelection: PcrBankSelection.Sha256,
            invariants256: invariants,
            invariants384: new PcrSpec384[](0),
            attributes: new Attribute[](0)
        });
    }

    function _variants(PcrSpec256[] memory variantPcrs256)
        private
        pure
        returns (MeasurementVariant[][] memory variants)
    {
        variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](1);
        variants[0][0] = MeasurementVariant({
            name: "variant",
            variantPcrs256: variantPcrs256,
            variantPcrs384: new PcrSpec384[](0),
            attributes: new Attribute[](0)
        });
    }

    function _variantsNamed(string memory name, PcrSpec256 memory spec)
        private
        pure
        returns (MeasurementVariant[][] memory variants)
    {
        variants = new MeasurementVariant[][](1);
        variants[0] = new MeasurementVariant[](1);
        variants[0][0] = MeasurementVariant({
            name: name,
            variantPcrs256: _pcrSpecs(spec),
            variantPcrs384: new PcrSpec384[](0),
            attributes: new Attribute[](0)
        });
    }

    function _identity(uint8 typeId, uint8 marker) private pure returns (PublicIdentity memory identity) {
        bytes memory key = new bytes(65);
        key[0] = 0x04;
        key[64] = bytes1(marker);
        identity = PublicIdentity({typeId: typeId, key: key});
    }
}

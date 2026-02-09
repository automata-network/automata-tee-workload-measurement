// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test, console} from "forge-std/Test.sol";

import {SignatureVerifier} from "../src/SignatureVerifier.sol";
import {BaseImageRegistry} from "../src/BaseImageRegistry.sol";
import {WorkloadRegistry} from "../src/WorkloadRegistry.sol";
import {SessionRegistry} from "../src/SessionRegistry.sol";
import {MockAutomataDcapAttestation} from "../src/mock/MockAutomataDcapAttestation.sol";
import {MockAutomataSnpAttestation} from "../src/mock/MockAutomataSnpAttestation.sol";
import {TpmAttestation} from "@automata-network/automata-tpm-attestation/TpmAttestation.sol";

import {
    BaseImageSpec,
    PlatformProfile,
    MeasurementVariant,
    WorkloadSpec,
    PublicIdentity,
    PcrSpec,
    Attribute,
    AccessMode,
    PcrVerifyType,
    AttributeRequirement
} from "../src/types/Common.sol";
import {
    AttestationEvidence,
    TeeReport,
    TpmReport,
    AkPubCollateral,
    VerificationBackendType,
    TEEType,
    TpmReportType,
    AkPubCollateralType
} from "../src/types/Evidence.sol";
import {BASEIMAGE_DOMAIN, PLATFORM_PROFILE_DOMAIN, PLATFORM_VARIANT_DOMAIN, WORKLOAD_DOMAIN, ALGO_ID_ES256K} from "../src/types/Constants.sol";

contract SessionRegistryTest is Test {
    // Deployed contracts
    SignatureVerifier public signatureVerifier;
    BaseImageRegistry public baseImageRegistry;
    WorkloadRegistry public workloadRegistry;
    SessionRegistry public sessionRegistry;
    MockAutomataDcapAttestation public mockDcap;
    MockAutomataSnpAttestation public mockSnp;
    TpmAttestation public tpmAttestation;

    address constant P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
    address constant owner = address(0x1234);

    // Test data: owner identity (ES256K)
    PublicIdentity ownerIdentity;

    function setUp() public {
        _deployP256();

        // Warp to a valid timestamp (2025-01-01) for certificate validation
        vm.warp(1770568586);

        // Set up owner identity
        ownerIdentity = PublicIdentity({
            typeId: ALGO_ID_ES256K,
            key: hex"048318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed753547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5"
        });

        vm.startPrank(owner);

        // Deploy mock Automata contracts
        mockDcap = new MockAutomataDcapAttestation();
        mockSnp = new MockAutomataSnpAttestation();
        tpmAttestation = new TpmAttestation(owner, P256_VERIFIER);

        // Deploy SignatureVerifier
        signatureVerifier = new SignatureVerifier(P256_VERIFIER);

        // Deploy BaseImageRegistry
        baseImageRegistry = new BaseImageRegistry(signatureVerifier);

        // Deploy WorkloadRegistry
        workloadRegistry = new WorkloadRegistry(signatureVerifier);

        // Deploy SessionRegistry
        sessionRegistry = new SessionRegistry(
            mockDcap,
            mockSnp,
            tpmAttestation,
            signatureVerifier,
            baseImageRegistry,
            workloadRegistry
        );

        // Add GCP vTPM Root CA to TpmAttestation
        tpmAttestation.addCA(_gcpRootCa());

        vm.stopPrank();

        // Mock SignatureVerifier.verify() to always return true for testing
        // This allows testing the flow without real signatures
        vm.mockCall(
            address(signatureVerifier),
            abi.encodeWithSelector(signatureVerifier.verify.selector),
            abi.encode(true)
        );

        console.log("=== Contracts Deployed ===");
        console.log("SignatureVerifier:", address(signatureVerifier));
        console.log("BaseImageRegistry:", address(baseImageRegistry));
        console.log("WorkloadRegistry:", address(workloadRegistry));
        console.log("SessionRegistry:", address(sessionRegistry));
    }

    function testFullRegistrationFlow() public {
        // Step 1: Register BaseImage
        bytes32 baseImageId = _registerBaseImage();
        console.log("BaseImage registered with ID:");
        console.logBytes32(baseImageId);

        // Step 2: Register Workload (pass baseImageId to whitelist it)
        bytes32 workloadId = _registerWorkload(baseImageId);
        console.log("Workload registered with ID:");
        console.logBytes32(workloadId);

        // Step 3: Verify registrations
        assertTrue(baseImageRegistry.isBaseImageActive(baseImageId), "BaseImage should be active");
        assertTrue(workloadRegistry.isWorkloadActive(workloadId), "Workload should be active");
        assertTrue(workloadRegistry.isBaseImageAllowed(workloadId, baseImageId), "BaseImage should be allowed for workload");

        // Step 4: Register Session (placeholder - actual calldata to be provided)
        // _registerSession(baseImageId, workloadId);
    }

    function _registerBaseImage() internal returns (bytes32 baseImageId) {
        // BaseImage spec
        BaseImageSpec memory spec = BaseImageSpec({
            name: "automata-linux",
            version: "v0.0.6",
            uri: "https://github.com"
        });

        // Platform profiles
        PlatformProfile[] memory platformProfiles = new PlatformProfile[](2);

        // Profile 1: gcp-snp
        {
            Attribute[] memory attrs1 = new Attribute[](2);
            attrs1[0] = Attribute({
                key: 0x1c70be22fd56ec721e249e7fa08836877236811f23b34a81521b28073a38ec9c,
                value: 0x5729ca8d7ea61c5e423c48840172cd82efe5fcb67746394e4038f408429cb1ba
            });
            attrs1[1] = Attribute({
                key: 0x78322755010a0b82e66a2aad98525efb30eee81fe7dc43a42f875fcc221382b7,
                value: 0x4e93d92ff4e2ad9500a6fc01fef91a80e1033c510ab256548c2df61fd8beb4e3
            });

            platformProfiles[0] = PlatformProfile({
                name: "gcp-snp",
                invariants: new PcrSpec[](0),
                attributes: attrs1
            });
        }

        // Profile 2: gcp-tdx
        {
            Attribute[] memory attrs2 = new Attribute[](2);
            attrs2[0] = Attribute({
                key: 0x1c70be22fd56ec721e249e7fa08836877236811f23b34a81521b28073a38ec9c,
                value: 0x5729ca8d7ea61c5e423c48840172cd82efe5fcb67746394e4038f408429cb1ba
            });
            attrs2[1] = Attribute({
                key: 0x78322755010a0b82e66a2aad98525efb30eee81fe7dc43a42f875fcc221382b7,
                value: 0x34bef19ef372626c712f3e728d74b5544a621e4ba1df121959d2b6c15b51a989
            });

            platformProfiles[1] = PlatformProfile({
                name: "gcp-tdx",
                invariants: new PcrSpec[](0),
                attributes: attrs2
            });
        }

        // Measurement variants (parallel array with platformProfiles)
        MeasurementVariant[][] memory measurementVariants = new MeasurementVariant[][](2);

        // Variants for gcp-snp: n2d-standard-2
        measurementVariants[0] = new MeasurementVariant[](1);
        measurementVariants[0][0] = _createN2dStandard2Variant();

        // Variants for gcp-tdx: c3-standard-4
        measurementVariants[1] = new MeasurementVariant[](1);
        measurementVariants[1][0] = _createC3Standard4Variant();

        uint64 expireAt = 1770547477;
        bytes memory signature = hex"e51236c453cad477b48d11c448cdcab96fe6e94ed306fd02ee7d0251e6dc37264ba08f0ac5823adf62f0d7746fde131c52d7ba954886e98848cd11f37753d7c51b";

        // Warp to before expiration
        vm.warp(expireAt - 1000);

        baseImageId = baseImageRegistry.registerBaseImage(
            spec,
            platformProfiles,
            measurementVariants,
            expireAt,
            ownerIdentity,
            signature
        );
    }

    function _createN2dStandard2Variant() internal pure returns (MeasurementVariant memory) {
        PcrSpec[] memory pcrs = new PcrSpec[](8);

        bytes32[] memory matchData0 = new bytes32[](1);
        matchData0[0] = 0x50597a27846e91d025eef597abbc89f72bff9af849094db97b0684d8bc4c515e;
        pcrs[0] = PcrSpec({pcrIndex: 0, verifyType: PcrVerifyType.STATIC, matchData: matchData0});

        bytes32[] memory matchData2 = new bytes32[](1);
        matchData2[0] = 0x3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969;
        pcrs[1] = PcrSpec({pcrIndex: 2, verifyType: PcrVerifyType.STATIC, matchData: matchData2});

        bytes32[] memory matchData4 = new bytes32[](1);
        matchData4[0] = 0xd2286adeb60246435929b5297510225d7fb7c503f4974b383c9899b94c3aaffa;
        pcrs[2] = PcrSpec({pcrIndex: 4, verifyType: PcrVerifyType.STATIC, matchData: matchData4});

        bytes32[] memory matchData7 = new bytes32[](1);
        matchData7[0] = 0x0a3f60cea411388b09eac782999f5e62246ab5469f9047eb508aa22c4dcd2237;
        pcrs[3] = PcrSpec({pcrIndex: 7, verifyType: PcrVerifyType.STATIC, matchData: matchData7});

        bytes32[] memory matchData9 = new bytes32[](1);
        matchData9[0] = 0x58fb1c936187af0c6432e4953a2a334f4e28859dcb87db1fee274c5954ec69ae;
        pcrs[4] = PcrSpec({pcrIndex: 9, verifyType: PcrVerifyType.STATIC, matchData: matchData9});

        bytes32[] memory matchData11 = new bytes32[](1);
        matchData11[0] = 0x0000000000000000000000000000000000000000000000000000000000000000;
        pcrs[5] = PcrSpec({pcrIndex: 11, verifyType: PcrVerifyType.STATIC, matchData: matchData11});

        bytes32[] memory matchData16 = new bytes32[](1);
        matchData16[0] = 0x0000000000000000000000000000000000000000000000000000000000000000;
        pcrs[6] = PcrSpec({pcrIndex: 16, verifyType: PcrVerifyType.STATIC, matchData: matchData16});

        bytes32[] memory matchData23 = new bytes32[](1);
        matchData23[0] = 0x0000000000000000000000000000000000000000000000000000000000000000;
        pcrs[7] = PcrSpec({pcrIndex: 23, verifyType: PcrVerifyType.STATIC, matchData: matchData23});

        return MeasurementVariant({
            name: "n2d-standard-2",
            overridePcrs: pcrs,
            attributes: new Attribute[](0)
        });
    }

    function _createC3Standard4Variant() internal pure returns (MeasurementVariant memory) {
        PcrSpec[] memory pcrs = new PcrSpec[](8);

        bytes32[] memory matchData0 = new bytes32[](1);
        matchData0[0] = 0x0cca9ec161b09288802e5a112255d21340ed5b797f5fe29cecccfd8f67b9f802;
        pcrs[0] = PcrSpec({pcrIndex: 0, verifyType: PcrVerifyType.STATIC, matchData: matchData0});

        bytes32[] memory matchData2 = new bytes32[](1);
        matchData2[0] = 0x0fb87efae3c3aee3e0ee8e85c5149b1985d442f4bed22afdce0610bb55ee4270;
        pcrs[1] = PcrSpec({pcrIndex: 2, verifyType: PcrVerifyType.STATIC, matchData: matchData2});

        bytes32[] memory matchData4 = new bytes32[](1);
        matchData4[0] = 0xc36d9e765efa54f2981707bb7dec3c38385476cf91a413f7d85dced9f092e21f;
        pcrs[2] = PcrSpec({pcrIndex: 4, verifyType: PcrVerifyType.STATIC, matchData: matchData4});

        bytes32[] memory matchData7 = new bytes32[](1);
        matchData7[0] = 0xa11c5239a222bb78072c2c73caa691bb9a0f118de2d95cdce1fce06711e4d3ed;
        pcrs[3] = PcrSpec({pcrIndex: 7, verifyType: PcrVerifyType.STATIC, matchData: matchData7});

        bytes32[] memory matchData9 = new bytes32[](1);
        matchData9[0] = 0x41551ed5a5003d5174f42a03b77d1cb2be954acca10cfb7eae040e99f4d8284a;
        pcrs[4] = PcrSpec({pcrIndex: 9, verifyType: PcrVerifyType.STATIC, matchData: matchData9});

        bytes32[] memory matchData11 = new bytes32[](1);
        matchData11[0] = 0x0000000000000000000000000000000000000000000000000000000000000000;
        pcrs[5] = PcrSpec({pcrIndex: 11, verifyType: PcrVerifyType.STATIC, matchData: matchData11});

        bytes32[] memory matchData16 = new bytes32[](1);
        matchData16[0] = 0x0000000000000000000000000000000000000000000000000000000000000000;
        pcrs[6] = PcrSpec({pcrIndex: 16, verifyType: PcrVerifyType.STATIC, matchData: matchData16});

        bytes32[] memory matchData23 = new bytes32[](1);
        matchData23[0] = 0x0000000000000000000000000000000000000000000000000000000000000000;
        pcrs[7] = PcrSpec({pcrIndex: 23, verifyType: PcrVerifyType.STATIC, matchData: matchData23});

        return MeasurementVariant({
            name: "c3-standard-4",
            overridePcrs: pcrs,
            attributes: new Attribute[](0)
        });
    }

    function _registerWorkload(bytes32 baseImageId) internal returns (bytes32 workloadId) {
        bytes32[] memory baseImageIds = new bytes32[](1);
        baseImageIds[0] = baseImageId;

        WorkloadSpec memory spec = WorkloadSpec({
            name: "secure-signer",
            version: "v0.0.6",
            ttl: 0,
            baseImageMode: AccessMode.WHITELIST,
            baseImageIds: baseImageIds,
            requirements: new AttributeRequirement[](0),
            pcrs: new PcrSpec[](0)
        });

        uint64 expireAt = 1770547589;
        bytes memory signature = hex"4517531794e04ee1f950e7b1bd016ea460e1fe06e5c222469676642080f01d3b4b0f9090064717d49708001bf77958490bec3e3c18dc11f385932d9aca0a88311c";

        // Warp to before expiration
        vm.warp(expireAt - 1000);

        workloadId = workloadRegistry.registerWorkload(
            spec,
            expireAt,
            ownerIdentity,
            signature
        );
    }

    /// @notice Register session using raw calldata (decodes and calls)
    /// @dev Decodes the calldata and calls sessionRegistry.registerSession
    /// @param callData Full calldata including function selector (4 bytes) + abi-encoded params
    function _registerSessionWithCalldata(bytes memory callData) internal returns (bytes32 sessionId) {
        // Skip the 4-byte function selector
        bytes memory params = new bytes(callData.length - 4);
        for (uint256 i = 4; i < callData.length; i++) {
            params[i - 4] = callData[i];
        }

        // Decode parameters
        (
            AttestationEvidence memory evidence,
            bytes32 workloadId,
            bytes32 baseImageId,
            bytes32 platformProfileId,
            bytes32 variantId,
            uint64 expireAt,
            PublicIdentity memory decodedOwnerIdentity,
            bytes memory ownerSignature
        ) = abi.decode(
            params,
            (AttestationEvidence, bytes32, bytes32, bytes32, bytes32, uint64, PublicIdentity, bytes)
        );


        // Warp to before expiration if needed
        vm.warp(1770567955);

        // Call registerSession
        sessionId = sessionRegistry.registerSession(
            evidence,
            workloadId,
            baseImageId,
            platformProfileId,
            variantId,
            expireAt,
            decodedOwnerIdentity,
            ownerSignature
        );

        console.log("Session registered with ID:");
        console.logBytes32(sessionId);

        return sessionId;
    }

    /// @notice Direct call to sessionRegistry with raw calldata
    /// @dev Use this for testing with exact calldata from external source
    /// @param callData Full calldata including function selector
    function _registerSessionDirect(bytes memory callData) internal returns (bytes32 sessionId) {
        (bool success, bytes memory result) = address(sessionRegistry).call(callData);
        require(success, "Session registration failed");
        sessionId = abi.decode(result, (bytes32));

        console.log("Session registered with ID:");
        console.logBytes32(sessionId);

        return sessionId;
    }

    /// @notice Test session registration with raw calldata
    /// @dev Use this function to test with actual hex-encoded calldata
    function testSessionRegistrationWithCalldata() public {
        // First register base image and workload
        bytes32 baseImageId = _registerBaseImage();
        bytes32 workloadId = _registerWorkload(baseImageId);

        // Compute platform profile ID and variant ID
        // bytes32 platformProfileId = keccak256(abi.encode(PLATFORM_PROFILE_DOMAIN, baseImageId, "gcp-snp"));
        // bytes32 variantId = keccak256(abi.encode(PLATFORM_VARIANT_DOMAIN, platformProfileId, "n2d-standard-2"));

        console.log("Ready for session registration");
        console.log("BaseImageId:");
        console.logBytes32(baseImageId);
        console.log("WorkloadId:");
        console.logBytes32(workloadId);
        // console.log("PlatformProfileId:");
        // console.logBytes32(platformProfileId);
        // console.log("VariantId:");
        // console.logBytes32(variantId);

        // TODO: Replace with actual session registration calldata
        bytes32 sessionId = _registerSessionDirect(sessionCalldata());

        // Option 2: Decode and call (allows inspection of params)
        // bytes memory sessionCalldata = hex"...";
        // bytes32 sessionId = _registerSessionWithCalldata(sessionCalldata);

        // Verify session
        assertTrue(sessionRegistry.isSessionActive(sessionId), "Session should be active");
    }

    function sessionCalldata() private view returns (bytes memory) {
        string memory hexString = vm.readFile("test/session_register.hex");
        return vm.parseBytes(hexString);
    }

    function _deployP256() private {
        bytes memory txdata =
            hex"00000000000000000000000000000000000000000000000000000000000000006080806040523461001657610dd1908161001c8239f35b600080fdfe60e06040523461001a57610012366100c7565b602081519101f35b600080fd5b6040810190811067ffffffffffffffff82111761003b57604052565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60e0810190811067ffffffffffffffff82111761003b57604052565b90601f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0910116810190811067ffffffffffffffff82111761003b57604052565b60a08103610193578060201161001a57600060409180831161018f578060601161018f578060801161018f5760a01161018c57815182810181811067ffffffffffffffff82111761015f579061013291845260603581526080356020820152833560203584356101ab565b15610156575060ff6001915b5191166020820152602081526101538161001f565b90565b60ff909161013e565b6024837f4e487b710000000000000000000000000000000000000000000000000000000081526041600452fd5b80fd5b5080fd5b5060405160006020820152602081526101538161001f565b909283158015610393575b801561038b575b8015610361575b6103585780519060206101dc818301938451906103bd565b1561034d57604051948186019082825282604088015282606088015260808701527fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f60a08701527fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551958660c082015260c081526102588161006a565b600080928192519060055afa903d15610345573d9167ffffffffffffffff831161031857604051926102b1857fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f8401160185610086565b83523d828585013e5b156102eb57828280518101031261018c5750015190516102e693929185908181890994099151906104eb565b061490565b807f4e487b7100000000000000000000000000000000000000000000000000000000602492526001600452fd5b6024827f4e487b710000000000000000000000000000000000000000000000000000000081526041600452fd5b6060916102ba565b505050505050600090565b50505050600090565b507fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325518310156101c4565b5082156101bd565b507fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325518410156101b6565b7fffffffff00000001000000000000000000000000ffffffffffffffffffffffff90818110801590610466575b8015610455575b61044d577f5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b8282818080957fffffffff00000001000000000000000000000000fffffffffffffffffffffffc0991818180090908089180091490565b505050600090565b50801580156103f1575082156103f1565b50818310156103ea565b7f800000000000000000000000000000000000000000000000000000000000000081146104bc577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0190565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b909192608052600091600160a05260a05193600092811580610718575b61034d57610516838261073d565b95909460ff60c05260005b600060c05112156106ef575b60a05181036106a1575050507f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5957f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2969594939291965b600060c05112156105c7575050505050507fffffffff00000001000000000000000000000000ffffffffffffffffffffffff91506105c260a051610ca2565b900990565b956105d9929394959660a05191610a98565b9097929181928960a0528192819a6105f66080518960c051610722565b61060160c051610470565b60c0528061061b5750505050505b96959493929196610583565b969b5061067b96939550919350916001810361068857507f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5937f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29693610952565b979297919060a05261060f565b6002036106985786938a93610952565b88938893610952565b600281036106ba57505050829581959493929196610583565b9197917ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd0161060f575095508495849661060f565b506106ff6080518560c051610722565b8061070b60c051610470565b60c052156105215761052d565b5060805115610508565b91906002600192841c831b16921c1681018091116104bc5790565b8015806107ab575b6107635761075f91610756916107b3565b92919091610c42565b9091565b50507f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296907f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f590565b508115610745565b919082158061094a575b1561080f57507f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29691507f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5906001908190565b7fb01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a917fffffffff00000001000000000000000000000000ffffffffffffffffffffffff808481600186090894817f94e82e0c1ed3bdb90743191a9c5bbf0d88fc827fd214cc5f0b5ec6ba27673d6981600184090893841561091b575050808084800993840994818460010994828088600109957f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29609918784038481116104bc5784908180867fffffffff00000001000000000000000000000000fffffffffffffffffffffffd0991818580090808978885038581116104bc578580949281930994080908935b93929190565b9350935050921560001461093b5761093291610b6d565b91939092610915565b50506000806000926000610915565b5080156107bd565b91949592939095811580610a90575b15610991575050831580610989575b61097a5793929190565b50600093508392508291508190565b508215610970565b85919294951580610a88575b610a78577fffffffff00000001000000000000000000000000ffffffffffffffffffffffff968703918783116104bc5787838189850908938689038981116104bc5789908184840908928315610a5d575050818880959493928180848196099b8c9485099b8c920999099609918784038481116104bc5784908180867fffffffff00000001000000000000000000000000fffffffffffffffffffffffd0991818580090808978885038581116104bc578580949281930994080908929190565b965096505050509093501560001461093b5761093291610b6d565b9550509150915091906001908190565b50851561099d565b508015610961565b939092821580610b65575b61097a577fffffffff00000001000000000000000000000000ffffffffffffffffffffffff908185600209948280878009809709948380888a0998818080808680097fffffffff00000001000000000000000000000000fffffffffffffffffffffffc099280096003090884808a7fffffffff00000001000000000000000000000000fffffffffffffffffffffffd09818380090898898603918683116104bc57888703908782116104bc578780969481809681950994089009089609930990565b508015610aa3565b919091801580610c3a575b610c2d577fffffffff00000001000000000000000000000000ffffffffffffffffffffffff90818460020991808084800980940991817fffffffff00000001000000000000000000000000fffffffffffffffffffffffc81808088860994800960030908958280837fffffffff00000001000000000000000000000000fffffffffffffffffffffffd09818980090896878403918483116104bc57858503928584116104bc5785809492819309940890090892565b5060009150819081908190565b508215610b78565b909392821580610c9a575b610c8d57610c5a90610ca2565b9182917fffffffff00000001000000000000000000000000ffffffffffffffffffffffff80809581940980099009930990565b5050509050600090600090565b508015610c4d565b604051906020918281019183835283604083015283606083015260808201527fffffffff00000001000000000000000000000000fffffffffffffffffffffffd60a08201527fffffffff00000001000000000000000000000000ffffffffffffffffffffffff60c082015260c08152610d1a8161006a565b600080928192519060055afa903d15610d93573d9167ffffffffffffffff83116103185760405192610d73857fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f8401160185610086565b83523d828585013e5b156102eb57828280518101031261018c5750015190565b606091610d7c56fea2646970667358221220fa55558b04ced380e93d0a46be01bb895ff30f015c50c516e898c341cd0a230264736f6c63430008150033";
        (bool succ,) = address(0x4e59b44847b379578588920cA78FbF26c0B4956C).call(txdata);
        require(succ, "Failed to deploy P256");

        // check code
        uint256 codesize = P256_VERIFIER.code.length;
        require(codesize > 0, "P256 deployed to the wrong address");
    }

    /// @notice GCP vTPM Root CA certificate (EK/AK CA Root)
    function _gcpRootCa() private pure returns (bytes memory) {
        return hex"30820601308203e9a003020102021400a65da4f9e328f38035c3a73d4f72432bdf15dc300d06092a864886f70d01010b0500307e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731133011060355040a130a476f6f676c65204c4c4331153013060355040b130c476f6f676c6520436c6f7564311630140603550403130d454b2f414b20434120526f6f743020170d3232303730383030343033345a180f32313232303730383035353732335a307e310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731133011060355040a130a476f6f676c65204c4c4331153013060355040b130c476f6f676c6520436c6f7564311630140603550403130d454b2f414b20434120526f6f7430820222300d06092a864886f70d01010105000382020f003082020a02820201009d25f550a8c8964b4a897c2b284da5b4bba419ee89c13aa6daddb71016211d939cbc52831345891eddaeda1fc48d2bb9c7a8088a6c6bd34720aaf3dec33f37f13c98534788902ec957f7a4fa660e92c9650d6a7bcc87929192b372a3dece58616b4479c0957f336ce0cb4abc67c0f96281e3d03a3688bc47d4751a89cb20deb04975f790fd626d19f434681daa07e045ee470b790a0218d9eac713f046f548695a0721b31395a81939cd6f289f932c7da146715d526caafdaaeb5d56ddaa5b3f17207aff33e495d051baeb43b11b3b44ad2b50ec291b0a2ee0fe60bc63ac1450e14788379587a7a1b4be06223a9b479ba60a67141e98efe454c2d1cec9b50181fb78d3857a470120a4634aaa64e66e2e774e2aba6e9fd21063de213f3def83bc86d584b87d22d02e9c848640f03d7581207c0fea5a2afea54ecb577a61a4b78686e965f06ff362642117785e8346ee211ef469abf34fc88b010af154c35164910633020dfedabc6224f7fb711921c4aaaba1801a38ae570dcd22c5c2dfe0ae489190e466c3a78f4b73a5563c7796785bf04941a0c4a5eae6bd7e3d1b286202ba4b886179c817117e5ced1b5ae9370594415bd172bd7e9cb576bf3d2de146c54069743bcac4344b326dc541e9fcae647f3d245e11c26c6aa6d43ffabb3dcee4d117c5f4c6fa01f3d97e7aa0a58250f88152afd1234525b5c0f70bd37ce84cfe3b0203010001a3753073300e0603551d0f0101ff04040302010630100603551d250409300706056781050801300f0603551d130101ff040530030101ff301d0603551d0e0416041449e74a5b5629f59d79b7a6303c03b28fe714dd4c301f0603551d2304183016801449e74a5b5629f59d79b7a6303c03b28fe714dd4c300d06092a864886f70d01010b0500038202010095f1d1bce077089a0b4e5d581bf02f8c6a1992934cca9e57e637b5202090ebc6f6f7a127f6121495c618ffe9ee10f48f5230c0de2cf027c0c07d5e11120a50ceaa21e97851dd38327c75e327a0c2ee9bb3120b73175fb01d2854a41a1edc72ae2f85a1077aefc24d9212cb9d06ef76a3d06e06370327f196e4646da43fc7ef51c013cac8f63278d674b416f9248da5f4825b27b4c5545e2c1cb5af0623440e1368a3b09070938d6e406b7460e8f6486944c0d002e43053079919efee97f71184ebf73e3374c003438da17d7cacd7e27fde1c0b1fe63d83acf2952400d440438693441be906baf2193f11d5a85306431e4501b7b5db0b1d14fc7c908550035de562d6b22f37d34e72fd6b8ccfcfe014a7343cbf85f8cb9b0ac2753833d346c707f774254b8cc4320e610c0224b3e7c3a1127642244eaa8ec602a6d373b49329f19cafdfa96bade76bb7f7a32d6c64f58f77107cb71e73de582188f3f792d431ff22bfd45c1fd61831247172ff651c686b8e5d14514cfc849e9a59a7cd8a8a0b3d68f1d6b5a566dbf2eb5d7d9fbd3f6233f9340a8bcd023f2bced1f1b14128034c499d238934fa5ef4f45d8ec4e3effbb75eeea140b34d89d047808dc77268bbd381cc31dff7c99e36e0e3ab4b7db2969794d687901c5acb13a8585f8fedb4c1136e611220a776ad382cb4fa2d4af92e0794e58db2983d1fa5abb8506afd7a5381";
    }
}

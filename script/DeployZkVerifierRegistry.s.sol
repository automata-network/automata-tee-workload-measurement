// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {DeploymentConfig} from "./utils/DeploymentConfig.sol";
import {
    AMD_SEV_SNP_ZK_VERIFIER_ADAPTER_SALT,
    AWS_NITROTPM_ZK_VERIFIER_ADAPTER_SALT,
    INTEL_TDX_DCAP_ZK_VERIFIER_ADAPTER_SALT,
    TPM_QUOTE_ZK_VERIFIER_ADAPTER_SALT,
    ZK_VERIFIER_REGISTRY_IMPL_SALT,
    ZK_VERIFIER_REGISTRY_PROXY_SALT
} from "./utils/Salt.sol";
import {ZkVerifierRegistry} from "../src/ZkVerifierRegistry.sol";
import {IDcapAttestation} from "../src/interfaces/external/IDcapAttestation.sol";
import {ISnpAttestation} from "../src/interfaces/external/ISnpAttestation.sol";
import {ISp1Verifier} from "../src/interfaces/zk/IZkVerifierAdapters.sol";
import {VerificationBackendType} from "../src/types/Evidence.sol";
import {ZkProofType} from "../src/types/Zk.sol";
import {
    AmdSevSnpZkVerifierAdapter,
    AwsNitroTpmZkVerifierAdapter,
    IntelTdxDcapZkVerifierAdapter,
    TpmQuoteZkVerifierAdapter
} from "../src/zk/ZkVerifierAdapters.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/console.sol";

contract DeployZkVerifierRegistry is DeploymentConfig {
    bytes32 internal constant INTEL_TDX_DCAP_PROGRAM_IDENTIFIER =
        0x00ed85153a35a84ea1fff62d16ac42f850082f11caea923bf25c20a432bdae46;
    bytes32 internal constant AMD_SEV_SNP_PROGRAM_IDENTIFIER =
        0x007589387c69b403fe8d2b0e1c7db05175155daff7125fc981ac6ecd1985d18c;
    bytes32 internal constant TPM_QUOTE_PROGRAM_IDENTIFIER =
        0x004b8dbbef212fa2002717517013cc2bf744243ec71ca93bcd6a273ccd800fc3;
    bytes32 internal constant AWS_NITROTPM_PROGRAM_IDENTIFIER =
        0x00cd086453546fe7d98b1d429c024ca657abce6231b04645b465f3ca965cc9eb;

    function _deployZkVerifierRegistry() internal returns (address) {
        address owner = vm.envAddress("OWNER");
        address dcapAttestationAddress = vm.envAddress("DCAP_ATTESTATION_ADDR");
        uint32 dcapTcbEvaluationDataNumber = uint32(vm.envUint("DCAP_TCB_EVALUATION_DATA_NUMBER"));
        address snpAttestationAddress = vm.envAddress("SNP_ATTESTATION_ADDR");
        address sp1VerifierAddress = vm.envAddress("SP1_VERIFIER_ADDR");

        ZkVerifierRegistry implementation = new ZkVerifierRegistry{salt: ZK_VERIFIER_REGISTRY_IMPL_SALT}();
        ZkVerifierRegistry registry = ZkVerifierRegistry(
            address(
                new ERC1967Proxy{salt: ZK_VERIFIER_REGISTRY_PROXY_SALT}(
                    address(implementation), abi.encodeCall(ZkVerifierRegistry.initialize, (owner))
                )
            )
        );
        IntelTdxDcapZkVerifierAdapter intelAdapter = new IntelTdxDcapZkVerifierAdapter{
            salt: INTEL_TDX_DCAP_ZK_VERIFIER_ADAPTER_SALT
        }(
            IDcapAttestation(dcapAttestationAddress),
            IDcapAttestation.ZkCoProcessorType.Succinct,
            dcapTcbEvaluationDataNumber
        );
        AmdSevSnpZkVerifierAdapter amdAdapter = new AmdSevSnpZkVerifierAdapter{
            salt: AMD_SEV_SNP_ZK_VERIFIER_ADAPTER_SALT
        }(
            ISnpAttestation(snpAttestationAddress), ISnpAttestation.ZkCoProcessorType.Succinct
        );
        TpmQuoteZkVerifierAdapter tpmAdapter =
            new TpmQuoteZkVerifierAdapter{salt: TPM_QUOTE_ZK_VERIFIER_ADAPTER_SALT}(ISp1Verifier(sp1VerifierAddress));
        AwsNitroTpmZkVerifierAdapter awsAdapter = new AwsNitroTpmZkVerifierAdapter{
            salt: AWS_NITROTPM_ZK_VERIFIER_ADAPTER_SALT
        }(
            ISp1Verifier(sp1VerifierAddress)
        );

        registry.setZkProgramConfig(
            ZkProofType.IntelTdxDcap,
            VerificationBackendType.ZkSuccinct,
            INTEL_TDX_DCAP_PROGRAM_IDENTIFIER,
            address(intelAdapter),
            true
        );
        registry.setZkProgramConfig(
            ZkProofType.AmdSevSnp,
            VerificationBackendType.ZkSuccinct,
            AMD_SEV_SNP_PROGRAM_IDENTIFIER,
            address(amdAdapter),
            true
        );
        registry.setZkProgramConfig(
            ZkProofType.TpmQuote,
            VerificationBackendType.ZkSuccinct,
            TPM_QUOTE_PROGRAM_IDENTIFIER,
            address(tpmAdapter),
            true
        );
        registry.setZkProgramConfig(
            ZkProofType.AwsNitroTpm,
            VerificationBackendType.ZkSuccinct,
            AWS_NITROTPM_PROGRAM_IDENTIFIER,
            address(awsAdapter),
            true
        );

        writeToJson("ZkVerifierRegistryImpl", address(implementation));
        writeToJson("ZkVerifierRegistry", address(registry));
        writeToJson("IntelTdxDcapZkVerifierAdapter", address(intelAdapter));
        writeToJson("AmdSevSnpZkVerifierAdapter", address(amdAdapter));
        writeToJson("TpmQuoteZkVerifierAdapter", address(tpmAdapter));
        writeToJson("AwsNitroTpmZkVerifierAdapter", address(awsAdapter));
        console.log("ZkVerifierRegistry deployed at:", address(registry));
        return address(registry);
    }

    function deployZkVerifierRegistry() public virtual {
        vm.startBroadcast(vm.envAddress("OWNER"));
        _deployZkVerifierRegistry();
        vm.stopBroadcast();
    }

    function run() public virtual {
        deployZkVerifierRegistry();
    }
}

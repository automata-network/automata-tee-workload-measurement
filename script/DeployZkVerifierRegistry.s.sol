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
        0x003e867031f3ecfb37bfa94d669b407a3ddb9b4e6e051201226d8bdad3a49120;
    bytes32 internal constant AMD_SEV_SNP_PROGRAM_IDENTIFIER =
        0x00bc5bae7f7c200ec91f866ee2f2927cc01fcf365a55f76c819648e5277d1286;
    bytes32 internal constant TPM_QUOTE_PROGRAM_IDENTIFIER =
        0x0093daf8d7fac35987977a557eaaed760c9f7acd3abce4b21b58611eec08c108;
    bytes32 internal constant AWS_NITROTPM_PROGRAM_IDENTIFIER =
        0x000f530085e51691cf679b131ebc02b69534f0ad8ee06291ec3ba11ff7c97150;

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

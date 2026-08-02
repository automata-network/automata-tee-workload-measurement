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
        0x00f92be42225bed0ce76e07219d6383a4fa3cb1c6bd5dd805492b8fe5dcdedea;
    bytes32 internal constant AMD_SEV_SNP_PROGRAM_IDENTIFIER =
        0x00bc5bae7f7c200ec91f866ee2f2927cc01fcf365a55f76c819648e5277d1286;
    bytes32 internal constant TPM_QUOTE_PROGRAM_IDENTIFIER =
        0x0095ee2d1d0faa1d40db3e79fb7abfd4c9350f1a5d75086213e1bf0d94cc4ed8;
    bytes32 internal constant AWS_NITROTPM_PROGRAM_IDENTIFIER =
        0x00c57d71a011d4c7dc778a6135f3dddb238878f25228d998c1283deef53e9b0a;

    function _deployZkVerifierRegistry() internal returns (address) {
        address owner = vm.envAddress("OWNER");
        address dcapAttestationAddress = vm.envAddress("DCAP_ATTESTATION_ADDR");
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
            IDcapAttestation(dcapAttestationAddress), IDcapAttestation.ZkCoProcessorType.Succinct
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

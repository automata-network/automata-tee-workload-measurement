// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {UpdateAmdSnpSecurityPolicies} from "../script/UpdateAmdSnpSecurityPolicies.s.sol";
import {AmdSnpSecurityPolicyUpdate} from "../src/interfaces/registries/IAmdSnpSecurityPolicyRegistry.sol";

contract UpdateAmdSnpSecurityPoliciesHarness is UpdateAmdSnpSecurityPolicies {
    function parsePolicyUpdates(string memory policyJson) external view returns (AmdSnpSecurityPolicyUpdate[] memory) {
        return _parsePolicyUpdates(policyJson);
    }
}

contract UpdateAmdSnpSecurityPoliciesTest is Test {
    function testParsesDocumentedNamedFieldJson() public {
        string memory policyJson = string.concat(
            '{"policies":[{',
            '"cpuid":1638657,',
            '"revision":7,',
            '"active":true,',
            '"minimumTcb":"0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004",',
            '"platformInfoPolicy":"0x0000000000000000000000000000000000000000000000000000000000000020"',
            "}]}"
        );

        UpdateAmdSnpSecurityPoliciesHarness harness = new UpdateAmdSnpSecurityPoliciesHarness();
        AmdSnpSecurityPolicyUpdate[] memory policies = harness.parsePolicyUpdates(policyJson);

        assertEq(policies.length, 1);
        assertEq(policies[0].cpuid, 0x190101);
        assertEq(policies[0].revision, 7);
        assertTrue(policies[0].active);
        assertEq(policies[0].minimumTcb, 0x00000000de1d000400000000de1d000400000000de1d000400000000de1d0004);
        assertEq(policies[0].platformInfoPolicy, 0x0000000000000000000000000000000000000000000000000000000000000020);
    }
}

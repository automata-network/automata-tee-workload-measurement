// SPDX-License-Identifier: Apache2
// Automata Contracts
pragma solidity ^0.8.15;

import {Script, console} from "forge-std/Script.sol";
import { stdJson } from "forge-std/StdJson.sol";

contract Deploy is Script {
    using stdJson for string;
    
    function readFile(string memory file) public view returns (string memory) {
        return vm.readFile(string(abi.encodePacked("./test/testdata/", file, ".json")));
    }

    function deployP256Verifier() internal {
        string memory json = readFile("p256");
        address target = json.readAddress(".address");
        bytes memory cd = json.readBytes(".calldata");
        (bool isSucc,) = address(target).call(cd);
        require(isSucc, "Failed to deploy P256Verifier");
    }
}
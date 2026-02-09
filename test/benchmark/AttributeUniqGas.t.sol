// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.15;

import {Test} from "forge-std/Test.sol";

contract AttributeUniqGasTest is Test {
    struct Attribute {
        bytes32 key;
        bytes32 value;
    }

    function testGasValidate10() public {
        Attribute[] memory attrs = _makeAttrs(10);

        vm.pauseGasMetering();
        bytes memory data = abi.encodeWithSelector(this._validate.selector, attrs);
        vm.resumeGasMetering();

        uint256 gasBefore = gasleft();
        (bool ok,) = address(this).call(data);
        uint256 gasAfter = gasleft();
        require(ok, "validate failed");

        emit log_named_uint("validate_10_gas", gasBefore - gasAfter);
    }

    function testGasValidate50() public {
        Attribute[] memory attrs = _makeAttrs(50);

        vm.pauseGasMetering();
        bytes memory data = abi.encodeWithSelector(this._validate.selector, attrs);
        vm.resumeGasMetering();

        uint256 gasBefore = gasleft();
        (bool ok,) = address(this).call(data);
        uint256 gasAfter = gasleft();
        require(ok, "validate failed");

        emit log_named_uint("validate_50_gas", gasBefore - gasAfter);
    }

    function _validate(Attribute[] calldata attrs) external pure {
        uint256 len = attrs.length;
        if (len < 2) {
            return;
        }

        uint256 cap = 1;
        while (cap < len * 2) {
            cap <<= 1;
        }

        bytes32[] memory keys = new bytes32[](cap);
        bool[] memory used = new bool[](cap);

        for (uint256 i = 0; i < len; i++) {
            bytes32 key = attrs[i].key;
            uint256 slot = uint256(key) & (cap - 1);
            while (used[slot]) {
                if (keys[slot] == key) {
                    revert("Duplicate");
                }
                slot = (slot + 1) & (cap - 1);
            }
            used[slot] = true;
            keys[slot] = key;
        }
    }

    function _makeAttrs(uint256 count) private pure returns (Attribute[] memory attrs) {
        attrs = new Attribute[](count);
        for (uint256 i = 0; i < count; i++) {
            attrs[i] = Attribute({key: bytes32(uint256(i + 1)), value: bytes32(uint256(i + 1))});
        }
    }
}

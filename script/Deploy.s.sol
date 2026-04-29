// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {SocialRecoveryModule} from "src/SocialRecoveryModule.sol";

contract DeployScript is Script {
    SocialRecoveryModule public module; // 0x3f0fF6225A17FB2bC4d3b3B834c1D29b62AC6555
    address deployer = 0x4F43446a48292726a381249423EE126CaBfd36B4;


    uint256 minimumCooldown = 7 days;

    function setUp() public {}

    function run() public {
        vm.startBroadcast(deployer);

        module = new SocialRecoveryModule(minimumCooldown);

        vm.stopBroadcast();
    }
}

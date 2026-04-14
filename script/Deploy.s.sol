// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {SocialRecoveryModule} from "src/SocialRecoveryModule.sol";

contract DeployScript is Script {
    SocialRecoveryModule public module; // 0x9e80f134f2D2ECEF84D6886827bbc6F06F0e5A56
    address deployer = 0xedEd14C7b5ac8B2adA30D70B61E1a64CAA37f6c9;

    uint256 minimumCooldown = 7 days;

    function setUp() public {}

    function run() public {
        vm.startBroadcast(deployer);

        module = new SocialRecoveryModule(minimumCooldown);

        vm.stopBroadcast();
    }
}

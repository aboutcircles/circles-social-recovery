// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {SocialRecoveryModule} from "src/SocialRecoveryModule.sol";

contract DeployScript is Script {
    SocialRecoveryModule public module;
    address deployer = 0x77e2b886ED1dDc826F04F9835BA08DA3FefaA40B;

    uint256 minimumCooldown = 7 days;

    function setUp() public {}

    function run() public {
        vm.startBroadcast(deployer);

        module = new SocialRecoveryModule(minimumCooldown);

        vm.stopBroadcast();
    }
}

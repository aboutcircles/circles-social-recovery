// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import {SocialRecoveryModule} from "src/SocialRecoveryModule.sol";

/// @dev Minimal Safe mock used to exercise the reentrancy surface of
///      SocialRecoveryModule. Implements only the parts of the Safe interface
///      the module actually calls: isModuleEnabled, getThreshold,
///      addOwnerWithThreshold, and execTransactionFromModuleReturnData.
///      The last one is the CEI gap in executeRecovery — state is still
///      "active" when the Safe is invoked, so the Safe can call back into SRM.
contract ReentrantSafe {
    SocialRecoveryModule public immutable SRM;

    mapping(address => bool) internal _modules;
    uint256 public ownerThreshold = 1;
    address[] internal _owners;

    address public reenterTarget;
    bytes public reenterCalldata;
    bool public reenterOnExec;

    bool public reentered;
    bool public reenterSuccess;
    bytes public reenterReturnData;

    constructor(SocialRecoveryModule _srm) {
        SRM = _srm;
        _modules[address(_srm)] = true;
    }

    /// @notice Arm a one-shot reentrant call to `target` on the next
    ///         execTransactionFromModuleReturnData invocation. `target` may be
    ///         SRM directly (msg.sender = this safe) or a collaborator such as
    ///         an evil guardian that then forwards into SRM (msg.sender = guardian).
    function arm(address target, bytes calldata data) external {
        reenterTarget = target;
        reenterCalldata = data;
        reenterOnExec = true;
        reentered = false;
        reenterSuccess = false;
        delete reenterReturnData;
    }

    function ownersLength() external view returns (uint256) {
        return _owners.length;
    }

    function ownerAt(uint256 i) external view returns (address) {
        return _owners[i];
    }

    function isModuleEnabled(address module) external view returns (bool) {
        return _modules[module];
    }

    function enableModule(address module) external {
        _modules[module] = true;
    }

    function getThreshold() external view returns (uint256) {
        return ownerThreshold;
    }

    function addOwnerWithThreshold(address owner, uint256 _threshold) external {
        _owners.push(owner);
        ownerThreshold = _threshold;
    }

    /// @dev The reentry point. SRM calls this from _addRecoveryOwner
    ///      BEFORE clearing recovery state, which lets us hit SRM again
    ///      with recovery still flagged active.
    function execTransactionFromModuleReturnData(address to, uint256 value, bytes calldata data, uint8)
        external
        returns (bool success, bytes memory returnData)
    {
        require(_modules[msg.sender], "not module");

        if (reenterOnExec && !reentered) {
            reenterOnExec = false;
            reentered = true;
            (reenterSuccess, reenterReturnData) = reenterTarget.call(reenterCalldata);
        }

        (success, returnData) = to.call{value: value}(data);
    }
}

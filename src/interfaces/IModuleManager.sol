// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

interface IModuleManager {
    event DisabledModule(address indexed module);
    event EnabledModule(address indexed module);
    event ExecutionFromModuleFailure(address indexed module);
    event ExecutionFromModuleSuccess(address indexed module);

    function disableModule(address prevModule, address module) external;
    function enableModule(address module) external;
    function execTransactionFromModule(address to, uint256 value, bytes memory data, uint8 operation)
        external
        returns (bool success);
    function execTransactionFromModuleReturnData(address to, uint256 value, bytes memory data, uint8 operation)
        external
        returns (bool success, bytes memory returnData);
    function getModulesPaginated(address start, uint256 pageSize)
        external
        view
        returns (address[] memory array, address next);
    function isModuleEnabled(address module) external view returns (bool);
}

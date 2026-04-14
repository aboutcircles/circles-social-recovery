// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

interface IOwnerManager {
    function addOwnerWithThreshold(address owner, uint256 _threshold) external;
    function getThreshold() external view returns (uint256);
}

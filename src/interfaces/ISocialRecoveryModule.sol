// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

interface ISocialRecoveryModule {
    error AlreadyConfigured(address safe);
    error CooldownBelowMinimum();
    error DuplicateListElement(address element);
    error GuardianAlreadyApprovedRecovery();
    error GuardianHasNotApprovedRecovery();
    error InvalidApprovalCount();
    error InvalidGuardiansCount();
    error InvalidListElement();
    error InvalidPasskey();
    error InvalidThreshold();
    error ModuleNotEnabled();
    error NoActiveRecovery();
    error NotConfigured();
    error NotGuardian();
    error OnlyHuman();
    error OnlyMutualTrust();
    error RecoveryAlreadyActive();
    error RecoveryPeriodEnded();
    error RecoveryPeriodNotEnded();
    error SelfGuardianNotAllowed();
    error ThresholdCannotBeReached();

    event ConfigurationRemoved(address indexed safe);
    event ConfigurationRemovedOnGuardianOptOut(address indexed safe, address indexed guardian);
    event GuardianAdded(address indexed safe, address indexed guardian);
    event GuardianOptedOut(address indexed safe, address indexed guardian);
    event GuardianRemoved(address indexed safe, address indexed guardian);
    event ModuleConfigured(
        address indexed safe, uint256 threshold, uint256 recoveryCooldown, uint256 guardiansCount, address[] guardians
    );
    event RecoveryApprovalRevoked(address indexed safe, address indexed guardian, address indexed newPasskey);
    event RecoveryApproved(address indexed safe, address indexed guardian, address indexed newPasskey);
    event RecoveryCanceledByInitiator(address indexed safe, address indexed guardian);
    event RecoveryCanceledByInitiatorOptOut(address indexed safe);
    event RecoveryCanceledBySafe(address indexed safe);
    event RecoveryCooldownUpdated(address indexed safe, uint256 recoveryCooldown);
    event RecoveryExecuted(address indexed safe, address indexed newPasskey, address[] approvingGuardians);
    event RecoveryExpiredInsufficientApprovals(address indexed safe);
    event RecoveryInitiated(
        address indexed safe,
        address indexed initiatorGuardian,
        address indexed newPasskey,
        uint256 startTime,
        uint256 endTime
    );
    event RecoveryThresholdLost(address indexed safe);
    event RecoveryThresholdReached(address indexed safe);
    event ThresholdAutoReducedOnGuardianOptOut(address indexed safe, address indexed guardian, uint256 newThreshold);
    event ThresholdUpdated(address indexed safe, uint256 threshold);

    function HUB() external view returns (address);
    function SAFE_WEB_AUTHN_SIGNER_FACTORY() external view returns (address);
    function addGuardian(address guardian, uint256 newThreshold) external;
    function approveRecovery(address safe) external;
    function cancelExpiredRecovery(address safe) external;
    function cancelRecovery() external;
    function configure(uint256 threshold, uint256 recoveryCooldown, address[] memory guardians) external;
    function executeRecovery(address safe) external;
    function getConfiguration(address safe)
        external
        view
        returns (uint256 threshold, uint256 recoveryCooldown, address[] memory guardians);
    function getRecovery(address safe)
        external
        view
        returns (
            address initiator,
            address newPasskey,
            uint256 approvalCount,
            uint256 initiationTimestamp,
            address[] memory approvingGuardians
        );
    function getWards(address guardian) external view returns (address[] memory wards_);
    function initiateRecovery(address safe, address newPasskey) external;
    function optOutAsGuardian(address safe) external;
    function removeConfiguration() external;
    function removeGuardian(address guardian, uint256 newThreshold) external;
    function revokeRecoveryApproval(address safe) external;
    function updateRecoveryCooldown(uint256 recoveryCooldown) external;
    function updateThreshold(uint256 newThreshold) external;
}

// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import {IHub} from "src/interfaces/IHub.sol";
import {IModuleManager} from "src/interfaces/IModuleManager.sol";
import {IOwnerManager} from "src/interfaces/IOwnerManager.sol";
import {ISafeWebAuthnSignerFactory} from "src/interfaces/ISafeWebAuthnSignerFactory.sol";
import {ISafeWebAuthnSignerProxy} from "src/interfaces/ISafeWebAuthnSignerProxy.sol";

/// @title SocialRecoveryModule
/// @notice Enables Circles-human guardian based social recovery for Safe accounts.
/// @dev
/// The module lets a Safe configure a guardian set, a recovery threshold, and a cooldown period.
/// Guardians can initiate a recovery toward a replacement WebAuthn signer and collectively approve it.
/// Once the cooldown expires, anyone can execute the recovery if enough approvals were collected.
/// Guardian membership is stored as sentinel-based linked lists in storage to support enumeration.
contract SocialRecoveryModule {
    /// @notice Configuration data for a Safe that enabled social recovery.
    /// @param threshold Minimum number of guardian approvals required for a recovery to succeed.
    /// @param recoveryCooldown Cooldown duration in seconds between recovery initiation and execution.
    /// @param guardiansCount Number of configured guardians.
    /// @param guardians Sentinel-based linked list of guardians for the Safe.
    struct Config {
        uint256 threshold;
        uint256 recoveryCooldown;
        uint256 guardiansCount;
        mapping(address => address) guardians;
    }

    /// @notice Recovery state for a Safe with an active recovery attempt.
    /// @param initiator Guardian that initiated the currently active recovery.
    /// @param newPasskey Proposed replacement passkey signer to add as a Safe owner.
    /// @param initiationTimestamp Block timestamp at which the recovery was started.
    /// @param approvalCount Number of guardians currently approving the recovery.
    /// @param approvingGuardians Sentinel-based linked list of guardians that approved the recovery.
    struct Recovery {
        address initiator;
        address newPasskey;
        uint256 initiationTimestamp;
        uint256 approvalCount;
        mapping(address => address) approvingGuardians;
    }

    /*//////////////////////////////////////////////////////////////
                                Errors
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when an address is required to be recognized as human by the Circles Hub.
    error OnlyHuman();

    /// @notice Thrown when a guardian and ward do not have mutual trust in the Circles Hub.
    error OnlyMutualTrust();

    /// @notice Thrown when a threshold value is zero.
    error InvalidThreshold();

    /// @notice Thrown when a guardians count is zero.
    error InvalidGuardiansCount();

    /// @notice Thrown when an approval count is set below one for an active recovery.
    error InvalidApprovalCount();

    /// @notice Thrown when a configured recovery cooldown is below the immutable minimum.
    error CooldownBelowMinimum();

    /// @notice Thrown when attempting to configure a Safe that is already configured.
    /// @param safe Safe address that already has a configuration.
    error AlreadyConfigured(address safe);

    /// @notice Thrown when the module is not enabled on the calling Safe.
    error ModuleNotEnabled();

    /// @notice Thrown when a proposed passkey is not a valid Safe WebAuthn signer proxy.
    error InvalidPasskey();

    /// @notice Thrown when attempting to start a second recovery while one is already active.
    error RecoveryAlreadyActive();

    /// @notice Thrown when a requested threshold exceeds the number of guardians that can approve.
    error ThresholdCannotBeReached();

    /// @notice Thrown when a linked-list element is zero address or the sentinel.
    error InvalidListElement();

    /// @notice Thrown when the Safe attempts to add itself as a guardian.
    error SelfGuardianNotAllowed();

    /// @notice Thrown when attempting to insert a duplicate element into a linked list.
    /// @param element Duplicate address that is already present.
    error DuplicateListElement(address element);

    /// @notice Thrown when an operation requires an existing configuration but none is present.
    error NotConfigured();

    /// @notice Thrown when an operation requires the caller or target to be a guardian but it is not.
    error NotGuardian();

    /// @notice Thrown when an operation requires an active recovery but none exists.
    error NoActiveRecovery();

    /// @notice Thrown when a guardian attempts to approve a recovery more than once.
    error GuardianAlreadyApprovedRecovery();

    /// @notice Thrown when a guardian attempts to revoke an approval that does not exist.
    error GuardianHasNotApprovedRecovery();

    /// @notice Thrown when trying to approve or revoke after the recovery approval window has ended.
    error RecoveryPeriodEnded();

    /// @notice Thrown when trying to execute a recovery before the cooldown period has elapsed.
    error RecoveryPeriodNotEnded();

    /*//////////////////////////////////////////////////////////////
                                Events
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a Safe configures the module for the first time.
    /// @param safe Safe that created the configuration.
    /// @param threshold Required approval threshold.
    /// @param recoveryCooldown Cooldown duration in seconds.
    /// @param guardiansCount Number of configured guardians.
    /// @param guardians Guardian addresses configured for the Safe.
    event ModuleConfigured(
        address indexed safe, uint256 threshold, uint256 recoveryCooldown, uint256 guardiansCount, address[] guardians
    );

    /// @notice Emitted when a Safe fully removes its configuration.
    /// @param safe Safe whose configuration was removed.
    event ConfigurationRemoved(address indexed safe);

    /// @notice Emitted when the Safe cancels an active recovery.
    /// @param safe Safe whose recovery was canceled.
    event RecoveryCanceledBySafe(address indexed safe);

    /// @notice Emitted when a guardian initiates a recovery.
    /// @param safe Safe for which the recovery was initiated.
    /// @param initiatorGuardian Guardian that initiated the recovery.
    /// @param newPasskey Proposed replacement passkey.
    /// @param startTime Timestamp when recovery began.
    /// @param endTime Timestamp when the cooldown ends and execution becomes possible.
    event RecoveryInitiated(
        address indexed safe,
        address indexed initiatorGuardian,
        address indexed newPasskey,
        uint256 startTime,
        uint256 endTime
    );

    /// @notice Emitted when a guardian approves the active recovery.
    /// @param safe Safe under recovery.
    /// @param guardian Guardian that approved.
    /// @param newPasskey Proposed replacement passkey being approved.
    event RecoveryApproved(address indexed safe, address indexed guardian, address indexed newPasskey);

    /// @notice Emitted when a guardian revokes a previously given approval.
    /// @param safe Safe under recovery.
    /// @param guardian Guardian that revoked approval.
    /// @param newPasskey Proposed replacement passkey for the recovery.
    event RecoveryApprovalRevoked(address indexed safe, address indexed guardian, address indexed newPasskey);

    /// @notice Emitted when an expired recovery ends without enough approvals.
    /// @param safe Safe whose recovery expired unsuccessfully.
    event RecoveryExpiredInsufficientApprovals(address indexed safe);

    /// @notice Emitted when the initiating guardian cancels recovery by revoking their own approval.
    /// @param safe Safe whose recovery was canceled.
    /// @param guardian Guardian that initiated and canceled the recovery.
    event RecoveryCanceledByInitiator(address indexed safe, address indexed guardian);

    /// @notice Emitted when approvals reach or exceed the configured threshold.
    /// @param safe Safe whose recovery reached threshold.
    event RecoveryThresholdReached(address indexed safe);

    /// @notice Emitted when approvals drop from at/above threshold to below threshold.
    /// @param safe Safe whose recovery fell below threshold.
    event RecoveryThresholdLost(address indexed safe);

    /// @notice Emitted when a guardian is added to a Safe configuration.
    /// @param safe Safe receiving the guardian.
    /// @param guardian Guardian that was added.
    event GuardianAdded(address indexed safe, address indexed guardian);

    /// @notice Emitted when a Safe threshold is updated.
    /// @param safe Safe whose threshold changed.
    /// @param threshold New threshold value.
    event ThresholdUpdated(address indexed safe, uint256 threshold);

    /// @notice Emitted when a Safe recovery cooldown is updated.
    /// @param safe Safe whose cooldown changed.
    /// @param recoveryCooldown New cooldown duration in seconds.
    event RecoveryCooldownUpdated(address indexed safe, uint256 recoveryCooldown);

    /// @notice Emitted when a guardian is removed from a Safe configuration.
    /// @param safe Safe from which the guardian was removed.
    /// @param guardian Guardian that was removed.
    event GuardianRemoved(address indexed safe, address indexed guardian);

    /// @notice Emitted when the initiating guardian opts out and thereby cancels the active recovery.
    /// @param safe Safe whose recovery was canceled.
    event RecoveryCanceledByInitiatorOptOut(address indexed safe);

    /// @notice Emitted when a recovery successfully executes and adds the new passkey as a Safe owner.
    /// @param safe Safe whose ownership was recovered.
    /// @param newPasskey Newly added passkey owner.
    /// @param approvingGuardians Guardians that were approving at execution time.
    event RecoveryExecuted(address indexed safe, address indexed newPasskey, address[] approvingGuardians);

    /// @notice Emitted when the last guardian opts out and this removes the Safe configuration entirely.
    /// @param safe Safe whose configuration was removed.
    /// @param guardian Guardian that opted out.
    event ConfigurationRemovedOnGuardianOptOut(address indexed safe, address indexed guardian);

    /// @notice Emitted when guardian opt-out forces the threshold to be automatically reduced.
    /// @param safe Safe whose threshold was reduced.
    /// @param guardian Guardian that opted out.
    /// @param newThreshold Resulting threshold after the forced reduction.
    event ThresholdAutoReducedOnGuardianOptOut(address indexed safe, address indexed guardian, uint256 newThreshold);

    /// @notice Emitted when a guardian opts out of guarding a Safe.
    /// @param safe Safe the guardian opted out from.
    /// @param guardian Guardian that opted out.
    event GuardianOptedOut(address indexed safe, address indexed guardian);

    /*//////////////////////////////////////////////////////////////
                              Constants & Immutables
    //////////////////////////////////////////////////////////////*/

    /// @notice The Circles v2 Hub contract.
    IHub public constant HUB = IHub(address(0xc12C1E50ABB450d6205Ea2C3Fa861b3B834d13e8));

    /// @notice Factory used to validate canonical Safe WebAuthn signer proxy addresses.
    ISafeWebAuthnSignerFactory public constant SAFE_WEB_AUTHN_SIGNER_FACTORY =
        ISafeWebAuthnSignerFactory(address(0xF7488fFbe67327ac9f37D5F722d83Fc900852Fbf));

    /// @notice Sentinel node for the internal linked list.
    address private constant SENTINEL = address(0x1);

    /// @notice Minimum allowed cooldown duration for any configuration.
    uint256 internal immutable MINIMUM_COOLDOWN;

    /*//////////////////////////////////////////////////////////////
                                Storage
    //////////////////////////////////////////////////////////////*/

    /// @notice Per-Safe social recovery configuration.
    mapping(address safe => Config config) internal configurations;

    /// @notice Per-Safe active recovery state.
    mapping(address safe => Recovery recovery) internal recoveries;

    /// @notice Reverse index from guardian to Safes guarded by that guardian.
    mapping(address guardian => mapping(address => address)) internal wards;

    /*//////////////////////////////////////////////////////////////
                                 Modifiers
    //////////////////////////////////////////////////////////////*/

    /// @notice Restricts a function to Safes that have already configured the module.
    /// @param safe Safe whose configuration is required.
    modifier onlyConfigured(address safe) {
        if (_getThreshold(safe) == 0) revert NotConfigured();
        _;
    }

    /// @notice Restricts a function to Safes that currently have an active recovery.
    /// @param safe Safe whose recovery must be active.
    modifier onlyActiveRecovery(address safe) {
        if (!_isRecoveryActive(safe)) revert NoActiveRecovery();
        _;
    }

    /// @notice Restricts a function to addresses that are guardians of a given Safe.
    /// @param safe Safe whose guardian set is checked.
    /// @param guardian Address that must be a guardian.
    modifier onlyGuardian(address safe, address guardian) {
        if (!_isGuardian(safe, guardian)) revert NotGuardian();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                               Constructor
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the global minimum cooldown accepted for future configurations.
    /// @param minimumCooldown Minimum cooldown duration in seconds.
    constructor(uint256 minimumCooldown) {
        MINIMUM_COOLDOWN = minimumCooldown;
    }

    /*//////////////////////////////////////////////////////////////
                               Configuration
    //////////////////////////////////////////////////////////////*/

    /// @notice Configures social recovery for the calling Safe.
    /// @dev
    /// Requirements:
    /// - Caller must be recognized as human by the Circles Hub.
    /// - This module must already be enabled on the caller Safe.
    /// - The Safe must not already be configured.
    /// - `threshold` must be non-zero and at most `guardians.length`.
    /// - `recoveryCooldown` must be at least `MINIMUM_COOLDOWN`.
    /// - Each guardian must be human, distinct, not the Safe itself, and have mutual trust with the Safe.
    /// @param threshold Number of guardian approvals required to execute recovery.
    /// @param recoveryCooldown Cooldown duration in seconds before recovery can be executed.
    /// @param guardians List of guardian addresses to configure.
    function configure(uint256 threshold, uint256 recoveryCooldown, address[] memory guardians) external {
        address safe = msg.sender;
        _requireHuman(safe);
        if (!IModuleManager(safe).isModuleEnabled(address(this))) revert ModuleNotEnabled();
        if (_getThreshold(safe) != 0) revert AlreadyConfigured(safe);
        if (threshold > guardians.length) revert ThresholdCannotBeReached();
        _setThreshold(safe, threshold);
        _setRecoveryCooldown(safe, recoveryCooldown);
        _setGuardiansCount(safe, guardians.length);
        mapping(address => address) storage guardiansList = _getGuardiansList(safe);
        for (uint256 i; i < guardians.length;) {
            _addGuardian(safe, guardians[i], guardiansList);
            unchecked {
                ++i;
            }
        }
        emit ModuleConfigured(safe, threshold, recoveryCooldown, guardians.length, guardians);
    }

    /*//////////////////////////////////////////////////////////////
                            Safe Reconfiguration
    //////////////////////////////////////////////////////////////*/

    /// @notice Updates the approval threshold for the calling Safe.
    /// @dev Any active recovery is removed before the threshold is changed.
    /// @param newThreshold New approval threshold to set.
    function updateThreshold(uint256 newThreshold) external onlyConfigured(msg.sender) {
        address safe = msg.sender;
        if (_isRecoveryActive(safe)) _removeRecovery(safe);

        uint256 guardiansCount = _getGuardiansCount(safe);
        if (newThreshold > guardiansCount) revert ThresholdCannotBeReached();

        _setThreshold(safe, newThreshold);
    }

    /// @notice Updates the recovery cooldown for the calling Safe.
    /// @dev Any active recovery is removed before the cooldown is changed.
    /// @param recoveryCooldown New cooldown duration in seconds.
    function updateRecoveryCooldown(uint256 recoveryCooldown) external onlyConfigured(msg.sender) {
        address safe = msg.sender;
        if (_isRecoveryActive(safe)) _removeRecovery(safe);
        _setRecoveryCooldown(safe, recoveryCooldown);
    }

    /// @notice Adds a guardian to the calling Safe and optionally updates the threshold.
    /// @dev Any active recovery is removed before guardian membership changes.
    /// @param guardian Guardian address to add.
    /// @param newThreshold Threshold to set after addition.
    function addGuardian(address guardian, uint256 newThreshold) external onlyConfigured(msg.sender) {
        address safe = msg.sender;
        // safe is accesible, the recovery has no sense
        if (_isRecoveryActive(safe)) _removeRecovery(safe);

        uint256 guardiansCount = _getGuardiansCount(safe);
        // Only allow to add a guardian, if threshold can still be reached.
        if (newThreshold > guardiansCount + 1) revert ThresholdCannotBeReached();

        _addGuardian(safe, guardian, _getGuardiansList(safe));
        _setGuardiansCount(safe, guardiansCount + 1);
        if (_getThreshold(safe) != newThreshold) _setThreshold(safe, newThreshold);
    }

    /// @notice Removes a guardian from the calling Safe and optionally updates the threshold.
    /// @dev Any active recovery is removed before guardian membership changes.
    /// @param guardian Guardian address to remove.
    /// @param newThreshold Threshold to set after removal.
    function removeGuardian(address guardian, uint256 newThreshold) external onlyConfigured(msg.sender) {
        address safe = msg.sender;
        // safe is accesible, the recovery has no sense
        if (_isRecoveryActive(safe)) _removeRecovery(safe);

        uint256 guardiansCount = _getGuardiansCount(safe);
        // Only allow to remove a guardian, if threshold can still be reached.
        if (newThreshold > guardiansCount - 1) revert ThresholdCannotBeReached();

        mapping(address => address) storage guardians = _getGuardiansList(safe);
        if (!_isInLinkedList(guardian, guardians)) revert NotGuardian();
        _removeFromLinkedList(guardian, guardians);
        _removeFromLinkedList(safe, _getWardsList(guardian));
        _setGuardiansCount(safe, guardiansCount - 1);

        emit GuardianRemoved(safe, guardian);
        if (_getThreshold(safe) != newThreshold) _setThreshold(safe, newThreshold);
    }

    /// @notice Removes the entire social recovery configuration for the calling Safe.
    /// @dev Any active recovery is removed first.
    function removeConfiguration() external onlyConfigured(msg.sender) {
        address safe = msg.sender;
        if (_isRecoveryActive(safe)) _removeRecovery(safe);
        _removeConfiguration(safe);
        emit ConfigurationRemoved(safe);
    }

    /// @notice Lets a guardian opt out from guarding a Safe.
    /// @dev
    /// If the guardian is the initiator of an active recovery, the recovery is canceled.
    /// If the guardian had approved an active recovery, that approval is removed.
    /// If opt-out leaves no guardians, the full configuration is removed.
    /// If opt-out would make the current threshold unreachable, the threshold is automatically reduced.
    /// @param safe Safe from which the caller wants to opt out as guardian.
    function optOutAsGuardian(address safe) external onlyConfigured(safe) onlyGuardian(safe, msg.sender) {
        address guardian = msg.sender;
        bool activeRecovery = _isRecoveryActive(safe);
        uint256 threshold = _getThreshold(safe);
        uint256 guardiansCount = _getGuardiansCount(safe);
        if (activeRecovery) {
            if (guardian == _getInitiator(safe)) {
                // if guardian is initiator and opts out - cancel initiated recovery
                _removeRecovery(safe);
                emit RecoveryCanceledByInitiatorOptOut(safe);
            } else {
                mapping(address => address) storage approvingGuardians = _getApprovingGuardiansList(safe);
                if (_isInLinkedList(guardian, approvingGuardians)) {
                    // if approved recovery - revoke approval
                    _removeFromLinkedList(guardian, approvingGuardians);
                    uint256 approvalCount = _getApprovalCount(safe);
                    uint256 newApprovalCount = approvalCount - uint256(1);
                    if (approvalCount >= threshold && newApprovalCount < threshold && threshold <= guardiansCount - 1) {
                        emit RecoveryThresholdLost(safe);
                    }
                    _setApprovalCount(safe, newApprovalCount);
                }
            }
        }
        if (guardiansCount == 1) {
            if (activeRecovery) _removeRecovery(safe);
            // remove configuration
            _removeConfiguration(safe);
            emit ConfigurationRemovedOnGuardianOptOut(safe, guardian);
            return;
        }

        if (threshold > guardiansCount - 1) {
            // enforce threshold drop
            _setThreshold(safe, threshold - 1);
            emit ThresholdAutoReducedOnGuardianOptOut(safe, guardian, threshold - 1);
        }

        _removeFromLinkedList(guardian, _getGuardiansList(safe));
        _removeFromLinkedList(safe, _getWardsList(guardian));
        _setGuardiansCount(safe, guardiansCount - 1);
        emit GuardianOptedOut(safe, guardian);
    }

    /*//////////////////////////////////////////////////////////////
                            Safe Recovery
    //////////////////////////////////////////////////////////////*/

    /// @notice Starts a recovery for a Safe toward a new passkey.
    /// @dev
    /// The caller becomes both the recovery initiator and the first approving guardian.
    /// The recovery must not already be active.
    /// @param safe Safe for which recovery is being initiated.
    /// @param newPasskey Proposed replacement passkey signer to add upon successful execution.
    function initiateRecovery(address safe, address newPasskey) external onlyGuardian(safe, msg.sender) {
        if (_isRecoveryActive(safe)) revert RecoveryAlreadyActive();
        address initiatorGuardian = msg.sender;

        // insert recovery
        _setInitiator(safe, initiatorGuardian);
        _setRecoveryPasskey(safe, newPasskey);
        _setInitiationTimestamp(safe);
        _setApprovalCount(safe, uint256(1));

        _insertIntoLinkedList(initiatorGuardian, _getApprovingGuardiansList(safe));

        emit RecoveryInitiated(
            safe, initiatorGuardian, newPasskey, block.timestamp, block.timestamp + _getRecoveryCooldown(safe)
        );
    }

    /// @notice Approves an active recovery.
    /// @param safe Safe whose active recovery is being approved.
    function approveRecovery(address safe) external onlyActiveRecovery(safe) onlyGuardian(safe, msg.sender) {
        address guardian = msg.sender;
        if (block.timestamp >= _getRecoveryCooldown(safe) + _getInitiationTimestamp(safe)) {
            revert RecoveryPeriodEnded();
        }

        mapping(address => address) storage approvingGuardians = _getApprovingGuardiansList(safe);
        if (_isInLinkedList(guardian, approvingGuardians)) revert GuardianAlreadyApprovedRecovery();

        uint256 newApprovalCount = _getApprovalCount(safe) + uint256(1);

        _setApprovalCount(safe, newApprovalCount);
        _insertIntoLinkedList(guardian, approvingGuardians);

        if (newApprovalCount >= _getThreshold(safe)) emit RecoveryThresholdReached(safe);

        emit RecoveryApproved(safe, guardian, _getNewPasskey(safe));
    }

    /// @notice Revokes the caller's approval for an active recovery.
    /// @dev If the caller is the initiating guardian, the entire recovery is canceled.
    /// @param safe Safe whose active recovery approval is being revoked.
    function revokeRecoveryApproval(address safe) external onlyActiveRecovery(safe) onlyGuardian(safe, msg.sender) {
        address guardian = msg.sender;
        if (block.timestamp >= _getRecoveryCooldown(safe) + _getInitiationTimestamp(safe)) {
            revert RecoveryPeriodEnded();
        }

        mapping(address => address) storage approvingGuardians = _getApprovingGuardiansList(safe);
        if (!_isInLinkedList(guardian, approvingGuardians)) revert GuardianHasNotApprovedRecovery();

        // if guardian is initiator and revokes approval - cancel initiated recovery
        if (guardian == _getInitiator(safe)) {
            _removeRecovery(safe);
            emit RecoveryCanceledByInitiator(safe, guardian);
            return;
        }

        uint256 approvalCount = _getApprovalCount(safe);
        uint256 newApprovalCount = approvalCount - uint256(1);
        uint256 threshold = _getThreshold(safe);
        if (approvalCount >= threshold && newApprovalCount < threshold) emit RecoveryThresholdLost(safe);

        _setApprovalCount(safe, newApprovalCount);
        _removeFromLinkedList(guardian, approvingGuardians);

        emit RecoveryApprovalRevoked(safe, guardian, _getNewPasskey(safe));
    }

    /// @notice Executes an active recovery once the cooldown has elapsed.
    /// @dev
    /// If approvals meet the threshold, the new passkey is added as a Safe owner via module execution.
    /// Otherwise the recovery simply expires.
    /// Recovery state is removed in all cases.
    /// @param safe Safe whose recovery is being executed.
    function executeRecovery(address safe) external onlyActiveRecovery(safe) {
        if (block.timestamp < _getRecoveryCooldown(safe) + _getInitiationTimestamp(safe)) {
            revert RecoveryPeriodNotEnded();
        }

        bool ok = _getApprovalCount(safe) >= _getThreshold(safe);
        address newPasskey = _getNewPasskey(safe);
        address[] memory approvers = _getArrayFromList(_approvingGuardiansSlot(safe), _getApprovingGuardiansList(safe));

        _removeRecovery(safe);
        if (ok) {
            _addRecoveryOwner(safe, newPasskey);
            emit RecoveryExecuted(safe, newPasskey, approvers);
        } else {
            emit RecoveryExpiredInsufficientApprovals(safe);
        }
    }

    /// @notice Cancels an expired recovery that failed to reach threshold.
    /// @dev No effect unless the recovery is active, expired, and below threshold.
    /// @param safe Safe whose expired recovery should be cleared.
    function cancelExpiredRecovery(address safe) external {
        if (
            _isRecoveryActive(safe) && _getThreshold(safe) > _getApprovalCount(safe)
                && block.timestamp >= _getRecoveryCooldown(safe) + _getInitiationTimestamp(safe)
        ) {
            _removeRecovery(safe);
            emit RecoveryExpiredInsufficientApprovals(safe);
        }
    }

    /// @notice Lets the calling Safe cancel its active recovery, if any.
    function cancelRecovery() external {
        address safe = msg.sender;
        if (_isRecoveryActive(safe)) {
            _removeRecovery(safe);
            emit RecoveryCanceledBySafe(safe);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                 View
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the social recovery configuration for a Safe.
    /// @param safe Safe whose configuration is queried.
    /// @return threshold Required guardian approval threshold.
    /// @return recoveryCooldown Recovery cooldown duration in seconds.
    /// @return guardians Current guardian list.
    function getConfiguration(address safe)
        external
        view
        returns (uint256 threshold, uint256 recoveryCooldown, address[] memory guardians)
    {
        threshold = _getThreshold(safe);
        recoveryCooldown = _getRecoveryCooldown(safe);
        guardians = _getArrayFromList(_guardiansSlot(safe), _getGuardiansList(safe));
    }

    /// @notice Returns the current recovery state for a Safe.
    /// @param safe Safe whose recovery state is queried.
    /// @return initiator Guardian that initiated the recovery.
    /// @return newPasskey Proposed replacement passkey.
    /// @return approvalCount Number of current approvals.
    /// @return initiationTimestamp Timestamp at which recovery started.
    /// @return approvingGuardians Guardians currently approving the recovery.
    function getRecovery(address safe)
        external
        view
        returns (
            address initiator,
            address newPasskey,
            uint256 approvalCount,
            uint256 initiationTimestamp,
            address[] memory approvingGuardians
        )
    {
        (
            initiator, newPasskey, approvalCount, initiationTimestamp, approvingGuardians
        ) =
            (
                _getInitiator(safe),
                _getNewPasskey(safe),
                _getApprovalCount(safe),
                _getInitiationTimestamp(safe),
                _getArrayFromList(_approvingGuardiansSlot(safe), _getApprovingGuardiansList(safe))
            );
    }

    /// @notice Returns the list of Safes currently guarded by a guardian.
    /// @param guardian Guardian whose wards are queried.
    /// @return wards_ Array of Safe addresses guarded by `guardian`.
    function getWards(address guardian) external view returns (address[] memory wards_) {
        wards_ = _getArrayFromList(_wardsSlot(guardian), _getWardsList(guardian));
    }

    /*//////////////////////////////////////////////////////////////
                            Internal Linked List
    //////////////////////////////////////////////////////////////*/

    /// @notice Inserts an element at the head of a sentinel-based linked list.
    /// @dev Reverts for zero address, sentinel, or duplicates.
    /// @param element Address to insert.
    /// @param list Storage linked list to mutate.
    function _insertIntoLinkedList(address element, mapping(address => address) storage list) internal {
        if (element == address(0) || element == SENTINEL) revert InvalidListElement();
        if (list[element] != address(0)) revert DuplicateListElement(element);
        address head = list[SENTINEL];
        if (head == address(0)) head = SENTINEL;

        list[element] = head;
        list[SENTINEL] = element;
    }

    /// @notice Removes an element from a sentinel-based linked list if present.
    /// @dev Silently returns if the element is zero, sentinel, or absent.
    /// @param element Address to remove.
    /// @param list Storage linked list to mutate.
    function _removeFromLinkedList(address element, mapping(address => address) storage list) internal {
        if (element == SENTINEL || element == address(0) || list[element] == address(0)) return; // nothing to remove
        address current = list[SENTINEL];
        address prev = SENTINEL;
        while (current != SENTINEL) {
            if (current == element) {
                // unlink the node
                list[prev] = list[current];

                // delete the removed node
                delete list[current];
                return;
            }
            prev = current;
            current = list[current];
        }
    }

    /// @notice Deletes every element from a sentinel-based linked list.
    /// @param list Storage linked list to clear.
    function _deleteLinkedList(mapping(address => address) storage list) internal {
        address head = list[SENTINEL];
        if (head == address(0)) return; // empty list
        while (head != SENTINEL) {
            address next = list[head];
            list[head] = address(0);
            head = next;
        }
        list[SENTINEL] = address(0);
    }

    /// @notice Checks whether an address is present in a sentinel-based linked list.
    /// @param element Address to test.
    /// @param list Storage linked list to inspect.
    /// @return True if the element exists in the list.
    function _isInLinkedList(address element, mapping(address => address) storage list) internal view returns (bool) {
        return list[element] != address(0);
    }

    /// @notice Materializes a linked list into memory by reading storage directly.
    /// @dev
    /// `initSlot` must be the storage slot of the mapping that backs the linked list.
    /// `next` must be the first element after the sentinel, not the sentinel itself.
    /// @param next First list element.
    /// @param initSlot Storage slot of the mapping backing the list.
    /// @return linkedList In-memory array containing list elements in traversal order.
    function _getLinkedList(address next, uint256 initSlot) internal view returns (address[] memory linkedList) {
        assembly {
            // Store the mapping storage slot
            mstore(0x20, initSlot)
            // Store the array at the free memory location
            linkedList := mload(0x40)
            // clean linked list word
            mstore(linkedList, 0x0000000000000000000000000000000000000000000000000000000000000000)
            // Update free memory pointer
            mstore(0x40, add(mload(0x40), 0x20))
            // Start with the first node from solidity
            let element := next
            // While element != SENTINEL
            for {} iszero(eq(element, 0x01)) {} {
                // Increase free memory pointer by 0x20 for the new element
                mstore(0x40, add(mload(0x40), 0x20))
                // Increment array length
                mstore(linkedList, add(mload(linkedList), 0x01))
                // Store the new element in array
                mstore(add(linkedList, mul(mload(linkedList), 0x20)), element)

                // Compute the storage slot
                mstore(0, element)
                let nextSlot := keccak256(0, 0x40)

                // Move to next node
                element := sload(nextSlot)
            }
        }
    }

    /// @notice Converts a linked list mapping into an address array.
    /// @param slot Storage slot of the mapping backing the list.
    /// @param list Storage linked list to read.
    /// @return Array representation of the list.
    function _getArrayFromList(uint256 slot, mapping(address => address) storage list)
        internal
        view
        returns (address[] memory)
    {
        address nextElement = list[SENTINEL];
        if (nextElement == address(0) || nextElement == SENTINEL) return new address[](0);
        return _getLinkedList(nextElement, slot);
    }

    /*//////////////////////////////////////////////////////////////
                        Internal Configuration
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the configured recovery threshold for a Safe.
    /// @param safe Safe whose threshold is queried.
    /// @return Threshold value.
    function _getThreshold(address safe) internal view returns (uint256) {
        return configurations[safe].threshold;
    }

    /// @notice Returns the configured recovery cooldown for a Safe.
    /// @param safe Safe whose cooldown is queried.
    /// @return Cooldown duration in seconds.
    function _getRecoveryCooldown(address safe) internal view returns (uint256) {
        return configurations[safe].recoveryCooldown;
    }

    /// @notice Returns the number of guardians configured for a Safe.
    /// @param safe Safe whose guardian count is queried.
    /// @return Number of guardians.
    function _getGuardiansCount(address safe) internal view returns (uint256) {
        return configurations[safe].guardiansCount;
    }

    /// @notice Returns the guardian linked-list storage mapping for a Safe.
    /// @param safe Safe whose guardian list is queried.
    /// @return Storage reference to the guardian linked list.
    function _getGuardiansList(address safe) internal view returns (mapping(address => address) storage) {
        return configurations[safe].guardians;
    }

    /// @notice Computes the storage slot of the guardian linked-list mapping for a Safe.
    /// @param safe Safe whose guardian mapping slot is computed.
    /// @return Storage slot used by the guardian mapping.
    function _guardiansSlot(address safe) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(safe, uint256(0)))) + 3;
    }

    /// @notice Returns the wards linked-list storage mapping for a guardian.
    /// @param guardian Guardian whose wards list is queried.
    /// @return Storage reference to the wards linked list.
    function _getWardsList(address guardian) internal view returns (mapping(address => address) storage) {
        return wards[guardian];
    }

    /// @notice Computes the storage slot of the wards linked-list mapping for a guardian.
    /// @param guardian Guardian whose wards mapping slot is computed.
    /// @return Storage slot used by the wards mapping.
    function _wardsSlot(address guardian) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(guardian, uint256(2))));
    }

    /// @notice Checks whether an address is a configured guardian of a Safe.
    /// @param safe Safe whose guardian set is checked.
    /// @param guardian Address to test.
    /// @return True if `guardian` is configured for `safe`.
    function _isGuardian(address safe, address guardian) internal view returns (bool) {
        mapping(address => address) storage guardians = _getGuardiansList(safe);
        return _isInLinkedList(guardian, guardians);
    }

    /// @notice Sets the approval threshold for a Safe.
    /// @param safe Safe whose threshold is updated.
    /// @param threshold New threshold value.
    function _setThreshold(address safe, uint256 threshold) internal {
        if (threshold < 1) revert InvalidThreshold();
        configurations[safe].threshold = threshold;
        emit ThresholdUpdated(safe, threshold);
    }

    /// @notice Sets the recovery cooldown for a Safe.
    /// @param safe Safe whose cooldown is updated.
    /// @param recoveryCooldown New cooldown duration in seconds.
    function _setRecoveryCooldown(address safe, uint256 recoveryCooldown) internal {
        if (recoveryCooldown < MINIMUM_COOLDOWN) revert CooldownBelowMinimum();
        configurations[safe].recoveryCooldown = recoveryCooldown;
        emit RecoveryCooldownUpdated(safe, recoveryCooldown);
    }

    /// @notice Sets the guardian count for a Safe.
    /// @param safe Safe whose guardian count is updated.
    /// @param guardiansCount New guardian count.
    function _setGuardiansCount(address safe, uint256 guardiansCount) internal {
        if (guardiansCount < 1) revert InvalidGuardiansCount();
        configurations[safe].guardiansCount = guardiansCount;
    }

    /// @notice Adds a guardian relationship between a Safe and a guardian.
    /// @dev Also updates the reverse `wards` index for the guardian.
    /// @param safe Safe being guarded.
    /// @param guardian Guardian to add.
    /// @param guardians Storage linked list for the Safe guardian set.
    function _addGuardian(address safe, address guardian, mapping(address => address) storage guardians) internal {
        if (guardian == safe) revert SelfGuardianNotAllowed();
        _requireHuman(guardian);
        _requireMutualTrust(guardian, safe);
        _insertIntoLinkedList(guardian, guardians);
        _insertIntoLinkedList(safe, _getWardsList(guardian));
        emit GuardianAdded(safe, guardian);
    }

    /// @notice Removes the full configuration for a Safe.
    /// @dev Also removes reverse ward references from all guardians.
    /// @param safe Safe whose configuration is deleted.
    function _removeConfiguration(address safe) internal {
        configurations[safe].threshold = 0;
        configurations[safe].recoveryCooldown = 0;
        configurations[safe].guardiansCount = 0;

        address[] memory guardians = _getArrayFromList(_guardiansSlot(safe), _getGuardiansList(safe));
        for (uint256 i; i < guardians.length;) {
            _removeFromLinkedList(safe, _getWardsList(guardians[i]));
            unchecked {
                ++i;
            }
        }

        _deleteLinkedList(_getGuardiansList(safe));
    }

    /*//////////////////////////////////////////////////////////////
                        Internal Recovery
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the initiator guardian for an active recovery.
    /// @param safe Safe whose recovery initiator is queried.
    /// @return Initiator address.
    function _getInitiator(address safe) internal view returns (address) {
        return recoveries[safe].initiator;
    }

    /// @notice Returns the proposed new passkey for an active recovery.
    /// @param safe Safe whose proposed passkey is queried.
    /// @return New passkey address.
    function _getNewPasskey(address safe) internal view returns (address) {
        return recoveries[safe].newPasskey;
    }

    /// @notice Returns the current approval count for an active recovery.
    /// @param safe Safe whose approval count is queried.
    /// @return Approval count.
    function _getApprovalCount(address safe) internal view returns (uint256) {
        return recoveries[safe].approvalCount;
    }

    /// @notice Returns the timestamp when recovery was initiated.
    /// @param safe Safe whose recovery timestamp is queried.
    /// @return Initiation timestamp.
    function _getInitiationTimestamp(address safe) internal view returns (uint256) {
        return recoveries[safe].initiationTimestamp;
    }

    /// @notice Returns the approving-guardians linked-list storage mapping for a Safe recovery.
    /// @param safe Safe whose approving guardian list is queried.
    /// @return Storage reference to the approving guardians linked list.
    function _getApprovingGuardiansList(address safe) internal view returns (mapping(address => address) storage) {
        return recoveries[safe].approvingGuardians;
    }

    /// @notice Computes the storage slot of the approving-guardians linked-list mapping for a Safe recovery.
    /// @param safe Safe whose approving guardian mapping slot is computed.
    /// @return Storage slot used by the approving guardians mapping.
    function _approvingGuardiansSlot(address safe) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(safe, uint256(1)))) + 4;
    }

    /// @notice Checks whether a Safe currently has an active recovery.
    /// @param safe Safe to test.
    /// @return True if recovery state exists.
    function _isRecoveryActive(address safe) internal view returns (bool) {
        return _getInitiator(safe) != address(0);
    }

    /// @notice Sets the initiator guardian for a Safe recovery.
    /// @param safe Safe whose recovery initiator is set.
    /// @param initiator Initiator guardian address.
    function _setInitiator(address safe, address initiator) internal {
        recoveries[safe].initiator = initiator;
    }

    /// @notice Sets the proposed new passkey for a Safe recovery.
    /// @param safe Safe whose recovery passkey is set.
    /// @param newPasskey Proposed replacement passkey.
    function _setRecoveryPasskey(address safe, address newPasskey) internal {
        if (!_isValidPasskey(newPasskey)) revert InvalidPasskey();
        recoveries[safe].newPasskey = newPasskey;
    }

    /// @notice Sets the recovery initiation timestamp to the current block timestamp.
    /// @param safe Safe whose recovery timestamp is set.
    function _setInitiationTimestamp(address safe) internal {
        recoveries[safe].initiationTimestamp = block.timestamp;
    }

    /// @notice Sets the number of guardian approvals on an active recovery.
    /// @param safe Safe whose approval count is updated.
    /// @param approvalCount New approval count.
    function _setApprovalCount(address safe, uint256 approvalCount) internal {
        if (approvalCount < 1) revert InvalidApprovalCount();
        recoveries[safe].approvalCount = approvalCount;
    }

    /// @notice Removes all active recovery state for a Safe.
    /// @param safe Safe whose recovery state is cleared.
    function _removeRecovery(address safe) internal {
        recoveries[safe].initiator = address(0);
        recoveries[safe].newPasskey = address(0);
        recoveries[safe].initiationTimestamp = uint256(0);
        recoveries[safe].approvalCount = uint256(0);
        _deleteLinkedList(_getApprovingGuardiansList(safe));
    }

    /*//////////////////////////////////////////////////////////////
                                 Internal
    //////////////////////////////////////////////////////////////*/

    /// @notice Requires that an account is recognized as human by the Circles Hub.
    /// @param account Address to validate.
    function _requireHuman(address account) internal view {
        if (!HUB.isHuman(account)) revert OnlyHuman();
    }

    /// @notice Requires that guardian and ward mutually trust each other in the Circles Hub.
    /// @param guardian Proposed guardian address.
    /// @param ward Safe or ward address.
    function _requireMutualTrust(address guardian, address ward) internal view {
        if (!HUB.isTrusted(guardian, ward)) revert OnlyMutualTrust();
        if (!HUB.isTrusted(ward, guardian)) revert OnlyMutualTrust();
    }

    /// @notice Checks whether an address is a valid canonical Safe WebAuthn signer proxy.
    /// @param passkey Address to validate.
    /// @return True if the address exposes a valid configuration and matches the factory-derived signer address.
    function _isValidPasskey(address passkey) internal view returns (bool) {
        try ISafeWebAuthnSignerProxy(passkey).getConfiguration() returns (uint256 x, uint256 y, uint176 verifiers) {
            return SAFE_WEB_AUTHN_SIGNER_FACTORY.getSigner(x, y, verifiers) == passkey;
        } catch {
            return false;
        }
    }

    /// @notice Adds the recovered passkey as a Safe owner using module execution.
    /// @dev Reverts bubbling up return data if the Safe module transaction fails.
    /// @param safe Safe that will receive the new owner.
    /// @param newPasskey New passkey owner to add.
    function _addRecoveryOwner(address safe, address newPasskey) internal {
        uint256 safeOwnerThreshold = IOwnerManager(safe).getThreshold();
        bytes memory callData = abi.encodeWithSelector(
            bytes4(IOwnerManager.addOwnerWithThreshold.selector), newPasskey, safeOwnerThreshold
        );
        (bool success, bytes memory returnData) =
            IModuleManager(safe).execTransactionFromModuleReturnData(safe, 0, callData, uint8(0));
        if (!success) {
            assembly {
                revert(add(returnData, 0x20), mload(returnData))
            }
        }
    }
}

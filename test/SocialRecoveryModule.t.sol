// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import {stdError} from "forge-std/StdError.sol";
import {Test, console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {CirclesV2Setup, ISafeWebAuthnSignerFactory} from "./helpers/CirclesV2Setup.sol";
import {HubStorageWrites} from "./helpers/HubStorageWrites.sol";
import {ReentrantSafe} from "./helpers/ReentrantSafe.sol";
import {EvilGuardian} from "./helpers/EvilGuardian.sol";
import {IModuleManager} from "src/interfaces/IModuleManager.sol";
import {SocialRecoveryModule} from "src/SocialRecoveryModule.sol";

/// @title SocialRecoveryModuleTest
/// @notice End-to-end test suite for `SocialRecoveryModule`, exercised against a
///         live Circles v2 Hub fork and real Safe proxies (see `CirclesV2Setup` /
///         `HubStorageWrites` helpers). Tests cover the full module lifecycle:
///           - Configuration & reconfiguration: `testConfigure`, `testUpdateThreshold`,
///             `testUpdateRecoveryCooldown`, `testAddAndRemoveGuardian`,
///             `testRemoveConfiguration`.
///           - Guardian opt-out & edge cases: `testOptOutAsGuardian`,
///             `testOptOut_doubleRemoveRecovery_whenInitiatorIsLastGuardian`.
///           - Recovery flow: `testInitiateRecovery`, `testApproveAndRevokeRecovery`,
///             `testExecuteRecovery`, `testCancelExpiredRecovery`, `testCancelRecovery`,
///             `testRecoverWithoutMutualTrust`.
///           - Security regressions: `testReentrancy` and `testReentrancyViaEvilGuardian`
///             pin the post-fix of `executeRecovery` and will fail if
///             that fix is reverted.
/// @dev Helpers `ReentrantSafe` and `EvilGuardian` (in `./helpers/`) model an
///      attacker-controlled Safe and an attacker-controlled guardian that can
///      reenter SRM during module execution. Passkey creation reuses a shared
///      P-256 key derived in `setUp()`.

contract SocialRecoveryModuleTest is CirclesV2Setup, HubStorageWrites {
    /// @notice The current day, calculated from the block timestamp.
    uint64 public day;

    SocialRecoveryModule srModule;
    address guardianA;
    address guardianB;
    address guardianC;
    address guardianD;
    address alice;
    address bob;
    address[] guardiansList = new address[](3);

    uint256 minimumCooldown = 500;

    function setUp() public override {
        super.setUp();
        vm.warp(INVITATION_ONLY_TIME + 1);
        // set current day
        day = HUB_V2.day(block.timestamp);

        srModule = new SocialRecoveryModule(minimumCooldown);

        alice = makeAddr("alice");
        bob = makeAddr("bob");
        guardianA = makeAddr("guardianA");
        guardianB = makeAddr("guardianB");
        guardianC = makeAddr("guardianC");
        guardianD = makeAddr("guardianD");
        // 4 guardians,
        _registerHuman(guardianA);
        _registerHuman(guardianB);
        _registerHuman(guardianC);
        _registerHuman(guardianD);
        _registerHuman(alice);
        _registerHuman(bob);

        // Shared P-256 passkey used for alice/bob Safes.
        (sharedPubX, sharedPubY) = vm.publicKeyP256(uint256(0xabcdefff));

        _simulateSafe(guardianA, false);
        _simulateSafe(guardianB, false);
        _simulateSafe(guardianC, false);
        _simulateSafe(guardianD, false);
        _simulateSafe(alice, true);
        _simulateSafe(bob, true);

        _createMutualTrust(guardianA, alice);
        _createMutualTrust(guardianB, alice);
        _createMutualTrust(guardianC, alice);
        _createMutualTrust(guardianD, alice);

        guardiansList[0] = guardianA;
        guardiansList[1] = guardianB;
        guardiansList[2] = guardianC;
    }

    /// @notice Fuzzes `configure()` over every revert branch — non-human caller,
    ///         module disabled, invalid/over-sized threshold, cooldown below
    ///         minimum, self-as-guardian, non-human guardian, non-mutual-trust,
    ///         duplicates — then asserts the happy-path state and event.
    function testConfigure(uint256 _threshold, uint256 _recoveryCooldown) public {
        (uint256 threshold, uint256 recoveryCooldown, address[] memory guardians) =
            srModule.getConfiguration(address(alice));
        assertEq(threshold, 0);
        assertEq(recoveryCooldown, 0);
        assertEq(guardians.length, 0);

        address nonHuman = makeAddr("nonHuman");
        vm.prank(nonHuman);
        vm.expectRevert(SocialRecoveryModule.OnlyHuman.selector);
        srModule.configure(_threshold, _recoveryCooldown, guardiansList);

        vm.startPrank(alice);
        vm.expectRevert(SocialRecoveryModule.ModuleNotEnabled.selector);
        srModule.configure(_threshold, _recoveryCooldown, guardiansList);

        IModuleManager(alice).enableModule(address(srModule));
        if (_threshold == 0) {
            vm.expectRevert(SocialRecoveryModule.InvalidThreshold.selector);
            srModule.configure(_threshold, _recoveryCooldown, guardiansList);
            _threshold = guardiansList.length;
        }
        if (_threshold > guardiansList.length) {
            vm.expectRevert(SocialRecoveryModule.ThresholdCannotBeReached.selector);
            srModule.configure(_threshold, _recoveryCooldown, guardiansList);

            address[] memory emptyGuardian = new address[](0);
            vm.expectRevert(SocialRecoveryModule.ThresholdCannotBeReached.selector);
            srModule.configure(_threshold, _recoveryCooldown, emptyGuardian);
            _threshold = guardiansList.length;
        }

        if (_recoveryCooldown < minimumCooldown) {
            vm.expectRevert(SocialRecoveryModule.CooldownBelowMinimum.selector);
            srModule.configure(_threshold, _recoveryCooldown, guardiansList);
            _recoveryCooldown = minimumCooldown;
        }

        {
            guardiansList[1] = alice;
            vm.expectRevert(SocialRecoveryModule.SelfGuardianNotAllowed.selector);
            srModule.configure(_threshold, _recoveryCooldown, guardiansList);

            guardiansList[1] = nonHuman;
            vm.expectRevert(SocialRecoveryModule.OnlyHuman.selector);
            srModule.configure(_threshold, _recoveryCooldown, guardiansList);

            // alice and bob don't have mutual trust
            guardiansList[1] = bob;
            vm.expectRevert(SocialRecoveryModule.OnlyMutualTrust.selector);
            srModule.configure(_threshold, _recoveryCooldown, guardiansList);

            // guarndianA is already in the list
            guardiansList[1] = guardianA;
            vm.expectRevert(abi.encodeWithSelector(SocialRecoveryModule.DuplicateListElement.selector, guardianA));
            srModule.configure(_threshold, _recoveryCooldown, guardiansList);

            guardiansList[1] = guardianB;
            vm.expectEmit();
            emit SocialRecoveryModule.ModuleConfigured(
                alice, _threshold, _recoveryCooldown, guardiansList.length, guardiansList
            );
            srModule.configure(_threshold, _recoveryCooldown, guardiansList);

            (threshold, recoveryCooldown, guardians) = srModule.getConfiguration(address(alice));
            assertEq(threshold, _threshold);
            assertEq(recoveryCooldown, _recoveryCooldown);
            assertEq(guardians.length, guardiansList.length);

            vm.stopPrank();
        }
    }

    /// @notice Fuzzes `updateThreshold`: asserts the happy-path update plus the
    ///         `InvalidThreshold` (zero) and `ThresholdCannotBeReached` branches.
    function testUpdateThreshold(uint256 _newThreshold) public {
        (uint256 threshold, uint256 recoveryCooldown, address[] memory guardians) =
            srModule.getConfiguration(address(alice));

        vm.startPrank(alice);
        IModuleManager(alice).enableModule(address(srModule));

        emit SocialRecoveryModule.ModuleConfigured(alice, 2, minimumCooldown, guardiansList.length, guardiansList);
        srModule.configure(2, minimumCooldown, guardiansList);

        if (_newThreshold <= guardiansList.length && _newThreshold != 0) {
            vm.expectEmit();
            emit SocialRecoveryModule.ThresholdUpdated(address(alice), _newThreshold);
            srModule.updateThreshold(_newThreshold);

            (threshold, recoveryCooldown, guardians) = srModule.getConfiguration(address(alice));
            assertEq(threshold, _newThreshold);
            assertEq(recoveryCooldown, minimumCooldown);
            assertEq(guardians.length, guardiansList.length);
        } else if (_newThreshold == 0) {
            vm.expectRevert(SocialRecoveryModule.InvalidThreshold.selector);
            srModule.updateThreshold(_newThreshold);
        } else {
            vm.expectRevert(SocialRecoveryModule.ThresholdCannotBeReached.selector);
            srModule.updateThreshold(_newThreshold);
        }

        vm.stopPrank();
    }

    /// @notice Fuzzes `updateRecoveryCooldown`: covers the happy path and the
    ///         `CooldownBelowMinimum` revert.
    function testUpdateRecoveryCooldown(uint256 _newRecoveryCooldown) public {
        vm.startPrank(alice);
        IModuleManager(alice).enableModule(address(srModule));

        emit SocialRecoveryModule.ModuleConfigured(alice, 2, minimumCooldown, guardiansList.length, guardiansList);
        srModule.configure(2, minimumCooldown, guardiansList);

        if (_newRecoveryCooldown < minimumCooldown) {
            vm.expectRevert(SocialRecoveryModule.CooldownBelowMinimum.selector);
            srModule.updateRecoveryCooldown(_newRecoveryCooldown);
        } else if (_newRecoveryCooldown >= (type(uint256).max) - 1) {
            srModule.updateRecoveryCooldown(_newRecoveryCooldown);
            vm.stopPrank();

            vm.warp(block.timestamp + 1);

            // initiateRecovery itself panics (overflow in RecoveryInitiated event  block.timestamp + _getRecoveryCooldown(safe))
            address pk = _createNewPassKey(vm.randomUint());
            vm.prank(guardianA);
            vm.expectRevert(stdError.arithmeticError);
            srModule.initiateRecovery(alice, pk);

            // No active recovery exists, so approve/revoke revert with NoActiveRecovery (not overflow)
            vm.prank(guardianB);
            vm.expectRevert(SocialRecoveryModule.NoActiveRecovery.selector);
            srModule.approveRecovery(alice);

            vm.expectRevert(SocialRecoveryModule.NoActiveRecovery.selector);
            srModule.executeRecovery(alice);

            // cancelExpiredRecovery is a silent no-op
            srModule.cancelExpiredRecovery(alice);

            // Safe can still reset via updateRecoveryCooldown to a sane value
            vm.prank(alice);
            srModule.updateRecoveryCooldown(minimumCooldown);

            vm.prank(guardianA);
            srModule.initiateRecovery(alice, pk); // now works
        } else {
            vm.expectEmit();
            emit SocialRecoveryModule.RecoveryCooldownUpdated(address(alice), _newRecoveryCooldown);
            srModule.updateRecoveryCooldown(_newRecoveryCooldown);
        }

        vm.stopPrank();
    }

    /// @notice Fuzzes `addGuardian` then `removeGuardian`, asserting the updated
    ///         guardian list and threshold bounds (`ThresholdCannotBeReached`
    ///         when the new threshold exceeds the resulting guardian count).
    function testAddAndRemoveGuardian(uint256 _newThreshold) public {
        vm.assume(_newThreshold != 0);

        vm.startPrank(alice);
        IModuleManager(alice).enableModule(address(srModule));

        emit SocialRecoveryModule.ModuleConfigured(alice, 2, minimumCooldown, guardiansList.length, guardiansList);
        srModule.configure(2, minimumCooldown, guardiansList);

        (uint256 threshold, uint256 recoveryCooldown, address[] memory guardians) =
            srModule.getConfiguration(address(alice));
        assertEq(threshold, 2);
        assertEq(recoveryCooldown, minimumCooldown);
        assertEq(guardians[0], guardiansList[2]);
        assertEq(guardians[1], guardiansList[1]);
        assertEq(guardians[2], guardiansList[0]);

        if (_newThreshold > guardiansList.length + 1) {
            vm.expectRevert(SocialRecoveryModule.ThresholdCannotBeReached.selector);
            srModule.addGuardian(guardianD, _newThreshold);
        } else {
            srModule.addGuardian(guardianD, _newThreshold);

            (threshold, recoveryCooldown, guardians) = srModule.getConfiguration(address(alice));
            assertEq(threshold, _newThreshold);
            assertEq(recoveryCooldown, minimumCooldown);
            assertEq(guardians[0], guardianD);
            assertEq(guardians[1], guardiansList[2]);
            assertEq(guardians[2], guardiansList[1]);
            assertEq(guardians[3], guardiansList[0]);
        }

        /// Start to remove guardian

        address guardianToRemove = guardians[_newThreshold % guardians.length];

        if (_newThreshold < guardians.length) {
            srModule.removeGuardian(guardianToRemove, _newThreshold);

            (threshold, recoveryCooldown, guardians) = srModule.getConfiguration(address(alice));
            assertEq(threshold, _newThreshold);
            assertEq(recoveryCooldown, minimumCooldown);
            assertTrue(guardians[0] != guardianToRemove);
            assertTrue(guardians[1] != guardianToRemove);
            assertTrue(guardians[2] != guardianToRemove);
        } else {
            vm.expectRevert(SocialRecoveryModule.ThresholdCannotBeReached.selector);
            srModule.removeGuardian(guardianToRemove, _newThreshold);
        }

        vm.stopPrank();
    }

    /// @notice Configures the module, calls `removeConfiguration`, and asserts
    ///         that threshold, cooldown, and guardians are all fully cleared.
    function testRemoveConfiguration() public {
        vm.startPrank(alice);
        IModuleManager(alice).enableModule(address(srModule));

        emit SocialRecoveryModule.ModuleConfigured(alice, 2, minimumCooldown, guardiansList.length, guardiansList);
        srModule.configure(2, minimumCooldown, guardiansList);
        (uint256 threshold, uint256 recoveryCooldown, address[] memory guardians) =
            srModule.getConfiguration(address(alice));
        assertEq(threshold, 2);
        assertEq(recoveryCooldown, minimumCooldown);
        assertEq(guardians[0], guardiansList[2]);
        assertEq(guardians[1], guardiansList[1]);
        assertEq(guardians[2], guardiansList[0]);

        srModule.removeConfiguration();

        (threshold, recoveryCooldown, guardians) = srModule.getConfiguration(address(alice));
        assertEq(threshold, 0);
        assertEq(recoveryCooldown, 0);
        assertEq(guardians.length, 0);

        vm.stopPrank();
    }

    /// @notice Exercises `optOutAsGuardian` across its branches: simple opt-out,
    ///         opt-out during an active recovery (approval withdrawal vs.
    ///         initiator cancellation), auto-threshold-reduction, and full
    ///         configuration removal when the last guardian leaves.
    function testOptOutAsGuardian() public {
        vm.startPrank(alice);
        IModuleManager(alice).enableModule(address(srModule));

        srModule.configure(2, minimumCooldown, guardiansList);

        (uint256 threshold, uint256 recoveryCooldown, address[] memory guardians) =
            srModule.getConfiguration(address(alice));
        assertEq(threshold, 2);
        assertEq(recoveryCooldown, minimumCooldown);
        assertEq(guardians[0], guardiansList[2]);
        assertEq(guardians[1], guardiansList[1]);
        assertEq(guardians[2], guardiansList[0]);

        vm.stopPrank();

        vm.prank(guardianA);
        vm.expectEmit();
        emit SocialRecoveryModule.GuardianOptedOut(address(alice), address(guardianA));
        srModule.optOutAsGuardian(address(alice));

        (threshold, recoveryCooldown, guardians) = srModule.getConfiguration(address(alice));
        assertEq(threshold, 2);
        assertEq(recoveryCooldown, minimumCooldown);

        address newPasskey = _createNewPassKey(vm.randomUint());
        vm.prank(guardianB);

        srModule.initiateRecovery(address(alice), newPasskey);

        vm.prank(guardianC);
        vm.recordLogs();

        srModule.optOutAsGuardian(address(alice));

        Vm.Log[] memory entries = vm.getRecordedLogs();
        assertEq(entries.length, 4);

        // emit SocialRecoveryModule.ThresholdAutoReducedOnGuardianOptOut(address(alice), guardianC, threshold - 1);
        // emit ThresholdUpdated(safe: alice, threshold: 1)
        // emit RecoveryThresholdReached(safe: alice)
        // emit GuardianOptedOut(safe: alice, guardian: guardianC)

        vm.prank(guardianB);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryCanceledByInitiatorOptOut(address(alice));
        srModule.optOutAsGuardian(address(alice));

        guardiansList = new address[](1);
        guardiansList[0] = guardianA;
        vm.prank(alice);
        srModule.configure(1, minimumCooldown, guardiansList);

        vm.prank(guardianA);
        vm.expectEmit();
        emit SocialRecoveryModule.ConfigurationRemovedOnGuardianOptOut(address(alice), guardianA);
        srModule.optOutAsGuardian(address(alice));
    }

    function testOptOutAsGuardianAfterCooldown() public {
        guardiansList = new address[](3);
        guardiansList[0] = guardianA;
        guardiansList[1] = guardianB;
        guardiansList[2] = guardianC;

        address _newPasskey = _enableModuleAndInitiateRecovery(alice, guardiansList, 3, minimumCooldown);

        (
            address initiator,
            address newPasskey,
            uint256 approvalCount,
            uint256 initiationTimestamp,
            address[] memory approvingGuardians
        ) = srModule.getRecovery(address(alice));
        assertEq(initiator, guardianA);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 1);
        assertEq(initiationTimestamp, block.timestamp);
        assertEq(approvingGuardians[0], guardianA);
        assertEq(approvingGuardians.length, 1);
        // approval 2/3
        vm.prank(guardianB);
        srModule.approveRecovery(address(alice));
        (initiator, newPasskey, approvalCount, initiationTimestamp, approvingGuardians) =
            srModule.getRecovery(address(alice));
        assertEq(initiator, guardianA);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 2);
        assertEq(initiationTimestamp, block.timestamp);
        assertEq(approvingGuardians[0], guardianB);
        assertEq(approvingGuardians[1], guardianA);
        assertEq(approvingGuardians.length, 2);
        (uint256 threshold, uint256 recoveryCooldown, address[] memory guardians) =
            srModule.getConfiguration(address(alice));
        assertEq(threshold, 3);
        assertEq(recoveryCooldown, minimumCooldown);
        assertEq(guardians[0], guardianC);
        assertEq(guardians[1], guardianB);
        assertEq(guardians[2], guardianA);

        // guardianB wants to opt out after cooldown period
        vm.warp(block.timestamp + minimumCooldown + 1);

        vm.prank(guardianB);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryThresholdReached(address(alice));
        srModule.optOutAsGuardian(address(alice));

        // approval 2/2
        (initiator, newPasskey, approvalCount, initiationTimestamp, approvingGuardians) =
            srModule.getRecovery(address(alice));
        assertEq(initiator, guardianA);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 2);
        assertEq(initiationTimestamp, block.timestamp - minimumCooldown - 1);
        assertEq(approvingGuardians[0], guardianB);
        assertEq(approvingGuardians[1], guardianA);
        assertEq(approvingGuardians.length, 2);
        (threshold, recoveryCooldown, guardians) = srModule.getConfiguration(address(alice));
        assertEq(threshold, 2);
        assertEq(recoveryCooldown, minimumCooldown);
        assertEq(guardians[0], guardianC);
        assertEq(guardians[1], guardianA);

        // C opt out as guardian
        vm.prank(guardianC);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryThresholdReached(address(alice));
        srModule.optOutAsGuardian(address(alice));

        // approval 2/1
        (initiator, newPasskey, approvalCount, initiationTimestamp, approvingGuardians) =
            srModule.getRecovery(address(alice));
        assertEq(initiator, guardianA);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 2);
        assertEq(initiationTimestamp, block.timestamp - minimumCooldown - 1);
        assertEq(approvingGuardians[0], guardianB);
        assertEq(approvingGuardians[1], guardianA);
        assertEq(approvingGuardians.length, 2);

        (threshold, recoveryCooldown, guardians) = srModule.getConfiguration(address(alice));
        assertEq(threshold, 1);
        assertEq(recoveryCooldown, minimumCooldown);
        assertEq(guardians[0], guardianA);

        // After the cooldownperiod, even though guardianA is the initiator, allow to remove recovery and configuration anyway
        vm.prank(guardianA);
        vm.expectEmit();
        emit SocialRecoveryModule.ConfigurationRemovedOnGuardianOptOut(address(alice), guardianA);

        srModule.optOutAsGuardian(address(alice));

        (threshold, recoveryCooldown, guardians) = srModule.getConfiguration(address(alice));
        assertEq(threshold, 0);
        assertEq(recoveryCooldown, 0);
        assertEq(guardians.length, 0);
    }

    /// @notice Edge case where the recovery initiator is also the last remaining
    ///         guardian after another guardian opts out. Measures the extra gas
    ///         used by the double `_removeRecovery` / `_removeConfiguration` path.
    function testOptOut_doubleRemoveRecovery_whenInitiatorIsLastGuardian() public {
        guardiansList = new address[](2);
        guardiansList[0] = guardianA;
        guardiansList[1] = guardianB;
        //
        address _newPasskey = _enableModuleAndInitiateRecovery(alice, guardiansList, 2, minimumCooldown);

        (
            address initiator,
            address newPasskey,
            uint256 approvalCount,
            uint256 initiationTimestamp,
            address[] memory approvingGuardians
        ) = srModule.getRecovery(address(alice));
        assertEq(initiator, guardianA);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 1);
        assertEq(initiationTimestamp, block.timestamp);
        assertEq(approvingGuardians[0], guardianA);
        assertEq(approvingGuardians.length, 1);

        vm.startSnapshotGas("executeFunctionSnapshot");
        vm.prank(guardianB);
        srModule.optOutAsGuardian(alice);
        uint256 gasUsed = vm.stopSnapshotGas();

        console.log("Gas used by function: ", gasUsed);

        vm.startSnapshotGas("executeFunctionSnapshot");
        vm.prank(guardianA);
        srModule.optOutAsGuardian(alice);
        gasUsed = vm.stopSnapshotGas();

        console.log("Gas used by function: ", gasUsed);
        // Extra gas is used when initiator is also the last guardians
    }

    /// @notice Asserts happy-path `initiateRecovery` state + event, then verifies
    ///         a second call reverts with `RecoveryAlreadyActive`.
    function testInitiateRecovery() public {
        vm.startPrank(alice);
        IModuleManager(alice).enableModule(address(srModule));

        srModule.configure(2, minimumCooldown, guardiansList);

        (uint256 threshold, uint256 recoveryCooldown, address[] memory guardians) =
            srModule.getConfiguration(address(alice));
        assertEq(threshold, 2);
        assertEq(recoveryCooldown, minimumCooldown);
        assertEq(guardians[0], guardiansList[2]);
        assertEq(guardians[1], guardiansList[1]);
        assertEq(guardians[2], guardiansList[0]);

        vm.stopPrank();

        address _newPasskey = _createNewPassKey(vm.randomUint());

        vm.prank(guardianA);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryInitiated(
            address(alice), address(guardianA), _newPasskey, block.timestamp, block.timestamp + recoveryCooldown
        );

        srModule.initiateRecovery(address(alice), _newPasskey);

        (
            address initiator,
            address newPasskey,
            uint256 approvalCount,
            uint256 initiationTimestamp,
            address[] memory approvingGuardians
        ) = srModule.getRecovery(address(alice));
        assertEq(initiator, guardianA);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 1);
        assertEq(initiationTimestamp, block.timestamp);
        assertEq(approvingGuardians[0], guardianA);
        assertEq(approvingGuardians.length, 1);

        vm.prank(guardianB);
        vm.expectRevert(SocialRecoveryModule.RecoveryAlreadyActive.selector);
        srModule.initiateRecovery(address(alice), newPasskey);
    }

    /// @notice Walks the full approve / revoke cycle: duplicate-approval revert,
    ///         threshold-reached event, initiator revoke cancels the recovery,
    ///         non-initiator revoke drops approval and emits `RecoveryThresholdLost`.
    function testApproveAndRevokeRecovery() public {
        guardiansList = new address[](4);
        guardiansList[0] = guardianA;
        guardiansList[1] = guardianB;
        guardiansList[2] = guardianC;
        guardiansList[3] = guardianD;

        address _newPasskey = _enableModuleAndInitiateRecovery(alice, guardiansList, 2, minimumCooldown);

        (
            address initiator,
            address newPasskey,
            uint256 approvalCount,
            uint256 initiationTimestamp,
            address[] memory approvingGuardians
        ) = srModule.getRecovery(address(alice));

        assertEq(initiator, guardiansList[0]);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 1);
        assertEq(initiationTimestamp, block.timestamp);

        vm.prank(guardianA);
        vm.expectRevert(SocialRecoveryModule.GuardianAlreadyApprovedRecovery.selector);
        srModule.approveRecovery(address(alice));

        vm.prank(guardianB);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryApproved(address(alice), guardianB, _newPasskey);
        srModule.approveRecovery(address(alice));
        (initiator, newPasskey, approvalCount, initiationTimestamp, approvingGuardians) =
            srModule.getRecovery(address(alice));
        assertEq(initiator, guardianA);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 2);
        assertEq(initiationTimestamp, block.timestamp);
        assertEq(approvingGuardians[0], guardianB);
        assertEq(approvingGuardians[1], guardianA);
        assertEq(approvingGuardians.length, 2);

        vm.prank(guardianC);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryThresholdReached(address(alice));
        srModule.approveRecovery(address(alice));
        (initiator, newPasskey, approvalCount, initiationTimestamp, approvingGuardians) =
            srModule.getRecovery(address(alice));
        assertEq(initiator, guardianA);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 3);
        assertEq(initiationTimestamp, block.timestamp);
        assertEq(approvingGuardians[0], guardianC);
        assertEq(approvingGuardians[1], guardianB);
        assertEq(approvingGuardians[2], guardianA);
        assertEq(approvingGuardians.length, 3);

        vm.warp(block.timestamp + minimumCooldown + 1);
        vm.prank(guardianA);
        vm.expectRevert(SocialRecoveryModule.RecoveryPeriodEnded.selector);
        srModule.revokeRecoveryApproval(address(alice));

        vm.warp(block.timestamp - minimumCooldown - 1);

        vm.prank(guardianB);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryApprovalRevoked(address(alice), guardianB, _newPasskey);

        srModule.revokeRecoveryApproval(address(alice));

        vm.prank(guardianC);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryThresholdLost(address(alice));
        srModule.revokeRecoveryApproval(address(alice));

        vm.prank(guardianD);
        vm.expectRevert(SocialRecoveryModule.GuardianHasNotApprovedRecovery.selector);
        srModule.revokeRecoveryApproval(address(alice));

        vm.prank(guardianA);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryCanceledByInitiator(address(alice), guardianA);
        srModule.revokeRecoveryApproval(address(alice));
    }

    /// @notice Happy-path `executeRecovery`: after cooldown and threshold are met,
    ///         the new passkey is added as a Safe owner and the `RecoveryExecuted`
    ///         event carries the full approving-guardians list.
    function testExecuteRecovery() public {
        address _newPasskey = _enableModuleAndInitiateRecovery(alice, guardiansList, 2, minimumCooldown);

        (
            address initiator,
            address newPasskey,
            uint256 approvalCount,
            uint256 initiationTimestamp,
            address[] memory approvingGuardians
        ) = srModule.getRecovery(address(alice));
        assertEq(initiator, guardianA);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 1);
        assertEq(initiationTimestamp, block.timestamp);
        assertEq(approvingGuardians[0], guardianA);
        assertEq(approvingGuardians.length, 1);

        (, uint256 recoveryCooldown,) = srModule.getConfiguration(address(alice));

        // anyone can executeRecovery
        vm.prank(bob);

        vm.expectRevert(SocialRecoveryModule.RecoveryPeriodNotEnded.selector);
        srModule.executeRecovery(address(alice));

        uint256 snapshot = vm.snapshotState();
        vm.warp(initiationTimestamp + recoveryCooldown + 1);

        //Test case 1: we remove Recovery first
        vm.startPrank(bob);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryExpiredInsufficientApprovals(address(alice));
        srModule.executeRecovery(address(alice));

        vm.expectRevert(SocialRecoveryModule.NoActiveRecovery.selector);
        srModule.executeRecovery(address(alice));

        vm.stopPrank();
        vm.revertToState(snapshot);

        // Test case 2: approve first and reach the threshold
        vm.warp(initiationTimestamp + recoveryCooldown - 1);

        vm.prank(guardianB);
        srModule.approveRecovery(address(alice));

        (initiator, newPasskey, approvalCount, initiationTimestamp, approvingGuardians) =
            srModule.getRecovery(address(alice));
        assertEq(initiator, guardianA);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 2);
        assertEq(initiationTimestamp, block.timestamp - recoveryCooldown + 1);
        assertEq(approvingGuardians[0], guardianB);
        assertEq(approvingGuardians[1], guardianA);
        assertEq(approvingGuardians.length, 2);

        vm.warp(block.timestamp + 1); // Warp to recovery cool down end timestamp

        vm.prank(bob);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryExecuted(address(alice), newPasskey, approvingGuardians);
        srModule.executeRecovery(address(alice));
    }

    /// @notice Verifies `cancelExpiredRecovery` is a no-op before the cooldown
    ///         ends and clears recovery state + emits
    ///         `RecoveryExpiredInsufficientApprovals` once expired without
    ///         reaching threshold.
    function testCancelExpiredRecovery() public {
        address _newPasskey =
            _enableModuleAndInitiateRecovery(alice, guardiansList, guardiansList.length, minimumCooldown);

        (
            address initiator,
            address newPasskey,
            uint256 approvalCount,
            uint256 initiationTimestamp,
            address[] memory approvingGuardians
        ) = srModule.getRecovery(address(alice));

        assertEq(initiator, guardiansList[0]);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 1);
        assertEq(initiationTimestamp, block.timestamp);

        (, uint256 recoveryCooldown,) = srModule.getConfiguration(address(alice));

        vm.prank(guardianA);

        srModule.cancelExpiredRecovery(address(alice));
        (initiator, newPasskey, approvalCount, initiationTimestamp, approvingGuardians) =
            srModule.getRecovery(address(alice));

        // Should expect nothing changes because recoveryPeriod not ended
        assertEq(initiator, guardianA);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 1);
        assertEq(initiationTimestamp, block.timestamp);

        vm.warp(block.timestamp + recoveryCooldown);

        vm.prank(guardianA);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryExpiredInsufficientApprovals(address(alice));
        srModule.cancelExpiredRecovery(address(alice));

        (initiator, newPasskey, approvalCount, initiationTimestamp, approvingGuardians) =
            srModule.getRecovery(address(alice));

        assertEq(initiator, address(0));
        assertEq(newPasskey, address(0));
        assertEq(approvalCount, 0);
        assertEq(initiationTimestamp, 0);
    }

    /// @notice Safe cancels its own active recovery via `cancelRecovery()` and
    ///         asserts recovery state is fully cleared plus the
    ///         `RecoveryCanceledBySafe` event.
    function testCancelRecovery() public {
        address _newPasskey =
            _enableModuleAndInitiateRecovery(alice, guardiansList, guardiansList.length, minimumCooldown);

        (
            address initiator,
            address newPasskey,
            uint256 approvalCount,
            uint256 initiationTimestamp,
            address[] memory approvingGuardians
        ) = srModule.getRecovery(address(alice));

        assertEq(initiator, guardiansList[0]);
        assertEq(newPasskey, _newPasskey);
        assertEq(approvalCount, 1);
        assertEq(initiationTimestamp, block.timestamp);

        vm.prank(alice);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryCanceledBySafe(address(alice));
        srModule.cancelRecovery();

        (initiator, newPasskey, approvalCount, initiationTimestamp, approvingGuardians) =
            srModule.getRecovery(address(alice));

        assertEq(initiator, address(0));
        assertEq(newPasskey, address(0));
        assertEq(approvalCount, 0);
        assertEq(initiationTimestamp, 0);
    }

    // Helper function
    function _enableModuleAndInitiateRecovery(
        address _user,
        address[] memory _guardiansList,
        uint256 _threshold,
        uint256 _minimumCooldown
    ) internal returns (address _newPasskey) {
        vm.startPrank(_user);
        IModuleManager(_user).enableModule(address(srModule));

        srModule.configure(_threshold, _minimumCooldown, _guardiansList);

        (uint256 threshold, uint256 recoveryCooldown, address[] memory guardians) =
            srModule.getConfiguration(address(alice));
        assertEq(threshold, _threshold);
        assertEq(recoveryCooldown, _minimumCooldown);
        assertEq(guardians.length, _guardiansList.length);
        vm.stopPrank();

        _newPasskey = _createNewPassKey(vm.randomUint());

        vm.prank(_guardiansList[0]);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryInitiated(
            _user, _guardiansList[0], _newPasskey, block.timestamp, block.timestamp + recoveryCooldown
        );

        srModule.initiateRecovery(address(_user), _newPasskey);
    }

    // Suggestion: should revert if guardian don't have mutual trust when initiateRecovery/approveRecovery/executeRecovery is called
    /// @notice Documents that recovery still succeeds after the mutual-trust
    ///         relationship between a guardian and the Safe is removed in the
    ///         Circles Hub — mutual trust is only enforced at
    ///         configure time, not at recovery time.
    function testRecoverWithoutMutualTrust() public {
        vm.startPrank(alice);
        IModuleManager(alice).enableModule(address(srModule));

        srModule.configure(2, minimumCooldown, guardiansList);

        (uint256 threshold, uint256 recoveryCooldown, address[] memory guardians) =
            srModule.getConfiguration(address(alice));
        assertEq(threshold, 2);
        assertEq(recoveryCooldown, minimumCooldown);
        assertEq(guardians.length, guardiansList.length);

        HUB_V2.trust(guardiansList[0], uint96(block.timestamp));
        HUB_V2.trust(guardiansList[1], uint96(block.timestamp));
        HUB_V2.trust(guardiansList[2], uint96(block.timestamp));
        vm.stopPrank();

        vm.prank(guardiansList[0]);
        HUB_V2.trust(alice, uint96(block.timestamp));

        vm.warp(block.timestamp + 1);
        address newPasskey = _createNewPassKey(vm.randomUint());

        vm.prank(guardiansList[2]);
        srModule.initiateRecovery(alice, newPasskey);

        vm.prank(guardiansList[1]);
        srModule.approveRecovery(alice);

        vm.prank(guardiansList[0]);
        srModule.approveRecovery(alice);

        vm.warp(block.timestamp + recoveryCooldown);
        vm.prank(bob);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryExecuted(alice, newPasskey, guardiansList);
        srModule.executeRecovery(alice);
    }

    /// @dev    A malicious Safe still reenters SRM with cancelRecovery() during the module's
    ///         execTransactionFromModuleReturnData call, but after the fix the effects
    ///         (_removeRecovery + approvers snapshot) run BEFORE the external call. So:
    ///           - the reentrant cancelRecovery() sees no active recovery and is a silent
    ///             no-op (no RecoveryCanceledBySafe event emitted),
    ///           - the outer RecoveryExecuted event carries the full approving-guardians
    ///             array captured pre-interaction.
    ///         On the original contract the inverse held: RecoveryCanceledBySafe
    ///         fired before RecoveryExecuted and the latter carried an empty guardians
    ///         array. The assertions below would fail on that original contract.
    function testReentrancy() public {
        ReentrantSafe evilSafe = new ReentrantSafe(srModule);

        _registerHuman(address(evilSafe));
        _createMutualTrust(guardianA, address(evilSafe));
        _createMutualTrust(guardianB, address(evilSafe));
        _createMutualTrust(guardianC, address(evilSafe));

        vm.prank(address(evilSafe));
        srModule.configure(2, minimumCooldown, guardiansList);

        address newPasskey = _createNewPassKey(vm.randomUint());

        vm.prank(guardianA);
        srModule.initiateRecovery(address(evilSafe), newPasskey);

        vm.prank(guardianB);
        srModule.approveRecovery(address(evilSafe));

        vm.warp(block.timestamp + minimumCooldown + 1);

        evilSafe.arm(address(srModule), abi.encodeCall(srModule.cancelRecovery, ()));

        vm.recordLogs();
        srModule.executeRecovery(address(evilSafe));
        Vm.Log[] memory entries = vm.getRecordedLogs();

        assertTrue(evilSafe.reentered(), "reentry did not fire");
        assertTrue(evilSafe.reenterSuccess(), "reentrant cancelRecovery reverted");

        bytes32 executedSig = keccak256("RecoveryExecuted(address,address,address[])");
        bytes32 canceledSig = keccak256("RecoveryCanceledBySafe(address)");

        bool sawExecuted;
        bool sawCanceled;
        for (uint256 i; i < entries.length; ++i) {
            bytes32 sig = entries[i].topics[0];
            if (sig == canceledSig) sawCanceled = true;
            if (sig == executedSig) {
                sawExecuted = true;
                (address[] memory emittedGuardians) = abi.decode(entries[i].data, (address[]));
                // Post-fix: approvers were snapshotted before _removeRecovery, so the
                // full approving-guardians list must be emitted. On the original
                // contract this array was empty — so this assertion guards the fix.
                assertEq(
                    emittedGuardians.length,
                    2,
                    "RecoveryExecuted must emit the snapshotted approvers (regression on pre-fix contract)"
                );
            }
        }
        // Post-fix: reentrant cancelRecovery() is a silent no-op because state was
        // already cleared. The original contract emitted RecoveryCanceledBySafe
        // before RecoveryExecuted — so this assertion also regresses on the old code.
        assertFalse(sawCanceled, "RecoveryCanceledBySafe must not fire: state cleared before external call");
        assertTrue(sawExecuted, "RecoveryExecuted not emitted");

        (address initiator,, uint256 approvalCount,,) = srModule.getRecovery(address(evilSafe));
        assertEq(initiator, address(0), "recovery state should be cleared");
        assertEq(approvalCount, 0, "approval count should be cleared");

        assertEq(evilSafe.ownersLength(), 1, "addOwnerWithThreshold should still have executed");
        assertEq(evilSafe.ownerAt(0), newPasskey, "added owner should be the proposed passkey");
    }

    /// @dev    During executeRecovery the Safe still calls evilGuardian.trigger(), which
    ///         reenters SRM as `optOutAsGuardian(evilSafe)`. Post-fix, recovery state
    ///         was cleared BEFORE the external call, so inside optOutAsGuardian
    ///         `activeRecovery` is false: the initiator-opt-out branch is skipped
    ///         (no RecoveryCanceledByInitiatorOptOut), but guardian removal still runs
    ///         (GuardianOptedOut is still emitted). The outer RecoveryExecuted event
    ///         carries the snapshotted approvers list. The original contract
    ///         would emit RecoveryCanceledByInitiatorOptOut before RecoveryExecuted
    ///         and produce an empty approvers array — so these assertions regress on
    ///         the pre-fix code.
    function testReentrancyViaEvilGuardian() public {
        ReentrantSafe evilSafe = new ReentrantSafe(srModule);
        EvilGuardian evilGuardian = new EvilGuardian(srModule);

        _registerHuman(address(evilSafe));
        _registerHuman(address(evilGuardian));

        _createMutualTrust(address(evilGuardian), address(evilSafe));
        _createMutualTrust(guardianA, address(evilSafe));
        _createMutualTrust(guardianB, address(evilSafe));

        address[] memory guardians = new address[](3);
        guardians[0] = address(evilGuardian);
        guardians[1] = guardianA;
        guardians[2] = guardianB;

        vm.prank(address(evilSafe));
        srModule.configure(2, minimumCooldown, guardians);

        address newPasskey = _createNewPassKey(vm.randomUint());

        // evilGuardian initiates so the initiator-opt-out branch clears recovery state.
        vm.prank(address(evilGuardian));
        srModule.initiateRecovery(address(evilSafe), newPasskey);

        vm.prank(guardianA);
        srModule.approveRecovery(address(evilSafe));

        vm.warp(block.timestamp + minimumCooldown + 1);

        // Arm: evilGuardian calls SRM.optOutAsGuardian(evilSafe) when triggered.
        evilGuardian.arm(abi.encodeCall(srModule.optOutAsGuardian, (address(evilSafe))));
        // Arm: evilSafe routes its reentry through evilGuardian.trigger().
        evilSafe.arm(address(evilGuardian), abi.encodeCall(EvilGuardian.trigger, ()));

        vm.recordLogs();
        srModule.executeRecovery(address(evilSafe));
        Vm.Log[] memory entries = vm.getRecordedLogs();

        assertTrue(evilSafe.reentered(), "safe-level reentry did not fire");
        assertTrue(evilSafe.reenterSuccess(), "evilGuardian.trigger call reverted");
        assertTrue(evilGuardian.fired(), "evilGuardian.trigger did not run");
        assertTrue(evilGuardian.triggerSuccess(), "optOutAsGuardian reverted in reentry");

        bytes32 executedSig = keccak256("RecoveryExecuted(address,address,address[])");
        bytes32 initiatorOptOutSig = keccak256("RecoveryCanceledByInitiatorOptOut(address)");
        bytes32 guardianOptedOutSig = keccak256("GuardianOptedOut(address,address)");

        bool sawExecuted;
        bool sawInitiatorOptOut;
        bool sawGuardianOptedOutBeforeExecuted;
        for (uint256 i; i < entries.length; ++i) {
            bytes32 sig = entries[i].topics[0];
            if (sig == initiatorOptOutSig) sawInitiatorOptOut = true;
            if (!sawExecuted && sig == guardianOptedOutSig) sawGuardianOptedOutBeforeExecuted = true;
            if (sig == executedSig) {
                sawExecuted = true;
                (address[] memory emittedGuardians) = abi.decode(entries[i].data, (address[]));
                // Post-fix: snapshot captured [evilGuardian, guardianA] before clearing.
                // Pre-fix would have been empty — so this pins the fix.
                assertEq(
                    emittedGuardians.length,
                    2,
                    "RecoveryExecuted must emit the snapshotted approvers (regression on pre-fix contract)"
                );
            }
        }
        // Post-fix: inside the reentrant optOutAsGuardian, _isRecoveryActive is false,
        // so the initiator-opt-out branch is skipped entirely (no event). The original
        // buggy contract emitted this — so this assertion also regresses on old code.
        assertFalse(
            sawInitiatorOptOut, "RecoveryCanceledByInitiatorOptOut must not fire: state cleared before external call"
        );
        // Guardian removal still runs in both cases — evilGuardian is a guardian, still
        // gets opted out from the set.
        assertTrue(sawGuardianOptedOutBeforeExecuted, "GuardianOptedOut must fire before RecoveryExecuted");
        assertTrue(sawExecuted, "RecoveryExecuted not emitted");

        // Recovery state cleared.
        (address initiator,, uint256 approvalCount,,) = srModule.getRecovery(address(evilSafe));
        assertEq(initiator, address(0));
        assertEq(approvalCount, 0);

        // evilGuardian has been removed from the guardian set mid-execute.
        (,, address[] memory finalGuardians) = srModule.getConfiguration(address(evilSafe));
        assertEq(finalGuardians.length, 2, "evilGuardian should be removed from guardian set");
        for (uint256 i; i < finalGuardians.length; ++i) {
            assertTrue(finalGuardians[i] != address(evilGuardian), "evilGuardian should not remain in guardian list");
        }

        // Passkey was still added as owner — the Safe-side call completed.
        assertEq(evilSafe.ownersLength(), 1);
        assertEq(evilSafe.ownerAt(0), newPasskey);
    }
}

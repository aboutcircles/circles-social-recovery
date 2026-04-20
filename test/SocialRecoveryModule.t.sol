// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {CirclesV2Setup, ISafeWebAuthnSignerFactory} from "./helpers/CirclesV2Setup.sol";
import {HubStorageWrites} from "./helpers/HubStorageWrites.sol";
import {IModuleManager} from "src/interfaces/IModuleManager.sol";
import {SocialRecoveryModule} from "src/SocialRecoveryModule.sol";

///@dev mstore(0x20, keccak256(0, 0x40)) from line 708 should be removed to make the tests valid
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
        // 3 guardians,
        _registerHuman(guardianA);
        _registerHuman(guardianB);
        _registerHuman(guardianC);
        _registerHuman(guardianD);
        _registerHuman(alice);
        _registerHuman(bob);

        // Shared P-256 passkey used for alice/bob Safes.
        (sharedPubX, sharedPubY) = vm.publicKeyP256(uint256(0xBEEF));

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

    // TODO: cannot reach branch in line 832, from _setGuardiansCount line 314, because if threshold=0, it will revert in the previous check
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

    function testUpdateRecoveryCooldown(uint256 _newRecoveryCooldown) public {
        vm.startPrank(alice);
        IModuleManager(alice).enableModule(address(srModule));

        emit SocialRecoveryModule.ModuleConfigured(alice, 2, minimumCooldown, guardiansList.length, guardiansList);
        srModule.configure(2, minimumCooldown, guardiansList);

        if (_newRecoveryCooldown < minimumCooldown) {
            vm.expectRevert(SocialRecoveryModule.CooldownBelowMinimum.selector);
            srModule.updateRecoveryCooldown(_newRecoveryCooldown);
        } else {
            vm.expectEmit();
            emit SocialRecoveryModule.RecoveryCooldownUpdated(address(alice), _newRecoveryCooldown);
            srModule.updateRecoveryCooldown(_newRecoveryCooldown);
        }

        vm.stopPrank();
    }

    function testAddAndRemoveGuardian(uint256 _newThreshold, address _newGuardian) public {
        vm.assume(_newThreshold != 0);

        vm.startPrank(alice);
        IModuleManager(alice).enableModule(address(srModule));

        emit SocialRecoveryModule.ModuleConfigured(alice, 2, minimumCooldown, guardiansList.length, guardiansList);
        srModule.configure(2, minimumCooldown, guardiansList);

        // TODO: If _isRecoveryActive -> create new threshold and guardian

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
        vm.expectEmit();
        emit SocialRecoveryModule.ThresholdAutoReducedOnGuardianOptOut(address(alice), guardianC, threshold - 1);
        srModule.optOutAsGuardian(address(alice));

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

    function testApproveAndRevokeRecovery() public {
        address guardianD = makeAddr("guardianD");
        _registerHuman(guardianD);
        _createMutualTrust(alice, guardianD);

        address[] memory guardiansList = new address[](4);
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
        address[] memory guardiansList,
        uint256 _threshold,
        uint256 _minimumCooldown
    ) internal returns (address _newPasskey) {
        vm.startPrank(_user);
        IModuleManager(_user).enableModule(address(srModule));

        srModule.configure(_threshold, _minimumCooldown, guardiansList);

        (uint256 threshold, uint256 recoveryCooldown, address[] memory guardians) =
            srModule.getConfiguration(address(alice));
        assertEq(threshold, _threshold);
        assertEq(recoveryCooldown, _minimumCooldown);
        assertEq(guardians.length, guardiansList.length);
        vm.stopPrank();

        _newPasskey = _createNewPassKey(vm.randomUint());

        vm.prank(guardiansList[0]);
        vm.expectEmit();
        emit SocialRecoveryModule.RecoveryInitiated(
            _user, guardiansList[0], _newPasskey, block.timestamp, block.timestamp + recoveryCooldown
        );

        srModule.initiateRecovery(address(_user), _newPasskey);
    }

    function testReadLinkedList() public {
        address _newPasskey =
            _enableModuleAndInitiateRecovery(alice, guardiansList, guardiansList.length, minimumCooldown);

        (
            address initiator,
            address newPasskey,
            uint256 approvalCount,
            uint256 initiationTimestamp,
            address[] memory approvingGuardians
        ) = srModule.getRecovery(address(alice));
    }
}

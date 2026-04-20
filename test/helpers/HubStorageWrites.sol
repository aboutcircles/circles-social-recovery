// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

contract HubStorageWrites is Test {
    // Hub storage slots
    uint256 internal constant DISCOUNTED_BALANCES_SLOT = 17;
    uint256 internal constant DISCOUNTED_TOTAL_SUPPLIES_SLOT = 18;
    uint256 internal constant OPERATOR_APPROVAL_SLOT = 19;
    uint256 internal constant MINT_TIMES_SLOT = 21;
    uint256 internal constant AVATARS_SLOT = 26;
    uint256 internal constant TRUST_MARKERS_SLOT = 29;

    // Hub address
    /// @dev use constant, but in case of updates refactor into immutable
    address internal constant HUB = 0xc12C1E50ABB450d6205Ea2C3Fa861b3B834d13e8;

    // The address used as the first element of the linked list of avatars.
    uint256 private constant SENTINEL = uint256(1);
    bytes32 private constant MAX_EXPIRY = bytes32(uint256(type(uint96).max) << 160);
    bytes32 private constant TRUE = bytes32(uint256(1));

    // Safe 1.4.1 + WebAuthn stack addresses (Gnosis Chain)
    address internal constant SAFE_141_SINGLETON = 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762;
    address internal constant SAFE_4337_MODULE = 0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226;
    address internal constant SAFE_SHARED_SIGNER = 0xfD90FAd33ee8b58f32c00aceEad1358e4AFC23f9;
    address internal constant P256_VERIFIER = 0x445a0683e494ea0c5AF3E83c5159fBE47Cf9e765;

    // Safe fallback handler storage slot: keccak256("fallback_manager.handler.address")
    bytes32 internal constant FALLBACK_HANDLER_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    // SafeWebAuthnSharedSigner SIGNER_SLOT (per-Safe storage written via delegatecall layout)
    uint256 internal constant SIGNER_SLOT = 0x553c9d7e83c58cdf3a427b0c81460372fe0d5da8900473788d506425c7ffdc5a;

    // Safe 1.4.1 storage slot layout
    uint256 private constant SAFE_SLOT_SINGLETON = 0;
    uint256 private constant SAFE_SLOT_MODULES = 1;
    uint256 private constant SAFE_SLOT_OWNERS = 2;
    uint256 private constant SAFE_SLOT_OWNER_COUNT = 3;
    uint256 private constant SAFE_SLOT_THRESHOLD = 4;

    // Safe 1.4.1 proxy runtime bytecode (matches production and CirclesV2Setup.sol:593)
    bytes internal constant SAFE_PROXY_CODE_V141 =
        hex"608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e0000000000000000000000000000000000000000000000000000000060003514156050578060005260206000f35b3660008037600080366000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea2646970667358221220d1429297349653a4918076d650332de1a1068c5f3e07c5c82360c277770b955264736f6c63430007060033";

    // Shared P-256 passkey used for all test Safes that require passkey config.
    // Initialized in test setUp via vm.publicKeyP256(...).
    uint256 internal sharedPubX;
    uint256 internal sharedPubY;

    /// @dev Sets Hub ERC1155 balance of id for account.
    function _setCRCBalance(uint256 id, address account, uint64 lastUpdatedDay, uint192 balance) internal {
        // set balance
        bytes32 idSlot = keccak256(abi.encodePacked(id, DISCOUNTED_BALANCES_SLOT));
        bytes32 accountSlot = keccak256(abi.encodePacked(uint256(uint160(account)), idSlot));
        uint256 discountedBalance = (uint256(lastUpdatedDay) << 192) + balance;
        vm.store(HUB, accountSlot, bytes32(discountedBalance));
        // set supply
        idSlot = keccak256(abi.encodePacked(id, DISCOUNTED_TOTAL_SUPPLIES_SLOT));
        vm.store(HUB, idSlot, bytes32(discountedBalance));
    }

    /// @dev Sets max expiry trust.
    function _setTrust(address truster, address trusted) internal {
        bytes32 trusterSlot = keccak256(abi.encodePacked(uint256(uint160(truster)), TRUST_MARKERS_SLOT));
        bytes32 trustedSlot = keccak256(abi.encodePacked(uint256(uint160(trusted)), trusterSlot));
        vm.store(HUB, trustedSlot, MAX_EXPIRY);
    }

    /// @dev Simulates human registration.
    function _registerHuman(address account) internal {
        _insertAvatar(account);
        _setMintTime(account);
        _setTrust(account, account);
    }

    function _setOperatorApproval(address account, address operator) internal {
        bytes32 accountSlot = keccak256(abi.encodePacked(uint256(uint160(account)), OPERATOR_APPROVAL_SLOT));
        bytes32 operatorSlot = keccak256(abi.encodePacked(uint256(uint160(operator)), accountSlot));
        vm.store(HUB, operatorSlot, TRUE);
    }

    /// @dev Sets Hub mint times for avatar.
    function _insertAvatar(address avatar) internal {
        // last and avatar slots
        bytes32 lastAvatarSlot = keccak256(abi.encodePacked(SENTINEL, AVATARS_SLOT));
        bytes32 newAvatarSlot = keccak256(abi.encodePacked(uint256(uint160(avatar)), AVATARS_SLOT));
        // read last value
        bytes32 lastAvatarValue = vm.load(HUB, lastAvatarSlot);
        // write new value to last slot
        vm.store(HUB, lastAvatarSlot, bytes32(uint256(uint160(avatar))));
        // write last value to new slot
        vm.store(HUB, newAvatarSlot, lastAvatarValue);
    }

    /// @dev Sets Hub mint times for avatar.
    function _setMintTime(address avatar) internal {
        bytes32 avatarSlot = keccak256(abi.encodePacked(uint256(uint160(avatar)), MINT_TIMES_SLOT));
        uint256 mintTime = block.timestamp << 160;
        vm.store(HUB, avatarSlot, bytes32(mintTime));
    }

    /// @dev Places a Safe 1.4.1 at `avatar` with production-equivalent storage:
    ///      singleton pointer, Safe4337Module enabled, shared WebAuthn signer as sole owner,
    ///      threshold=1, fallback handler wired. Optionally writes the shared passkey config
    ///      into the Safe's own storage (read by SafeWebAuthnSharedSigner.getConfiguration).
    function _simulateSafe(address avatar, bool configurePasskey) internal {
        // 1. Etch Safe 1.4.1 proxy runtime bytecode
        vm.etch(avatar, SAFE_PROXY_CODE_V141);

        // 2. Implementation pointer (slot 0)
        vm.store(avatar, bytes32(SAFE_SLOT_SINGLETON), bytes32(uint256(uint160(SAFE_141_SINGLETON))));

        // 3. Enable Safe4337Module: modules[SENTINEL]=4337, modules[4337]=SENTINEL
        bytes32 modSentinelSlot = keccak256(abi.encode(SENTINEL, SAFE_SLOT_MODULES));
        bytes32 mod4337Slot = keccak256(abi.encode(uint256(uint160(SAFE_4337_MODULE)), SAFE_SLOT_MODULES));
        vm.store(avatar, modSentinelSlot, bytes32(uint256(uint160(SAFE_4337_MODULE))));
        vm.store(avatar, mod4337Slot, bytes32(SENTINEL));

        // 4. Owners: WebAuthn shared signer as sole owner
        bytes32 ownSentinelSlot = keccak256(abi.encode(SENTINEL, SAFE_SLOT_OWNERS));
        bytes32 ownSharedSlot = keccak256(abi.encode(uint256(uint160(SAFE_SHARED_SIGNER)), SAFE_SLOT_OWNERS));
        vm.store(avatar, ownSentinelSlot, bytes32(uint256(uint160(SAFE_SHARED_SIGNER))));
        vm.store(avatar, ownSharedSlot, bytes32(SENTINEL));

        // 5. ownerCount = 1, threshold = 1
        vm.store(avatar, bytes32(SAFE_SLOT_OWNER_COUNT), bytes32(uint256(1)));
        vm.store(avatar, bytes32(SAFE_SLOT_THRESHOLD), bytes32(uint256(1)));

        // 6. Fallback handler -> Safe4337Module
        vm.store(avatar, FALLBACK_HANDLER_SLOT, bytes32(uint256(uint160(SAFE_4337_MODULE))));

        // 7. Optional shared-signer passkey config written directly into the Safe's storage
        //    (mirrors delegatecall-time writes done by SafeWebAuthnSharedSigner.configure)
        if (configurePasskey) {
            vm.store(avatar, bytes32(SIGNER_SLOT), bytes32(sharedPubX));
            vm.store(avatar, bytes32(SIGNER_SLOT + 1), bytes32(sharedPubY));
            vm.store(avatar, bytes32(SIGNER_SLOT + 2), bytes32(uint256(uint176(uint160(P256_VERIFIER)))));
        }
    }
}

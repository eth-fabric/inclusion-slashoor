// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

// Adapted from https://github.com/chainbound/bolt/tree/unstable/bolt-contracts

import {Test, console} from "forge-std/Test.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {SecureMerkleTrie} from "urc/example/lib/trie/SecureMerkleTrie.sol";
import {RLPReader} from "urc/example/lib/rlp/RLPReader.sol";
import {RLPWriter} from "urc/example/lib/rlp/RLPWriter.sol";
import {TransactionDecoder} from "urc/example/lib/TransactionDecoder.sol";
import {BytesUtils} from "urc/example/lib/BytesUtils.sol";
import {MerkleTrie} from "urc/example/lib/trie/MerkleTrie.sol";

import {ISlasher} from "urc/src/ISlasher.sol";
import {IRegistry} from "urc/src/IRegistry.sol";
import {Registry} from "urc/src/Registry.sol";
import {UnitTestHelper} from "urc/test/UnitTestHelper.sol";
import {BLS} from "solady/utils/ext/ithaca/BLS.sol";
import {BLSUtils} from "urc/src/lib/BLSUtils.sol";
import {MerkleTree} from "urc/src/lib/MerkleTree.sol";
import {InclusionSlasher} from "../src/InclusionSlasher.sol";

contract InclusionSlasherTest is UnitTestHelper {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using BytesUtils for bytes;
    using TransactionDecoder for TransactionDecoder.Transaction;
    using TransactionDecoder for bytes;

    InclusionSlasher slasher;
    IRegistry.Config registryConfig;
    InclusionSlasher.Config config;

    // Proposer to register to URC
    BLS.G1Point proposerPubKey;
    uint256 constant proposerBLSSecretKey = 67890;
    address proposer = makeAddr("proposer");

    // Gateway to sign commitments
    BLS.G1Point gatewayPubKey;
    uint256 constant gatewayBLSSecretKey = 12345;
    uint256 gatewayECDSASecretKey;
    address gateway;

    // Signing params
    bytes32 signingId = keccak256("test-signing-id");
    uint64 nonce = uint64(1337);

    // Relay for slashing
    address relay = makeAddr("relay");

    // Test params: https://etherscan.io/block/20785012
    uint256 constant inclusionBlockNumber = 20_785_012;
    uint64 constant inclusionSlot = 9_994_114;

    function setUp() public {
        registryConfig = defaultConfig();
        registry = new Registry(registryConfig);

        config = InclusionSlasher.Config({
            urc: address(registry),
            slashAmountWei: registryConfig.minCollateralWei,
            gatewayCollateralWei: 1 ether,
            challengeBondWei: 1 ether,
            challengeWindowSeconds: 86400,
            commitmentType: 0x00,
            eth2GenesisTimestamp: 1606824023, // mainnet
            slotSeconds: 12,
            finalizationSlots: 64,
            blockhashLookback: 256,
            slotTime: 12
        });

        address[] memory relays = new address[](1);
        relays[0] = relay;
        slasher = new InclusionSlasher(config, relays);

        proposerPubKey = BLSUtils.toPublicKey(proposerBLSSecretKey);
        gatewayPubKey = BLSUtils.toPublicKey(gatewayBLSSecretKey);
        (gateway, gatewayECDSASecretKey) = makeAddrAndKey("gateway");
        vm.deal(proposer, 100 ether);
        vm.deal(gateway, 100 ether);
        vm.deal(challenger, 100 ether);
    }

    function setupRegistration(address operator, address delegate, uint64 slot)
        internal
        returns (RegisterAndDelegateResult memory result)
    {
        // Register operator to URC
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: proposerBLSSecretKey,
            collateral: registryConfig.minCollateralWei,
            owner: operator,
            delegateSecretKey: gatewayBLSSecretKey,
            committerSecretKey: gatewayECDSASecretKey,
            committer: delegate,
            slasher: address(slasher),
            metadata: "",
            slot: slot,
            signingId: signingId,
            nonce: nonce
        });

        // Register operator to URC and signs delegation message
        vm.startPrank(proposer);
        result = registerAndDelegate(params);
        vm.stopPrank();
    }

    function setupSlash()
        public
        returns (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            InclusionSlasher.InclusionProof memory inclusionProof
        )
    {
        uint256 targetTimestamp = slasher._getTimestampFromSlot(inclusionSlot);

        // Start at target block number minus fraud proof window
        vm.roll(inclusionBlockNumber - registry.getConfig().fraudProofWindow / 12);
        vm.warp(targetTimestamp - registry.getConfig().fraudProofWindow);

        // Register to URC and sign delegation
        result = setupRegistration(proposer, gateway, inclusionSlot);

        // Advance past registration fraud proof window to the target slot
        vm.roll(inclusionBlockNumber);
        vm.warp(targetTimestamp);

        // Gateway signs a commitment to include a TX
        InclusionSlasher.InclusionPayload memory payload =
            _createInclusionCommitment(inclusionBlockNumber, inclusionSlot);
        signedCommitment = basicCommitment(gatewayECDSASecretKey, address(slasher), abi.encode(payload));

        // Build the inclusion and account proofs
        string memory encodedParentHeader = vm.readFile("./test/testdata/header_20785011.json");
        string memory encodedInclusionHeader = vm.readFile("./test/testdata/header_20785012.json");
        string memory accountProof = vm.readFile("./test/testdata/eth_proof_20785011.json");
        string memory txProof = vm.readFile("./test/testdata/tx_mpt_proof_20785012.json");

        // Assemble the inclusion proof
        inclusionProof = InclusionSlasher.InclusionProof({
            inclusionBlockNumber: inclusionBlockNumber,
            parentBlockHeaderRLP: vm.parseJsonBytes(encodedParentHeader, ".result"),
            inclusionBlockHeaderRLP: vm.parseJsonBytes(encodedInclusionHeader, ".result"),
            accountMerkleProof: _RLPEncodeList(vm.parseJsonBytesArray(accountProof, ".result.accountProof")),
            txMerkleProof: _RLPEncodeList(vm.parseJsonBytesArray(txProof, ".proof")),
            txIndexInBlock: vm.parseJsonUint(txProof, ".index")
        });

        // check that the inclusion block transactions root matches the root in the tx proof data.
        bytes32 inclusionTxRoot = slasher._decodeBlockHeaderRLP(inclusionProof.inclusionBlockHeaderRLP).txRoot;
        assertEq(inclusionTxRoot, vm.parseJsonBytes32(txProof, ".root"));
    }

    function test_challenge() public {
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            InclusionSlasher.InclusionProof memory inclusionProof
        ) = setupSlash();

        // Start at target slot number plus finalization slots
        uint256 targetTimestamp = slasher._getTimestampFromSlot(result.signedDelegation.delegation.slot);
        vm.warp(targetTimestamp + config.finalizationSlots * config.slotTime);

        vm.prank(challenger);
        bytes32 challengeID = slasher.createChallenge{value: config.challengeBondWei}(
            signedCommitment.commitment, result.signedDelegation.delegation
        );
        assertEq(challengeID, keccak256(abi.encode(signedCommitment.commitment, result.signedDelegation.delegation)));
    }

    function test_revert_challenge_incorrectBond() public {
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            InclusionSlasher.InclusionProof memory inclusionProof
        ) = setupSlash();

        uint256 bond = config.challengeBondWei - 1;
        // Try with incorrect bond amount
        vm.expectRevert(InclusionSlasher.IncorrectChallengeBond.selector);
        slasher.createChallenge{value: bond}(signedCommitment.commitment, result.signedDelegation.delegation);
    }

    function test_revert_challenge_alreadyExists() public {
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            InclusionSlasher.InclusionProof memory inclusionProof
        ) = setupSlash();

        // Start at target slot number plus finalization slots
        uint256 targetTimestamp = slasher._getTimestampFromSlot(result.signedDelegation.delegation.slot);
        vm.warp(targetTimestamp + config.finalizationSlots * config.slotTime);

        vm.prank(challenger);
        bytes32 challengeID = slasher.createChallenge{value: config.challengeBondWei}(
            signedCommitment.commitment, result.signedDelegation.delegation
        );

        // Try to create duplicate challenge
        vm.expectRevert(InclusionSlasher.ChallengeAlreadyExists.selector);
        vm.prank(challenger);
        slasher.createChallenge{value: config.challengeBondWei}(
            signedCommitment.commitment, result.signedDelegation.delegation
        );
    }

    function test_revert_challenge_mismatchedSlot() public {
        (address alice,) = makeAddrAndKey("alice_expired");
        (address delegate, uint256 delegatePK) = makeAddrAndKey("delegate");
        vm.deal(alice, 100 ether);

        // Register with a mismatched slot
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: proposerBLSSecretKey,
            collateral: registryConfig.minCollateralWei,
            owner: proposer,
            delegateSecretKey: gatewayBLSSecretKey,
            committerSecretKey: gatewayECDSASecretKey,
            committer: gateway,
            slasher: address(slasher),
            metadata: "",
            slot: inclusionSlot - 1, // mismatched slot
            signingId: signingId,
            nonce: nonce
        });
        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Create commitment for mismatched slot
        vm.roll(inclusionBlockNumber);
        vm.warp(slasher._getTimestampFromSlot(inclusionSlot));
        InclusionSlasher.InclusionPayload memory payload =
            _createInclusionCommitment(inclusionBlockNumber, inclusionSlot);

        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(gatewayECDSASecretKey, address(slasher), abi.encode(payload));

        // Advance to first finalized slot after the target slot
        uint256 targetTimestamp = slasher._getTimestampFromSlot(inclusionSlot);
        vm.warp(targetTimestamp + config.finalizationSlots * config.slotTime);

        // Try to create challenge with mismatched slot
        vm.prank(challenger);
        vm.expectRevert(InclusionSlasher.MismatchedSlot.selector);
        slasher.createChallenge{value: config.challengeBondWei}(
            signedCommitment.commitment, result.signedDelegation.delegation
        );
    }

    function test_slash_proposer() public {
        // Register at URC and generate slashable evidence
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            InclusionSlasher.InclusionProof memory inclusionProof
        ) = setupSlash();

        // Save initial balances for comparison
        uint256 challengerBalanceBefore = challenger.balance;
        uint256 proposerBalanceBefore = proposer.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // Advance to first finalized slot after the target slot
        uint256 targetTimestamp = slasher._getTimestampFromSlot(inclusionSlot);
        uint256 time = targetTimestamp + config.finalizationSlots * config.slotTime;
        vm.warp(time);

        // Create challenge
        vm.prank(challenger);
        bytes32 challengeID = slasher.createChallenge{value: config.challengeBondWei}(
            signedCommitment.commitment, result.signedDelegation.delegation
        );

        // Verify challenger's balance decreased by bond amount
        assertEq(challenger.balance, challengerBalanceBefore - config.challengeBondWei);

        // Skip ahead past the challenge window
        vm.warp(time + config.challengeWindowSeconds + 1);

        // Merkle proof for URC registration
        IRegistry.RegistrationProof memory proof =
            registry.getRegistrationProof(result.registrations, proposer, 0, signingId);

        // Evidence for slashing the proposer
        bytes memory evidence = abi.encode(InclusionSlasher.FaultAttribution.Proposer);

        // Slash via URC
        vm.prank(relay);
        registry.slashCommitment(proof, result.signedDelegation, signedCommitment, evidence);

        _verifySlashCommitmentBalances(challenger, config.slashAmountWei, 0, challengerBalanceBefore, urcBalanceBefore);

        // Retrieve operator data
        IRegistry.OperatorData memory operatorData = registry.getOperatorData(result.registrationRoot);

        // Verify operator's slashedAt is set
        assertEq(operatorData.slashedAt, block.timestamp, "slashedAt not set");

        // Verify operator's collateralGwei is decremented
        assertEq(
            operatorData.collateralWei,
            registryConfig.minCollateralWei - config.slashAmountWei,
            "collateralWei not decremented"
        );

        // Verify the slashedBefore mapping is set
        bytes32 slashingDigest = keccak256(
            abi.encode(result.signedDelegation, signedCommitment, keccak256(evidence), result.registrationRoot)
        );
        assertEq(registry.slashingEvidenceAlreadyUsed(slashingDigest), true, "slashedBefore not set");
    }

    function test_slash_gateway() public {
        // Register at URC and generate slashable evidence
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            InclusionSlasher.InclusionProof memory inclusionProof
        ) = setupSlash();

        // Add collateral to the gateway
        vm.prank(gateway);
        slasher.addCollateral{value: config.gatewayCollateralWei}();

        // Save initial balances for comparison
        uint256 gatewayBalanceBefore = slasher.getGatewayCollateral(gateway);

        // Advance to first finalized slot after the target slot
        uint256 targetTimestamp = slasher._getTimestampFromSlot(inclusionSlot);
        uint256 time = targetTimestamp + config.finalizationSlots * config.slotTime;
        vm.warp(time);

        // Create challenge
        vm.prank(challenger);
        bytes32 challengeID = slasher.createChallenge{value: config.challengeBondWei}(
            signedCommitment.commitment, result.signedDelegation.delegation
        );

        // Skip ahead past the challenge window
        vm.warp(time + config.challengeWindowSeconds + 1);

        // Merkle proof for URC registration
        IRegistry.RegistrationProof memory proof =
            registry.getRegistrationProof(result.registrations, proposer, 0, signingId);

        // Evidence for slashing the gateway
        bytes memory evidence = abi.encode(InclusionSlasher.FaultAttribution.Gateway);

        // Slash via URC
        vm.prank(relay);
        registry.slashCommitment(proof, result.signedDelegation, signedCommitment, evidence);

        // Verify gateway's collateralGwei is decremented
        assertEq(slasher.getGatewayCollateral(gateway), 0, "gateway collateral not decremented");
    }

    function test_revert_slash_onlyApprovedRelays() public {
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            InclusionSlasher.InclusionProof memory inclusionProof
        ) = setupSlash();

        // Start at target slot number plus finalization slots
        uint256 targetTimestamp = slasher._getTimestampFromSlot(result.signedDelegation.delegation.slot);
        uint256 time = targetTimestamp + config.finalizationSlots * config.slotTime;
        vm.warp(time);

        vm.prank(challenger);
        bytes32 challengeID = slasher.createChallenge{value: config.challengeBondWei}(
            signedCommitment.commitment, result.signedDelegation.delegation
        );

        // Skip ahead past the challenge window
        vm.warp(time + config.challengeWindowSeconds + 1);

        // Merkle proof for URC registration
        IRegistry.RegistrationProof memory proof =
            registry.getRegistrationProof(result.registrations, proposer, 0, signingId);

        // Try to slash as not an approved relay
        vm.prank(challenger);
        vm.expectRevert(InclusionSlasher.OnlyApprovedRelays.selector);
        registry.slashCommitment(proof, result.signedDelegation, signedCommitment, abi.encode(inclusionProof));
    }

    function test_revert_slash_notURC() public {
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            InclusionSlasher.InclusionProof memory inclusionProof
        ) = setupSlash();

        // Try to call slash directly (not through URC)
        vm.prank(relay);
        vm.expectRevert(InclusionSlasher.NotURC.selector);
        slasher.slash(
            result.signedDelegation.delegation, signedCommitment.commitment, gateway, abi.encode(inclusionProof), relay
        );
    }

    function test_defendChallenge() public {
        // Register at URC and generate slashable evidence
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            InclusionSlasher.InclusionProof memory inclusionProof
        ) = setupSlash();

        // Save initial balances for comparison
        uint256 challengerBalanceBefore = challenger.balance;
        uint256 proposerBalanceBefore = proposer.balance;
        uint256 bond = config.challengeBondWei;

        // Advance to first finalized slot after the target slot
        uint256 targetTimestamp = slasher._getTimestampFromSlot(inclusionSlot);
        uint256 time = targetTimestamp + config.finalizationSlots * config.slotTime;
        vm.warp(time);
        vm.roll(inclusionBlockNumber + config.finalizationSlots);

        // Create challenge
        vm.prank(challenger);
        bytes32 challengeID =
            slasher.createChallenge{value: bond}(signedCommitment.commitment, result.signedDelegation.delegation);

        // Verify challenger's balance decreased by bond amount
        assertEq(challenger.balance, challengerBalanceBefore - bond);

        // To save on RPC calls, we pre-fill the blockhashes with the expected values
        vm.setBlockhash(inclusionProof.inclusionBlockNumber - 1, keccak256(inclusionProof.parentBlockHeaderRLP));
        vm.setBlockhash(inclusionProof.inclusionBlockNumber, keccak256(inclusionProof.inclusionBlockHeaderRLP));

        // Prove the challenge is fraudulent (transaction was actually included)
        vm.prank(proposer);
        slasher.defendChallenge(result.signedDelegation.delegation, signedCommitment, inclusionProof);

        // Verify challenger lost their bond (transferred to proposer)
        assertEq(proposer.balance, proposerBalanceBefore + bond);
        assertEq(challenger.balance, challengerBalanceBefore - bond);

        // Verify challenge was deleted
        InclusionSlasher.Challenge memory challenge = slasher.getChallenge(challengeID);
        assertEq(challenge.challenger, address(0));
    }

    function test_revert_defendChallenge_nonexistentChallenge() public {
        (
            RegisterAndDelegateResult memory result,
            ISlasher.SignedCommitment memory signedCommitment,
            InclusionSlasher.InclusionProof memory inclusionProof
        ) = setupSlash();

        // Try to prove fraudulent for a challenge that doesn't exist
        vm.expectRevert(InclusionSlasher.ChallengeDoesNotExist.selector);
        slasher.defendChallenge(result.signedDelegation.delegation, signedCommitment, inclusionProof);
    }

    // =========== Helper functions ===========

    // Helper to create a test inclusion proof with a recent slot, valid for a recent challenge
    function _createInclusionCommitment(uint256 blockNumber, uint64 slot)
        internal
        view
        returns (InclusionSlasher.InclusionPayload memory payload)
    {
        // pattern: ./test/testdata/signed_tx_{blockNumber}.json
        string memory base = "./test/testdata/signed_tx_";
        string memory extension = string.concat(vm.toString(blockNumber), ".json");
        string memory path = string.concat(base, extension);

        // Get the signed transaction
        payload.signedTx = vm.parseJsonBytes(vm.readFile(path), ".raw");
        payload.slot = slot;

        return payload;
    }

    // Helper to encode a list of bytes[] into an RLP list with each item RLP-encoded
    function _RLPEncodeList(bytes[] memory _items) internal pure returns (bytes memory) {
        bytes[] memory encodedItems = new bytes[](_items.length);
        for (uint256 i = 0; i < _items.length; i++) {
            encodedItems[i] = RLPWriter.writeBytes(_items[i]);
        }
        return RLPWriter.writeList(encodedItems);
    }

    // Helper to convert a u64 to a little-endian bytes
    function _toLittleEndian(uint64 x) internal pure returns (bytes memory) {
        bytes memory b = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            b[i] = bytes1(uint8(x >> (8 * i)));
        }
        return b;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {ISlasher} from "urc/src/ISlasher.sol";
import {IRegistry} from "urc/src/IRegistry.sol";
import {MerkleTrie} from "urc/example/lib/trie/MerkleTrie.sol";
import {SecureMerkleTrie} from "urc/example/lib/trie/SecureMerkleTrie.sol";
import {RLPReader} from "urc/example/lib/rlp/RLPReader.sol";
import {RLPWriter} from "urc/example/lib/rlp/RLPWriter.sol";
import {TransactionDecoder} from "urc/example/lib/TransactionDecoder.sol";

contract Slasher is ISlasher {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using TransactionDecoder for bytes;
    using TransactionDecoder for TransactionDecoder.Transaction;

    struct Config {
        address urc;
        uint256 slashAmountWei;
        uint256 challengeBondWei;
        uint256 challengeWindowSeconds;
        uint256 commitmentType;
        // Beacon chain related
        uint256 eth2GenesisTimestamp;
        uint256 slotSeconds;
        uint256 finalizationSlots;
        uint256 blockhashLookback;
        uint256 slotTime;
    }

    struct BlockHeaderData {
        bytes32 parentHash;
        bytes32 stateRoot;
        bytes32 txRoot;
        uint256 blockNumber;
        uint256 timestamp;
        uint256 baseFee;
    }

    struct TransactionData {
        address sender;
        bytes32 txHash;
        uint256 nonce;
        uint256 gasLimit;
    }

    struct AccountData {
        uint256 nonce;
        uint256 balance;
    }

    struct InclusionPayload {
        uint64 slot;
        bytes signedTx;
    }

    struct InclusionProof {
        // block number where the transaction is included
        uint256 inclusionBlockNumber;
        // RLP-encoded block header of the previous block of the inclusion block
        // (for clarity: `parentBlockHeaderRLP.number == inclusionBlockNumber - 1`)
        bytes parentBlockHeaderRLP;
        // RLP-encoded block header where the committed transaction is included
        bytes inclusionBlockHeaderRLP;
        // merkle inclusion proof of the account in the state trie of the previous block
        // (checked against the parentBlockHeaderRLP.stateRoot)
        bytes accountMerkleProof;
        // merkle inclusion proof of the transaction in the transaction trie of the inclusion block
        // (checked against the inclusionBlockHeader.txRoot).
        bytes txMerkleProof;
        // index of the committed transaction in the block.
        uint256 txIndexInBlock;
    }

    struct Challenge {
        address challenger;
        uint256 challengeTimestamp;
    }

    /**
     *
     *                                        E V E N T S   &   E R R O R S                                         *
     *
     */
    error IncorrectChallengeBond();
    error InvalidCommitmentType();
    error BlockIsNotFinalized();
    error OnlyApprovedRelays();
    error BeaconRootNotFound();
    error ChallengeAlreadyExists();
    error ChallengeDoesNotExist();
    error DelegationExpired();
    error EthTransferFailed();
    error BlockIsTooOld();
    error InvalidParentBlockHash();
    error InvalidBlockHash();
    error UnexpectedSigner();
    error TransactionExcluded();
    error WrongTransactionHashProof();
    error AccountDoesNotExist();
    error AccountNonceTooHigh();
    error AccountBalanceTooLow();
    error WrongSlotNumberProof();

    /**
     *
     *                                        S T A T E   V A R I A B L E S                                         *
     *
     */
    Config internal _config;

    // Mapping of challenges
    mapping(bytes32 _challengeID => Challenge _challenge) internal _challenges;

    // Mapping of approved relays
    mapping(address _relay => bool _approved) internal _approvedRelays;

    /**
     *
     *                                              M O D I F I E R S                                               *
     *
     */
    //todo

    /**
     *
     *                                              F U N C T I O N S                                               *
     *
     */
    constructor(Config memory config, address[] memory relays) {
        _config = config;

        for (uint256 i = 0; i < relays.length; i++) {
            _approvedRelays[relays[i]] = true;
        }
    }

    /// @notice Create a challenge for a given commitment and delegation
    /// @dev The challenge is created by locking a challenge bond amount of `_config.challengeBondWei`
    /// @param commitment The commitment
    /// @param delegation The delegation
    /// @return challengeID The challenge ID
    function createChallenge(ISlasher.Commitment calldata commitment, ISlasher.Delegation calldata delegation)
        external
        payable
        returns (bytes32 challengeID)
    {
        // Check that the attached bond amount is correct
        if (msg.value != _config.challengeBondWei) {
            revert IncorrectChallengeBond();
        }

        // Check that the commitment type is valid
        if (commitment.commitmentType != _config.commitmentType) {
            revert InvalidCommitmentType();
        }

        // Prevent challenges for slots that are not finalized by Ethereum consensus yet.
        if (delegation.slot > _getCurrentSlot() - _config.finalizationSlots) {
            revert BlockIsNotFinalized();
        }

        // Decode the opaque commitment payload
        InclusionPayload memory payload = abi.decode(commitment.payload, (InclusionPayload));

        // Check if the delegation applies to the slot of the commitment
        if (delegation.slot != payload.slot) {
            revert DelegationExpired();
        }

        // Compute the challenge ID
        challengeID = _computeChallengeID(commitment, delegation);

        // Check if the challenge already exists
        if (_challenges[challengeID].challenger != address(0)) {
            revert ChallengeAlreadyExists();
        }

        // Save the challenge
        _challenges[challengeID] = Challenge({challenger: msg.sender, challengeTimestamp: block.timestamp});
    }

    /// @notice Defend a challenge for a given commitment and delegation
    /// @param delegation The delegation
    /// @param signedCommitment The signed commitment
    /// @param proof The inclusion proof
    function defendChallenge(
        ISlasher.Delegation calldata delegation,
        ISlasher.SignedCommitment calldata signedCommitment,
        InclusionProof calldata proof
    ) external {
        // Recover the challengeId
        bytes32 challengeID = _computeChallengeID(signedCommitment.commitment, delegation);
        Challenge memory challenge = _challenges[challengeID];

        // Verify the challenge exists
        if (challenge.challenger == address(0)) {
            revert ChallengeDoesNotExist();
        }

        // Verify the commitment was signed by the Delegation.committer
        address committer =
            ECDSA.recover(keccak256(abi.encode(signedCommitment.commitment)), signedCommitment.signature);
        if (committer != delegation.committer) revert UnexpectedSigner();

        // Decode the opaque commitment payload
        InclusionPayload memory payload = abi.decode(signedCommitment.commitment.payload, (InclusionPayload));

        // Decode the signed transaction from the payload
        TransactionDecoder.Transaction memory decodedTx = payload.signedTx.decodeEnveloped();
        TransactionData memory txData = TransactionData({
            sender: decodedTx.recoverSender(),
            txHash: keccak256(payload.signedTx),
            nonce: decodedTx.nonce,
            gasLimit: decodedTx.gasLimit
        });

        // If the inclusion proof is valid (doesn't revert) it means the the tx was included
        // This means the challenge was fraudulent and their bond is forfeited
        _resolveWithProof(txData, proof, payload.slot);

        // Delete the challenge
        delete _challenges[challengeID];

        // Transfer the challenger's bond to the msg sender
        (bool success,) = msg.sender.call{value: _config.challengeBondWei}("");
        if (!success) {
            revert EthTransferFailed();
        }
    }

    function slash(
        Delegation calldata delegation,
        Commitment calldata commitment,
        address committer,
        bytes calldata evidence,
        address challenger
    ) external returns (uint256 _slashAmountWei) {
        if (!_approvedRelays[challenger]) revert OnlyApprovedRelays();

        _slashAmountWei = _config.slashAmountWei;
    }

    // =================================================== Getters ===================================================
    function slashAmountWei() external view returns (uint256) {
        return _config.slashAmountWei;
    }

    function getChallenge(bytes32 challengeID) external view returns (Challenge memory) {
        return _challenges[challengeID];
    }

    function getChallenge(ISlasher.Commitment calldata commitment, ISlasher.Delegation calldata delegation)
        external
        view
        returns (Challenge memory)
    {
        return _challenges[_computeChallengeID(commitment, delegation)];
    }

    // =================================================== Setters ===================================================
    // todo
    // ================================================== Internal ===================================================

    /// @notice Verify the inclusion proof for a given transaction data and inclusion / account proof
    /// @dev Will pass if it's proven the account could not afford the transaction gasLimit or nonce was too high
    /// @dev Will pass if it's proven the transaction was included in the block
    /// @dev Will revert if the transaction doesn't exist according to the proof
    /// @param txData The transaction data
    /// @param proof The inclusion proof
    /// @param targetSlot The target slot of the block
    function _resolveWithProof(TransactionData memory txData, InclusionProof memory proof, uint256 targetSlot)
        internal
        view
    {
        Config memory config = _config;

        // If the parent blockhash is available, the inclusion blockhash will be too
        uint256 parentBlockNumber = proof.inclusionBlockNumber - 1;
        if (parentBlockNumber > block.number || parentBlockNumber < block.number - config.blockhashLookback) {
            revert BlockIsTooOld();
        }

        // Verify the proof's previous block header is canonical
        if (blockhash(parentBlockNumber) != keccak256(proof.parentBlockHeaderRLP)) {
            revert InvalidParentBlockHash();
        }

        // Verify the proof's inclusion block header is canonical
        if (blockhash(proof.inclusionBlockNumber) != keccak256(proof.inclusionBlockHeaderRLP)) {
            revert InvalidBlockHash();
        }

        // Decode the RLP-encoded block header of the previous block to the inclusion block.
        //
        // The previous block's state root is necessary to verify the account had the correct balance and
        // nonce at the top of the inclusion block (before any transactions were applied).
        BlockHeaderData memory parentBlockHeader = _decodeBlockHeaderRLP(proof.parentBlockHeaderRLP);

        // Decode the RLP-encoded block header of the inclusion block.
        //
        // The inclusion block is necessary to extract the transaction root and verify the inclusion of the
        // committed transactions. By checking against the previous block's parent hash we can ensure this
        // is the correct block trusting a single block hash.
        BlockHeaderData memory inclusionBlockHeader = _decodeBlockHeaderRLP(proof.inclusionBlockHeaderRLP);

        // Sanity check to verify that the inclusion block is a child of the previous block
        if (inclusionBlockHeader.parentHash != keccak256(proof.parentBlockHeaderRLP)) {
            revert InvalidParentBlockHash();
        }

        // Verify that the inclusion block is in the target slot
        if (_getSlotFromTimestamp(inclusionBlockHeader.timestamp) != targetSlot) {
            revert WrongSlotNumberProof();
        }

        // Decode the account fields by checking the account proof against the state root of the previous block header.
        // The key in the account trie is the account pubkey (address) that sent the committed transactions.
        (bool accountExists, bytes memory accountRLP) =
            SecureMerkleTrie.get(abi.encodePacked(txData.sender), proof.accountMerkleProof, parentBlockHeader.stateRoot);
        if (!accountExists) revert AccountDoesNotExist();

        // Extract the nonce and balance of the account from the RLP-encoded data
        AccountData memory account = _decodeAccountRLP(accountRLP);

        // The tx sender (aka "txData.sender") has sent a transaction with a higher nonce
        // than the committed transaction, before the proposer could include it. Consider the challenge
        // defended, as the preconfer is not at fault.
        if (account.nonce > txData.nonce) {
            return;
        }

        // The tx sender account doesn't have enough balance to pay for the worst-case baseFee of the committed
        // transaction. Consider the challenge defended, as the proposer is not at fault.
        if (account.balance < inclusionBlockHeader.baseFee * txData.gasLimit) {
            return;
        }

        // The key in the transaction trie is the RLP-encoded index of the transaction in the block
        bytes memory txLeaf = RLPWriter.writeUint(proof.txIndexInBlock);

        // Verify transaction inclusion proof
        //
        // The transactions trie is built with raw leaves, without hashing them first
        // (This denotes why we use `MerkleTrie.get()` as opposed to `SecureMerkleTrie.get()`).
        (bool txExists, bytes memory txRLP) = MerkleTrie.get(txLeaf, proof.txMerkleProof, inclusionBlockHeader.txRoot);

        // Not valid to slash them since the transaction doesn't exist according to the proof
        if (!txExists) {
            revert TransactionExcluded();
        }

        // Check if the committed transaction hash matches the hash of the included transaction
        if (txData.txHash != keccak256(txRLP)) {
            revert WrongTransactionHashProof();
        }
    }

    function _computeChallengeID(ISlasher.Commitment calldata commitment, ISlasher.Delegation calldata delegation)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(commitment, delegation));
    }

    /// @notice Helper to convert a u64 to a little-endian bytes
    /// @param x The u64 to convert
    /// @return b The little-endian bytes
    function _toLittleEndian(uint64 x) internal pure returns (bytes memory) {
        bytes memory b = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            b[i] = bytes1(uint8(x >> (8 * i)));
        }
        return b;
    }

    /// @notice Decode the block header fields from an RLP-encoded block header.
    /// @param headerRLP The RLP-encoded block header to decode
    function _decodeBlockHeaderRLP(bytes memory headerRLP) public pure returns (BlockHeaderData memory blockHeader) {
        RLPReader.RLPItem[] memory headerFields = headerRLP.toRLPItem().readList();

        blockHeader.parentHash = headerFields[0].readBytes32();
        blockHeader.stateRoot = headerFields[3].readBytes32();
        blockHeader.txRoot = headerFields[4].readBytes32();
        blockHeader.blockNumber = headerFields[8].readUint256();
        blockHeader.timestamp = headerFields[11].readUint256();
        blockHeader.baseFee = headerFields[15].readUint256();
    }

    /// @notice Decode the account fields from an RLP-encoded account.
    /// @param accountRLP The RLP-encoded account to decode
    /// @return account The decoded account data.
    function _decodeAccountRLP(bytes memory accountRLP) internal pure returns (AccountData memory account) {
        RLPReader.RLPItem[] memory accountFields = accountRLP.toRLPItem().readList();

        account.nonce = accountFields[0].readUint256();
        account.balance = accountFields[1].readUint256();
    }

    /// @notice Get the slot number from a given timestamp
    /// @param _timestamp The timestamp
    /// @return The slot number
    function _getSlotFromTimestamp(uint256 _timestamp) public view returns (uint256) {
        return (_timestamp - _config.eth2GenesisTimestamp) / _config.slotSeconds;
    }

    /// @notice Get the timestamp from a given slot
    /// @param _slot The slot number
    /// @return The timestamp
    function _getTimestampFromSlot(uint256 _slot) public view returns (uint256) {
        return _config.eth2GenesisTimestamp + _slot * _config.slotSeconds;
    }

    /// @notice Get the current slot
    /// @return The current slot
    function _getCurrentSlot() public view returns (uint256) {
        return _getSlotFromTimestamp(block.timestamp);
    }
}

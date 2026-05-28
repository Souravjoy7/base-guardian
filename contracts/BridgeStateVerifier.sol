// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title BridgeStateVerifier
 * @notice Cross-chain state proof verification for Base L2 ↔ L1 message passing
 * @dev Validates Merkle proofs for L2 withdrawal messages and state roots
 */
contract BridgeStateVerifier is AccessControl , ReentrancyGuard {
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant SUBMITTER_ROLE = keccak256("SUBMITTER_ROLE");

    struct StateRoot {
        bytes32 root;
        uint256 l2BlockNumber;
        uint256 timestamp;
        address submitter;
        uint256 confirmationCount;
        bool finalized;
    }

    struct WithdrawalProof {
        bytes32 stateRoot;
        bytes32[] proof;
        address l2Token;
        address l1Token;
        address from;
        address to;
        uint256 amount;
        uint256 l2BlockNumber;
        bool verified;
        bool claimed;
    }

    // State root storage
    mapping(uint256 => StateRoot) public stateRoots;
    uint256 public stateRootCount;
    uint256 public requiredConfirmations = 3;

    // Withdrawal proof storage
    mapping(bytes32 => WithdrawalProof) public withdrawalProofs;
    mapping(bytes32 => bool) public proofExists;

    // Verification stats
    uint256 public totalVerified;
    uint256 public totalClaimed;
    uint256 public totalRejected;

    // Challenge period
    uint256 public constant CHALLENGE_PERIOD = 7 days;
    mapping(uint256 => uint256) public stateRootChallengeDeadline;

    event StateRootSubmitted(uint256 indexed rootId, bytes32 root, uint256 l2BlockNumber, address submitter);
    event StateRootConfirmed(uint256 indexed rootId, bytes32 root, uint256 confirmations);
    event StateRootFinalized(uint256 indexed rootId, bytes32 root);
    event WithdrawalProofSubmitted(bytes32 indexed proofHash, address from, address to, uint256 amount);
    event WithdrawalVerified(bytes32 indexed proofHash, bool valid);
    event WithdrawalClaimed(bytes32 indexed proofHash, address to, uint256 amount);
    event ProofRejected(bytes32 indexed proofHash, string reason);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(SUBMITTER_ROLE, msg.sender);
    }

    /**
     * @notice Submit a new L2 state root
     * @param root The Merkle state root from L2
     * @param l2BlockNumber The L2 block number this root represents
     */
    function submitStateRoot(bytes32 root, uint256 l2BlockNumber) external onlyRole(SUBMITTER_ROLE) {
        stateRootCount++;
        stateRoots[stateRootCount] = StateRoot({
            root: root,
            l2BlockNumber: l2BlockNumber,
            timestamp: block.timestamp,
            submitter: msg.sender,
            confirmationCount: 1,
            finalized: false
        });

        stateRootChallengeDeadline[stateRootCount] = block.timestamp + CHALLENGE_PERIOD;
        emit StateRootSubmitted(stateRootCount, root, l2BlockNumber, msg.sender);
    }

    /**
     * @notice Confirm a state root (multi-validator confirmation)
     * @param rootId The state root ID to confirm
     */
    function confirmStateRoot(uint256 rootId) external onlyRole(VERIFIER_ROLE) {
        StateRoot storage sr = stateRoots[rootId];
        require(sr.root != bytes32(0), "Root does not exist");
        require(!sr.finalized, "Already finalized");

        sr.confirmationCount++;

        if (sr.confirmationCount >= requiredConfirmations) {
            emit StateRootConfirmed(rootId, sr.root, sr.confirmationCount);
        }
    }

    /**
     * @notice Finalize a state root after challenge period
     * @param rootId The state root ID to finalize
     */
    function finalizeStateRoot(uint256 rootId) external onlyRole(VERIFIER_ROLE) {
        StateRoot storage sr = stateRoots[rootId];
        require(sr.root != bytes32(0), "Root does not exist");
        require(!sr.finalized, "Already finalized");
        require(sr.confirmationCount >= requiredConfirmations, "Insufficient confirmations");
        require(block.timestamp >= stateRootChallengeDeadline[rootId], "Challenge period active");

        sr.finalized = true;
        emit StateRootFinalized(rootId, sr.root);
    }

    /**
     * @notice Submit a withdrawal proof
     * @param stateRootId The state root this proof is against
     * @param proof Merkle proof path
     * @param l2Token L2 token address
     * @param l1Token L1 token address
     * @param from Sender on L2
     * @param to Recipient on L1
     * @param amount Withdrawal amount
     * @param l2BlockNumber L2 block of the withdrawal
     */
    function submitWithdrawalProof(
        uint256 stateRootId,
        bytes32[] calldata proof,
        address l2Token,
        address l1Token,
        address from,
        address to,
        uint256 amount,
        uint256 l2BlockNumber
    ) external onlyRole(SUBMITTER_ROLE) {
        StateRoot storage sr = stateRoots[stateRootId];
        require(sr.root != bytes32(0), "State root does not exist");

        // Compute leaf hash
        bytes32 leaf = keccak256(abi.encodePacked(l2Token, l1Token, from, to, amount, l2BlockNumber));
        bytes32 proofHash = keccak256(abi.encodePacked(sr.root, leaf));

        require(!proofExists[proofHash], "Proof already submitted");

        withdrawalProofs[proofHash] = WithdrawalProof({
            stateRoot: sr.root,
            proof: proof,
            l2Token: l2Token,
            l1Token: l1Token,
            from: from,
            to: to,
            amount: amount,
            l2BlockNumber: l2BlockNumber,
            verified: false,
            claimed: false
        });

        proofExists[proofHash] = true;
        emit WithdrawalProofSubmitted(proofHash, from, to, amount);
    }

    /**
     * @notice Verify a withdrawal proof against a finalized state root
     * @param proofHash The proof hash to verify
     */
    function verifyWithdrawal(bytes32 proofHash) external onlyRole(VERIFIER_ROLE) {
        WithdrawalProof storage wp = withdrawalProofs[proofHash];
        require(wp.stateRoot != bytes32(0), "Proof does not exist");
        require(!wp.verified, "Already verified");

        bytes32 leaf = keccak256(abi.encodePacked(
            wp.l2Token, wp.l1Token, wp.from, wp.to, wp.amount, wp.l2BlockNumber
        ));

        bool valid = MerkleProof.verify(wp.proof, wp.stateRoot, leaf);
        wp.verified = valid;

        if (valid) {
            totalVerified++;
        } else {
            totalRejected++;
        }

        emit WithdrawalVerified(proofHash, valid);
    }

    /**
     * @notice Claim a verified withdrawal
     * @param proofHash The proof hash to claim
     */
    function claimWithdrawal(bytes32 proofHash) external nonReentrant {
        WithdrawalProof storage wp = withdrawalProofs[proofHash];
        require(wp.verified, "Not verified");
        require(!wp.claimed, "Already claimed");
        require(wp.to == msg.sender, "Not recipient");

        wp.claimed = true;
        totalClaimed++;

        // In production, this would trigger actual token transfer
        emit WithdrawalClaimed(proofHash, wp.to, wp.amount);
    }

    /**
     * @notice Get verification statistics
     */
    function getVerificationStats() external view returns (
        uint256 verified,
        uint256 claimed,
        uint256 rejected,
        uint256 roots
    ) {
        return (totalVerified, totalClaimed, totalRejected, stateRootCount);
    }

    function setRequiredConfirmations(uint256 _required) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_required > 0 && _required <= 10, "Invalid count");
        requiredConfirmations = _required;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title ThreatRegistry
 * @notice On-chain threat intelligence storage and address blacklisting
 * @dev Stores threat patterns, blacklisted addresses, and attack signatures
 */
contract ThreatRegistry is AccessControl, ReentrancyGuard {
    bytes32 public constant ANALYST_ROLE = keccak256("ANALYST_ROLE");
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    enum ThreatType {
        PHISHING,
        EXPLOIT,
        FLASH_LOAN_ATTACK,
        ORACLE_MANIPULATION,
        GOVERNANCE_ATTACK,
        BRIDGE_EXPLOIT,
        SEQUENCER_ATTACK,
        MEV_ABUSE,
        RUG_PULL,
        OTHER
    }

    struct Threat {
        uint256 id;
        ThreatType threatType;
        uint8 severity; // 1-10
        address attacker;
        string description;
        bytes32 txHash;
        uint256 blockNumber;
        uint256 timestamp;
        address reporter;
        bool verified;
        bool mitigated;
    }

    struct BlacklistEntry {
        address target;
        ThreatType reason;
        uint256 addedAt;
        address addedBy;
        bool active;
        uint256 appealDeadline;
    }

    // Threat storage
    mapping(uint256 => Threat) public threats;
    uint256 public threatCount;

    // Blacklist
    mapping(address => BlacklistEntry) public blacklist;
    address[] public blacklistedAddresses;
    uint256 public constant APPEAL_PERIOD = 30 days;

    // Attack signatures (hashed patterns)
    mapping(bytes32 => bool) public knownSignatures;
    uint256 public signatureCount;

    // Stats
    uint256 public totalThreatsReported;
    uint256 public totalThreatsVerified;
    uint256 public totalBlacklisted;

    event ThreatReported(uint256 indexed threatId, ThreatType threatType, uint8 severity, address attacker);
    event ThreatVerified(uint256 indexed threatId, address verifier);
    event ThreatMitigated(uint256 indexed threatId);
    event AddressBlacklisted(address indexed target, ThreatType reason, address addedBy);
    event AddressUnblacklisted(address indexed target, address removedBy);
    event SignatureAdded(bytes32 indexed signature, ThreatType threatType);
    event AppealSubmitted(address indexed target, uint256 deadline);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ANALYST_ROLE, msg.sender);
        _grantRole(GOVERNANCE_ROLE, msg.sender);
    }

    /**
     * @notice Report a new threat
     * @param threatType Type of threat
     * @param severity Severity 1-10
     * @param attacker Attacker address (address(0) if unknown)
     * @param description Human-readable description
     * @param txHash Transaction hash of the attack
     * @param blockNumber Block where attack occurred
     */
    function reportThreat(
        ThreatType threatType,
        uint8 severity,
        address attacker,
        string calldata description,
        bytes32 txHash,
        uint256 blockNumber
    ) external onlyRole(ANALYST_ROLE) nonReentrant {
        require(severity >= 1 && severity <= 10, "Invalid severity");

        threatCount++;
        totalThreatsReported++;

        threats[threatCount] = Threat({
            id: threatCount,
            threatType: threatType,
            severity: severity,
            attacker: attacker,
            description: description,
            txHash: txHash,
            blockNumber: blockNumber,
            timestamp: block.timestamp,
            reporter: msg.sender,
            verified: false,
            mitigated: false
        });

        emit ThreatReported(threatCount, threatType, severity, attacker);
    }

    /**
     * @notice Verify a reported threat
     * @param threatId The threat to verify
     */
    function verifyThreat(uint256 threatId) external onlyRole(GOVERNANCE_ROLE) {
        require(threatId > 0 && threatId <= threatCount, "Invalid threat");
        require(!threats[threatId].verified, "Already verified");

        threats[threatId].verified = true;
        totalThreatsVerified++;

        emit ThreatVerified(threatId, msg.sender);
    }

    /**
     * @notice Mark a threat as mitigated
     * @param threatId The threat to mitigate
     */
    function mitigateThreat(uint256 threatId) external onlyRole(ANALYST_ROLE) {
        require(threatId > 0 && threatId <= threatCount, "Invalid threat");
        require(threats[threatId].verified, "Not verified");

        threats[threatId].mitigated = true;
        emit ThreatMitigated(threatId);
    }

    /**
     * @notice Blacklist an address
     * @param target Address to blacklist
     * @param reason Reason for blacklisting
     */
    function blacklistAddress(
        address target,
        ThreatType reason
    ) external onlyRole(GOVERNANCE_ROLE) nonReentrant {
        require(target != address(0), "Zero address");
        require(!blacklist[target].active, "Already blacklisted");

        blacklist[target] = BlacklistEntry({
            target: target,
            reason: reason,
            addedAt: block.timestamp,
            addedBy: msg.sender,
            active: true,
            appealDeadline: block.timestamp + APPEAL_PERIOD
        });

        blacklistedAddresses.push(target);
        totalBlacklisted++;

        emit AddressBlacklisted(target, reason, msg.sender);
    }

    /**
     * @notice Remove address from blacklist (governance only)
     * @param target Address to unblacklist
     */
    function unblacklistAddress(address target) external onlyRole(GOVERNANCE_ROLE) {
        require(blacklist[target].active, "Not blacklisted");

        blacklist[target].active = false;
        emit AddressUnblacklisted(target, msg.sender);
    }

    /**
     * @notice Submit appeal for blacklisted address
     * @param target Address appealing
     */
    function submitAppeal(address target) external {
        require(blacklist[target].active, "Not blacklisted");
        require(blacklist[target].target == msg.sender || hasRole(GOVERNANCE_ROLE, msg.sender), "Unauthorized");
        require(block.timestamp < blacklist[target].appealDeadline, "Appeal period expired");

        // Extend deadline for review
        blacklist[target].appealDeadline = block.timestamp + 7 days;
        emit AppealSubmitted(target, blacklist[target].appealDeadline);
    }

    /**
     * @notice Add a known attack signature
     * @param signature Hashed attack pattern
     * @param threatType Type of threat this signature detects
     */
    function addSignature(bytes32 signature, ThreatType threatType) external onlyRole(ANALYST_ROLE) {
        require(!knownSignatures[signature], "Already known");

        knownSignatures[signature] = true;
        signatureCount++;

        emit SignatureAdded(signature, threatType);
    }

    /**
     * @notice Check if an address is blacklisted
     */
    function isBlacklisted(address target) external view returns (bool) {
        return blacklist[target].active;
    }

    /**
     * @notice Get blacklist details
     */
    function getBlacklistEntry(address target) external view returns (
        ThreatType reason,
        uint256 addedAt,
        address addedBy,
        bool active,
        uint256 appealDeadline
    ) {
        BlacklistEntry storage entry = blacklist[target];
        return (entry.reason, entry.addedAt, entry.addedBy, entry.active, entry.appealDeadline);
    }

    /**
     * @notice Get threat details
     */
    function getThreat(uint256 threatId) external view returns (
        ThreatType threatType,
        uint8 severity,
        address attacker,
        string memory description,
        bool verified,
        bool mitigated
    ) {
        Threat storage t = threats[threatId];
        return (t.threatType, t.severity, t.attacker, t.description, t.verified, t.mitigated);
    }

    /**
     * @notice Get total blacklisted count
     */
    function getBlacklistedCount() external view returns (uint256) {
        return blacklistedAddresses.length;
    }
}

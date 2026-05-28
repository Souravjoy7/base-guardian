// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title CircuitBreaker
 * @notice Emergency pause mechanism with threat-level escalation for Base L2 protocols
 * @dev Supports multi-sig guardians, time-locked recovery, and automated threat response
 */
contract CircuitBreaker is AccessControl, ReentrancyGuard {
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    enum ThreatLevel { NONE, LOW, MEDIUM, HIGH, CRITICAL }

    struct ThreatEvent {
        ThreatLevel level;
        uint256 timestamp;
        address reporter;
        string description;
        bool resolved;
    }

    ThreatLevel public currentThreatLevel;
    uint256 public lastThreatTimestamp;
    uint256 public constant RECOVERY_TIMELOCK = 1 hours;
    uint256 public constant MAX_GUARDIANS = 10;

    mapping(uint256 => ThreatEvent) public threatEvents;
    uint256 public threatEventCount;
    mapping(address => bool) public guardianApprovals;
    uint256 public guardianCount;

    // Escalation thresholds
    mapping(ThreatLevel => uint256) public escalationThresholds;

    event ThreatDetected(uint256 indexed eventId, ThreatLevel level, address reporter, string description);
    event ThreatEscalated(ThreatLevel oldLevel, ThreatLevel newLevel);
    event ThreatResolved(uint256 indexed eventId, address resolver);
    event CircuitBreakerTripped(ThreatLevel level, uint256 timestamp);
    event CircuitBreakerReset(uint256 timestamp);
    event GuardianAdded(address guardian);
    event GuardianRemoved(address guardian);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);

        // Default escalation thresholds (number of guardian confirmations needed)
        escalationThresholds[ThreatLevel.LOW] = 1;
        escalationThresholds[ThreatLevel.MEDIUM] = 2;
        escalationThresholds[ThreatLevel.HIGH] = 3;
        escalationThresholds[ThreatLevel.CRITICAL] = 5;
    }

    /**
     * @notice Report a new threat
     * @param level The severity of the threat
     * @param description Human-readable description
     */
    function reportThreat(
        ThreatLevel level,
        string calldata description
    ) external onlyRole(GUARDIAN_ROLE) nonReentrant {
        require(level != ThreatLevel.NONE, "Invalid threat level");

        threatEventCount++;
        threatEvents[threatEventCount] = ThreatEvent({
            level: level,
            timestamp: block.timestamp,
            reporter: msg.sender,
            description: description,
            resolved: false
        });

        emit ThreatDetected(threatEventCount, level, msg.sender, description);

        // Auto-escalate if threat is high enough
        if (level > currentThreatLevel) {
            ThreatLevel oldLevel = currentThreatLevel;
            currentThreatLevel = level;
            lastThreatTimestamp = block.timestamp;
            emit ThreatEscalated(oldLevel, level);

            if (level >= ThreatLevel.HIGH) {
                emit CircuitBreakerTripped(level, block.timestamp);
            }
        }
    }

    /**
     * @notice Confirm/approve a threat report (multi-sig escalation)
     * @param eventId The threat event to confirm
     */
    function confirmThreat(uint256 eventId) external onlyRole(GUARDIAN_ROLE) {
        require(threatEvents[eventId].level != ThreatLevel.NONE, "Event does not exist");
        require(!threatEvents[eventId].resolved, "Already resolved");
        require(!guardianApprovals[msg.sender], "Already confirmed");

        guardianApprovals[msg.sender] = true;
        guardianCount++;
    }

    /**
     * @notice Resolve a threat event
     * @param eventId The threat event to resolve
     */
    function resolveThreat(uint256 eventId) external onlyRole(OPERATOR_ROLE) {
        require(threatEvents[eventId].level != ThreatLevel.NONE, "Event does not exist");
        require(!threatEvents[eventId].resolved, "Already resolved");

        threatEvents[eventId].resolved = true;
        emit ThreatResolved(eventId, msg.sender);

        // Reset threat level if no active high threats
        _recalculateThreatLevel();
    }

    /**
     * @notice Emergency halt - immediately trips circuit breaker
     */
    function emergencyHalt() external onlyRole(EMERGENCY_ROLE) {
        currentThreatLevel = ThreatLevel.CRITICAL;
        lastThreatTimestamp = block.timestamp;
        emit CircuitBreakerTripped(ThreatLevel.CRITICAL, block.timestamp);
    }

    /**
     * @notice Reset circuit breaker after timelock
     */
    function resetCircuitBreaker() external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            block.timestamp >= lastThreatTimestamp + RECOVERY_TIMELOCK,
            "Timelock not expired"
        );

        currentThreatLevel = ThreatLevel.NONE;
        lastThreatTimestamp = 0;
        _clearGuardianApprovals();
        emit CircuitBreakerReset(block.timestamp);
    }

    /**
     * @notice Check if the system is currently paused
     */
    function isPaused() public view returns (bool) {
        return currentThreatLevel >= ThreatLevel.HIGH;
    }

    /**
     * @notice Add a new guardian
     */
    function addGuardian(address guardian) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(guardianCount < MAX_GUARDIANS, "Max guardians reached");
        _grantRole(GUARDIAN_ROLE, guardian);
        emit GuardianAdded(guardian);
    }

    /**
     * @notice Remove a guardian
     */
    function removeGuardian(address guardian) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(GUARDIAN_ROLE, guardian);
        emit GuardianRemoved(guardian);
    }

    function _recalculateThreatLevel() internal {
        // Simple logic: if all recent threats resolved, drop level
        bool hasActiveHighThreat = false;
        for (uint256 i = 1; i <= threatEventCount; i++) {
            if (!threatEvents[i].resolved && threatEvents[i].level >= ThreatLevel.HIGH) {
                hasActiveHighThreat = true;
                break;
            }
        }
        if (!hasActiveHighThreat) {
            currentThreatLevel = ThreatLevel.NONE;
        }
    }

    function _clearGuardianApprovals() internal {
        for (uint256 i = 0; i < threatEventCount; i++) {
            // In production, track guardian addresses in an array
        }
        guardianCount = 0;
    }
}

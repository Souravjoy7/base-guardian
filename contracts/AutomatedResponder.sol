// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./CircuitBreaker.sol";
import "./ThreatRegistry.sol";

/**
 * @title AutomatedResponder
 * @notice Executes automated defensive actions based on threat level
 * @dev Integrates with CircuitBreaker and ThreatRegistry for autonomous security response
 */
contract AutomatedResponder is AccessControl, ReentrancyGuard {
    bytes32 public constant RESPONDER_ROLE = keccak256("RESPONDER_ROLE");
    bytes32 public constant STRATEGIST_ROLE = keccak256("STRATEGIST_ROLE");

    enum ActionType {
        MIGRATE_FUNDS,
        PAUSE_PROTOCOL,
        ADJUST_PARAMETERS,
        NOTIFY_GOVERNANCE,
        BLACKLIST_ADDRESS,
        EMERGENCY_WITHDRAW
    }

    struct ResponseAction {
        ActionType actionType;
        address target;
        bytes data;
        uint256 value;
        uint256 executeAfter;
        uint256 expiresAt;
        bool executed;
        bool cancelled;
        address proposer;
    }

    struct SafeWallet {
        address wallet;
        uint256 capacity;
        uint256 currentBalance;
        bool active;
    }

    // References
    CircuitBreaker public circuitBreaker;
    ThreatRegistry public threatRegistry;

    // Response queue
    mapping(uint256 => ResponseAction) public actions;
    uint256 public actionCount;
    uint256 public constant ACTION_DELAY = 5 minutes;
    uint256 public constant ACTION_EXPIRY = 1 hours;

    // Safe wallets for fund migration
    mapping(address => SafeWallet) public safeWallets;
    address[] public safeWalletList;
    uint256 public totalMigrated;

    // Execution history
    uint256 public totalExecuted;
    uint256 public totalCancelled;

    // Whitelisted protocols that can be paused
    mapping(address => bool) public whitelistedProtocols;

    event ActionProposed(uint256 indexed actionId, ActionType actionType, address target);
    event ActionExecuted(uint256 indexed actionId, ActionType actionType, address target);
    event ActionCancelled(uint256 indexed actionId);
    event FundsMigrated(address indexed from, address indexed to, uint256 amount);
    event SafeWalletAdded(address indexed wallet, uint256 capacity);
    event ProtocolWhitelisted(address indexed protocol);
    event EmergencyWithdrawal(address indexed token, address indexed to, uint256 amount);

    constructor(address _circuitBreaker, address _threatRegistry) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(RESPONDER_ROLE, msg.sender);
        _grantRole(STRATEGIST_ROLE, msg.sender);

        circuitBreaker = CircuitBreaker(_circuitBreaker);
        threatRegistry = ThreatRegistry(_threatRegistry);
    }

    /**
     * @notice Propose an automated response action
     * @param actionType Type of action
     * @param target Target address
     * @param data Encoded function call
     * @param value ETH value to send
     */
    function proposeAction(
        ActionType actionType,
        address target,
        bytes calldata data,
        uint256 value
    ) external onlyRole(STRATEGIST_ROLE) nonReentrant {
        actionCount++;

        actions[actionCount] = ResponseAction({
            actionType: actionType,
            target: target,
            data: data,
            value: value,
            executeAfter: block.timestamp + ACTION_DELAY,
            expiresAt: block.timestamp + ACTION_DELAY + ACTION_EXPIRY,
            executed: false,
            cancelled: false,
            proposer: msg.sender
        });

        emit ActionProposed(actionCount, actionType, target);
    }

    /**
     * @notice Execute a proposed action after timelock
     * @param actionId The action to execute
     */
    function executeAction(uint256 actionId) external onlyRole(RESPONDER_ROLE) nonReentrant {
        ResponseAction storage action = actions[actionId];
        require(action.target != address(0), "Action does not exist");
        require(!action.executed, "Already executed");
        require(!action.cancelled, "Cancelled");
        require(block.timestamp >= action.executeAfter, "Timelock not expired");
        require(block.timestamp <= action.expiresAt, "Action expired");

        // Check circuit breaker for non-emergency actions
        if (action.actionType != ActionType.EMERGENCY_WITHDRAW) {
            require(!circuitBreaker.isPaused(), "Circuit breaker active");
        }

        action.executed = true;
        totalExecuted++;

        // Execute based on action type
        if (action.actionType == ActionType.MIGRATE_FUNDS) {
            _executeFundMigration(action);
        } else if (action.actionType == ActionType.PAUSE_PROTOCOL) {
            _executeProtocolPause(action);
        } else if (action.actionType == ActionType.ADJUST_PARAMETERS) {
            _executeParameterAdjustment(action);
        }

        emit ActionExecuted(actionId, action.actionType, action.target);
    }

    /**
     * @notice Cancel a proposed action
     * @param actionId The action to cancel
     */
    function cancelAction(uint256 actionId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        ResponseAction storage action = actions[actionId];
        require(!action.executed, "Already executed");

        action.cancelled = true;
        totalCancelled++;

        emit ActionCancelled(actionId);
    }

    /**
     * @notice Add a safe wallet for fund migration
     * @param wallet Safe wallet address
     * @param capacity Maximum capacity
     */
    function addSafeWallet(address wallet, uint256 capacity) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(wallet != address(0), "Zero address");

        safeWallets[wallet] = SafeWallet({
            wallet: wallet,
            capacity: capacity,
            currentBalance: 0,
            active: true
        });

        safeWalletList.push(wallet);
        emit SafeWalletAdded(wallet, capacity);
    }

    /**
     * @notice Whitelist a protocol for automated pausing
     * @param protocol Protocol address
     */
    function whitelistProtocol(address protocol) external onlyRole(DEFAULT_ADMIN_ROLE) {
        whitelistedProtocols[protocol] = true;
        emit ProtocolWhitelisted(protocol);
    }

    /**
     * @notice Emergency withdrawal of tokens
     * @param token Token address
     * @param to Destination address
     * @param amount Amount to withdraw
     */
    function emergencyWithdraw(
        address token,
        address to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        require(to != address(0), "Zero address");

        // In production, this would call token.transfer(to, amount)
        emit EmergencyWithdrawal(token, to, amount);
    }

    /**
     * @notice Get action details
     */
    function getAction(uint256 actionId) external view returns (
        ActionType actionType,
        address target,
        uint256 executeAfter,
        uint256 expiresAt,
        bool executed,
        bool cancelled
    ) {
        ResponseAction storage a = actions[actionId];
        return (a.actionType, a.target, a.executeAfter, a.expiresAt, a.executed, a.cancelled);
    }

    /**
     * @notice Get safe wallet details
     */
    function getSafeWallet(address wallet) external view returns (
        uint256 capacity,
        uint256 currentBalance,
        bool active
    ) {
        SafeWallet storage sw = safeWallets[wallet];
        return (sw.capacity, sw.currentBalance, sw.active);
    }

    function _executeFundMigration(ResponseAction storage action) internal {
        // Find available safe wallet
        for (uint256 i = 0; i < safeWalletList.length; i++) {
            SafeWallet storage sw = safeWallets[safeWalletList[i]];
            if (sw.active && sw.currentBalance + action.value <= sw.capacity) {
                sw.currentBalance += action.value;
                totalMigrated += action.value;
                emit FundsMigrated(action.target, sw.wallet, action.value);
                return;
            }
        }
    }

    function _executeProtocolPause(ResponseAction storage action) internal {
        require(whitelistedProtocols[action.target], "Not whitelisted");
        // In production, call pause() on the target protocol
    }

    function _executeParameterAdjustment(ResponseAction storage action) internal {
        // In production, decode and apply parameter changes
    }
}

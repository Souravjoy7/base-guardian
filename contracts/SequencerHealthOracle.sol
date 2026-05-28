// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title SequencerHealthOracle
 * @notice On-chain oracle tracking Base sequencer liveness, gas anomalies, and reorgs
 * @dev Guardians submit heartbeat proofs; contract tracks uptime and flags anomalies
 */
contract SequencerHealthOracle is AccessControl {
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");

    struct Heartbeat {
        uint256 timestamp;
        uint256 blockNumber;
        uint256 gasPrice;
        uint256 sequencerBalance;
        address submitter;
        bool verified;
    }

    struct AnomalyReport {
        uint256 timestamp;
        uint8 anomalyType; // 0=missed_heartbeat, 1=gas_spike, 2=reorg, 3=sequencer_down
        uint256 severity;  // 1-10
        string details;
        bool confirmed;
    }

    // Heartbeat tracking
    uint256 public heartbeatInterval = 12 seconds;
    uint256 public lastHeartbeatTimestamp;
    uint256 public missedHeartbeats;
    uint256 public totalHeartbeats;
    uint256 public constant MAX_MISSED_HEARTBEATS = 50;

    // Gas tracking
    uint256 public lastGasPrice;
    uint256 public gasSpikeThreshold = 200; // 200% increase = spike
    uint256 public gasSpikeCount;

    // Reorg tracking
    uint256 public lastReorgDepth;
    uint256 public reorgCount;
    uint256 public constant MAX_REORG_DEPTH = 10;

    // Anomaly storage
    mapping(uint256 => AnomalyReport) public anomalies;
    uint256 public anomalyCount;

    // Heartbeat history (last 100)
    mapping(uint256 => Heartbeat) public heartbeats;
    uint256 public heartbeatIndex;

    // Status
    bool public sequencerHealthy = true;
    uint256 public downtimeStart;
    uint256 public totalDowntime;

    event HeartbeatReceived(uint256 indexed heartbeatId, uint256 blockNumber, uint256 gasPrice);
    event HeartbeatMissed(uint256 expectedTime, uint256 actualTime, uint256 missed);
    event GasSpikeDetected(uint256 oldPrice, uint256 newPrice, uint256 percentIncrease);
    event ReorgDetected(uint256 depth, uint256 blockNumber);
    event SequencerDown(uint256 timestamp);
    event SequencerRecovered(uint256 timestamp, uint256 downtimeDuration);
    event AnomalyReported(uint256 indexed anomalyId, uint8 anomalyType, uint256 severity);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ORACLE_ROLE, msg.sender);
        _grantRole(VALIDATOR_ROLE, msg.sender);
    }

    /**
     * @notice Submit a sequencer heartbeat
     * @param blockNumber Current L2 block number
     * @param gasPrice Current gas price on Base
     */
    function submitHeartbeat(uint256 blockNumber, uint256 gasPrice) external onlyRole(ORACLE_ROLE) {
        // Check for missed heartbeats
        if (lastHeartbeatTimestamp > 0) {
            uint256 elapsed = block.timestamp - lastHeartbeatTimestamp;
            if (elapsed > heartbeatInterval * 3) {
                missedHeartbeats += (elapsed / heartbeatInterval) - 1;
                emit HeartbeatMissed(lastHeartbeatTimestamp, block.timestamp, missedHeartbeats);

                if (missedHeartbeats >= MAX_MISSED_HEARTBEATS && sequencerHealthy) {
                    sequencerHealthy = false;
                    downtimeStart = block.timestamp;
                    emit SequencerDown(block.timestamp);
                }
            }
        }

        // Check for gas spike
        if (lastGasPrice > 0 && gasPrice > lastGasPrice) {
            uint256 percentIncrease = ((gasPrice - lastGasPrice) * 100) / lastGasPrice;
            if (percentIncrease >= gasSpikeThreshold) {
                gasSpikeCount++;
                emit GasSpikeDetected(lastGasPrice, gasPrice, percentIncrease);

                anomalyCount++;
                anomalies[anomalyCount] = AnomalyReport({
                    timestamp: block.timestamp,
                    anomalyType: 1,
                    severity: percentIncrease > 500 ? 9 : percentIncrease > 300 ? 7 : 5,
                    details: "Gas spike detected",
                    confirmed: true
                });
                emit AnomalyReported(anomalyCount, 1, anomalies[anomalyCount].severity);
            }
        }

        // Recovery detection
        if (!sequencerHealthy) {
            sequencerHealthy = true;
            totalDowntime += block.timestamp - downtimeStart;
            emit SequencerRecovered(block.timestamp, block.timestamp - downtimeStart);
            missedHeartbeats = 0;
        }

        // Store heartbeat
        heartbeats[heartbeatIndex] = Heartbeat({
            timestamp: block.timestamp,
            blockNumber: blockNumber,
            gasPrice: gasPrice,
            sequencerBalance: address(this).balance,
            submitter: msg.sender,
            verified: true
        });

        lastHeartbeatTimestamp = block.timestamp;
        lastGasPrice = gasPrice;
        totalHeartbeats++;
        heartbeatIndex = (heartbeatIndex + 1) % 100;

        emit HeartbeatReceived(totalHeartbeats, blockNumber, gasPrice);
    }

    /**
     * @notice Report a reorg event
     * @param depth Depth of the reorg
     * @param blockNumber The block where reorg occurred
     */
    function reportReorg(uint256 depth, uint256 blockNumber) external onlyRole(VALIDATOR_ROLE) {
        require(depth > 0 && depth <= MAX_REORG_DEPTH, "Invalid depth");

        reorgCount++;
        lastReorgDepth = depth;
        emit ReorgDetected(depth, blockNumber);

        anomalyCount++;
        anomalies[anomalyCount] = AnomalyReport({
            timestamp: block.timestamp,
            anomalyType: 2,
            severity: depth > 5 ? 9 : depth > 2 ? 6 : 3,
            details: "Reorg detected",
            confirmed: true
        });
        emit AnomalyReported(anomalyCount, 2, anomalies[anomalyCount].severity);
    }

    /**
     * @notice Get sequencer uptime percentage (last 1000 heartbeats)
     */
    function getUptimePercentage() external view returns (uint256) {
        if (totalHeartbeats == 0) return 10000; // 100.00%
        uint256 expectedHeartbeats = totalHeartbeats + missedHeartbeats;
        return (totalHeartbeats * 10000) / expectedHeartbeats;
    }

    /**
     * @notice Get health summary
     */
    function getHealthSummary() external view returns (
        bool healthy,
        uint256 uptimeBps,
        uint256 totalSpikes,
        uint256 totalReorgs,
        uint256 lastGas
    ) {
        uint256 uptime = 10000;
        if (totalHeartbeats > 0) {
            uint256 expected = totalHeartbeats + missedHeartbeats;
            uptime = (totalHeartbeats * 10000) / expected;
        }
        return (sequencerHealthy, uptime, gasSpikeCount, reorgCount, lastGasPrice);
    }

    function setHeartbeatInterval(uint256 _interval) external onlyRole(DEFAULT_ADMIN_ROLE) {
        heartbeatInterval = _interval;
    }

    function setGasSpikeThreshold(uint256 _threshold) external onlyRole(DEFAULT_ADMIN_ROLE) {
        gasSpikeThreshold = _threshold;
    }
}

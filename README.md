# 🛡️ Base Guardian

**Production-grade L2 security monitoring, threat detection, and automated response framework for Base.**

Base Guardian is not another token template. It's a comprehensive security infrastructure that monitors Base L2 in real-time, detects threats before they escalate, and executes automated defensive responses through on-chain circuit breakers.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BASE GUARDIAN SYSTEM                       │
├──────────────┬──────────────┬──────────────┬────────────────┤
│  Sequencer   │   Mempool    │   Anomaly    │   Bridge       │
│  Health      │   Scanner    │   Detector   │   Verifier     │
│  Monitor     │              │              │                │
├──────────────┴──────────────┴──────────────┴────────────────┤
│              Real-time Monitoring Layer (Node.js)             │
├─────────────────────────────────────────────────────────────┤
│              Threat Intelligence Aggregation                   │
├──────────┬──────────┬──────────┬──────────┬─────────────────┤
│ Circuit  │ Sequencer│ Bridge   │ Threat   │ Automated       │
│ Breaker  │ Health   │ State    │ Registry │ Responder       │
│ Contract │ Oracle   │ Verifier │          │                  │
└──────────┴──────────┴──────────┴──────────┴─────────────────┘
```

## Smart Contracts

### CircuitBreaker.sol
Emergency pause mechanism that can halt protocol operations when anomalies are detected. Features:
- Multi-sig threat level escalation (LOW → MEDIUM → HIGH → CRITICAL)
- Time-locked automatic recovery
- Role-based access (Guardians, Operators, Emergency)
- Event-driven alert system

### SequencerHealthOracle.sol
Tracks Base sequencer liveness and performance:
- Heartbeat monitoring with configurable thresholds
- Historical downtime tracking
- Gas price anomaly detection
- Reorg depth monitoring

### BridgeStateVerifier.sol
Cross-chain state proof verification:
- L2→L1 message verification using Merkle proofs
- Withdrawal safety validation
- Cross-chain state consistency checks

### ThreatRegistry.sol
On-chain threat intelligence storage:
- Threat classification and severity scoring
- Address blacklisting with governance controls
- Historical attack pattern storage
- Integration with external threat feeds

### AutomatedResponder.sol
Executes defensive actions based on threat level:
- Automated fund migration to safe wallets
- Contract parameter adjustment
- Emergency governance proposals
- Notification dispatch

## Quick Start

```bash
# Clone and install
git clone https://github.com/Souravjoy7/base-guardian.git
cd base-guardian
npm install

# Compile contracts
npx hardhat compile

# Run tests
npx hardhat test

# Deploy to Base Goerli
npx hardhat run scripts/deploy.js --network base_goerli

# Start monitoring (requires .env config)
node src/monitor/index.js
```

## Environment Configuration

Create `.env` from the template:

```bash
cp .env.example .env
```

Required variables:
- `PRIVATE_KEY` - Deployer wallet private key
- `BASE_RPC_URL` - Base RPC endpoint (Infura/Alchemy)
- `BASE_WS_URL` - Base WebSocket endpoint for real-time monitoring
- `ALERT_WEBHOOK_URL` - Discord/Slack webhook for alerts
- `ETHERSCAN_API_KEY` - For contract verification

## Testing

```bash
# Unit tests
npx hardhat test

# Coverage report
npx hardhat coverage

# Gas reporting
REPORT_GAS=true npx hardhat test
```

## Deployment

### Testnet (Base Goerli)
```bash
npx hardhat run scripts/deploy.js --network base_goerli
```

### Mainnet (Base)
```bash
npx hardhat run scripts/deploy.js --network base_mainnet
```

### Contract Verification
```bash
npx hardhat verify --network base_goerli <CONTRACT_ADDRESS>
```

## Monitoring Dashboard

The monitoring service exposes a REST API:

```
GET /api/status          - Overall system status
GET /api/threats         - Active threats
GET /api/sequencer       - Sequencer health metrics
GET /api/bridge          - Bridge state verification
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Security

This project is a security tool itself. If you find vulnerabilities:
- DO NOT open a public issue
- Email: security@example.com
- We will respond within 24 hours

## License

MIT © 2026 Sourav Joy

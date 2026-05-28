const hre = require("hardhat");

async function main() {
  console.log("Deploying Base Guardian contracts...\n");

  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Account balance:", (await deployer.getBalance()).toString(), "\n");

  // 1. Deploy CircuitBreaker
  console.log("1. Deploying CircuitBreaker...");
  const CircuitBreaker = await hre.ethers.getContractFactory("CircuitBreaker");
  const circuitBreaker = await CircuitBreaker.deploy();
  await circuitBreaker.deployed();
  console.log("   CircuitBreaker deployed to:", circuitBreaker.address);

  // 2. Deploy SequencerHealthOracle
  console.log("2. Deploying SequencerHealthOracle...");
  const SequencerHealthOracle = await hre.ethers.getContractFactory("SequencerHealthOracle");
  const oracle = await SequencerHealthOracle.deploy();
  await oracle.deployed();
  console.log("   SequencerHealthOracle deployed to:", oracle.address);

  // 3. Deploy BridgeStateVerifier
  console.log("3. Deploying BridgeStateVerifier...");
  const BridgeStateVerifier = await hre.ethers.getContractFactory("BridgeStateVerifier");
  const bridgeVerifier = await BridgeStateVerifier.deploy();
  await bridgeVerifier.deployed();
  console.log("   BridgeStateVerifier deployed to:", bridgeVerifier.address);

  // 4. Deploy ThreatRegistry
  console.log("4. Deploying ThreatRegistry...");
  const ThreatRegistry = await hre.ethers.getContractFactory("ThreatRegistry");
  const threatRegistry = await ThreatRegistry.deploy();
  await threatRegistry.deployed();
  console.log("   ThreatRegistry deployed to:", threatRegistry.address);

  // 5. Deploy AutomatedResponder (linked to CircuitBreaker + ThreatRegistry)
  console.log("5. Deploying AutomatedResponder...");
  const AutomatedResponder = await hre.ethers.getContractFactory("AutomatedResponder");
  const responder = await AutomatedResponder.deploy(circuitBreaker.address, threatRegistry.address);
  await responder.deployed();
  console.log("   AutomatedResponder deployed to:", responder.address);

  console.log("\n=== Deployment Complete ===");
  console.log("CircuitBreaker:       ", circuitBreaker.address);
  console.log("SequencerHealthOracle:", oracle.address);
  console.log("BridgeStateVerifier:  ", bridgeVerifier.address);
  console.log("ThreatRegistry:       ", threatRegistry.address);
  console.log("AutomatedResponder:   ", responder.address);
  console.log("========================\n");

  // Save deployment addresses
  const fs = require("fs");
  const deployments = {
    network: hre.network.name,
    chainId: (await hre.ethers.provider.getNetwork()).chainId,
    deployer: deployer.address,
    contracts: {
      CircuitBreaker: circuitBreaker.address,
      SequencerHealthOracle: oracle.address,
      BridgeStateVerifier: bridgeVerifier.address,
      ThreatRegistry: threatRegistry.address,
      AutomatedResponder: responder.address,
    },
    timestamp: new Date().toISOString(),
  };

  fs.writeFileSync(
    `deployments-${hre.network.name}.json`,
    JSON.stringify(deployments, null, 2)
  );
  console.log(`Deployment addresses saved to deployments-${hre.network.name}.json`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

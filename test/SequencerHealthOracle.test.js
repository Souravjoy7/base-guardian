const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("SequencerHealthOracle", function () {
  let oracle, owner, oracleRole, validator;

  beforeEach(async function () {
    [owner, oracleRole, validator] = await ethers.getSigners();
    const Oracle = await ethers.getContractFactory("SequencerHealthOracle");
    oracle = await Oracle.deploy();
    await oracle.deployed();

    await oracle.grantRole(await oracle.ORACLE_ROLE(), oracleRole.address);
    await oracle.grantRole(await oracle.VALIDATOR_ROLE(), validator.address);
  });

  describe("Heartbeat", function () {
    it("should accept valid heartbeat", async function () {
      await expect(
        oracle.connect(oracleRole).submitHeartbeat(1000, 1000000000)
      ).to.emit(oracle, "HeartbeatReceived");
    });

    it("should track total heartbeats", async function () {
      await oracle.connect(oracleRole).submitHeartbeat(1000, 1000000000);
      await oracle.connect(oracleRole).submitHeartbeat(1001, 1100000000);
      expect(await oracle.totalHeartbeats()).to.equal(2);
    });

    it("should reject heartbeat from non-oracle", async function () {
      await expect(
        oracle.connect(validator).submitHeartbeat(1000, 1000000000)
      ).to.be.reverted;
    });
  });

  describe("Gas Spike Detection", function () {
    it("should detect gas spike", async function () {
      await oracle.connect(oracleRole).submitHeartbeat(1000, 1000000000);
      await expect(
        oracle.connect(oracleRole).submitHeartbeat(1001, 5000000000) // 500% increase
      ).to.emit(oracle, "GasSpikeDetected");
    });
  });

  describe("Reorg Reporting", function () {
    it("should accept valid reorg report", async function () {
      await expect(
        oracle.connect(validator).reportReorg(3, 1000)
      ).to.emit(oracle, "ReorgDetected");
    });

    it("should reject invalid reorg depth", async function () {
      await expect(
        oracle.connect(validator).reportReorg(0, 1000)
      ).to.be.revertedWith("Invalid depth");
    });

    it("should reject depth > MAX_REORG_DEPTH", async function () {
      await expect(
        oracle.connect(validator).reportReorg(11, 1000)
      ).to.be.revertedWith("Invalid depth");
    });
  });

  describe("Health Summary", function () {
    it("should return correct health summary", async function () {
      await oracle.connect(oracleRole).submitHeartbeat(1000, 1000000000);
      const [healthy, uptime, spikes, reorgs, lastGas] = await oracle.getHealthSummary();
      expect(healthy).to.be.true;
      expect(uptime).to.equal(10000); // 100.00%
      expect(spikes).to.equal(0);
      expect(reorgs).to.equal(0);
      expect(lastGas).to.equal(1000000000);
    });
  });
});

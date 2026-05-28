const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("CircuitBreaker", function () {
  let circuitBreaker, owner, guardian1, guardian2, operator;

  beforeEach(async function () {
    [owner, guardian1, guardian2, operator] = await ethers.getSigners();
    const CircuitBreaker = await ethers.getContractFactory("CircuitBreaker");
    circuitBreaker = await CircuitBreaker.deploy();
    await circuitBreaker.deployed();

    // Grant roles
    await circuitBreaker.addGuardian(guardian1.address);
    await circuitBreaker.addGuardian(guardian2.address);
    await circuitBreaker.grantRole(await circuitBreaker.OPERATOR_ROLE(), operator.address);
  });

  describe("Threat Reporting", function () {
    it("should allow guardian to report threat", async function () {
      await expect(
        circuitBreaker.connect(guardian1).reportThreat(1, "Low severity test")
      ).to.emit(circuitBreaker, "ThreatDetected");
    });

    it("should reject threat report from non-guardian", async function () {
      await expect(
        circuitBreaker.connect(operator).reportThreat(1, "Unauthorized")
      ).to.be.reverted;
    });

    it("should escalate threat level on high severity", async function () {
      await circuitBreaker.connect(guardian1).reportThreat(4, "Critical threat");
      expect(await circuitBreaker.currentThreatLevel()).to.equal(4);
    });

    it("should trip circuit breaker on HIGH threat", async function () {
      await expect(
        circuitBreaker.connect(guardian1).reportThreat(3, "High threat")
      ).to.emit(circuitBreaker, "CircuitBreakerTripped");

      expect(await circuitBreaker.isPaused()).to.be.true;
    });
  });

  describe("Threat Confirmation", function () {
    it("should allow multiple guardians to confirm", async function () {
      // Report threat first so eventId 1 exists
      await circuitBreaker.connect(guardian1).reportThreat(3, "High severity threat");
      await circuitBreaker.connect(guardian1).confirmThreat(1);
      await circuitBreaker.connect(guardian2).confirmThreat(1);
      // Should not revert
    });

    it("should reject duplicate confirmation", async function () {
      // Report threat first so eventId 1 exists
      await circuitBreaker.connect(guardian1).reportThreat(3, "High severity threat");
      await circuitBreaker.connect(guardian1).confirmThreat(1);
      await expect(
        circuitBreaker.connect(guardian1).confirmThreat(1)
      ).to.be.revertedWith("Already confirmed");
    });
  });

  describe("Emergency Halt", function () {
    it("should allow emergency role to halt immediately", async function () {
      await circuitBreaker.emergencyHalt();
      expect(await circuitBreaker.currentThreatLevel()).to.equal(4);
      expect(await circuitBreaker.isPaused()).to.be.true;
    });
  });

  describe("Recovery", function () {
    it("should not allow reset before timelock", async function () {
      await circuitBreaker.emergencyHalt();
      await expect(
        circuitBreaker.resetCircuitBreaker()
      ).to.be.revertedWith("Timelock not expired");
    });
  });
});

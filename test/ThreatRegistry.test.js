const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ThreatRegistry", function () {
  let registry, owner, analyst, governance, outsider;

  beforeEach(async function () {
    [owner, analyst, governance, outsider] = await ethers.getSigners();
    const ThreatRegistry = await ethers.getContractFactory("ThreatRegistry");
    registry = await ThreatRegistry.deploy();
    await registry.deployed();

    await registry.grantRole(await registry.ANALYST_ROLE(), analyst.address);
    await registry.grantRole(await registry.GOVERNANCE_ROLE(), governance.address);
  });

  describe("Threat Reporting", function () {
    it("should allow analyst to report threat", async function () {
      await expect(
        registry.connect(analyst).reportThreat(
          0, // PHISHING
          5,
          outsider.address,
          "Phishing attack detected",
          ethers.constants.HashZero,
          1000
        )
      ).to.emit(registry, "ThreatReported");
    });

    it("should reject invalid severity", async function () {
      await expect(
        registry.connect(analyst).reportThreat(0, 0, outsider.address, "Bad", ethers.constants.HashZero, 1000)
      ).to.be.revertedWith("Invalid severity");
    });

    it("should increment threat count", async function () {
      await registry.connect(analyst).reportThreat(0, 5, outsider.address, "Test", ethers.constants.HashZero, 1000);
      expect(await registry.threatCount()).to.equal(1);
    });
  });

  describe("Threat Verification", function () {
    it("should allow governance to verify threat", async function () {
      await registry.connect(analyst).reportThreat(0, 5, outsider.address, "Test", ethers.constants.HashZero, 1000);
      await expect(
        registry.connect(governance).verifyThreat(1)
      ).to.emit(registry, "ThreatVerified");
    });

    it("should reject verification from non-governance", async function () {
      await registry.connect(analyst).reportThreat(0, 5, outsider.address, "Test", ethers.constants.HashZero, 1000);
      await expect(
        registry.connect(analyst).verifyThreat(1)
      ).to.be.reverted;
    });
  });

  describe("Blacklisting", function () {
    it("should allow governance to blacklist address", async function () {
      await expect(
        registry.connect(governance).blacklistAddress(outsider.address, 1) // EXPLOIT
      ).to.emit(registry, "AddressBlacklisted");

      expect(await registry.isBlacklisted(outsider.address)).to.be.true;
    });

    it("should allow unblacklisting", async function () {
      await registry.connect(governance).blacklistAddress(outsider.address, 1);
      await registry.connect(governance).unblacklistAddress(outsider.address);
      expect(await registry.isBlacklisted(outsider.address)).to.be.false;
    });

    it("should reject duplicate blacklist", async function () {
      await registry.connect(governance).blacklistAddress(outsider.address, 1);
      await expect(
        registry.connect(governance).blacklistAddress(outsider.address, 1)
      ).to.be.revertedWith("Already blacklisted");
    });
  });

  describe("Signatures", function () {
    it("should allow analyst to add signature", async function () {
      const sig = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("flash_loan_pattern"));
      await expect(
        registry.connect(analyst).addSignature(sig, 2) // FLASH_LOAN_ATTACK
      ).to.emit(registry, "SignatureAdded");
    });
  });
});

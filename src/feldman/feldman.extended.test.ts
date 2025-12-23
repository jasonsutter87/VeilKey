/**
 * Extended Tests for Feldman Verifiable Secret Sharing
 *
 * Comprehensive test suite covering:
 * - Malicious dealer detection
 * - Commitment tampering detection
 * - Verification with wrong commitments
 * - Large coefficient tests
 * - Curve point edge cases
 * - Parallel verification scenarios
 * - Invalid curve points
 * - Commitment consistency checks
 * - Combined Shamir+Feldman workflows
 */

import { describe, it, expect } from 'vitest';
import {
  split,
  verify,
  combine,
  getPublicCommitment,
  verifyAll,
  FeldmanVSS,
} from './index.js';
import type { FeldmanShare, FeldmanCommitments, CurvePoint } from './types.js';
import { SECP256K1_ORDER } from '../shamir/index.js';

describe('Feldman VSS - Extended Tests', () => {
  // ===========================================================================
  // Malicious Dealer Detection
  // ===========================================================================

  describe('malicious dealer detection', () => {
    it('should detect when dealer provides invalid share', () => {
      const result = split(12345n, 3, 5);

      // Dealer gives a bad share (tampered value)
      const badShare: FeldmanShare = {
        ...result.shares[0],
        y: result.shares[0].y + 1n,
      };

      const verification = verify(badShare, result.commitments);
      expect(verification.valid).toBe(false);
    });

    it('should detect when dealer provides share from different polynomial', () => {
      const result1 = split(11111n, 2, 3);
      const result2 = split(22222n, 2, 3);

      // Try to verify share from result2 using commitments from result1
      const verification = verify(result2.shares[0], result1.commitments);
      expect(verification.valid).toBe(false);
    });

    it('should detect inconsistent share index', () => {
      const result = split(33333n, 3, 5);

      // Share claims wrong index
      const badShare: FeldmanShare = {
        x: result.shares[0].x,
        y: result.shares[1].y, // y from different share
        index: result.shares[0].index,
      };

      const verification = verify(badShare, result.commitments);
      expect(verification.valid).toBe(false);
    });

    it('should verify that all valid shares are independently verifiable', () => {
      const result = split(44444n, 3, 7);

      // Each share should verify independently
      for (const share of result.shares) {
        const verification = verify(share, result.commitments);
        expect(verification.valid).toBe(true);
      }
    });
  });

  // ===========================================================================
  // Commitment Tampering Detection
  // ===========================================================================

  describe('commitment tampering detection', () => {
    it('should detect when single commitment is tampered', () => {
      const result = split(55555n, 3, 5);

      // Tamper with one commitment
      const tamperedCommitments = [...result.commitments];
      tamperedCommitments[1] = {
        x: tamperedCommitments[1].x + 1n,
        y: tamperedCommitments[1].y,
      };

      const verification = verify(result.shares[0], tamperedCommitments);
      expect(verification.valid).toBe(false);
    });

    it('should detect when public commitment (first) is tampered', () => {
      const result = split(66666n, 2, 4);

      // Tamper with public commitment (g^secret)
      const tamperedCommitments = [...result.commitments];
      tamperedCommitments[0] = {
        x: tamperedCommitments[0].x,
        y: tamperedCommitments[0].y + 1n,
      };

      const verification = verify(result.shares[0], tamperedCommitments);
      expect(verification.valid).toBe(false);
    });

    it('should detect when all commitments are replaced', () => {
      const result1 = split(77777n, 2, 3);
      const result2 = split(88888n, 2, 3);

      // Try to verify shares from result1 with commitments from result2
      const verification = verify(result1.shares[0], result2.commitments);
      expect(verification.valid).toBe(false);
    });

    it('should detect when commitment order is scrambled', () => {
      const result = split(99999n, 3, 5);

      // Reverse commitment order
      const scrambledCommitments = [...result.commitments].reverse();

      const verification = verify(result.shares[0], scrambledCommitments);
      expect(verification.valid).toBe(false);
    });
  });

  // ===========================================================================
  // Verification with Wrong Commitments
  // ===========================================================================

  describe('verification with wrong commitments', () => {
    it('should fail with insufficient commitments', () => {
      const result = split(111222n, 3, 5);

      // Only provide 2 commitments instead of 3
      const insufficientCommitments = result.commitments.slice(0, 2);

      const verification = verify(result.shares[0], insufficientCommitments);
      expect(verification.valid).toBe(false);
    });

    it('should fail with too many commitments', () => {
      const result = split(222333n, 2, 4);

      // Add an extra random commitment
      const extraCommitments = [
        ...result.commitments,
        { x: 12345n, y: 67890n },
      ];

      const verification = verify(result.shares[0], extraCommitments);
      expect(verification.valid).toBe(false);
    });

    it('should fail with empty commitments array', () => {
      const result = split(333444n, 2, 3);

      expect(() => verify(result.shares[0], [])).toThrow();
    });

    it('should handle commitments from different threshold', () => {
      const result3 = split(444555n, 3, 5);
      const result2 = split(444555n, 2, 5); // Same secret, different threshold

      // Commitments have different length
      expect(result3.commitments).toHaveLength(3);
      expect(result2.commitments).toHaveLength(2);

      // Shares from one cannot be verified with commitments from other
      const verification = verify(result3.shares[0], result2.commitments);
      expect(verification.valid).toBe(false);
    });
  });

  // ===========================================================================
  // Large Coefficient Tests
  // ===========================================================================

  describe('large coefficient tests', () => {
    it('should work with very large secret (near prime)', () => {
      const largeSecret = SECP256K1_ORDER - 1000n;
      const result = split(largeSecret, 3, 5);

      for (const share of result.shares) {
        expect(verify(share, result.commitments).valid).toBe(true);
      }

      expect(combine(result.shares.slice(0, 3))).toBe(largeSecret);
    });

    it('should work with maximum valid secret', () => {
      const maxSecret = SECP256K1_ORDER - 1n;
      const result = split(maxSecret, 2, 4);

      expect(verifyAll(result.shares, result.commitments)).toBe(true);
      expect(combine(result.shares.slice(0, 2))).toBe(maxSecret);
    });

    it('should handle secret = 1', () => {
      const minSecret = 1n;
      const result = split(minSecret, 2, 3);

      expect(verifyAll(result.shares, result.commitments)).toBe(true);
      expect(combine(result.shares.slice(0, 2))).toBe(minSecret);
    });

    it('should work with mid-range secrets', () => {
      const midSecret = SECP256K1_ORDER / 2n;
      const result = split(midSecret, 4, 7);

      expect(verifyAll(result.shares, result.commitments)).toBe(true);
      expect(combine(result.shares.slice(0, 4))).toBe(midSecret);
    });
  });

  // ===========================================================================
  // Curve Point Edge Cases
  // ===========================================================================

  describe('curve point edge cases', () => {
    it('should produce valid curve points for all commitments', () => {
      const result = split(123456n, 5, 10);

      // All commitments should be valid curve points
      for (const commitment of result.commitments) {
        expect(commitment.x).toBeDefined();
        expect(commitment.y).toBeDefined();
        expect(typeof commitment.x).toBe('bigint');
        expect(typeof commitment.y).toBe('bigint');
      }
    });

    it('should have different commitments for different secrets', () => {
      const result1 = split(11111n, 2, 3);
      const result2 = split(22222n, 2, 3);

      // Public commitments (g^secret) should differ
      expect(result1.publicCommitment.x).not.toBe(result2.publicCommitment.x);
    });

    it('should have consistent public commitment for same secret', () => {
      const secret = 99999n;
      const result1 = split(secret, 2, 3);
      const result2 = split(secret, 2, 3);

      // g^secret should be same (deterministic)
      expect(result1.publicCommitment.x).toBe(result2.publicCommitment.x);
      expect(result1.publicCommitment.y).toBe(result2.publicCommitment.y);
    });

    it('should produce unique commitments for polynomial coefficients', () => {
      const result = split(55555n, 5, 7);

      // Each commitment should be unique (different coefficients)
      const commitmentStrings = result.commitments.map(c => `${c.x},${c.y}`);
      const uniqueCommitments = new Set(commitmentStrings);

      expect(uniqueCommitments.size).toBe(result.commitments.length);
    });
  });

  // ===========================================================================
  // Parallel Verification
  // ===========================================================================

  describe('parallel verification', () => {
    it('should allow independent verification of multiple shares', () => {
      const result = split(777888n, 3, 10);

      // Verify shares in any order
      const verifications = [
        verify(result.shares[0], result.commitments),
        verify(result.shares[5], result.commitments),
        verify(result.shares[9], result.commitments),
      ];

      verifications.forEach(v => expect(v.valid).toBe(true));
    });

    it('should detect mix of valid and invalid shares', () => {
      const result = split(888999n, 3, 5);

      const tamperedShare: FeldmanShare = {
        ...result.shares[2],
        y: result.shares[2].y + 100n,
      };

      const shares = [
        result.shares[0], // valid
        result.shares[1], // valid
        tamperedShare,    // invalid
        result.shares[3], // valid
      ];

      expect(verify(shares[0], result.commitments).valid).toBe(true);
      expect(verify(shares[1], result.commitments).valid).toBe(true);
      expect(verify(shares[2], result.commitments).valid).toBe(false);
      expect(verify(shares[3], result.commitments).valid).toBe(true);
    });

    it('should support verifyAll for batch verification', () => {
      const result = split(123321n, 4, 8);

      expect(verifyAll(result.shares, result.commitments)).toBe(true);

      // Tamper one share
      const shares = [...result.shares];
      shares[3] = { ...shares[3], y: shares[3].y + 1n };

      expect(verifyAll(shares, result.commitments)).toBe(false);
    });
  });

  // ===========================================================================
  // Invalid Curve Points
  // ===========================================================================

  describe('invalid curve points', () => {
    it('should reject commitment with invalid x-coordinate', () => {
      const result = split(111000n, 2, 3);

      const invalidCommitments: FeldmanCommitments = [
        { x: 0n, y: result.commitments[0].y }, // Invalid point
        ...result.commitments.slice(1),
      ];

      const verification = verify(result.shares[0], invalidCommitments);
      expect(verification.valid).toBe(false);
    });

    it('should reject commitment with invalid y-coordinate', () => {
      const result = split(222000n, 2, 3);

      const invalidCommitments: FeldmanCommitments = [
        { x: result.commitments[0].x, y: 0n }, // Invalid point
        ...result.commitments.slice(1),
      ];

      const verification = verify(result.shares[0], invalidCommitments);
      expect(verification.valid).toBe(false);
    });

    it('should handle commitments with coordinates out of range', () => {
      const result = split(333000n, 2, 3);

      const invalidCommitments: FeldmanCommitments = [
        { x: SECP256K1_ORDER + 1n, y: result.commitments[0].y },
        ...result.commitments.slice(1),
      ];

      const verification = verify(result.shares[0], invalidCommitments);
      expect(verification.valid).toBe(false);
    });
  });

  // ===========================================================================
  // Commitment Consistency Checks
  // ===========================================================================

  describe('commitment consistency checks', () => {
    it('should have publicCommitment equal to first commitment', () => {
      const result = split(444000n, 3, 5);

      expect(result.publicCommitment).toEqual(result.commitments[0]);
    });

    it('should have commitment count equal to threshold', () => {
      const testCases = [
        { threshold: 2, totalShares: 5 },
        { threshold: 3, totalShares: 7 },
        { threshold: 5, totalShares: 10 },
        { threshold: 10, totalShares: 20 },
      ];

      for (const { threshold, totalShares } of testCases) {
        const result = split(555000n, threshold, totalShares);
        expect(result.commitments).toHaveLength(threshold);
      }
    });

    it('should produce commitments independent of totalShares', () => {
      const secret = 666000n;
      const threshold = 3;

      const result1 = split(secret, threshold, 5);
      const result2 = split(secret, threshold, 10);

      // Same threshold and secret should give same public commitment
      expect(result1.publicCommitment.x).toBe(result2.publicCommitment.x);
      expect(result1.publicCommitment.y).toBe(result2.publicCommitment.y);
    });

    it('should use getPublicCommitment helper correctly', () => {
      const result = split(777000n, 2, 4);

      const publicCommitment = getPublicCommitment(result.commitments);

      expect(publicCommitment).toEqual(result.commitments[0]);
      expect(publicCommitment).toEqual(result.publicCommitment);
    });
  });

  // ===========================================================================
  // Combined Shamir+Feldman Flows
  // ===========================================================================

  describe('combined Shamir+Feldman workflows', () => {
    it('should complete full split-verify-combine workflow', () => {
      const secret = 888000n;
      const threshold = 3;
      const totalShares = 7;

      // Split
      const result = split(secret, threshold, totalShares);

      // Verify all shares
      for (const share of result.shares) {
        expect(verify(share, result.commitments).valid).toBe(true);
      }

      // Select threshold shares
      const selectedShares = result.shares.slice(0, threshold);

      // Verify selected shares
      expect(verifyAll(selectedShares, result.commitments)).toBe(true);

      // Combine
      const reconstructed = combine(selectedShares);

      expect(reconstructed).toBe(secret);
    });

    it('should handle workflow with non-consecutive shares', () => {
      const secret = 999000n;
      const result = split(secret, 4, 10);

      // Select non-consecutive shares: 1, 3, 7, 9
      const selectedShares = [
        result.shares[0],
        result.shares[2],
        result.shares[6],
        result.shares[8],
      ];

      // Verify
      expect(verifyAll(selectedShares, result.commitments)).toBe(true);

      // Combine
      expect(combine(selectedShares)).toBe(secret);
    });

    it('should detect and reject tampered shares before combining', () => {
      const secret = 100200n;
      const result = split(secret, 3, 5);

      // Tamper with one share
      const tamperedShares = [
        result.shares[0],
        { ...result.shares[1], y: result.shares[1].y + 10n },
        result.shares[2],
      ];

      // Verification should catch the tampered share
      expect(verify(tamperedShares[0], result.commitments).valid).toBe(true);
      expect(verify(tamperedShares[1], result.commitments).valid).toBe(false);
      expect(verify(tamperedShares[2], result.commitments).valid).toBe(true);

      // If we combine anyway, we get wrong result
      const wrongResult = combine(tamperedShares);
      expect(wrongResult).not.toBe(secret);
    });

    it('should work with threshold = totalShares', () => {
      const secret = 200300n;
      const result = split(secret, 5, 5);

      expect(verifyAll(result.shares, result.commitments)).toBe(true);
      expect(combine(result.shares)).toBe(secret);
    });

    it('should work with threshold = 1', () => {
      const secret = 300400n;
      const result = split(secret, 1, 5);

      // Any single share should work
      for (const share of result.shares) {
        expect(verify(share, result.commitments).valid).toBe(true);
        expect(combine([share])).toBe(secret);
      }
    });
  });

  // ===========================================================================
  // FeldmanVSS Class Tests
  // ===========================================================================

  describe('FeldmanVSS class extended', () => {
    it('should maintain consistent state across operations', () => {
      const vss = new FeldmanVSS();
      const secret1 = 111111n;
      const secret2 = 222222n;

      const result1 = vss.split(secret1, { threshold: 2, totalShares: 4 });
      const result2 = vss.split(secret2, { threshold: 3, totalShares: 5 });

      expect(vss.verifyAll(result1.shares, result1.commitments)).toBe(true);
      expect(vss.verifyAll(result2.shares, result2.commitments)).toBe(true);

      expect(vss.combine(result1.shares.slice(0, 2))).toBe(secret1);
      expect(vss.combine(result2.shares.slice(0, 3))).toBe(secret2);
    });

    it('should use custom prime in class', () => {
      const customPrime = 65537n;
      const vss = new FeldmanVSS({ prime: customPrime });

      expect(vss.getPrime()).toBe(customPrime);

      const secret = 1000n;
      const result = vss.split(secret, {
        threshold: 2,
        totalShares: 3,
        prime: customPrime,
      });

      expect(result.prime).toBe(customPrime);
      expect(vss.combine(result.shares.slice(0, 2))).toBe(secret);
    });

    it('should support all operations through class interface', () => {
      const vss = new FeldmanVSS();
      const secret = 333333n;

      const result = vss.split(secret, { threshold: 3, totalShares: 6 });

      // verify
      expect(vss.verify(result.shares[0], result.commitments).valid).toBe(true);

      // verifyAll
      expect(vss.verifyAll(result.shares, result.commitments)).toBe(true);

      // getPublicCommitment
      const pubCommit = vss.getPublicCommitment(result.commitments);
      expect(pubCommit).toEqual(result.publicCommitment);

      // combine
      expect(vss.combine(result.shares.slice(0, 3))).toBe(secret);
    });
  });

  // ===========================================================================
  // Multiple Threshold Combinations
  // ===========================================================================

  describe('multiple threshold combinations', () => {
    it('should work with 2-of-2', () => {
      const secret = 10001n;
      const result = split(secret, 2, 2);

      expect(verifyAll(result.shares, result.commitments)).toBe(true);
      expect(combine(result.shares)).toBe(secret);
    });

    it('should work with 2-of-10', () => {
      const secret = 20002n;
      const result = split(secret, 2, 10);

      expect(verifyAll(result.shares, result.commitments)).toBe(true);
      expect(combine(result.shares.slice(0, 2))).toBe(secret);
    });

    it('should work with 5-of-5', () => {
      const secret = 30003n;
      const result = split(secret, 5, 5);

      expect(verifyAll(result.shares, result.commitments)).toBe(true);
      expect(combine(result.shares)).toBe(secret);
    });

    it('should work with 7-of-15', () => {
      const secret = 40004n;
      const result = split(secret, 7, 15);

      expect(verifyAll(result.shares, result.commitments)).toBe(true);
      expect(combine(result.shares.slice(0, 7))).toBe(secret);
    });

    it('should work with 10-of-20', () => {
      const secret = 50005n;
      const result = split(secret, 10, 20);

      expect(verifyAll(result.shares, result.commitments)).toBe(true);
      expect(combine(result.shares.slice(0, 10))).toBe(secret);
    });
  });

  // ===========================================================================
  // Verification Error Messages
  // ===========================================================================

  describe('verification error messages', () => {
    it('should provide error message for invalid share', () => {
      const result = split(60006n, 2, 3);

      const badShare: FeldmanShare = {
        ...result.shares[0],
        y: result.shares[0].y + 1n,
      };

      const verification = verify(badShare, result.commitments);

      expect(verification.valid).toBe(false);
      expect(verification.error).toBeDefined();
      expect(verification.error).toContain('verification failed');
    });

    it('should have no error for valid share', () => {
      const result = split(70007n, 2, 3);

      const verification = verify(result.shares[0], result.commitments);

      expect(verification.valid).toBe(true);
      expect(verification.error).toBeUndefined();
    });
  });

  // ===========================================================================
  // Share Properties
  // ===========================================================================

  describe('share properties', () => {
    it('should have correct index field on shares', () => {
      const result = split(80008n, 3, 5);

      expect(result.shares[0].index).toBe(1);
      expect(result.shares[1].index).toBe(2);
      expect(result.shares[2].index).toBe(3);
      expect(result.shares[3].index).toBe(4);
      expect(result.shares[4].index).toBe(5);
    });

    it('should have x values matching indices', () => {
      const result = split(90009n, 3, 5);

      for (let i = 0; i < result.shares.length; i++) {
        expect(result.shares[i].x).toBe(BigInt(i + 1));
        expect(result.shares[i].index).toBe(i + 1);
      }
    });

    it('should have unique y values for all shares', () => {
      const result = split(100010n, 5, 10);

      const yValues = result.shares.map(s => s.y.toString());
      const uniqueYValues = new Set(yValues);

      expect(uniqueYValues.size).toBe(10);
    });
  });

  // ===========================================================================
  // Stress Tests
  // ===========================================================================

  describe('stress tests', () => {
    it('should handle many sequential operations', () => {
      const vss = new FeldmanVSS();

      for (let i = 1; i <= 20; i++) {
        const secret = BigInt(i * 1000);
        const result = vss.split(secret, { threshold: 2, totalShares: 4 });

        expect(vss.verifyAll(result.shares, result.commitments)).toBe(true);
        expect(vss.combine(result.shares.slice(0, 2))).toBe(secret);
      }
    });

    it('should handle large number of shares', () => {
      const secret = 123456789n;
      const result = split(secret, 50, 100);

      expect(result.shares).toHaveLength(100);
      expect(result.commitments).toHaveLength(50);

      // Verify a sample of shares
      for (let i = 0; i < 10; i++) {
        const randomIndex = Math.floor(Math.random() * 100);
        expect(verify(result.shares[randomIndex], result.commitments).valid).toBe(true);
      }

      expect(combine(result.shares.slice(0, 50))).toBe(secret);
    });

    it('should handle multiple verification rounds', () => {
      const result = split(987654321n, 3, 7);

      // Verify each share multiple times
      for (let round = 0; round < 5; round++) {
        for (const share of result.shares) {
          expect(verify(share, result.commitments).valid).toBe(true);
        }
      }
    });
  });
});

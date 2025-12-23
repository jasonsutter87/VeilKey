/**
 * Tests for Feldman Verifiable Secret Sharing
 */

import { describe, it, expect } from 'vitest';
import { split, verify, combine, getPublicCommitment, verifyAll, FeldmanVSS } from './index.js';
import type { FeldmanShare } from './types.js';

describe('Feldman VSS', () => {
  describe('split', () => {
    it('should split a secret into shares with commitments', () => {
      const secret = 12345n;
      const result = split(secret, 3, 5);

      expect(result.shares).toHaveLength(5);
      expect(result.commitments).toHaveLength(3); // threshold commitments
      expect(result.threshold).toBe(3);
      expect(result.publicCommitment).toBeDefined();
      expect(result.publicCommitment).toEqual(result.commitments[0]);
    });

    it('should generate unique shares', () => {
      const secret = 99999n;
      const result = split(secret, 2, 4);

      const yValues = result.shares.map(s => s.y.toString());
      const uniqueYValues = new Set(yValues);
      expect(uniqueYValues.size).toBe(4);
    });

    it('should throw error for invalid threshold', () => {
      expect(() => split(1000n, 0, 5)).toThrow('Threshold must be at least 1');
    });

    it('should throw error when totalShares < threshold', () => {
      expect(() => split(1000n, 5, 3)).toThrow('must be >= threshold');
    });

    it('should throw error for negative secret', () => {
      expect(() => split(-100n, 2, 3)).toThrow('must be in range');
    });
  });

  describe('verify', () => {
    it('should verify valid shares', () => {
      const secret = 42424242n;
      const result = split(secret, 3, 5);

      // All shares should be valid
      for (const share of result.shares) {
        const verification = verify(share, result.commitments);
        expect(verification.valid).toBe(true);
        expect(verification.error).toBeUndefined();
      }
    });

    it('should reject tampered shares (modified y value)', () => {
      const secret = 77777n;
      const result = split(secret, 2, 4);

      // Tamper with a share's y value
      const tamperedShare: FeldmanShare = {
        ...result.shares[0],
        y: result.shares[0].y + 1n,
      };

      const verification = verify(tamperedShare, result.commitments);
      expect(verification.valid).toBe(false);
      expect(verification.error).toBeDefined();
    });

    it('should reject tampered shares (modified x value)', () => {
      const secret = 88888n;
      const result = split(secret, 2, 3);

      // Tamper with a share's x value
      const tamperedShare: FeldmanShare = {
        ...result.shares[0],
        x: result.shares[0].x + 1n,
      };

      const verification = verify(tamperedShare, result.commitments);
      expect(verification.valid).toBe(false);
    });

    it('should verify shares independently', () => {
      const secret = 11111n;
      const result = split(secret, 2, 5);

      // Each share can be verified independently
      const share1Valid = verify(result.shares[0], result.commitments);
      const share3Valid = verify(result.shares[2], result.commitments);
      const share5Valid = verify(result.shares[4], result.commitments);

      expect(share1Valid.valid).toBe(true);
      expect(share3Valid.valid).toBe(true);
      expect(share5Valid.valid).toBe(true);
    });
  });

  describe('combine', () => {
    it('should reconstruct secret from threshold shares', () => {
      const secret = 123456789n;
      const result = split(secret, 3, 5);

      // Use exactly threshold shares
      const shares = result.shares.slice(0, 3);
      const reconstructed = combine(shares);

      expect(reconstructed).toBe(secret);
    });

    it('should reconstruct secret from more than threshold shares', () => {
      const secret = 987654321n;
      const result = split(secret, 2, 5);

      // Use more than threshold shares (4 out of 5)
      const shares = result.shares.slice(0, 4);
      const reconstructed = combine(shares);

      expect(reconstructed).toBe(secret);
    });

    it('should reconstruct secret from any subset of threshold shares', () => {
      const secret = 555555n;
      const result = split(secret, 3, 6);

      // Try different combinations of 3 shares
      const combination1 = [result.shares[0], result.shares[1], result.shares[2]];
      const combination2 = [result.shares[1], result.shares[3], result.shares[5]];
      const combination3 = [result.shares[0], result.shares[2], result.shares[4]];

      expect(combine(combination1)).toBe(secret);
      expect(combine(combination2)).toBe(secret);
      expect(combine(combination3)).toBe(secret);
    });

    it('should work with all shares', () => {
      const secret = 999999n;
      const result = split(secret, 2, 3);

      const reconstructed = combine(result.shares);
      expect(reconstructed).toBe(secret);
    });
  });

  describe('split/verify/combine workflow', () => {
    it('should complete full workflow successfully', () => {
      const secret = 314159265358979n;
      const threshold = 3;
      const totalShares = 5;

      // Step 1: Split the secret
      const result = split(secret, threshold, totalShares);

      // Step 2: Verify all shares
      const allValid = result.shares.every(share =>
        verify(share, result.commitments).valid
      );
      expect(allValid).toBe(true);

      // Step 3: Select threshold shares
      const selectedShares = result.shares.slice(0, threshold);

      // Step 4: Verify selected shares
      for (const share of selectedShares) {
        const verification = verify(share, result.commitments);
        expect(verification.valid).toBe(true);
      }

      // Step 5: Combine to reconstruct
      const reconstructed = combine(selectedShares);
      expect(reconstructed).toBe(secret);
    });

    it('should detect tampered share in workflow', () => {
      const secret = 271828n;
      const result = split(secret, 2, 4);

      // Verify original shares are valid
      expect(verify(result.shares[0], result.commitments).valid).toBe(true);
      expect(verify(result.shares[1], result.commitments).valid).toBe(true);

      // Tamper with one share
      const tamperedShares = [
        result.shares[0],
        { ...result.shares[1], y: result.shares[1].y + 100n },
      ];

      // Verification should fail for tampered share
      expect(verify(tamperedShares[0], result.commitments).valid).toBe(true);
      expect(verify(tamperedShares[1], result.commitments).valid).toBe(false);

      // Combining tampered shares won't reconstruct the correct secret
      const wrongSecret = combine(tamperedShares);
      expect(wrongSecret).not.toBe(secret);
    });
  });

  describe('getPublicCommitment', () => {
    it('should return the first commitment', () => {
      const secret = 123123n;
      const result = split(secret, 2, 3);

      const publicCommitment = getPublicCommitment(result.commitments);

      expect(publicCommitment).toEqual(result.commitments[0]);
      expect(publicCommitment.x).toBeDefined();
      expect(publicCommitment.y).toBeDefined();
    });

    it('should throw error for empty commitments', () => {
      expect(() => getPublicCommitment([])).toThrow('empty');
    });
  });

  describe('verifyAll', () => {
    it('should return true when all shares are valid', () => {
      const secret = 456456n;
      const result = split(secret, 2, 4);

      const allValid = verifyAll(result.shares, result.commitments);
      expect(allValid).toBe(true);
    });

    it('should return false when any share is invalid', () => {
      const secret = 789789n;
      const result = split(secret, 2, 4);

      // Tamper with one share
      const shares = [...result.shares];
      shares[1] = { ...shares[1], y: shares[1].y + 1n };

      const allValid = verifyAll(shares, result.commitments);
      expect(allValid).toBe(false);
    });
  });

  describe('commitment consistency', () => {
    it('should generate consistent commitments for same polynomial', () => {
      const secret = 654321n;
      const result1 = split(secret, 3, 5);
      const result2 = split(secret, 3, 5);

      // Commitments will be different because polynomials are random
      // But they should have the same structure
      expect(result1.commitments).toHaveLength(3);
      expect(result2.commitments).toHaveLength(3);

      // Public commitments (g^secret) should be the same
      expect(result1.publicCommitment.x).toBe(result2.publicCommitment.x);
      expect(result1.publicCommitment.y).toBe(result2.publicCommitment.y);
    });

    it('should have different commitments for different secrets', () => {
      const secret1 = 111n;
      const secret2 = 222n;

      const result1 = split(secret1, 2, 3);
      const result2 = split(secret2, 2, 3);

      // First commitment should be different (g^secret1 vs g^secret2)
      expect(result1.publicCommitment.x).not.toBe(result2.publicCommitment.x);
    });
  });

  describe('FeldmanVSS class', () => {
    it('should work with class interface', () => {
      const vss = new FeldmanVSS();
      const secret = 424242n;

      const result = vss.split(secret, {
        threshold: 3,
        totalShares: 5,
      });

      expect(result.shares).toHaveLength(5);
      expect(result.commitments).toHaveLength(3);

      // Verify using class method
      const share = result.shares[0];
      const verification = vss.verify(share, result.commitments);
      expect(verification.valid).toBe(true);

      // Combine using class method
      const reconstructed = vss.combine(result.shares.slice(0, 3));
      expect(reconstructed).toBe(secret);
    });

    it('should support verifyAll with class interface', () => {
      const vss = new FeldmanVSS();
      const secret = 535353n;

      const result = vss.split(secret, {
        threshold: 2,
        totalShares: 4,
      });

      const allValid = vss.verifyAll(result.shares, result.commitments);
      expect(allValid).toBe(true);
    });

    it('should support getPublicCommitment with class interface', () => {
      const vss = new FeldmanVSS();
      const secret = 646464n;

      const result = vss.split(secret, {
        threshold: 2,
        totalShares: 3,
      });

      const publicCommitment = vss.getPublicCommitment(result.commitments);
      expect(publicCommitment).toEqual(result.commitments[0]);
    });

    it('should allow custom prime field', () => {
      // Use a smaller prime for testing
      const smallPrime = 65537n;
      const vss = new FeldmanVSS({ prime: smallPrime });

      expect(vss.getPrime()).toBe(smallPrime);

      const secret = 1000n;
      const result = vss.split(secret, {
        threshold: 2,
        totalShares: 3,
        prime: smallPrime,
      });

      const reconstructed = vss.combine(result.shares.slice(0, 2));
      expect(reconstructed).toBe(secret);
    });
  });

  describe('edge cases', () => {
    it('should handle threshold of 1', () => {
      const secret = 11n;
      const result = split(secret, 1, 3);

      // Any single share should reconstruct the secret
      expect(combine([result.shares[0]])).toBe(secret);
      expect(combine([result.shares[1]])).toBe(secret);
      expect(combine([result.shares[2]])).toBe(secret);
    });

    it('should handle threshold equal to totalShares', () => {
      const secret = 22n;
      const result = split(secret, 4, 4);

      // Need all shares to reconstruct
      expect(combine(result.shares)).toBe(secret);
    });

    it('should handle large secrets', () => {
      // Use a large secret close to the prime modulus
      const secret = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140n;
      const result = split(secret, 3, 5);

      const reconstructed = combine(result.shares.slice(0, 3));
      expect(reconstructed).toBe(secret);
    });
  });
});

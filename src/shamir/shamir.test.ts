/**
 * Tests for Shamir Secret Sharing
 */

import { describe, it, expect } from 'vitest';
import {
  ShamirSecretSharing,
  split,
  combine,
  generatePolynomial,
  evaluatePolynomial,
  SECP256K1_ORDER,
} from './index.js';
import type { ShareWithIndex } from './types.js';

describe('Shamir Secret Sharing', () => {
  describe('generatePolynomial', () => {
    it('should generate polynomial with secret as constant term', () => {
      const secret = 12345n;
      const degree = 2;
      const coefficients = generatePolynomial(secret, degree);

      expect(coefficients).toHaveLength(degree + 1);
      expect(coefficients[0]).toBe(secret);
    });

    it('should generate different random coefficients each time', () => {
      const secret = 99999n;
      const degree = 3;

      const poly1 = generatePolynomial(secret, degree);
      const poly2 = generatePolynomial(secret, degree);

      // Constant terms should match
      expect(poly1[0]).toBe(poly2[0]);

      // But at least one random coefficient should differ
      const allCoefficientsMatch = poly1.slice(1).every((c, i) => c === poly2[i + 1]);
      expect(allCoefficientsMatch).toBe(false);
    });

    it('should throw on negative degree', () => {
      expect(() => generatePolynomial(123n, -1)).toThrow('degree must be non-negative');
    });

    it('should throw if secret >= prime', () => {
      expect(() => generatePolynomial(SECP256K1_ORDER, 2)).toThrow('Secret must be in range');
    });

    it('should throw if secret is negative', () => {
      expect(() => generatePolynomial(-5n, 2)).toThrow('Secret must be in range');
    });
  });

  describe('evaluatePolynomial', () => {
    it('should evaluate constant polynomial', () => {
      const coefficients = [42n];
      const result = evaluatePolynomial(coefficients, 5n);
      expect(result).toBe(42n);
    });

    it('should evaluate linear polynomial', () => {
      // f(x) = 3 + 2x
      const coefficients = [3n, 2n];

      expect(evaluatePolynomial(coefficients, 0n)).toBe(3n);
      expect(evaluatePolynomial(coefficients, 1n)).toBe(5n);
      expect(evaluatePolynomial(coefficients, 2n)).toBe(7n);
      expect(evaluatePolynomial(coefficients, 10n)).toBe(23n);
    });

    it('should evaluate quadratic polynomial', () => {
      // f(x) = 1 + 2x + 3x^2
      const coefficients = [1n, 2n, 3n];

      // f(0) = 1
      expect(evaluatePolynomial(coefficients, 0n)).toBe(1n);

      // f(1) = 1 + 2 + 3 = 6
      expect(evaluatePolynomial(coefficients, 1n)).toBe(6n);

      // f(2) = 1 + 4 + 12 = 17
      expect(evaluatePolynomial(coefficients, 2n)).toBe(17n);
    });

    it('should work modulo prime', () => {
      const prime = 97n;
      const coefficients = [50n, 60n]; // f(x) = 50 + 60x

      // f(2) = 50 + 120 = 170 ≡ 73 (mod 97)
      const result = evaluatePolynomial(coefficients, 2n, prime);
      expect(result).toBe(73n);
    });

    it('should throw on empty coefficients', () => {
      expect(() => evaluatePolynomial([], 5n)).toThrow('cannot be empty');
    });
  });

  describe('split', () => {
    it('should split secret into correct number of shares', () => {
      const secret = 123456789n;
      const result = split(secret, 3, 5);

      expect(result.shares).toHaveLength(5);
      expect(result.threshold).toBe(3);
      expect(result.prime).toBe(SECP256K1_ORDER);
    });

    it('should create shares with sequential x-coordinates', () => {
      const secret = 999n;
      const result = split(secret, 2, 4);

      expect(result.shares[0].x).toBe(1n);
      expect(result.shares[1].x).toBe(2n);
      expect(result.shares[2].x).toBe(3n);
      expect(result.shares[3].x).toBe(4n);
    });

    it('should create shares with different y-values', () => {
      const secret = 777n;
      const result = split(secret, 2, 5);

      const yValues = new Set(result.shares.map(s => s.y));
      expect(yValues.size).toBe(5); // All unique
    });

    it('should work with threshold = totalShares', () => {
      const secret = 111n;
      const result = split(secret, 3, 3);

      expect(result.shares).toHaveLength(3);
      expect(result.threshold).toBe(3);
    });

    it('should work with threshold = 1', () => {
      const secret = 555n;
      const result = split(secret, 1, 5);

      expect(result.shares).toHaveLength(5);
      expect(result.threshold).toBe(1);
    });

    it('should throw if threshold < 1', () => {
      expect(() => split(123n, 0, 5)).toThrow('Threshold must be at least 1');
    });

    it('should throw if totalShares < threshold', () => {
      expect(() => split(123n, 5, 3)).toThrow('Total shares (3) must be >= threshold (5)');
    });

    it('should throw if secret is negative', () => {
      expect(() => split(-123n, 2, 3)).toThrow('Secret must be non-negative');
    });

    it('should throw if secret >= prime', () => {
      expect(() => split(SECP256K1_ORDER, 2, 3)).toThrow('Secret must be less than prime');
    });

    it('should work with custom prime', () => {
      const secret = 42n;
      const customPrime = 97n;
      const result = split(secret, 2, 3, customPrime);

      expect(result.prime).toBe(customPrime);
      result.shares.forEach(share => {
        expect(share.y).toBeLessThan(customPrime);
      });
    });
  });

  describe('combine', () => {
    it('should reconstruct secret from threshold shares (2-of-3)', () => {
      const secret = 123456789n;
      const { shares } = split(secret, 2, 3);

      // Use first 2 shares
      const reconstructed = combine(shares.slice(0, 2));
      expect(reconstructed).toBe(secret);

      // Use last 2 shares
      const reconstructed2 = combine(shares.slice(1, 3));
      expect(reconstructed2).toBe(secret);

      // Use shares 1 and 3
      const reconstructed3 = combine([shares[0], shares[2]]);
      expect(reconstructed3).toBe(secret);
    });

    it('should reconstruct secret from threshold shares (3-of-5)', () => {
      const secret = 987654321n;
      const { shares } = split(secret, 3, 5);

      // Use first 3 shares
      const reconstructed = combine(shares.slice(0, 3));
      expect(reconstructed).toBe(secret);

      // Use last 3 shares
      const reconstructed2 = combine(shares.slice(2, 5));
      expect(reconstructed2).toBe(secret);

      // Use shares 1, 3, 5
      const reconstructed3 = combine([shares[0], shares[2], shares[4]]);
      expect(reconstructed3).toBe(secret);
    });

    it('should reconstruct from more than threshold shares', () => {
      const secret = 555555n;
      const { shares } = split(secret, 2, 5);

      // Use all 5 shares (more than threshold of 2)
      const reconstructed = combine(shares);
      expect(reconstructed).toBe(secret);
    });

    it('should work with threshold = totalShares', () => {
      const secret = 111111n;
      const { shares } = split(secret, 4, 4);

      const reconstructed = combine(shares);
      expect(reconstructed).toBe(secret);
    });

    it('should work with threshold = 1', () => {
      const secret = 777777n;
      const { shares } = split(secret, 1, 5);

      // Any single share should reconstruct the secret
      expect(combine([shares[0]])).toBe(secret);
      expect(combine([shares[2]])).toBe(secret);
      expect(combine([shares[4]])).toBe(secret);
    });

    it('should work with shares in different order', () => {
      const secret = 333333n;
      const { shares } = split(secret, 3, 5);

      const shuffled = [shares[4], shares[1], shares[2]];
      const reconstructed = combine(shuffled);
      expect(reconstructed).toBe(secret);
    });

    it('should work with large secrets (256-bit)', () => {
      const secret = SECP256K1_ORDER - 1n; // Maximum valid secret
      const { shares } = split(secret, 3, 5);

      const reconstructed = combine(shares.slice(0, 3));
      expect(reconstructed).toBe(secret);
    });

    it('should work with secret = 0', () => {
      const secret = 0n;
      const { shares } = split(secret, 2, 3);

      const reconstructed = combine(shares.slice(0, 2));
      expect(reconstructed).toBe(secret);
    });

    it('should throw on empty shares array', () => {
      expect(() => combine([])).toThrow('At least one share is required');
    });

    it('should throw on duplicate share indices', () => {
      const shares: ShareWithIndex[] = [
        { x: 1n, y: 100n },
        { x: 1n, y: 200n }, // Duplicate x
        { x: 3n, y: 300n },
      ];

      expect(() => combine(shares)).toThrow('Duplicate share indices');
    });

    it('should throw on invalid share structure', () => {
      const invalidShares = [
        { x: 1n, y: 100n },
        { x: 'invalid' as any, y: 200n },
      ];

      expect(() => combine(invalidShares)).toThrow('invalid structure');
    });

    it('should throw on invalid x-coordinate', () => {
      const shares: ShareWithIndex[] = [
        { x: 1n, y: 100n },
        { x: 0n, y: 200n }, // x must be > 0
      ];

      expect(() => combine(shares)).toThrow('invalid x-coordinate');
    });

    it('should work with custom prime', () => {
      const secret = 42n;
      const customPrime = 97n;
      const { shares } = split(secret, 2, 3, customPrime);

      const reconstructed = combine(shares.slice(0, 2), customPrime);
      expect(reconstructed).toBe(secret);
    });
  });

  describe('insufficient shares', () => {
    it('should NOT reconstruct secret with t-1 shares (2-of-3 with 1 share)', () => {
      const secret = 999999n;
      const { shares } = split(secret, 2, 3);

      // With only 1 share, we cannot reconstruct the secret
      const result = combine([shares[0]]);
      expect(result).not.toBe(secret);
    });

    it('should NOT reconstruct secret with t-1 shares (3-of-5 with 2 shares)', () => {
      const secret = 888888n;
      const { shares } = split(secret, 3, 5);

      // With only 2 shares (threshold is 3), we cannot reconstruct
      const result = combine(shares.slice(0, 2));
      expect(result).not.toBe(secret);
    });

    it('should NOT reconstruct secret with t-1 shares (5-of-7 with 4 shares)', () => {
      const secret = 777666n;
      const { shares } = split(secret, 5, 7);

      // With only 4 shares (threshold is 5), we cannot reconstruct
      const result = combine(shares.slice(0, 4));
      expect(result).not.toBe(secret);
    });
  });

  describe('ShamirSecretSharing class', () => {
    it('should create instance with default prime', () => {
      const shamir = new ShamirSecretSharing();
      expect(shamir.getPrime()).toBe(SECP256K1_ORDER);
    });

    it('should create instance with custom prime', () => {
      const customPrime = 97n;
      const shamir = new ShamirSecretSharing({ prime: customPrime });
      expect(shamir.getPrime()).toBe(customPrime);
    });

    it('should split and combine secrets', () => {
      const shamir = new ShamirSecretSharing();
      const secret = 123456789n;

      const result = shamir.split(secret, {
        threshold: 3,
        totalShares: 5,
      });

      expect(result.shares).toHaveLength(5);

      const reconstructed = shamir.combine(result.shares.slice(0, 3));
      expect(reconstructed).toBe(secret);
    });

    it('should allow overriding prime in split', () => {
      const shamir = new ShamirSecretSharing({ prime: 97n });
      const secret = 42n;

      const result = shamir.split(secret, {
        threshold: 2,
        totalShares: 3,
        prime: 101n, // Override the instance prime
      });

      expect(result.prime).toBe(101n);
    });
  });

  describe('edge cases and security', () => {
    it('should handle various secret sizes', () => {
      const secrets = [
        1n,
        255n,
        256n,
        65535n,
        65536n,
        0xFFFFFFFFn,
        0x100000000n,
        SECP256K1_ORDER / 2n,
        SECP256K1_ORDER - 1n,
      ];

      secrets.forEach(secret => {
        const { shares } = split(secret, 3, 5);
        const reconstructed = combine(shares.slice(0, 3));
        expect(reconstructed).toBe(secret);
      });
    });

    it('should generate different shares for same secret', () => {
      const secret = 123456n;

      const result1 = split(secret, 3, 5);
      const result2 = split(secret, 3, 5);

      // Shares should be different (randomized polynomial)
      const shares1Set = new Set(result1.shares.map(s => s.y.toString()));
      const shares2Set = new Set(result2.shares.map(s => s.y.toString()));

      // At least one share should be different
      const allMatch = result1.shares.every((s, i) => s.y === result2.shares[i].y);
      expect(allMatch).toBe(false);
    });

    it('should handle maximum threshold values', () => {
      const secret = 99999n;
      const maxShares = 100;

      const { shares } = split(secret, maxShares, maxShares);
      expect(shares).toHaveLength(maxShares);

      const reconstructed = combine(shares);
      expect(reconstructed).toBe(secret);
    });

    it('should maintain security with many shares (10-of-100)', () => {
      const secret = 555666777n;
      const { shares } = split(secret, 10, 100);

      expect(shares).toHaveLength(100);

      // 10 shares should reconstruct
      const reconstructed = combine(shares.slice(0, 10));
      expect(reconstructed).toBe(secret);

      // 9 shares should not
      const wrong = combine(shares.slice(0, 9));
      expect(wrong).not.toBe(secret);
    });
  });
});

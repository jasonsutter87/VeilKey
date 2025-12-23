/**
 * Extended Tests for Shamir Secret Sharing
 *
 * Comprehensive test suite covering:
 * - Property-based tests for arbitrary (t,n) combinations
 * - Edge cases and boundary conditions
 * - Share tampering and security scenarios
 * - Performance with large secrets and many shares
 * - Field arithmetic edge cases
 * - Reconstruction failures with invalid inputs
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

describe('Shamir Secret Sharing - Extended Tests', () => {
  // ===========================================================================
  // Property-Based Tests: Various (t,n) Combinations
  // ===========================================================================

  describe('property-based: arbitrary (t,n) combinations', () => {
    it('should work with 2-of-2', () => {
      const secret = 12345n;
      const { shares } = split(secret, 2, 2);

      expect(combine(shares)).toBe(secret);
    });

    it('should work with 2-of-4', () => {
      const secret = 98765n;
      const { shares } = split(secret, 2, 4);

      expect(combine(shares.slice(0, 2))).toBe(secret);
      expect(combine([shares[0], shares[2]])).toBe(secret);
      expect(combine([shares[1], shares[3]])).toBe(secret);
    });

    it('should work with 3-of-4', () => {
      const secret = 555555n;
      const { shares } = split(secret, 3, 4);

      expect(combine(shares.slice(0, 3))).toBe(secret);
      expect(combine(shares.slice(1, 4))).toBe(secret);
      expect(combine([shares[0], shares[1], shares[3]])).toBe(secret);
    });

    it('should work with 4-of-5', () => {
      const secret = 777777n;
      const { shares } = split(secret, 4, 5);

      expect(combine(shares.slice(0, 4))).toBe(secret);
      expect(combine(shares.slice(1, 5))).toBe(secret);
      expect(combine([shares[0], shares[1], shares[2], shares[4]])).toBe(secret);
    });

    it('should work with 5-of-7', () => {
      const secret = 999999n;
      const { shares } = split(secret, 5, 7);

      expect(combine(shares.slice(0, 5))).toBe(secret);
      expect(combine(shares.slice(2, 7))).toBe(secret);
      expect(combine([shares[0], shares[2], shares[3], shares[5], shares[6]])).toBe(secret);
    });

    it('should work with 7-of-10', () => {
      const secret = 123456789n;
      const { shares } = split(secret, 7, 10);

      expect(combine(shares.slice(0, 7))).toBe(secret);
      expect(combine(shares.slice(3, 10))).toBe(secret);
    });

    it('should work with 10-of-15', () => {
      const secret = 987654321n;
      const { shares } = split(secret, 10, 15);

      expect(combine(shares.slice(0, 10))).toBe(secret);
      expect(combine(shares.slice(5, 15))).toBe(secret);
    });

    it('should work with 15-of-20', () => {
      const secret = 111222333n;
      const { shares } = split(secret, 15, 20);

      expect(combine(shares.slice(0, 15))).toBe(secret);
      expect(combine(shares.slice(5, 20))).toBe(secret);
    });
  });

  // ===========================================================================
  // Edge Cases: Large n Values
  // ===========================================================================

  describe('edge cases: large n values', () => {
    it('should work with 2-of-20', () => {
      const secret = 424242n;
      const { shares } = split(secret, 2, 20);

      expect(shares).toHaveLength(20);
      expect(combine(shares.slice(0, 2))).toBe(secret);
      expect(combine([shares[5], shares[15]])).toBe(secret);
    });

    it('should work with 5-of-50', () => {
      const secret = 535353n;
      const { shares } = split(secret, 5, 50);

      expect(shares).toHaveLength(50);
      expect(combine(shares.slice(0, 5))).toBe(secret);
      expect(combine(shares.slice(20, 25))).toBe(secret);
    });

    it('should work with 10-of-100', () => {
      const secret = 646464n;
      const { shares } = split(secret, 10, 100);

      expect(shares).toHaveLength(100);
      expect(combine(shares.slice(0, 10))).toBe(secret);
      expect(combine(shares.slice(50, 60))).toBe(secret);
    });
  });

  // ===========================================================================
  // Edge Cases: t = n
  // ===========================================================================

  describe('edge cases: t = n (all shares required)', () => {
    it('should work with 2-of-2', () => {
      const secret = 11111n;
      const { shares } = split(secret, 2, 2);

      expect(combine(shares)).toBe(secret);
    });

    it('should work with 5-of-5', () => {
      const secret = 22222n;
      const { shares } = split(secret, 5, 5);

      expect(combine(shares)).toBe(secret);
    });

    it('should work with 10-of-10', () => {
      const secret = 33333n;
      const { shares } = split(secret, 10, 10);

      expect(combine(shares)).toBe(secret);
    });

    it('should work with 20-of-20', () => {
      const secret = 44444n;
      const { shares } = split(secret, 20, 20);

      expect(combine(shares)).toBe(secret);
    });
  });

  // ===========================================================================
  // Edge Cases: Minimum t = 2
  // ===========================================================================

  describe('edge cases: minimum threshold t = 2', () => {
    it('should work with 2-of-10', () => {
      const secret = 55555n;
      const { shares } = split(secret, 2, 10);

      expect(combine(shares.slice(0, 2))).toBe(secret);
      expect(combine([shares[3], shares[7]])).toBe(secret);
      expect(combine([shares[0], shares[9]])).toBe(secret);
    });

    it('should work with 2-of-50', () => {
      const secret = 66666n;
      const { shares } = split(secret, 2, 50);

      expect(combine(shares.slice(0, 2))).toBe(secret);
      expect(combine([shares[10], shares[40]])).toBe(secret);
    });
  });

  // ===========================================================================
  // Share Tampering Detection
  // ===========================================================================

  describe('share tampering detection', () => {
    it('should produce incorrect result when share y-value is tampered', () => {
      const secret = 123456n;
      const { shares } = split(secret, 3, 5);

      const tamperedShares = [
        shares[0],
        { ...shares[1], y: shares[1].y + 1n },
        shares[2],
      ];

      const result = combine(tamperedShares);
      expect(result).not.toBe(secret);
    });

    it('should produce incorrect result when share x-value is tampered', () => {
      const secret = 654321n;
      const { shares } = split(secret, 3, 5);

      const tamperedShares = [
        shares[0],
        { ...shares[1], x: shares[1].x + 1n },
        shares[2],
      ];

      const result = combine(tamperedShares);
      expect(result).not.toBe(secret);
    });

    it('should produce incorrect result when multiple shares are tampered', () => {
      const secret = 111222n;
      const { shares } = split(secret, 3, 5);

      const tamperedShares = [
        { ...shares[0], y: shares[0].y + 10n },
        { ...shares[1], y: shares[1].y - 5n },
        shares[2],
      ];

      const result = combine(tamperedShares);
      expect(result).not.toBe(secret);
    });

    it('should produce incorrect result when share is replaced with random value', () => {
      const secret = 333444n;
      const { shares } = split(secret, 2, 3);

      const tamperedShares = [
        shares[0],
        { x: shares[1].x, y: 999999999n },
      ];

      const result = combine(tamperedShares);
      expect(result).not.toBe(secret);
    });
  });

  // ===========================================================================
  // Reconstruction with Wrong Shares
  // ===========================================================================

  describe('reconstruction with wrong shares', () => {
    it('should fail with shares from different secrets', () => {
      const secret1 = 111n;
      const secret2 = 222n;

      const { shares: shares1 } = split(secret1, 2, 3);
      const { shares: shares2 } = split(secret2, 2, 3);

      // Mix shares from different secrets
      const mixedShares = [shares1[0], shares2[1]];
      const result = combine(mixedShares);

      expect(result).not.toBe(secret1);
      expect(result).not.toBe(secret2);
    });

    it('should fail with shares from different polynomials of same secret', () => {
      const secret = 555n;

      const { shares: shares1 } = split(secret, 2, 3);
      const { shares: shares2 } = split(secret, 2, 3);

      // Mix shares from different splits (different random polynomials)
      const mixedShares = [shares1[0], shares2[1]];
      const result = combine(mixedShares);

      // Will not reconstruct correctly (different polynomials)
      expect(result).not.toBe(secret);
    });

    it('should detect shares with x=0 (invalid)', () => {
      const invalidShares: ShareWithIndex[] = [
        { x: 0n, y: 100n },
        { x: 1n, y: 200n },
      ];

      expect(() => combine(invalidShares)).toThrow('invalid x-coordinate');
    });

    it('should detect shares with negative x', () => {
      const invalidShares: ShareWithIndex[] = [
        { x: -1n, y: 100n },
        { x: 2n, y: 200n },
      ];

      expect(() => combine(invalidShares)).toThrow('invalid x-coordinate');
    });
  });

  // ===========================================================================
  // Performance with Large Secrets
  // ===========================================================================

  describe('performance: large secrets', () => {
    it('should handle 128-bit secrets', () => {
      const secret = 0xABCDEF0123456789ABCDEF0123456789n;
      const { shares } = split(secret, 3, 5);

      expect(combine(shares.slice(0, 3))).toBe(secret);
    });

    it('should handle 192-bit secrets', () => {
      const secret = 0xABCDEF0123456789ABCDEF0123456789ABCDEF0123456789n;
      const { shares } = split(secret, 3, 5);

      expect(combine(shares.slice(0, 3))).toBe(secret);
    });

    it('should handle 255-bit secrets (near maximum)', () => {
      const secret = SECP256K1_ORDER - 1000n;
      const { shares } = split(secret, 5, 7);

      expect(combine(shares.slice(0, 5))).toBe(secret);
    });

    it('should handle secret at exact maximum (prime - 1)', () => {
      const secret = SECP256K1_ORDER - 1n;
      const { shares } = split(secret, 3, 5);

      expect(combine(shares.slice(0, 3))).toBe(secret);
    });
  });

  // ===========================================================================
  // Field Arithmetic Edge Cases
  // ===========================================================================

  describe('field arithmetic edge cases', () => {
    it('should handle polynomial with zero coefficient (besides constant)', () => {
      const secret = 42n;
      const coefficients = [secret, 0n, 100n]; // f(x) = 42 + 0*x + 100*x^2

      const y1 = evaluatePolynomial(coefficients, 1n);
      const y2 = evaluatePolynomial(coefficients, 2n);
      const y3 = evaluatePolynomial(coefficients, 3n);

      const shares: ShareWithIndex[] = [
        { x: 1n, y: y1 },
        { x: 2n, y: y2 },
        { x: 3n, y: y3 },
      ];

      expect(combine(shares)).toBe(secret);
    });

    it('should handle polynomial with coefficient = 1', () => {
      const secret = 100n;
      const coefficients = [secret, 1n, 1n]; // f(x) = 100 + x + x^2

      const y1 = evaluatePolynomial(coefficients, 1n);
      const y2 = evaluatePolynomial(coefficients, 2n);
      const y3 = evaluatePolynomial(coefficients, 3n);

      const shares: ShareWithIndex[] = [
        { x: 1n, y: y1 },
        { x: 2n, y: y2 },
        { x: 3n, y: y3 },
      ];

      expect(combine(shares)).toBe(secret);
    });

    it('should handle large coefficient values', () => {
      const secret = 999n;
      const largeCoeff = SECP256K1_ORDER / 2n;
      const coefficients = [secret, largeCoeff];

      const y1 = evaluatePolynomial(coefficients, 1n);
      const y2 = evaluatePolynomial(coefficients, 2n);

      const shares: ShareWithIndex[] = [
        { x: 1n, y: y1 },
        { x: 2n, y: y2 },
      ];

      expect(combine(shares)).toBe(secret);
    });

    it('should handle polynomial evaluation at large x values', () => {
      const secret = 12345n;
      const { shares } = split(secret, 2, 100);

      // Use shares with high x-coordinates
      const highShares = [shares[98], shares[99]];
      expect(combine(highShares)).toBe(secret);
    });
  });

  // ===========================================================================
  // Polynomial Edge Cases
  // ===========================================================================

  describe('polynomial generation edge cases', () => {
    it('should generate degree-0 polynomial (threshold=1)', () => {
      const secret = 777n;
      const poly = generatePolynomial(secret, 0);

      expect(poly).toHaveLength(1);
      expect(poly[0]).toBe(secret);
    });

    it('should generate high-degree polynomial', () => {
      const secret = 888n;
      const degree = 50;
      const poly = generatePolynomial(secret, degree);

      expect(poly).toHaveLength(degree + 1);
      expect(poly[0]).toBe(secret);

      // All coefficients should be in valid range
      poly.forEach(coeff => {
        expect(coeff).toBeGreaterThanOrEqual(0n);
        expect(coeff).toBeLessThan(SECP256K1_ORDER);
      });
    });

    it('should produce different polynomials on each call', () => {
      const secret = 999n;
      const degree = 5;

      const poly1 = generatePolynomial(secret, degree);
      const poly2 = generatePolynomial(secret, degree);

      // Constants should match
      expect(poly1[0]).toBe(poly2[0]);

      // At least one random coefficient should differ
      let differenceFound = false;
      for (let i = 1; i < poly1.length; i++) {
        if (poly1[i] !== poly2[i]) {
          differenceFound = true;
          break;
        }
      }
      expect(differenceFound).toBe(true);
    });
  });

  // ===========================================================================
  // Polynomial Evaluation Edge Cases
  // ===========================================================================

  describe('polynomial evaluation edge cases', () => {
    it('should evaluate at x=0 to get constant term', () => {
      const coefficients = [42n, 100n, 200n];
      const result = evaluatePolynomial(coefficients, 0n);

      expect(result).toBe(42n);
    });

    it('should handle very large x values', () => {
      const coefficients = [10n, 20n, 30n];
      const largeX = SECP256K1_ORDER / 2n;

      const result = evaluatePolynomial(coefficients, largeX);

      expect(result).toBeGreaterThanOrEqual(0n);
      expect(result).toBeLessThan(SECP256K1_ORDER);
    });

    it('should handle high-degree polynomial evaluation', () => {
      const coefficients = new Array(51).fill(0n).map((_, i) => BigInt(i + 1));
      const result = evaluatePolynomial(coefficients, 5n);

      expect(result).toBeGreaterThanOrEqual(0n);
      expect(result).toBeLessThan(SECP256K1_ORDER);
    });

    it('should produce consistent results for same inputs', () => {
      const coefficients = [1n, 2n, 3n, 4n, 5n];
      const x = 7n;

      const result1 = evaluatePolynomial(coefficients, x);
      const result2 = evaluatePolynomial(coefficients, x);

      expect(result1).toBe(result2);
    });
  });

  // ===========================================================================
  // Share Ordering and Combinations
  // ===========================================================================

  describe('share ordering and combinations', () => {
    it('should reconstruct with shares in reverse order', () => {
      const secret = 123123n;
      const { shares } = split(secret, 3, 5);

      const reversed = [shares[4], shares[3], shares[2]];
      expect(combine(reversed)).toBe(secret);
    });

    it('should reconstruct with shares in random order', () => {
      const secret = 456456n;
      const { shares } = split(secret, 4, 7);

      const randomOrder = [shares[5], shares[1], shares[3], shares[6]];
      expect(combine(randomOrder)).toBe(secret);
    });

    it('should work with non-consecutive share indices', () => {
      const secret = 789789n;
      const { shares } = split(secret, 3, 10);

      const nonConsecutive = [shares[1], shares[5], shares[8]];
      expect(combine(nonConsecutive)).toBe(secret);
    });

    it('should work with first and last shares only', () => {
      const secret = 111000n;
      const { shares } = split(secret, 2, 10);

      const firstLast = [shares[0], shares[9]];
      expect(combine(firstLast)).toBe(secret);
    });
  });

  // ===========================================================================
  // Custom Prime Field
  // ===========================================================================

  describe('custom prime field', () => {
    it('should work with small prime (97)', () => {
      const prime = 97n;
      const secret = 42n;
      const { shares } = split(secret, 2, 3, prime);

      expect(combine(shares.slice(0, 2), prime)).toBe(secret);
    });

    it('should work with medium prime (65537)', () => {
      const prime = 65537n;
      const secret = 12345n;
      const { shares } = split(secret, 3, 5, prime);

      expect(combine(shares.slice(0, 3), prime)).toBe(secret);
    });

    it('should work with large custom prime', () => {
      const prime = 2n ** 127n - 1n; // Mersenne prime M127
      const secret = 9999999999n;
      const { shares } = split(secret, 2, 4, prime);

      expect(combine(shares.slice(0, 2), prime)).toBe(secret);
    });

    it('should enforce secret < prime with custom prime', () => {
      const prime = 97n;
      const secret = 100n; // > prime

      expect(() => split(secret, 2, 3, prime)).toThrow('less than prime');
    });
  });

  // ===========================================================================
  // ShamirSecretSharing Class Tests
  // ===========================================================================

  describe('ShamirSecretSharing class extended', () => {
    it('should maintain state across multiple operations', () => {
      const shamir = new ShamirSecretSharing();
      const secret1 = 111n;
      const secret2 = 222n;

      const result1 = shamir.split(secret1, { threshold: 2, totalShares: 3 });
      const result2 = shamir.split(secret2, { threshold: 3, totalShares: 5 });

      expect(shamir.combine(result1.shares.slice(0, 2))).toBe(secret1);
      expect(shamir.combine(result2.shares.slice(0, 3))).toBe(secret2);
    });

    it('should work with custom prime in class', () => {
      const prime = 65537n;
      const shamir = new ShamirSecretSharing({ prime });
      const secret = 1000n;

      const result = shamir.split(secret, { threshold: 2, totalShares: 4 });

      expect(result.prime).toBe(prime);
      expect(shamir.combine(result.shares.slice(0, 2))).toBe(secret);
    });

    it('should allow prime override per split', () => {
      const defaultPrime = 97n;
      const shamir = new ShamirSecretSharing({ prime: defaultPrime });

      const overridePrime = 101n;
      const secret = 50n;

      const result = shamir.split(secret, {
        threshold: 2,
        totalShares: 3,
        prime: overridePrime,
      });

      expect(result.prime).toBe(overridePrime);
    });
  });

  // ===========================================================================
  // Validation and Error Handling
  // ===========================================================================

  describe('validation and error handling', () => {
    it('should reject empty share array in combine', () => {
      expect(() => combine([])).toThrow('At least one share is required');
    });

    it('should reject duplicate x-coordinates', () => {
      const shares: ShareWithIndex[] = [
        { x: 1n, y: 100n },
        { x: 1n, y: 200n },
        { x: 2n, y: 300n },
      ];

      expect(() => combine(shares)).toThrow('Duplicate share indices');
    });

    it('should reject malformed shares (missing x)', () => {
      const shares = [
        { x: 1n, y: 100n },
        { y: 200n } as any,
      ];

      expect(() => combine(shares)).toThrow('invalid structure');
    });

    it('should reject malformed shares (missing y)', () => {
      const shares = [
        { x: 1n, y: 100n },
        { x: 2n } as any,
      ];

      expect(() => combine(shares)).toThrow('invalid structure');
    });

    it('should reject malformed shares (wrong types)', () => {
      const shares = [
        { x: 1n, y: 100n },
        { x: '2', y: 200n } as any,
      ];

      expect(() => combine(shares)).toThrow('invalid structure');
    });

    it('should reject threshold > totalShares', () => {
      expect(() => split(100n, 5, 3)).toThrow('must be >= threshold');
    });

    it('should reject threshold = 0', () => {
      expect(() => split(100n, 0, 3)).toThrow('at least 1');
    });

    it('should reject negative threshold', () => {
      expect(() => split(100n, -1, 3)).toThrow('at least 1');
    });

    it('should reject secret >= SECP256K1_ORDER', () => {
      expect(() => split(SECP256K1_ORDER, 2, 3)).toThrow('less than prime');
    });

    it('should reject negative secret', () => {
      expect(() => split(-100n, 2, 3)).toThrow('non-negative');
    });

    it('should reject empty polynomial coefficients', () => {
      expect(() => evaluatePolynomial([], 5n)).toThrow('cannot be empty');
    });
  });

  // ===========================================================================
  // Security Properties
  // ===========================================================================

  describe('security properties', () => {
    it('should produce information-theoretically independent shares', () => {
      const secret = 424242n;
      const { shares } = split(secret, 3, 5);

      // Any 2 shares (less than threshold) reveal nothing about secret
      // We can't reconstruct the secret with t-1 shares
      const insufficient = combine(shares.slice(0, 2));
      expect(insufficient).not.toBe(secret);
    });

    it('should generate cryptographically random polynomials', () => {
      const secret = 535353n;
      const splits = [];

      for (let i = 0; i < 10; i++) {
        splits.push(split(secret, 3, 5));
      }

      // All splits should have different shares (due to random polynomials)
      const firstShareValues = splits.map(s => s.shares[0].y);
      const uniqueValues = new Set(firstShareValues);

      expect(uniqueValues.size).toBe(10);
    });

    it('should have threshold property: t shares work, t-1 do not', () => {
      const secret = 646464n;
      const { shares } = split(secret, 5, 10);

      // 5 shares should work
      expect(combine(shares.slice(0, 5))).toBe(secret);

      // 4 shares should not
      expect(combine(shares.slice(0, 4))).not.toBe(secret);
    });
  });

  // ===========================================================================
  // Stress Tests
  // ===========================================================================

  describe('stress tests', () => {
    it('should handle many sequential splits', () => {
      const secrets = [11n, 22n, 33n, 44n, 55n, 66n, 77n, 88n, 99n, 100n];

      for (const secret of secrets) {
        const { shares } = split(secret, 3, 5);
        expect(combine(shares.slice(0, 3))).toBe(secret);
      }
    });

    it('should handle split with 200 shares', () => {
      const secret = 777888n;
      const { shares } = split(secret, 100, 200);

      expect(shares).toHaveLength(200);
      expect(combine(shares.slice(0, 100))).toBe(secret);
    });

    it('should handle multiple reconstructions of same secret', () => {
      const secret = 999000n;
      const { shares } = split(secret, 3, 10);

      // Try many different combinations
      for (let i = 0; i <= 7; i++) {
        const subset = [shares[i], shares[i + 1], shares[i + 2]];
        expect(combine(subset)).toBe(secret);
      }
    });
  });
});

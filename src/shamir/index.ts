/**
 * Shamir Secret Sharing implementation
 *
 * Implements (t, n) threshold secret sharing where:
 * - A secret is split into n shares
 * - Any t shares can reconstruct the secret
 * - Fewer than t shares reveal no information about the secret
 *
 * Uses the secp256k1 curve order as the prime field by default.
 */

import { mod, modInverse, randomBigInt } from '../utils/mod-arithmetic.js';
import type { ShareWithIndex, ShamirConfig, SplitResult } from './types.js';

/**
 * The prime field modulus - secp256k1 curve order
 * This is a 256-bit prime: 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
 */
export const SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

/**
 * Generate a random polynomial of specified degree with the secret as the constant term.
 *
 * The polynomial is: f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_d*x^d
 * where a_0 = secret and a_1, ..., a_d are random coefficients
 *
 * @param secret - The secret value (constant term a_0)
 * @param degree - The degree of the polynomial (threshold - 1)
 * @param prime - The prime field modulus
 * @returns Array of coefficients [a_0, a_1, ..., a_d]
 */
export function generatePolynomial(
  secret: bigint,
  degree: number,
  prime: bigint = SECP256K1_ORDER
): bigint[] {
  if (degree < 0) {
    throw new Error('Polynomial degree must be non-negative');
  }

  if (secret < 0n || secret >= prime) {
    throw new Error(`Secret must be in range [0, ${prime})`);
  }

  // Coefficient array: [a_0, a_1, ..., a_degree]
  const coefficients: bigint[] = [secret];

  // Generate random coefficients for x, x^2, ..., x^degree
  for (let i = 0; i < degree; i++) {
    coefficients.push(randomBigInt(1n, prime));
  }

  return coefficients;
}

/**
 * Evaluate a polynomial at point x using Horner's method.
 *
 * For polynomial f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n
 * Horner's method computes: f(x) = a_0 + x(a_1 + x(a_2 + ... + x(a_n)))
 *
 * @param coefficients - Polynomial coefficients [a_0, a_1, ..., a_n]
 * @param x - The point at which to evaluate
 * @param prime - The prime field modulus
 * @returns The polynomial value at x (mod prime)
 */
export function evaluatePolynomial(
  coefficients: bigint[],
  x: bigint,
  prime: bigint = SECP256K1_ORDER
): bigint {
  if (coefficients.length === 0) {
    throw new Error('Coefficients array cannot be empty');
  }

  // Horner's method: work backwards through coefficients
  let result = coefficients[coefficients.length - 1]!;

  for (let i = coefficients.length - 2; i >= 0; i--) {
    const coeff = coefficients[i]!;
    result = mod(result * x + coeff, prime);
  }

  return result;
}

/**
 * Split a secret into shares using Shamir Secret Sharing.
 *
 * Creates n shares where any t shares can reconstruct the secret.
 * Shares are indexed from 1 to n (x-coordinates: 1, 2, 3, ..., n).
 *
 * @param secret - The secret to split (must be < prime)
 * @param threshold - Minimum number of shares needed to reconstruct (t)
 * @param totalShares - Total number of shares to create (n)
 * @param prime - The prime field modulus (default: secp256k1 order)
 * @returns Split result containing shares and metadata
 */
export function split(
  secret: bigint,
  threshold: number,
  totalShares: number,
  prime: bigint = SECP256K1_ORDER
): SplitResult {
  // Validation
  if (threshold < 1) {
    throw new Error('Threshold must be at least 1');
  }

  if (totalShares < threshold) {
    throw new Error(`Total shares (${totalShares}) must be >= threshold (${threshold})`);
  }

  if (totalShares < 1) {
    throw new Error('Total shares must be at least 1');
  }

  if (secret < 0n) {
    throw new Error('Secret must be non-negative');
  }

  if (secret >= prime) {
    throw new Error(`Secret must be less than prime field modulus (${prime})`);
  }

  // Generate random polynomial with degree = threshold - 1
  // This ensures we need exactly t shares to reconstruct
  const coefficients = generatePolynomial(secret, threshold - 1, prime);

  // Evaluate polynomial at points 1, 2, 3, ..., n
  const shares: ShareWithIndex[] = [];
  for (let i = 1; i <= totalShares; i++) {
    const x = BigInt(i);
    const y = evaluatePolynomial(coefficients, x, prime);
    shares.push({ x, y });
  }

  return {
    shares,
    threshold,
    prime,
  };
}

/**
 * Reconstruct a secret from shares using Lagrange interpolation.
 *
 * Given t shares (x_i, y_i), computes the constant term of the polynomial
 * that passes through all points. This is the original secret.
 *
 * Uses the formula:
 * f(0) = Σ y_i * L_i(0)
 * where L_i(0) = Π (0 - x_j) / (x_i - x_j) for j ≠ i
 *
 * @param shares - Array of at least t shares
 * @param prime - The prime field modulus (default: secp256k1 order)
 * @returns The reconstructed secret
 */
export function combine(
  shares: ShareWithIndex[],
  prime: bigint = SECP256K1_ORDER
): bigint {
  if (!shares || shares.length === 0) {
    throw new Error('At least one share is required');
  }

  // Verify all shares have valid structure
  for (let i = 0; i < shares.length; i++) {
    const share = shares[i]!;
    if (typeof share.x !== 'bigint' || typeof share.y !== 'bigint') {
      throw new Error(`Share ${i} has invalid structure`);
    }
    if (share.x <= 0n) {
      throw new Error(`Share ${i} has invalid x-coordinate (must be > 0)`);
    }
  }

  // Check for duplicate x-coordinates
  const xValues = new Set(shares.map(s => s.x.toString()));
  if (xValues.size !== shares.length) {
    throw new Error('Duplicate share indices detected');
  }

  // Lagrange interpolation at x = 0
  let secret = 0n;

  for (let i = 0; i < shares.length; i++) {
    const share = shares[i]!;
    const { x: xi, y: yi } = share;

    // Calculate Lagrange basis polynomial L_i(0)
    let numerator = 1n;
    let denominator = 1n;

    for (let j = 0; j < shares.length; j++) {
      if (i === j) continue;

      const otherShare = shares[j]!;
      const { x: xj } = otherShare;

      // L_i(0) = Π (0 - x_j) / (x_i - x_j) for j ≠ i
      // Numerator: (0 - x_j) = -x_j
      numerator = mod(numerator * (-xj), prime);

      // Denominator: (x_i - x_j)
      denominator = mod(denominator * (xi - xj), prime);
    }

    // Compute L_i(0) = numerator / denominator (mod prime)
    const lagrangeCoeff = mod(numerator * modInverse(denominator, prime), prime);

    // Add this term to the sum: y_i * L_i(0)
    secret = mod(secret + yi * lagrangeCoeff, prime);
  }

  return secret;
}

/**
 * Shamir Secret Sharing class with convenient API
 */
export class ShamirSecretSharing {
  private readonly prime: bigint;

  constructor(config?: { prime?: bigint }) {
    this.prime = config?.prime ?? SECP256K1_ORDER;
  }

  /**
   * Split a secret into shares
   */
  split(secret: bigint, config: ShamirConfig): SplitResult {
    const prime = config.prime ?? this.prime;
    return split(secret, config.threshold, config.totalShares, prime);
  }

  /**
   * Combine shares to reconstruct the secret
   */
  combine(shares: ShareWithIndex[]): bigint {
    return combine(shares, this.prime);
  }

  /**
   * Get the prime field being used
   */
  getPrime(): bigint {
    return this.prime;
  }
}

/**
 * Feldman Verifiable Secret Sharing (VSS) Implementation
 *
 * Extends Shamir Secret Sharing with the ability to verify shares without
 * reconstructing the secret. This is achieved by publishing commitments to
 * the polynomial coefficients using elliptic curve cryptography.
 *
 * Based on: Feldman, P. (1987). "A Practical Scheme for Non-interactive
 * Verifiable Secret Sharing."
 *
 * Algorithm:
 * 1. Split: Like Shamir, but also compute commitments C_j = g^{a_j} for each coefficient
 * 2. Verify: Check that g^{share_i} == ∏ C_j^{i^j} for all j
 * 3. Combine: Same as Shamir's reconstruction
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import {
  combine as shamirCombine,
  evaluatePolynomial,
  SECP256K1_ORDER,
} from '../shamir/index.js';
import { mod, randomBigInt } from '../utils/mod-arithmetic.js';
import type {
  FeldmanShare,
  FeldmanCommitments,
  FeldmanConfig,
  FeldmanSplitResult,
  CurvePoint,
  VerificationResult,
} from './types.js';
import type { ShareWithIndex } from '../shamir/types.js';

/**
 * The secp256k1 generator point (G)
 */
const G = secp256k1.ProjectivePoint.BASE;

/**
 * Converts a noble/curves ProjectivePoint to our CurvePoint type
 */
function projectiveToPoint(point: typeof G): CurvePoint {
  const affine = point.toAffine();
  return {
    x: affine.x,
    y: affine.y,
  };
}

/**
 * Converts our CurvePoint type to a noble/curves ProjectivePoint
 */
function pointToProjective(point: CurvePoint): typeof G {
  return secp256k1.ProjectivePoint.fromAffine({
    x: point.x,
    y: point.y,
  });
}

/**
 * Generates commitments to polynomial coefficients
 * For each coefficient a_j, compute C_j = g^{a_j}
 *
 * @param coefficients - Polynomial coefficients [a_0, a_1, ..., a_{t-1}]
 * @returns Array of curve points [g^{a_0}, g^{a_1}, ..., g^{a_{t-1}}]
 */
function generateCommitments(coefficients: bigint[]): FeldmanCommitments {
  const commitments: FeldmanCommitments = [];

  for (const coeff of coefficients) {
    // Compute g^coeff where g is the secp256k1 generator
    const commitment = G.multiply(coeff);
    commitments.push(projectiveToPoint(commitment));
  }

  return commitments;
}

/**
 * Splits a secret into verifiable shares using Feldman VSS
 *
 * @param secret - The secret to split (must be < prime)
 * @param threshold - Minimum number of shares needed to reconstruct (t)
 * @param totalShares - Total number of shares to create (n)
 * @param prime - Prime field modulus (default: secp256k1 order)
 * @returns Shares and commitments for verification
 *
 * @example
 * ```typescript
 * const secret = 12345n;
 * const result = split(secret, 3, 5);
 *
 * // Distribute shares to parties
 * // Anyone can verify a share using the commitments
 * const isValid = verify(result.shares[0], result.commitments);
 * ```
 */
export function split(
  secret: bigint,
  threshold: number,
  totalShares: number,
  prime: bigint = SECP256K1_ORDER
): FeldmanSplitResult {
  // Validation
  if (threshold < 1) {
    throw new Error('Threshold must be at least 1');
  }
  if (totalShares < threshold) {
    throw new Error(`Total shares (${totalShares}) must be >= threshold (${threshold})`);
  }
  if (secret < 0n || secret >= prime) {
    throw new Error(`Secret must be in range [0, ${prime})`);
  }

  // Generate polynomial coefficients: f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
  // where a_0 = secret
  const coefficients: bigint[] = [secret];
  for (let i = 1; i < threshold; i++) {
    coefficients.push(randomBigInt(1n, prime));
  }

  // Generate commitments to coefficients: C_j = g^{a_j}
  const commitments = generateCommitments(coefficients);

  // Generate shares by evaluating polynomial at x = 1, 2, ..., n
  const shares: FeldmanShare[] = [];
  for (let i = 1; i <= totalShares; i++) {
    const x = BigInt(i);
    const y = evaluatePolynomial(coefficients, x, prime);
    shares.push({ x, y, index: i });
  }

  return {
    shares,
    commitments,
    threshold,
    prime,
    publicCommitment: commitments[0], // g^secret is the first commitment
  };
}

/**
 * Verifies that a share is valid using the public commitments
 *
 * Verification equation: g^{share_i} == ∏_{j=0}^{t-1} C_j^{i^j}
 *
 * @param share - The share to verify
 * @param commitments - The public commitments
 * @param prime - Prime field modulus (default: secp256k1 order)
 * @returns Verification result
 *
 * @example
 * ```typescript
 * const result = split(secret, 3, 5);
 * const verification = verify(result.shares[0], result.commitments);
 * console.log(verification.valid); // true
 *
 * // Tampered share will fail
 * const tamperedShare = { ...result.shares[0], y: result.shares[0].y + 1n };
 * const badVerification = verify(tamperedShare, result.commitments);
 * console.log(badVerification.valid); // false
 * ```
 */
export function verify(
  share: FeldmanShare,
  commitments: FeldmanCommitments,
  prime: bigint = SECP256K1_ORDER
): VerificationResult {
  try {
    const { x, y } = share;

    // Left-hand side: g^{share_i.y}
    const lhs = G.multiply(y);

    // Right-hand side: ∏_{j=0}^{t-1} C_j^{i^j}
    // Start with identity point (neutral element)
    let rhs = secp256k1.ProjectivePoint.ZERO;

    // Compute i^j for each j and multiply the commitment
    let xPower = 1n; // i^0 = 1

    for (let j = 0; j < commitments.length; j++) {
      const commitment = pointToProjective(commitments[j]);

      // Add C_j^{i^j} to the product
      // In additive notation: rhs += C_j * (i^j)
      const term = commitment.multiply(xPower);
      rhs = rhs.add(term);

      // Update x^j for next iteration
      xPower = mod(xPower * x, prime);
    }

    // Check if lhs == rhs
    const valid = lhs.equals(rhs);

    return {
      valid,
      error: valid ? undefined : 'Share verification failed: commitment mismatch',
    };
  } catch (error) {
    return {
      valid: false,
      error: `Verification error: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * Combines verified shares to reconstruct the secret
 *
 * This delegates to Shamir's combine function. It's recommended to verify
 * all shares before combining them.
 *
 * @param shares - Array of at least t verified shares
 * @param prime - Prime field modulus (default: secp256k1 order)
 * @returns The reconstructed secret
 *
 * @example
 * ```typescript
 * const result = split(secret, 3, 5);
 *
 * // Verify shares first
 * const validShares = result.shares
 *   .filter(share => verify(share, result.commitments).valid)
 *   .slice(0, 3);
 *
 * // Reconstruct secret
 * const reconstructed = combine(validShares, result.prime);
 * console.log(reconstructed === secret); // true
 * ```
 */
export function combine(
  shares: FeldmanShare[],
  prime: bigint = SECP256K1_ORDER
): bigint {
  // Convert FeldmanShare to ShareWithIndex for Shamir's combine
  const shamirShares: ShareWithIndex[] = shares.map((share) => ({
    x: share.x,
    y: share.y,
  }));

  return shamirCombine(shamirShares, prime);
}

/**
 * Gets the public commitment to the secret (g^secret)
 *
 * This is the first commitment and represents the secret in the exponent.
 * It can be used as a public key if the secret is a private key.
 *
 * @param commitments - The commitments array
 * @returns The public commitment (g^secret)
 */
export function getPublicCommitment(commitments: FeldmanCommitments): CurvePoint {
  if (commitments.length === 0) {
    throw new Error('Commitments array is empty');
  }
  return commitments[0];
}

/**
 * Verifies that all shares in a set are valid
 *
 * @param shares - Shares to verify
 * @param commitments - The public commitments
 * @param prime - Prime field modulus
 * @returns True if all shares are valid
 */
export function verifyAll(
  shares: FeldmanShare[],
  commitments: FeldmanCommitments,
  prime: bigint = SECP256K1_ORDER
): boolean {
  return shares.every((share) => verify(share, commitments, prime).valid);
}

/**
 * Feldman VSS class with convenient API
 */
export class FeldmanVSS {
  private prime: bigint;

  constructor(config?: { prime?: bigint }) {
    this.prime = config?.prime ?? SECP256K1_ORDER;
  }

  /**
   * Split a secret into verifiable shares
   */
  split(secret: bigint, config: FeldmanConfig): FeldmanSplitResult {
    const prime = config.prime ?? this.prime;
    return split(secret, config.threshold, config.totalShares, prime);
  }

  /**
   * Verify a share against commitments
   */
  verify(share: FeldmanShare, commitments: FeldmanCommitments): VerificationResult {
    return verify(share, commitments, this.prime);
  }

  /**
   * Verify all shares
   */
  verifyAll(shares: FeldmanShare[], commitments: FeldmanCommitments): boolean {
    return verifyAll(shares, commitments, this.prime);
  }

  /**
   * Combine verified shares to reconstruct the secret
   */
  combine(shares: FeldmanShare[]): bigint {
    return combine(shares, this.prime);
  }

  /**
   * Get the public commitment (g^secret)
   */
  getPublicCommitment(commitments: FeldmanCommitments): CurvePoint {
    return getPublicCommitment(commitments);
  }

  /**
   * Get the prime field being used
   */
  getPrime(): bigint {
    return this.prime;
  }
}

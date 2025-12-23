/**
 * Types for Feldman Verifiable Secret Sharing (VSS)
 *
 * Feldman VSS extends Shamir Secret Sharing by adding the ability to verify
 * that shares are valid without reconstructing the secret.
 */

/**
 * A point on the elliptic curve (secp256k1)
 * Represented by (x, y) coordinates
 */
export interface CurvePoint {
  /** X-coordinate of the point */
  x: bigint;
  /** Y-coordinate of the point */
  y: bigint;
}

/**
 * Commitments to polynomial coefficients
 * For polynomial f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
 * commitments[j] = g^{a_j} where g is the generator point
 */
export type FeldmanCommitments = CurvePoint[];

/**
 * A Feldman share includes the Shamir share plus commitments for verification
 */
export interface FeldmanShare {
  /** The x-coordinate (share index) */
  x: bigint;
  /** The y-coordinate (share value) */
  y: bigint;
  /** Index of this share (1 to n) */
  index: number;
}

/**
 * Configuration for Feldman VSS
 */
export interface FeldmanConfig {
  /** Minimum number of shares required for reconstruction (threshold) */
  threshold: number;
  /** Total number of shares to generate */
  totalShares: number;
  /** Prime field modulus (default: secp256k1 order) */
  prime?: bigint;
}

/**
 * Result of splitting a secret using Feldman VSS
 */
export interface FeldmanSplitResult {
  /** The generated shares with their indices */
  shares: FeldmanShare[];
  /** Commitments to the polynomial coefficients (for verification) */
  commitments: FeldmanCommitments;
  /** The threshold required for reconstruction */
  threshold: number;
  /** The prime field modulus used */
  prime: bigint;
  /** The public commitment to the secret (g^secret) - first commitment */
  publicCommitment: CurvePoint;
}

/**
 * Share verification result
 */
export interface VerificationResult {
  /** Whether the share is valid */
  valid: boolean;
  /** Error message if verification failed */
  error?: string;
}

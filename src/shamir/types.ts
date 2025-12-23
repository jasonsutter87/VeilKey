/**
 * Types for Shamir Secret Sharing
 */

/**
 * A secret share value (y-coordinate)
 */
export interface Share {
  value: bigint;
}

/**
 * A secret share with its index (x-coordinate)
 */
export interface ShareWithIndex {
  /** The x-coordinate (share index, typically 1-indexed) */
  x: bigint;
  /** The y-coordinate (share value) */
  y: bigint;
}

/**
 * Configuration for Shamir Secret Sharing
 */
export interface ShamirConfig {
  /** Minimum number of shares required for reconstruction (threshold) */
  threshold: number;
  /** Total number of shares to generate */
  totalShares: number;
  /** Prime field modulus (default: secp256k1 order) */
  prime?: bigint;
}

/**
 * Result of splitting a secret
 */
export interface SplitResult {
  /** The generated shares with their indices */
  shares: ShareWithIndex[];
  /** The threshold required for reconstruction */
  threshold: number;
  /** The prime field modulus used */
  prime: bigint;
}

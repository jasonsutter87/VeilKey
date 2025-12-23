/**
 * Threshold BLS Type Definitions
 *
 * Types for BLS12-381 threshold signature scheme supporting:
 * - Threshold signing (non-interactive, aggregatable)
 * - Signature aggregation
 * - Batch verification
 *
 * BLS12-381 provides ~128-bit security with very compact signatures
 * and efficient aggregation - ideal for TVS voter signature verification.
 */

// =============================================================================
// Configuration
// =============================================================================

/**
 * Configuration for threshold BLS key generation
 */
export interface ThresholdBLSConfig {
  /** Minimum number of shares needed to sign (t) */
  threshold: number;

  /** Total number of shares to generate (n) */
  totalShares: number;

  /**
   * Signature mode:
   * - 'short': 48-byte signatures (G1), 96-byte public keys (G2) - DEFAULT
   * - 'long': 96-byte signatures (G2), 48-byte public keys (G1)
   */
  mode?: 'short' | 'long';
}

// =============================================================================
// Key Material
// =============================================================================

/**
 * A point on the BLS12-381 curve
 * Can be in G1 (48 bytes compressed) or G2 (96 bytes compressed)
 */
export interface BLSPoint {
  /** Hex-encoded compressed point */
  value: string;
  /** Which group: G1 or G2 */
  group: 'G1' | 'G2';
}

/**
 * A single BLS share held by a party/trustee
 *
 * Each share is a point on a polynomial in the scalar field Fr.
 * The share alone reveals nothing about the secret key.
 */
export interface BLSShare {
  /** Share index (1-based: 1, 2, ..., n) */
  index: number;

  /** Secret share value (scalar in Fr field) */
  value: bigint;

  /** Public verification key for this share: G^(share_value) */
  verificationKey: BLSPoint;
}

/**
 * Complete threshold BLS keypair
 *
 * The public key is used to verify aggregated signatures.
 * The shares are distributed to trustees - each trustee gets one.
 */
export interface ThresholdBLSKeyPair {
  /** Combined public key: G^secret (in G1 for short mode, G2 for long mode) */
  publicKey: BLSPoint;

  /** Secret shares distributed to parties */
  shares: BLSShare[];

  /** Verification keys for each share (for share verification) */
  verificationKeys: BLSPoint[];

  /** Configuration used to generate this keypair */
  config: ThresholdBLSConfig;
}

// =============================================================================
// Partial Operations
// =============================================================================

/**
 * Partial signature from a single party
 *
 * Created by computing H(m) * share_i where H(m) is hash-to-curve.
 * Multiple partials are combined using Lagrange interpolation.
 */
export interface PartialBLSSignature {
  /** Index of the party who created this partial */
  index: number;

  /** Partial signature point (in G2 for short mode, G1 for long mode) */
  value: BLSPoint;
}

// =============================================================================
// Complete Signatures
// =============================================================================

/**
 * Complete BLS signature (from threshold combination or single signer)
 */
export interface BLSSignature {
  /** Signature point (in G2 for short mode, G1 for long mode) */
  signature: BLSPoint;

  /** Indices of parties who contributed (for threshold sigs) */
  participantIndices?: number[];
}

/**
 * Aggregated BLS signature (multiple signers on same message)
 */
export interface AggregatedBLSSignature {
  /** Aggregated signature point */
  signature: BLSPoint;

  /** Number of signatures aggregated */
  count: number;
}

// =============================================================================
// Verification
// =============================================================================

/**
 * Result of signature verification
 */
export interface BLSVerificationResult {
  /** Whether the signature is valid */
  valid: boolean;

  /** Error message if verification failed */
  error?: string;
}

/**
 * Input for batch verification
 */
export interface BatchVerificationItem {
  /** Message that was signed (raw bytes) */
  message: Uint8Array;

  /** Signature to verify */
  signature: BLSPoint;

  /** Public key used for verification */
  publicKey: BLSPoint;
}

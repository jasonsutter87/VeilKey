/**
 * Threshold ECDSA Type Definitions (GG20 Protocol)
 *
 * Types for threshold ECDSA signature scheme supporting:
 * - Threshold signing (t-of-n parties must cooperate)
 * - Multiple curves (secp256k1, P-256)
 * - Presignature generation for fast signing
 *
 * Based on: Gennaro & Goldfeder "Fast Multiparty Threshold ECDSA" (2020)
 * https://eprint.iacr.org/2020/540
 *
 * Security: Provides ~128-bit security with secp256k1 or P-256.
 * Applications: Bitcoin, Ethereum, general-purpose digital signatures.
 */

// =============================================================================
// Configuration
// =============================================================================

/**
 * Supported elliptic curves
 * - secp256k1: Bitcoin, Ethereum (256-bit, ~128-bit security)
 * - P-256: NIST P-256 / secp256r1 (256-bit, ~128-bit security)
 */
export type ECDSACurve = 'secp256k1' | 'P-256';

/**
 * Configuration for threshold ECDSA key generation
 */
export interface ThresholdECDSAConfig {
  /** Elliptic curve to use */
  curve: ECDSACurve;

  /** Minimum number of shares needed to sign (t) */
  threshold: number;

  /** Total number of shares to generate (n) */
  totalShares: number;
}

// =============================================================================
// Key Material
// =============================================================================

/**
 * A point on the elliptic curve
 * Compressed format: 33 bytes (0x02/0x03 prefix + x-coordinate)
 */
export interface ECDSAPoint {
  /** Hex-encoded compressed point (33 bytes) */
  value: string;

  /** Curve this point belongs to */
  curve: ECDSACurve;
}

/**
 * A single ECDSA share held by a party
 *
 * Each share is a point on a polynomial in the scalar field.
 * The share alone reveals nothing about the private key.
 */
export interface ECDSAShare {
  /** Share index (1-based: 1, 2, ..., n) */
  index: number;

  /** Secret share value (scalar in field) */
  value: bigint;

  /** Public verification key for this share: G * share_value */
  verificationKey: ECDSAPoint;
}

/**
 * Complete threshold ECDSA keypair
 *
 * The public key is used to verify signatures.
 * The shares are distributed to parties - each party gets one.
 */
export interface ThresholdECDSAKeyPair {
  /** Combined public key: G * privateKey */
  publicKey: ECDSAPoint;

  /** Secret shares distributed to parties */
  shares: ECDSAShare[];

  /** Verification keys for each share (for share verification) */
  verificationKeys: ECDSAPoint[];

  /** Configuration used to generate this keypair */
  config: ThresholdECDSAConfig;
}

// =============================================================================
// Presignature (for GG20 optimization)
// =============================================================================

/**
 * Presignature data generated before knowing the message
 *
 * In GG20, parties can precompute most of the signing protocol
 * before the message is known, making actual signing very fast.
 *
 * For simplicity in Phase 2.1, we use a trusted dealer model
 * and skip the full interactive presignature generation.
 */
export interface ECDSAPresignature {
  /** Random nonce k (kept secret) */
  k: bigint;

  /** Inverse of k (mod order) */
  kInv: bigint;

  /** R point = k * G */
  R: ECDSAPoint;

  /** r value (x-coordinate of R) */
  r: bigint;

  /** Indices of parties involved */
  participantIndices: number[];

  /** Curve this presignature is for */
  curve: ECDSACurve;
}

// =============================================================================
// Partial Operations
// =============================================================================

/**
 * Partial signature from a single party
 *
 * Created during the signing protocol by each party.
 * Multiple partials are combined using Lagrange interpolation.
 */
export interface PartialECDSASignature {
  /** Index of the party who created this partial */
  index: number;

  /** Partial signature value */
  value: bigint;
}

// =============================================================================
// Complete Signatures
// =============================================================================

/**
 * Complete ECDSA signature (r, s)
 *
 * Standard format compatible with Bitcoin, Ethereum, etc.
 */
export interface ECDSASignature {
  /** r component (x-coordinate of R = k*G) */
  r: bigint;

  /** s component */
  s: bigint;

  /** Recovery ID (0-3), optional but useful for public key recovery */
  recoveryId?: number;

  /** Indices of parties who contributed (for threshold sigs) */
  participantIndices?: number[];
}

// =============================================================================
// Verification
// =============================================================================

/**
 * Result of signature verification
 */
export interface ECDSAVerificationResult {
  /** Whether the signature is valid */
  valid: boolean;

  /** Error message if verification failed */
  error?: string;
}

/**
 * Batch verification item
 */
export interface BatchVerificationItem {
  /** Message that was signed (raw bytes) */
  message: Uint8Array;

  /** Signature to verify */
  signature: ECDSASignature;

  /** Public key used for verification */
  publicKey: ECDSAPoint;
}

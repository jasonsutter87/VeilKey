/**
 * Threshold RSA Type Definitions
 *
 * Types for Shoup's practical threshold RSA scheme supporting:
 * - Threshold signing (for VeilSign)
 * - Threshold decryption (for TVS vote tallying)
 */

// =============================================================================
// Configuration
// =============================================================================

/**
 * Configuration for threshold RSA key generation
 */
export interface ThresholdRSAConfig {
  /** RSA key size in bits (minimum 2048 for security) */
  bits: number;

  /** Minimum number of shares needed to sign/decrypt (t) */
  threshold: number;

  /** Total number of shares to generate (n) */
  totalShares: number;
}

// =============================================================================
// Key Material
// =============================================================================

/**
 * A single RSA share held by a trustee/party
 *
 * Each share is a fragment of the private exponent d.
 * The share alone reveals nothing about d or any other share.
 */
export interface RSAShare {
  /** Share index (1-based: 1, 2, ..., n) */
  index: number;

  /** Secret share value (d_i, a point on the polynomial) */
  value: bigint;

  /** Verification key for this share: v^(Δ * d_i) mod n */
  verificationKey: bigint;
}

/**
 * Complete threshold RSA keypair
 *
 * The public key (n, e) is public and used for encryption/verification.
 * The shares are distributed to trustees - each trustee gets one.
 */
export interface ThresholdRSAKeyPair {
  /** RSA modulus: n = p * q */
  n: bigint;

  /** Public exponent: typically 65537 */
  e: bigint;

  /** Secret shares of private exponent d */
  shares: RSAShare[];

  /** Base for verification keys (random quadratic residue mod n) */
  verificationBase: bigint;

  /** Δ = totalShares! (factorial, for Lagrange coefficient integrality) */
  delta: bigint;

  /** Configuration used to generate this keypair */
  config: ThresholdRSAConfig;
}

// =============================================================================
// Partial Operations
// =============================================================================

/**
 * Partial signature from a single party
 *
 * Created by computing H(m)^(2 * Δ * d_i) mod n
 * Multiple partials are combined to form a complete signature.
 */
export interface PartialSignature {
  /** Index of the party who created this partial */
  index: number;

  /** Partial signature value */
  value: bigint;
}

/**
 * Partial decryption from a single trustee
 *
 * Created by computing c^(2 * Δ * d_i) mod n
 * Multiple partials are combined to recover the plaintext.
 */
export interface PartialDecryption {
  /** Index of the trustee who created this partial */
  index: number;

  /** Partial decryption value */
  value: bigint;
}

// =============================================================================
// Verification (Phase 2: Zero-Knowledge Proofs)
// =============================================================================

/**
 * Zero-knowledge proof of correct partial computation
 *
 * Proves that a partial signature/decryption was computed correctly
 * without revealing the share value.
 *
 * Note: Full implementation in Phase 2
 */
export interface PartialProof {
  /** Challenge value (hash of commitment) */
  c: bigint;

  /** Response value */
  z: bigint;
}

/**
 * Partial operation with attached proof
 */
export interface VerifiedPartial {
  /** The partial (signature or decryption) */
  partial: PartialSignature | PartialDecryption;

  /** Zero-knowledge proof of correctness */
  proof: PartialProof;
}

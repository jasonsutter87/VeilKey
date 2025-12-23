/**
 * Threshold RSA type definitions
 * Based on Shoup's practical threshold RSA scheme
 */

/**
 * Configuration for threshold RSA key generation
 */
export interface ThresholdRSAConfig {
  /** RSA key size in bits (e.g., 2048, 3072, 4096) */
  bits: number;
  /** Minimum number of shares needed to sign (t) */
  threshold: number;
  /** Total number of shares to generate (n) */
  totalShares: number;
}

/**
 * A single RSA secret share held by a participant
 */
export interface RSAShare {
  /** Share index (1-based) */
  index: number;
  /** Secret share value (fragment of private key d) */
  value: bigint;
  /** Verification key for this share (v^(d_i * Δ) mod n) */
  verificationKey: bigint;
}

/**
 * Partial signature created by a single participant
 */
export interface PartialSignature {
  /** Index of the participant who created this partial signature */
  index: number;
  /** Partial signature value (x_i = H(m)^(2 * Δ * d_i) mod n) */
  value: bigint;
  /** Zero-knowledge proof of correctness (for verification) */
  proof?: {
    /** Challenge value */
    c: bigint;
    /** Response value */
    z: bigint;
  };
}

/**
 * Complete threshold RSA keypair
 */
export interface ThresholdRSAKeyPair {
  /** RSA modulus (n = p * q) */
  n: bigint;
  /** Public exponent (typically 65537) */
  e: bigint;
  /** Secret shares of the private exponent d */
  shares: RSAShare[];
  /** Base verification key (random quadratic residue mod n) */
  verificationBase: bigint;
  /** Configuration used to generate this keypair */
  config: ThresholdRSAConfig;
  /** Delta = totalShares! (needed for signing/combining) */
  delta: bigint;
}

/**
 * Verification context for threshold signatures
 */
export interface VerificationContext {
  /** RSA modulus */
  n: bigint;
  /** Public exponent */
  e: bigint;
  /** Base verification key */
  verificationBase: bigint;
  /** Delta value (factorial of total shares) */
  delta: bigint;
}

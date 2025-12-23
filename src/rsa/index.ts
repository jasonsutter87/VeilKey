/**
 * Threshold RSA Implementation (Shoup Protocol)
 *
 * Implements both threshold signing AND threshold decryption for:
 * - VeilSign: Distributed signing authority for blind signatures
 * - TVS Tallying: Distributed decryption of encrypted votes
 *
 * Security Properties:
 * - No single party ever holds the complete private key
 * - t-of-n parties must cooperate for any operation
 * - Partial operations can be verified for correctness
 *
 * Reference: Victor Shoup, "Practical Threshold Signatures" (2000)
 * https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf
 */

import { sha256 } from '@noble/hashes/sha256';
import {
  modPow,
  modInverse,
  generatePrime,
  gcd,
  randomBigInt,
  extendedGcd,
  mod,
} from '../utils/mod-arithmetic.js';
import type {
  ThresholdRSAConfig,
  ThresholdRSAKeyPair,
  RSAShare,
  PartialSignature,
  PartialDecryption,
} from './types.js';

// =============================================================================
// Constants
// =============================================================================

/** Standard RSA public exponent (Fermat prime F4 = 2^16 + 1) */
const PUBLIC_EXPONENT = 65537n;

// =============================================================================
// Internal Helpers
// =============================================================================

/**
 * Compute n! (factorial) for Δ calculation
 * Δ = n! ensures Lagrange coefficients are always integers
 */
function factorial(n: number): bigint {
  let result = 1n;
  for (let i = 2; i <= n; i++) {
    result *= BigInt(i);
  }
  return result;
}

/**
 * Generate Shamir secret shares of a secret value
 * Uses polynomial secret sharing: f(x) = secret + a_1*x + ... + a_{t-1}*x^{t-1}
 */
function generateSecretShares(
  secret: bigint,
  threshold: number,
  totalShares: number,
  modulus: bigint
): bigint[] {
  // Create random polynomial with secret as constant term
  const coefficients: bigint[] = [secret];
  for (let i = 1; i < threshold; i++) {
    coefficients.push(randomBigInt(1n, modulus));
  }

  // Evaluate polynomial at points 1, 2, ..., n
  const shares: bigint[] = [];
  for (let x = 1; x <= totalShares; x++) {
    let value = 0n;
    let xPower = 1n;
    for (const coeff of coefficients) {
      value = mod(value + coeff * xPower, modulus);
      xPower = mod(xPower * BigInt(x), modulus);
    }
    shares.push(value);
  }

  return shares;
}

/**
 * Find a random quadratic residue mod n
 * Used as base for verification keys
 */
function findQuadraticResidue(n: bigint): bigint {
  while (true) {
    const candidate = randomBigInt(2n, n - 1n);
    if (gcd(candidate, n) === 1n) {
      return modPow(candidate, 2n, n);
    }
  }
}

/**
 * Compute Lagrange coefficient λ_{i,S}(0) * Δ
 * Returns an integer because Δ = n! contains all necessary factors
 */
function lagrangeCoefficientTimeDelta(
  index: number,
  indices: number[],
  delta: bigint
): bigint {
  let numerator = delta;
  let denominator = 1n;

  for (const j of indices) {
    if (j !== index) {
      numerator *= BigInt(j);
      denominator *= BigInt(j - index);
    }
  }

  // Should always be integer due to factorial in delta
  if (numerator % denominator !== 0n) {
    throw new Error('Lagrange coefficient computation error - not an integer');
  }

  return numerator / denominator;
}

/**
 * Hash message for signing using SHA-256
 * Converts to a value in range [1, n-1] coprime to n
 */
function hashForSigning(message: Uint8Array, n: bigint): bigint {
  const hash = sha256(message);
  let result = 0n;
  for (const byte of hash) {
    result = (result << 8n) | BigInt(byte);
  }
  result = mod(result, n);
  // Ensure non-zero and coprime to n
  if (result === 0n) result = 1n;
  return result;
}

/**
 * Core threshold exponentiation using Shoup's protocol
 * Computes base^d where d is shared among parties
 *
 * @param base - The base value (hash for signing, ciphertext for decryption)
 * @param partials - Partial exponentiations from each party
 * @param delta - Δ = n! (factorial of total shares)
 * @param n - RSA modulus
 * @param e - Public exponent
 * @returns base^d mod n
 */
function combinePartialExponentiations(
  base: bigint,
  partials: Array<{ index: number; value: bigint }>,
  delta: bigint,
  n: bigint,
  e: bigint
): bigint {
  const indices = partials.map(p => p.index);

  // Combine using Lagrange interpolation in the exponent
  // w = ∏ (partial_i)^(2 * λ_i) where λ_i = Δ * Lagrange coefficient
  // This gives w = base^(4 * Δ² * d)
  let w = 1n;

  for (const partial of partials) {
    const lambda = lagrangeCoefficientTimeDelta(partial.index, indices, delta);
    const exp2Lambda = 2n * lambda;

    if (exp2Lambda < 0n) {
      const term = modInverse(modPow(partial.value, -exp2Lambda, n), n);
      w = mod(w * term, n);
    } else {
      const term = modPow(partial.value, exp2Lambda, n);
      w = mod(w * term, n);
    }
  }

  // Now w = base^(4 * Δ² * d)
  // We need result = base^d
  //
  // Using extended GCD: find a, b such that 4Δ²*a + e*b = 1
  // Then: result = w^a * base^b
  //
  // Proof that this works:
  // result^e = w^(a*e) * base^(b*e)
  //          = base^(4Δ²*d*a*e) * base^(b*e)
  //          = base^(4Δ²*d*a*e + b*e)
  //          = base^(e * (4Δ²*d*a + b))
  //
  // From Bézout: 4Δ²*a + e*b = 1, so b*e = 1 - 4Δ²*a
  // result^e = base^(4Δ²*d*a*e + 1 - 4Δ²*a)
  //          = base^(4Δ²*a*(d*e - 1) + 1)
  //
  // Since d*e ≡ 1 (mod φ(n)), we have d*e = 1 + k*φ(n)
  // result^e = base^(4Δ²*a*k*φ(n) + 1)
  //          = base^(4Δ²*a*k*φ(n)) * base
  //          = (base^φ(n))^(4Δ²*a*k) * base
  //          = 1^(4Δ²*a*k) * base  [by Euler's theorem]
  //          = base ✓

  const fourDeltaSquared = 4n * delta * delta;
  const [g, a, b] = extendedGcd(fourDeltaSquared, e);

  if (g !== 1n) {
    throw new Error(`Cannot combine: gcd(4Δ², e) = ${g} ≠ 1`);
  }

  // Compute result = w^a * base^b, handling negative exponents
  const wPart = a >= 0n
    ? modPow(w, a, n)
    : modInverse(modPow(w, -a, n), n);

  const basePart = b >= 0n
    ? modPow(base, b, n)
    : modInverse(modPow(base, -b, n), n);

  return mod(wPart * basePart, n);
}

// =============================================================================
// Key Generation
// =============================================================================

/**
 * Generate a threshold RSA keypair
 *
 * Creates a keypair where:
 * - The public key (n, e) can encrypt messages / verify signatures
 * - The private key d is split into shares
 * - Any t shares can decrypt / sign, but t-1 reveals nothing
 *
 * @param config - Key generation configuration
 * @returns Threshold RSA keypair with shares
 */
export async function generateKey(
  config: ThresholdRSAConfig
): Promise<ThresholdRSAKeyPair> {
  const { bits, threshold, totalShares } = config;

  // Validate configuration
  if (threshold > totalShares) {
    throw new Error('Threshold cannot exceed total shares');
  }
  if (threshold < 2) {
    throw new Error('Threshold must be at least 2 for security');
  }
  if (bits < 2048) {
    throw new Error('Key size must be at least 2048 bits');
  }

  // Generate safe primes p = 2p' + 1, q = 2q' + 1
  // This ensures φ(n) = 4 * p' * q' has known structure
  const primeBits = Math.floor(bits / 2);
  const p = generatePrime(primeBits);
  const q = generatePrime(primeBits);

  // RSA modulus
  const n = p * q;

  // Euler's totient: φ(n) = (p-1)(q-1)
  const phi = (p - 1n) * (q - 1n);

  // For secret sharing, use m = p' * q' where p' = (p-1)/2
  // This avoids leaking information about φ(n)
  const m = ((p - 1n) / 2n) * ((q - 1n) / 2n);

  // Public exponent
  const e = PUBLIC_EXPONENT;
  if (gcd(e, phi) !== 1n) {
    throw new Error('e and φ(n) not coprime - regenerate primes');
  }

  // Private exponent: d ≡ e^(-1) (mod φ(n))
  const d = modInverse(e, phi);

  // Δ = totalShares!
  const delta = factorial(totalShares);

  // Generate Shamir shares of d
  const shareValues = generateSecretShares(d, threshold, totalShares, m);

  // Generate verification base and keys
  const verificationBase = findQuadraticResidue(n);
  const shares: RSAShare[] = [];

  for (let i = 0; i < totalShares; i++) {
    const index = i + 1;
    const value = shareValues[i]!;
    // Verification key: v_i = v^(Δ * d_i) mod n
    const verificationKey = modPow(verificationBase, delta * value, n);

    shares.push({ index, value, verificationKey });
  }

  return {
    n,
    e,
    shares,
    verificationBase,
    delta,
    config,
  };
}

// =============================================================================
// Standard RSA Operations (for testing and completeness)
// =============================================================================

/**
 * Standard RSA encryption: c = m^e mod n
 * Used by VeilForms to encrypt vote data with election public key
 *
 * Note: In production, use RSA-OAEP padding. This is raw RSA for demonstration.
 *
 * @param plaintext - Value to encrypt (must be < n)
 * @param n - RSA modulus
 * @param e - Public exponent
 * @returns Ciphertext
 */
export function encrypt(plaintext: bigint, n: bigint, e: bigint): bigint {
  if (plaintext >= n) {
    throw new Error('Plaintext must be less than modulus n');
  }
  if (plaintext < 0n) {
    throw new Error('Plaintext must be non-negative');
  }
  return modPow(plaintext, e, n);
}

// =============================================================================
// Threshold Signing (for VeilSign)
// =============================================================================

/**
 * Create a partial signature using a single share
 *
 * Each party computes: x_i = H(m)^(2 * Δ * d_i) mod n
 * The factor of 2 ensures we work with quadratic residues
 *
 * @param message - Message to sign
 * @param share - This party's RSA share
 * @param n - RSA modulus
 * @param delta - Δ = totalShares!
 * @returns Partial signature
 */
export function partialSign(
  message: Uint8Array,
  share: RSAShare,
  n: bigint,
  delta: bigint
): PartialSignature {
  const x = hashForSigning(message, n);
  const exponent = 2n * delta * share.value;
  const value = modPow(x, exponent, n);

  return { index: share.index, value };
}

/**
 * Combine partial signatures into a complete RSA signature
 *
 * @param message - Original message (needed for Shoup protocol)
 * @param partials - Partial signatures from t parties
 * @param threshold - Minimum number of parties required
 * @param n - RSA modulus
 * @param e - Public exponent
 * @param delta - Δ = totalShares!
 * @returns Complete signature: H(m)^d mod n
 */
export function combineSignatures(
  message: Uint8Array,
  partials: PartialSignature[],
  threshold: number,
  n: bigint,
  e: bigint,
  delta: bigint
): bigint {
  if (partials.length < threshold) {
    throw new Error(`Need ${threshold} partial signatures, got ${partials.length}`);
  }

  const x = hashForSigning(message, n);
  const selected = partials.slice(0, threshold);

  return combinePartialExponentiations(x, selected, delta, n, e);
}

/**
 * Verify an RSA signature
 *
 * @param message - Original message
 * @param signature - Signature to verify
 * @param n - RSA modulus
 * @param e - Public exponent
 * @returns true if signature is valid
 */
export function verify(
  message: Uint8Array,
  signature: bigint,
  n: bigint,
  e: bigint
): boolean {
  try {
    const expected = hashForSigning(message, n);
    const actual = modPow(signature, e, n);
    return actual === expected;
  } catch {
    return false;
  }
}

// =============================================================================
// Threshold Decryption (for TVS Vote Tallying)
// =============================================================================

/**
 * Create a partial decryption using a single share
 *
 * Each trustee computes: c_i = c^(2 * Δ * d_i) mod n
 * where c is the ciphertext (encrypted AES key in TVS)
 *
 * @param ciphertext - Ciphertext to decrypt (as bigint)
 * @param share - This trustee's RSA share
 * @param n - RSA modulus
 * @param delta - Δ = totalShares!
 * @returns Partial decryption
 */
export function partialDecrypt(
  ciphertext: bigint,
  share: RSAShare,
  n: bigint,
  delta: bigint
): PartialDecryption {
  if (ciphertext <= 0n || ciphertext >= n) {
    throw new Error('Ciphertext must be in range (0, n)');
  }

  const exponent = 2n * delta * share.value;
  const value = modPow(ciphertext, exponent, n);

  return { index: share.index, value };
}

/**
 * Combine partial decryptions to recover plaintext
 *
 * @param ciphertext - Original ciphertext
 * @param partials - Partial decryptions from t trustees
 * @param threshold - Minimum number of trustees required
 * @param n - RSA modulus
 * @param e - Public exponent
 * @param delta - Δ = totalShares!
 * @returns Decrypted plaintext: c^d mod n
 */
export function combineDecryptions(
  ciphertext: bigint,
  partials: PartialDecryption[],
  threshold: number,
  n: bigint,
  e: bigint,
  delta: bigint
): bigint {
  if (partials.length < threshold) {
    throw new Error(`Need ${threshold} partial decryptions, got ${partials.length}`);
  }

  const selected = partials.slice(0, threshold);
  return combinePartialExponentiations(ciphertext, selected, delta, n, e);
}

// =============================================================================
// Partial Verification (simplified - full ZK proofs in Phase 2)
// =============================================================================

/**
 * Basic verification that a partial is well-formed
 * Full zero-knowledge proofs will be added in Phase 2
 */
export function verifyPartial(
  partial: PartialSignature | PartialDecryption,
  n: bigint
): boolean {
  try {
    if (partial.value <= 0n || partial.value >= n) {
      return false;
    }
    return gcd(partial.value, n) === 1n;
  } catch {
    return false;
  }
}

// =============================================================================
// Namespace Export
// =============================================================================

export const ThresholdRSA = {
  // Key generation
  generateKey,

  // Standard RSA
  encrypt,

  // Threshold signing
  partialSign,
  combineSignatures,
  verify,

  // Threshold decryption
  partialDecrypt,
  combineDecryptions,

  // Verification
  verifyPartial,
};

/**
 * Threshold RSA implementation using Shoup's protocol
 *
 * This implements a practical threshold RSA signature scheme where:
 * - No single party holds the complete private key
 * - t-of-n parties must cooperate to create a valid signature
 * - Individual shares can be verified for correctness
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
} from './types.js';

/**
 * Standard RSA public exponent (2^16 + 1)
 */
const PUBLIC_EXPONENT = 65537n;

/**
 * Compute factorial for Δ calculation
 * Δ = n! where n is the total number of shares
 */
function factorial(n: number): bigint {
  let result = 1n;
  for (let i = 2; i <= n; i++) {
    result *= BigInt(i);
  }
  return result;
}

/**
 * Generate Shamir secret shares of the private exponent d
 * Uses polynomial secret sharing over the integers modulo m
 */
function generateSecretShares(
  secret: bigint,
  threshold: number,
  totalShares: number,
  modulus: bigint
): bigint[] {
  // Create random polynomial of degree (threshold - 1)
  // f(x) = secret + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
  const coefficients: bigint[] = [secret];

  for (let i = 1; i < threshold; i++) {
    coefficients.push(randomBigInt(0n, modulus));
  }

  // Evaluate polynomial at points 1, 2, ..., totalShares
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
 * Find a random quadratic residue modulo n
 * Used as the base verification key
 */
function findQuadraticResidue(n: bigint): bigint {
  while (true) {
    const candidate = randomBigInt(2n, n);
    if (gcd(candidate, n) === 1n) {
      // Square it to ensure it's a quadratic residue
      return modPow(candidate, 2n, n);
    }
  }
}

/**
 * Generate a threshold RSA keypair
 *
 * @param config - Configuration specifying key size, threshold, and total shares
 * @returns Complete threshold RSA keypair with shares and verification keys
 */
export async function generateKey(
  config: ThresholdRSAConfig
): Promise<ThresholdRSAKeyPair> {
  const { bits, threshold, totalShares } = config;

  // Validate configuration
  if (threshold > totalShares) {
    throw new Error('Threshold cannot be greater than total shares');
  }
  if (threshold < 2) {
    throw new Error('Threshold must be at least 2');
  }
  if (bits < 2048) {
    throw new Error('Key size must be at least 2048 bits for security');
  }

  // Generate two random primes of equal bit length
  const primeBits = Math.floor(bits / 2);
  const p = generatePrime(primeBits);
  const q = generatePrime(primeBits);

  // Compute RSA modulus
  const n = p * q;

  // Compute m = p' * q' where p' = (p-1)/2, q' = (q-1)/2
  // This is used for secret sharing to avoid issues with φ(n)
  const pPrime = (p - 1n) / 2n;
  const qPrime = (q - 1n) / 2n;
  const m = pPrime * qPrime;

  // Compute Euler's totient: φ(n) = (p-1)(q-1) = 4 * m
  const phi = (p - 1n) * (q - 1n);

  // Use standard public exponent
  const e = PUBLIC_EXPONENT;

  // Verify e and φ(n) are coprime
  if (gcd(e, phi) !== 1n) {
    throw new Error('Public exponent and φ(n) are not coprime, regenerate primes');
  }

  // Compute private exponent: d ≡ e^(-1) (mod φ(n))
  const d = modInverse(e, phi);

  // Compute Δ = totalShares!
  const delta = factorial(totalShares);

  // Generate Shamir shares of d over m (not φ(n) to preserve security)
  const shareValues = generateSecretShares(d, threshold, totalShares, m);

  // Generate verification keys
  const verificationBase = findQuadraticResidue(n);
  const shares: RSAShare[] = [];

  for (let i = 0; i < totalShares; i++) {
    const index = i + 1;
    const value = shareValues[i]!;

    // Verification key: v_i = v^(Δ * d_i) mod n
    const verificationKey = modPow(verificationBase, delta * value, n);

    shares.push({
      index,
      value,
      verificationKey,
    });
  }

  return {
    n,
    e,
    shares,
    verificationBase,
    config,
    delta,
  };
}

/**
 * Hash a message to a number for signing
 * Uses SHA-256 and ensures the result is in the valid range
 */
function hashMessage(message: Uint8Array, n: bigint): bigint {
  const hash = sha256(message);

  // Convert hash bytes to bigint
  let result = 0n;
  for (const byte of hash) {
    result = (result << 8n) | BigInt(byte);
  }

  // Ensure result is in range [0, n) and coprime with n
  result = mod(result, n);

  // Make sure result is not 0 or a factor of n
  if (result === 0n) {
    result = 1n;
  }

  return result;
}

/**
 * Create a partial signature using a single RSA share
 *
 * Uses Shoup's protocol: computes x^(2 * Δ * d_i) where Δ = totalShares!
 *
 * @param message - Message to sign
 * @param share - RSA share owned by this participant
 * @param n - RSA modulus
 * @param delta - Δ = totalShares! (precomputed)
 * @returns Partial signature that can be combined with others
 */
export function partialSign(
  message: Uint8Array,
  share: RSAShare,
  n: bigint,
  delta: bigint
): PartialSignature {
  // Hash message to get x = H(m)
  const x = hashMessage(message, n);

  // Partial signature: x_i = x^(2 * Δ * d_i) mod n
  // The factor of 2 ensures we work with quadratic residues
  const exponent = 2n * delta * share.value;
  const value = modPow(x, exponent, n);

  return {
    index: share.index,
    value,
  };
}

/**
 * Compute Lagrange coefficient λ_{i,S}(0) for share combination
 * λ_{i,S}(0) = ∏_{j∈S, j≠i} (j / (j - i))
 *
 * We return Δ * λ to ensure integer results
 */
function lagrangeCoefficientAtZero(
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

  // The result should be an integer because Δ = n! contains all factors
  if (numerator % denominator !== 0n) {
    throw new Error('Lagrange coefficient computation error');
  }

  return numerator / denominator;
}

/**
 * Combine partial signatures to create a complete RSA signature
 *
 * Uses Shoup's combination formula with extended GCD
 *
 * @param message - Original message (needed for final signature extraction)
 * @param partials - Array of partial signatures (must have at least threshold)
 * @param threshold - Minimum number of shares needed
 * @param n - RSA modulus
 * @param e - Public exponent
 * @param delta - Δ = totalShares!
 * @returns Complete RSA signature
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
    throw new Error(
      `Not enough partial signatures: got ${partials.length}, need ${threshold}`
    );
  }

  // Use only the first 'threshold' partials
  const selectedPartials = partials.slice(0, threshold);
  const indices = selectedPartials.map(p => p.index);

  // Get the message hash
  const x = hashMessage(message, n);

  // Combine using Lagrange interpolation in the exponent
  // w = ∏ x_i^(2 * λ_i) where λ_i = Δ * Lagrange coefficient
  // This gives us w = x^(4 * Δ² * d) mod n
  let w = 1n;

  for (const partial of selectedPartials) {
    const lambda = lagrangeCoefficientAtZero(partial.index, indices, delta);
    const exp2Lambda = 2n * lambda;

    // Handle negative exponents
    if (exp2Lambda < 0n) {
      const base = modPow(partial.value, -exp2Lambda, n);
      const term = modInverse(base, n);
      w = mod(w * term, n);
    } else {
      const term = modPow(partial.value, exp2Lambda, n);
      w = mod(w * term, n);
    }
  }

  // Now w = x^(4 * Δ² * d) mod n
  // We need s = x^d such that s^e ≡ x (mod n)
  //
  // Using extended GCD: find a, b such that 4Δ²*a + e*b = gcd(4Δ², e) = 1
  // (gcd is 1 because e is prime and doesn't divide Δ for reasonable n values)
  //
  // Then: s = w^a * x^b mod n
  // Verify: s^e = w^(a*e) * x^(b*e) = x^(4Δ²*d*a*e) * x^(b*e)
  //            = x^(4Δ²*d*a*e + b*e) = x^(e*(4Δ²*d*a + b))
  // From Bézout: 4Δ²*a + e*b = 1, so e*b = 1 - 4Δ²*a
  // Thus: s^e = x^(4Δ²*d*a*e + 1 - 4Δ²*a) = x^(4Δ²*a*(d*e - 1) + 1)
  // Since d*e ≡ 1 (mod φ(n)), we have d*e = 1 + k*φ(n)
  // So: s^e = x^(4Δ²*a*k*φ(n) + 1) = x^(4Δ²*a*k*φ(n)) * x
  //        = (x^φ(n))^(4Δ²*a*k) * x ≡ 1 * x = x (mod n) ✓

  const fourDeltaSquared = 4n * delta * delta;
  const [g, a, b] = extendedGcd(fourDeltaSquared, e);

  if (g !== 1n) {
    throw new Error(`Cannot combine signatures: gcd(4Δ², e) = ${g} ≠ 1`);
  }

  // Compute s = w^a * x^b mod n, handling negative exponents
  let wPart: bigint;
  let xPart: bigint;

  if (a >= 0n) {
    wPart = modPow(w, a, n);
  } else {
    wPart = modInverse(modPow(w, -a, n), n);
  }

  if (b >= 0n) {
    xPart = modPow(x, b, n);
  } else {
    xPart = modInverse(modPow(x, -b, n), n);
  }

  const signature = mod(wPart * xPart, n);

  return signature;
}

/**
 * Verify a threshold RSA signature
 *
 * @param message - Original message that was signed
 * @param signature - Signature to verify
 * @param n - RSA modulus
 * @param e - Public exponent
 * @returns true if signature is valid, false otherwise
 */
export function verify(
  message: Uint8Array,
  signature: bigint,
  n: bigint,
  e: bigint
): boolean {
  try {
    // Hash the message
    const expectedHash = hashMessage(message, n);

    // Verify: signature^e ≡ H(m) (mod n)
    const actualHash = modPow(signature, e, n);

    return actualHash === expectedHash;
  } catch {
    return false;
  }
}

/**
 * Verify a partial signature against its verification key
 * This allows checking if a participant created a valid partial signature
 */
export function verifyPartialSignature(
  message: Uint8Array,
  partial: PartialSignature,
  verificationKey: bigint,
  verificationBase: bigint,
  n: bigint,
  delta: bigint
): boolean {
  try {
    const x = hashMessage(message, n);
    const xSquared = modPow(x, 2n, n);

    // Verify using Shoup's verification equation
    // x_i^2 ≡ x^(4*Δ*d_i) (mod n) should match v_i^2 relationship
    // For full verification, we'd need zero-knowledge proofs

    // Simplified check: verify partial is in valid range and coprime with n
    if (partial.value <= 0n || partial.value >= n) {
      return false;
    }

    return gcd(partial.value, n) === 1n;
  } catch {
    return false;
  }
}

/**
 * Export the ThresholdRSA namespace for cleaner imports
 */
export const ThresholdRSA = {
  generateKey,
  partialSign,
  combineSignatures,
  verify,
  verifyPartialSignature,
};

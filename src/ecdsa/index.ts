/**
 * Threshold ECDSA Implementation (GG20 Protocol - Simplified)
 *
 * Implements threshold ECDSA signatures with:
 * - Distributed key generation (trusted dealer model for Phase 2.1)
 * - Threshold signing (t-of-n parties must cooperate)
 * - Standard ECDSA verification
 * - Support for secp256k1 and P-256 curves
 *
 * Security Properties:
 * - No single party ever holds the complete private key
 * - t-of-n parties must cooperate for signing
 * - Signatures are standard ECDSA, compatible with Bitcoin/Ethereum
 *
 * Note: This is a simplified trusted-dealer version for Phase 2.1.
 * Full interactive DKG and presignature generation will be added in Phase 3.
 *
 * Reference: Gennaro & Goldfeder "Fast Multiparty Threshold ECDSA" (2020)
 * https://eprint.iacr.org/2020/540
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { mod, randomBigInt } from '../utils/mod-arithmetic.js';
import type {
  ThresholdECDSAConfig,
  ThresholdECDSAKeyPair,
  ECDSAShare,
  ECDSAPoint,
  ECDSAPresignature,
  PartialECDSASignature,
  ECDSASignature,
  ECDSAVerificationResult,
  ECDSACurve,
  BatchVerificationItem,
} from './types.js';

// =============================================================================
// Curve Abstraction
// =============================================================================

/** Type for a noble/curves curve object */
type CurveType = typeof secp256k1 | typeof p256;

/**
 * Get the appropriate curve implementation
 */
function getCurve(curveName: ECDSACurve): CurveType {
  switch (curveName) {
    case 'secp256k1':
      return secp256k1;
    case 'P-256':
      return p256;
    default:
      throw new Error(`Unsupported curve: ${curveName}`);
  }
}

/**
 * Get the curve order (n) for a given curve
 */
function getCurveOrder(curveName: ECDSACurve): bigint {
  const curve = getCurve(curveName);
  return curve.CURVE.n;
}

// =============================================================================
// Internal Helpers
// =============================================================================

/**
 * Generate random polynomial coefficients for Shamir secret sharing
 * Returns coefficients [a_0, a_1, ..., a_{t-1}] where a_0 = secret
 */
function generatePolynomial(secret: bigint, threshold: number, order: bigint): bigint[] {
  const coefficients: bigint[] = [secret];
  for (let i = 1; i < threshold; i++) {
    coefficients.push(randomBigInt(1n, order));
  }
  return coefficients;
}

/**
 * Evaluate polynomial at point x using Horner's method
 * f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
 */
function evaluatePolynomial(coefficients: bigint[], x: bigint, order: bigint): bigint {
  let result = 0n;
  for (let i = coefficients.length - 1; i >= 0; i--) {
    result = mod(result * x + coefficients[i]!, order);
  }
  return result;
}

/**
 * Compute Lagrange coefficient λ_i(0) for index i given set of indices S
 * λ_i(0) = Π_{j∈S, j≠i} (j / (j - i))
 */
function lagrangeCoefficient(index: number, indices: number[], order: bigint): bigint {
  let numerator = 1n;
  let denominator = 1n;

  for (const j of indices) {
    if (j !== index) {
      numerator = mod(numerator * BigInt(j), order);
      denominator = mod(denominator * BigInt(j - index), order);
    }
  }

  // Compute modular inverse of denominator
  const denominatorInv = modInverse(denominator, order);
  return mod(numerator * denominatorInv, order);
}

/**
 * Modular inverse using Fermat's little theorem
 * a^(-1) = a^(p-2) mod p (when p is prime)
 */
function modInverse(a: bigint, p: bigint): bigint {
  return modPow(a, p - 2n, p);
}

/**
 * Modular exponentiation
 */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % mod;
    }
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Hash message to scalar in field for signing
 * Uses SHA-256 and reduces modulo curve order
 */
function hashToScalar(message: Uint8Array, order: bigint): bigint {
  const hash = sha256(message);
  let scalar = 0n;
  for (const byte of hash) {
    scalar = (scalar << 8n) | BigInt(byte);
  }
  return mod(scalar, order);
}

/**
 * Point to ECDSAPoint type
 */
function pointToECDSAPoint(point: any, curveName: ECDSACurve): ECDSAPoint {
  const compressed = point.toRawBytes(true); // compressed format
  return {
    value: bytesToHex(compressed),
    curve: curveName,
  };
}

/**
 * ECDSAPoint to curve point
 */
function ecdsaPointToPoint(ecdsaPoint: ECDSAPoint, curve: CurveType): any {
  const bytes = hexToBytes(ecdsaPoint.value);
  return curve.ProjectivePoint.fromHex(bytes);
}

// =============================================================================
// Key Generation
// =============================================================================

/**
 * Generate a threshold ECDSA keypair
 *
 * Creates a keypair where:
 * - The public key can verify signatures
 * - The private key is split into shares using Shamir secret sharing
 * - Any t shares can create a valid signature, but t-1 reveals nothing
 *
 * Note: Uses trusted dealer model. Full interactive DKG in Phase 3.
 *
 * @param config - Key generation configuration
 * @returns Threshold ECDSA keypair with shares
 */
export async function generateKey(
  config: ThresholdECDSAConfig
): Promise<ThresholdECDSAKeyPair> {
  const { curve: curveName, threshold, totalShares } = config;

  // Validate configuration
  if (threshold > totalShares) {
    throw new Error('Threshold cannot exceed total shares');
  }
  if (threshold < 2) {
    throw new Error('Threshold must be at least 2 for security');
  }
  if (totalShares < 2) {
    throw new Error('Total shares must be at least 2');
  }

  const curve = getCurve(curveName);
  const order = curve.CURVE.n;

  // Generate random private key
  const privateKeyBytes = curve.utils.randomPrivateKey();
  let privateKey = 0n;
  for (const byte of privateKeyBytes) {
    privateKey = (privateKey << 8n) | BigInt(byte);
  }
  privateKey = mod(privateKey, order);

  // Generate polynomial for Shamir secret sharing
  const polynomial = generatePolynomial(privateKey, threshold, order);

  // Generate shares by evaluating polynomial at points 1, 2, ..., n
  const shares: ECDSAShare[] = [];
  const verificationKeys: ECDSAPoint[] = [];

  for (let i = 1; i <= totalShares; i++) {
    const shareValue = evaluatePolynomial(polynomial, BigInt(i), order);

    // Compute verification key: G * share_value
    const vkPoint = curve.ProjectivePoint.BASE.multiply(shareValue);
    const verificationKey = pointToECDSAPoint(vkPoint, curveName);

    shares.push({
      index: i,
      value: shareValue,
      verificationKey,
    });

    verificationKeys.push(verificationKey);
  }

  // Compute combined public key: G * privateKey
  const pkPoint = curve.ProjectivePoint.BASE.multiply(privateKey);
  const publicKey = pointToECDSAPoint(pkPoint, curveName);

  return {
    publicKey,
    shares,
    verificationKeys,
    config,
  };
}

// =============================================================================
// Share Verification
// =============================================================================

/**
 * Verify that a share is valid against its verification key
 *
 * Checks that: G * share_value == verification_key
 *
 * @param share - Share to verify
 * @returns true if share is valid
 */
export function verifyShare(share: ECDSAShare): boolean {
  try {
    const curve = getCurve(share.verificationKey.curve);

    // Compute expected verification key
    const computedPoint = curve.ProjectivePoint.BASE.multiply(share.value);
    const computedBytes = computedPoint.toRawBytes(true);
    const computedHex = bytesToHex(computedBytes);

    // Compare with stored verification key
    return computedHex === share.verificationKey.value;
  } catch {
    return false;
  }
}

/**
 * Verify all shares in a keypair
 *
 * @param keypair - Keypair to verify
 * @returns true if all shares are valid
 */
export function verifyAllShares(keypair: ThresholdECDSAKeyPair): boolean {
  return keypair.shares.every(share => verifyShare(share));
}

// =============================================================================
// Presignature Generation (Simplified)
// =============================================================================

/**
 * Generate a presignature for threshold ECDSA
 *
 * In full GG20, this would be an interactive protocol.
 * For Phase 2.1, we use a trusted dealer to generate presignatures.
 *
 * A presignature contains:
 * - Random nonce k and its inverse
 * - R point (k * G)
 * - r value (x-coordinate of R)
 *
 * @param curveName - Curve to use
 * @param participantIndices - Indices of parties who will use this presignature
 * @returns Presignature data
 */
export function generatePresignature(
  curveName: ECDSACurve,
  participantIndices: number[]
): ECDSAPresignature {
  const curve = getCurve(curveName);
  const order = curve.CURVE.n;

  // Generate random nonce k
  const kBytes = curve.utils.randomPrivateKey();
  let k = 0n;
  for (const byte of kBytes) {
    k = (k << 8n) | BigInt(byte);
  }
  k = mod(k, order);

  // Compute k inverse
  const kInv = modInverse(k, order);

  // Compute R = k * G
  const RPoint = curve.ProjectivePoint.BASE.multiply(k);
  const R = pointToECDSAPoint(RPoint, curveName);

  // Get r (x-coordinate of R, mod order)
  const RAffine = RPoint.toAffine();
  const r = mod(RAffine.x, order);

  return {
    k,
    kInv,
    R,
    r,
    participantIndices,
    curve: curveName,
  };
}

// =============================================================================
// Threshold Signing
// =============================================================================

/**
 * Create a partial signature using a single share
 *
 * In ECDSA, signature is (r, s) where:
 * - r = x-coordinate of R = k*G
 * - s = k^(-1) * (H(m) + r * privateKey)
 *
 * For threshold: s_i = k^(-1) * H(m) + k^(-1) * r * share_i
 * Then combine: s = Σ (s_i * λ_i)
 *
 * @param message - Message to sign (raw bytes)
 * @param share - This party's ECDSA share
 * @param presignature - Presignature data
 * @returns Partial signature
 */
export function partialSign(
  message: Uint8Array,
  share: ECDSAShare,
  presignature: ECDSAPresignature
): PartialECDSASignature {
  const order = getCurveOrder(presignature.curve);

  // Hash message to scalar
  const h = hashToScalar(message, order);

  // Compute partial: s_i = k^(-1) * h + k^(-1) * r * share_i
  //                     = k^(-1) * (h + r * share_i)
  const kInv = presignature.kInv;
  const r = presignature.r;

  const rTimesShare = mod(r * share.value, order);
  const hPlusRShare = mod(h + rTimesShare, order);
  const partialValue = mod(kInv * hPlusRShare, order);

  return {
    index: share.index,
    value: partialValue,
  };
}

/**
 * Combine partial signatures into a complete ECDSA signature
 *
 * Uses Lagrange interpolation to reconstruct s:
 * s = Σ (s_i * λ_i) where λ_i are Lagrange coefficients
 *
 * @param partials - Partial signatures from t parties
 * @param threshold - Minimum number of parties required
 * @param presignature - Presignature used for signing
 * @returns Complete ECDSA signature (r, s)
 */
export function combineSignatures(
  partials: PartialECDSASignature[],
  threshold: number,
  presignature: ECDSAPresignature
): ECDSASignature {
  if (partials.length < threshold) {
    throw new Error(`Need ${threshold} partial signatures, got ${partials.length}`);
  }

  const order = getCurveOrder(presignature.curve);

  // Use only threshold number of partials
  const selected = partials.slice(0, threshold);
  const indices = selected.map(p => p.index);

  // Combine using Lagrange interpolation
  // s = Σ (s_i * λ_i(0))
  let s = 0n;

  for (const partial of selected) {
    const lambda = lagrangeCoefficient(partial.index, indices, order);
    const term = mod(partial.value * lambda, order);
    s = mod(s + term, order);
  }

  // Ensure s is in lower half (normalize for malleability)
  const halfOrder = order >> 1n;
  if (s > halfOrder) {
    s = order - s;
  }

  return {
    r: presignature.r,
    s,
    participantIndices: indices,
  };
}

// =============================================================================
// Signature Verification
// =============================================================================

/**
 * Verify an ECDSA signature
 *
 * Standard ECDSA verification:
 * 1. Verify r, s in [1, n-1]
 * 2. Compute w = s^(-1) mod n
 * 3. Compute u1 = H(m) * w mod n
 * 4. Compute u2 = r * w mod n
 * 5. Compute R' = u1*G + u2*pubKey
 * 6. Verify r == x-coordinate of R'
 *
 * @param message - Original message
 * @param signature - Signature to verify
 * @param publicKey - Public key
 * @returns Verification result
 */
export function verify(
  message: Uint8Array,
  signature: ECDSASignature,
  publicKey: ECDSAPoint
): ECDSAVerificationResult {
  try {
    const curve = getCurve(publicKey.curve);
    const order = curve.CURVE.n;

    const { r, s } = signature;

    // 1. Verify r, s in [1, n-1]
    if (r <= 0n || r >= order || s <= 0n || s >= order) {
      return { valid: false, error: 'r or s out of range' };
    }

    // 2. Compute w = s^(-1) mod n
    const w = modInverse(s, order);

    // 3. Compute u1 = H(m) * w mod n
    const h = hashToScalar(message, order);
    const u1 = mod(h * w, order);

    // 4. Compute u2 = r * w mod n
    const u2 = mod(r * w, order);

    // 5. Compute R' = u1*G + u2*pubKey
    const G = curve.ProjectivePoint.BASE;
    const pubKeyPoint = ecdsaPointToPoint(publicKey, curve);

    const point1 = G.multiply(u1);
    const point2 = pubKeyPoint.multiply(u2);
    const RPrime = point1.add(point2);

    // Check if point is at infinity
    if (RPrime.equals(curve.ProjectivePoint.ZERO)) {
      return { valid: false, error: 'R\' is point at infinity' };
    }

    // 6. Verify r == x-coordinate of R'
    const RPrimeAffine = RPrime.toAffine();
    const rPrime = mod(RPrimeAffine.x, order);

    const valid = r === rPrime;

    return { valid };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Unknown verification error',
    };
  }
}

/**
 * Verify a partial signature (simplified - full verification requires presignature check)
 *
 * Basic check that partial is in valid range
 *
 * @param partial - Partial signature to verify
 * @param curveName - Curve being used
 * @returns true if partial appears valid
 */
export function verifyPartial(partial: PartialECDSASignature, curveName: ECDSACurve): boolean {
  try {
    const order = getCurveOrder(curveName);
    return partial.value > 0n && partial.value < order;
  } catch {
    return false;
  }
}

// =============================================================================
// Batch Verification (Optional - for efficiency)
// =============================================================================

/**
 * Verify multiple ECDSA signatures
 *
 * For now, just verify each individually. True batch verification
 * would require random linear combinations (more complex).
 *
 * @param items - Array of (message, signature, publicKey) tuples
 * @returns Verification result (true only if ALL signatures are valid)
 */
export function batchVerify(items: BatchVerificationItem[]): ECDSAVerificationResult {
  if (items.length === 0) {
    return { valid: true };
  }

  try {
    for (const item of items) {
      const result = verify(item.message, item.signature, item.publicKey);
      if (!result.valid) {
        return result;
      }
    }
    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Batch verification failed',
    };
  }
}

// =============================================================================
// Namespace Export
// =============================================================================

export const ThresholdECDSA = {
  // Key generation
  generateKey,

  // Share verification
  verifyShare,
  verifyAllShares,

  // Presignature
  generatePresignature,

  // Threshold signing
  partialSign,
  combineSignatures,

  // Verification
  verify,
  verifyPartial,

  // Batch operations
  batchVerify,
};

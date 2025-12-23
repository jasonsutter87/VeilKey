/**
 * VeilKey - Main API for threshold cryptography
 *
 * This is the unified public API that users interact with.
 * Provides simple, high-level methods for threshold key generation,
 * partial signing, and signature combination.
 */

import { ThresholdRSA } from './rsa/index.js';
import type { RSAShare, PartialSignature } from './rsa/types.js';

export type Algorithm = 'RSA-2048' | 'RSA-4096';

export interface VeilKeyConfig {
  threshold: number;     // t - minimum shares needed
  parties: number;       // n - total shares
  algorithm: Algorithm;
}

export interface Share {
  index: number;
  value: string;         // Hex-encoded share value
  verificationKey?: string;
}

export interface KeyGroup {
  id: string;
  publicKey: string;     // Hex-encoded public key (n:e format)
  algorithm: Algorithm;
  threshold: number;
  parties: number;
  shares: Share[];       // Distributed to parties
  delta: string;         // Hex-encoded delta (n! factorial)
  createdAt: Date;
}

export interface PartialSignatureResult {
  index: number;
  partial: string;       // Hex-encoded partial signature
}

/**
 * VeilKey - Threshold Cryptography Made Simple
 *
 * @example
 * ```typescript
 * // Generate a 2-of-3 threshold key group
 * const keyGroup = await VeilKey.generate({
 *   threshold: 2,
 *   parties: 3,
 *   algorithm: 'RSA-2048'
 * });
 *
 * // Each party signs with their share
 * const message = 'Hello, VeilKey!';
 * const partial1 = await VeilKey.partialSign(message, keyGroup.shares[0], keyGroup);
 * const partial2 = await VeilKey.partialSign(message, keyGroup.shares[1], keyGroup);
 *
 * // Combine partial signatures
 * const signature = await VeilKey.combine(message, [partial1, partial2], keyGroup);
 *
 * // Verify the signature
 * const isValid = await VeilKey.verify(message, signature, keyGroup);
 * console.log('Signature valid:', isValid);
 * ```
 */
export class VeilKey {
  /**
   * Generate a new threshold key group
   *
   * @param config - Configuration specifying threshold, number of parties, and algorithm
   * @returns A KeyGroup containing the public key and all shares
   * @throws {Error} If configuration is invalid
   */
  static async generate(config: VeilKeyConfig): Promise<KeyGroup> {
    // Validate configuration
    validateConfig(config);

    const { threshold, parties, algorithm } = config;

    // Map algorithm to bit size
    const bits = algorithm === 'RSA-2048' ? 2048 : 4096;

    // Generate threshold RSA key pair
    const keyPair = await ThresholdRSA.generateKey({
      bits,
      threshold,
      totalShares: parties,
    });

    // Convert shares to hex-encoded format
    const shares: Share[] = keyPair.shares.map((share: RSAShare): Share => ({
      index: share.index,
      value: bigIntToHex(share.value),
      verificationKey: bigIntToHex(share.verificationKey),
    }));

    // Create key group
    const keyGroup: KeyGroup = {
      id: crypto.randomUUID(),
      publicKey: encodePublicKey({ n: keyPair.n, e: keyPair.e }),
      algorithm,
      threshold,
      parties,
      shares,
      delta: bigIntToHex(keyPair.delta),
      createdAt: new Date(),
    };

    return keyGroup;
  }

  /**
   * Create a partial signature using a share
   *
   * @param message - Message to sign (as Uint8Array or string)
   * @param share - The share to sign with
   * @param keyGroup - The key group containing public key and delta
   * @returns Partial signature result
   * @throws {Error} If signing fails
   */
  static async partialSign(
    message: Uint8Array | string,
    share: Share,
    keyGroup: KeyGroup
  ): Promise<PartialSignatureResult> {
    // Convert message to Uint8Array if it's a string
    const messageBytes = typeof message === 'string'
      ? new TextEncoder().encode(message)
      : message;

    // Decode share and public key
    const rsaShare: RSAShare = {
      index: share.index,
      value: hexToBigInt(share.value),
      verificationKey: hexToBigInt(share.verificationKey || '0'),
    };

    const decodedPublicKey = decodePublicKey(keyGroup.publicKey);
    const delta = hexToBigInt(keyGroup.delta);

    // Create partial signature
    const partialSig = ThresholdRSA.partialSign(
      messageBytes,
      rsaShare,
      decodedPublicKey.n,
      delta
    );

    return {
      index: partialSig.index,
      partial: bigIntToHex(partialSig.value),
    };
  }

  /**
   * Combine partial signatures into a full signature
   *
   * @param message - Original message (needed for Shoup protocol)
   * @param partials - Array of partial signatures (at least threshold many)
   * @param keyGroup - The key group containing public key and delta
   * @returns Combined signature (hex-encoded)
   * @throws {Error} If combination fails or insufficient partials
   */
  static async combine(
    message: Uint8Array | string,
    partials: PartialSignatureResult[],
    keyGroup: KeyGroup
  ): Promise<string> {
    // Validate we have enough partials
    if (partials.length < keyGroup.threshold) {
      throw new Error(
        `Insufficient partial signatures: need ${keyGroup.threshold}, got ${partials.length}`
      );
    }

    // Convert message to Uint8Array if it's a string
    const messageBytes = typeof message === 'string'
      ? new TextEncoder().encode(message)
      : message;

    // Decode partials
    const partialSigs: PartialSignature[] = partials.map((p) => ({
      index: p.index,
      value: hexToBigInt(p.partial),
    }));

    const decodedPublicKey = decodePublicKey(keyGroup.publicKey);
    const delta = hexToBigInt(keyGroup.delta);

    // Combine partial signatures
    const signature = ThresholdRSA.combineSignatures(
      messageBytes,
      partialSigs,
      keyGroup.threshold,
      decodedPublicKey.n,
      decodedPublicKey.e,
      delta
    );

    return bigIntToHex(signature);
  }

  /**
   * Verify a signature
   *
   * @param message - Original message (as Uint8Array or string)
   * @param signature - The signature to verify (hex-encoded)
   * @param keyGroup - The key group containing public key
   * @returns true if signature is valid, false otherwise
   */
  static async verify(
    message: Uint8Array | string,
    signature: string,
    keyGroup: KeyGroup
  ): Promise<boolean> {
    // Convert message to Uint8Array if it's a string
    const messageBytes = typeof message === 'string'
      ? new TextEncoder().encode(message)
      : message;

    const sig = hexToBigInt(signature);
    const decodedPublicKey = decodePublicKey(keyGroup.publicKey);

    return ThresholdRSA.verify(messageBytes, sig, decodedPublicKey.n, decodedPublicKey.e);
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Validate VeilKeyConfig
 */
function validateConfig(config: VeilKeyConfig): void {
  const { threshold, parties, algorithm } = config;

  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new Error(`Threshold must be a positive integer, got: ${threshold}`);
  }

  if (!Number.isInteger(parties) || parties < 1) {
    throw new Error(`Parties must be a positive integer, got: ${parties}`);
  }

  if (threshold > parties) {
    throw new Error(
      `Threshold (${threshold}) cannot exceed number of parties (${parties})`
    );
  }

  if (algorithm !== 'RSA-2048' && algorithm !== 'RSA-4096') {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

/**
 * Convert bigint to hex string
 */
function bigIntToHex(value: bigint): string {
  const hex = value.toString(16);
  // Ensure even length for proper byte alignment
  return hex.length % 2 === 0 ? hex : '0' + hex;
}

/**
 * Convert hex string to bigint
 */
function hexToBigInt(hex: string): bigint {
  if (!hex || hex.length === 0) {
    throw new Error('Invalid hex string: empty');
  }
  return BigInt('0x' + hex);
}

/**
 * Encode public key to hex string
 * Format: "n:e" where n is modulus and e is exponent
 */
function encodePublicKey(publicKey: { n: bigint; e: bigint }): string {
  const nHex = bigIntToHex(publicKey.n);
  const eHex = bigIntToHex(publicKey.e);
  return `${nHex}:${eHex}`;
}

/**
 * Decode public key from hex string
 */
function decodePublicKey(encoded: string): { n: bigint; e: bigint } {
  const parts = encoded.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid public key format: expected "n:e"');
  }

  const [nHex, eHex] = parts;
  if (!nHex || !eHex) {
    throw new Error('Invalid public key format: missing components');
  }

  return {
    n: hexToBigInt(nHex),
    e: hexToBigInt(eHex),
  };
}

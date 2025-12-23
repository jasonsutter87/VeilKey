/**
 * VeilKey - Threshold Cryptography Made Simple
 *
 * A unified API for threshold cryptographic operations:
 * - Key Generation: Create distributed keypairs
 * - Threshold Signing: Multiple parties sign without reconstructing the key
 * - Threshold Decryption: Multiple parties decrypt without reconstructing the key
 *
 * Use Cases:
 * - VeilSign: Threshold signing for blind signature authority
 * - TVS: Threshold decryption for vote tallying
 *
 * Security: No single party ever holds the complete private key.
 */

import { ThresholdRSA } from './rsa/index.js';
import type { RSAShare, PartialSignature, PartialDecryption } from './rsa/types.js';

// =============================================================================
// Types
// =============================================================================

export type Algorithm = 'RSA-2048' | 'RSA-4096';

/**
 * Configuration for key group generation
 */
export interface VeilKeyConfig {
  /** Minimum shares needed for any operation (t) */
  threshold: number;

  /** Total shares to generate (n) */
  parties: number;

  /** Cryptographic algorithm */
  algorithm: Algorithm;
}

/**
 * A share held by a single party/trustee
 * Hex-encoded for easy serialization and transmission
 */
export interface Share {
  /** Share index (1-based) */
  index: number;

  /** Hex-encoded share value */
  value: string;

  /** Hex-encoded verification key */
  verificationKey: string;
}

/**
 * A complete key group with distributed shares
 */
export interface KeyGroup {
  /** Unique identifier */
  id: string;

  /** Hex-encoded public key (format: "n:e") */
  publicKey: string;

  /** Algorithm used */
  algorithm: Algorithm;

  /** Threshold (t) */
  threshold: number;

  /** Total parties (n) */
  parties: number;

  /** Distributed shares (one per party) */
  shares: Share[];

  /** Hex-encoded delta (n! factorial) */
  delta: string;

  /** Creation timestamp */
  createdAt: Date;
}

/**
 * Result of a partial signing operation
 */
export interface PartialSignatureResult {
  /** Index of the signing party */
  index: number;

  /** Hex-encoded partial signature */
  partial: string;
}

/**
 * Result of a partial decryption operation
 */
export interface PartialDecryptionResult {
  /** Index of the decrypting trustee */
  index: number;

  /** Hex-encoded partial decryption */
  partial: string;
}

// =============================================================================
// VeilKey Class
// =============================================================================

/**
 * VeilKey - Threshold Cryptography API
 *
 * @example
 * ```typescript
 * // === TVS Vote Tallying Example ===
 *
 * // 1. Election setup: Generate 3-of-5 threshold key
 * const election = await VeilKey.generate({
 *   threshold: 3,
 *   parties: 5,
 *   algorithm: 'RSA-2048'
 * });
 *
 * // 2. Distribute shares to 5 trustees
 * // Each trustee securely stores their share
 *
 * // 3. Voting: Encrypt votes with public key
 * const aesKey = 0x123456789ABCDEFn; // Random AES key for vote
 * const encryptedKey = await VeilKey.encrypt(aesKey, election);
 *
 * // 4. Tallying: 3 trustees decrypt together
 * const partial1 = await VeilKey.partialDecrypt(encryptedKey, election.shares[0], election);
 * const partial2 = await VeilKey.partialDecrypt(encryptedKey, election.shares[2], election);
 * const partial3 = await VeilKey.partialDecrypt(encryptedKey, election.shares[4], election);
 *
 * // 5. Combine to recover AES key
 * const recoveredKey = await VeilKey.combineDecryptions(
 *   encryptedKey,
 *   [partial1, partial2, partial3],
 *   election
 * );
 * // recoveredKey === aesKey ✓
 * ```
 */
export class VeilKey {
  // ===========================================================================
  // Key Management
  // ===========================================================================

  /**
   * Generate a new threshold key group
   *
   * @param config - Generation configuration
   * @returns Key group with distributed shares
   */
  static async generate(config: VeilKeyConfig): Promise<KeyGroup> {
    validateConfig(config);

    const bits = config.algorithm === 'RSA-2048' ? 2048 : 4096;

    const keyPair = await ThresholdRSA.generateKey({
      bits,
      threshold: config.threshold,
      totalShares: config.parties,
    });

    const shares: Share[] = keyPair.shares.map((s: RSAShare): Share => ({
      index: s.index,
      value: bigIntToHex(s.value),
      verificationKey: bigIntToHex(s.verificationKey),
    }));

    return {
      id: crypto.randomUUID(),
      publicKey: `${bigIntToHex(keyPair.n)}:${bigIntToHex(keyPair.e)}`,
      algorithm: config.algorithm,
      threshold: config.threshold,
      parties: config.parties,
      shares,
      delta: bigIntToHex(keyPair.delta),
      createdAt: new Date(),
    };
  }

  // ===========================================================================
  // Encryption (Standard RSA - for VeilForms)
  // ===========================================================================

  /**
   * Encrypt a value with the public key
   *
   * Used by VeilForms to encrypt the AES key for a vote.
   * Only threshold decryption can recover the plaintext.
   *
   * @param plaintext - Value to encrypt (as bigint or hex string)
   * @param keyGroup - Key group containing the public key
   * @returns Hex-encoded ciphertext
   */
  static async encrypt(
    plaintext: bigint | string,
    keyGroup: KeyGroup
  ): Promise<string> {
    const value = typeof plaintext === 'string' ? hexToBigInt(plaintext) : plaintext;
    const { n, e } = decodePublicKey(keyGroup.publicKey);

    const ciphertext = ThresholdRSA.encrypt(value, n, e);
    return bigIntToHex(ciphertext);
  }

  // ===========================================================================
  // Threshold Signing (for VeilSign)
  // ===========================================================================

  /**
   * Create a partial signature using a share
   *
   * @param message - Message to sign
   * @param share - This party's share
   * @param keyGroup - Key group
   * @returns Partial signature
   */
  static async partialSign(
    message: Uint8Array | string,
    share: Share,
    keyGroup: KeyGroup
  ): Promise<PartialSignatureResult> {
    const msgBytes = typeof message === 'string'
      ? new TextEncoder().encode(message)
      : message;

    const rsaShare = decodeShare(share);
    const { n } = decodePublicKey(keyGroup.publicKey);
    const delta = hexToBigInt(keyGroup.delta);

    const partial = ThresholdRSA.partialSign(msgBytes, rsaShare, n, delta);

    return {
      index: partial.index,
      partial: bigIntToHex(partial.value),
    };
  }

  /**
   * Combine partial signatures into a complete signature
   *
   * @param message - Original message
   * @param partials - Partial signatures (need at least threshold)
   * @param keyGroup - Key group
   * @returns Hex-encoded signature
   */
  static async combineSignatures(
    message: Uint8Array | string,
    partials: PartialSignatureResult[],
    keyGroup: KeyGroup
  ): Promise<string> {
    if (partials.length < keyGroup.threshold) {
      throw new Error(
        `Need ${keyGroup.threshold} partial signatures, got ${partials.length}`
      );
    }

    const msgBytes = typeof message === 'string'
      ? new TextEncoder().encode(message)
      : message;

    const partialSigs: PartialSignature[] = partials.map(p => ({
      index: p.index,
      value: hexToBigInt(p.partial),
    }));

    const { n, e } = decodePublicKey(keyGroup.publicKey);
    const delta = hexToBigInt(keyGroup.delta);

    const signature = ThresholdRSA.combineSignatures(
      msgBytes,
      partialSigs,
      keyGroup.threshold,
      n,
      e,
      delta
    );

    return bigIntToHex(signature);
  }

  /**
   * Verify a signature
   *
   * @param message - Original message
   * @param signature - Hex-encoded signature
   * @param keyGroup - Key group
   * @returns true if valid
   */
  static async verify(
    message: Uint8Array | string,
    signature: string,
    keyGroup: KeyGroup
  ): Promise<boolean> {
    const msgBytes = typeof message === 'string'
      ? new TextEncoder().encode(message)
      : message;

    const sig = hexToBigInt(signature);
    const { n, e } = decodePublicKey(keyGroup.publicKey);

    return ThresholdRSA.verify(msgBytes, sig, n, e);
  }

  // ===========================================================================
  // Threshold Decryption (for TVS Vote Tallying)
  // ===========================================================================

  /**
   * Create a partial decryption using a share
   *
   * Each trustee calls this with their share to participate in decryption.
   *
   * @param ciphertext - Hex-encoded ciphertext to decrypt
   * @param share - This trustee's share
   * @param keyGroup - Key group
   * @returns Partial decryption
   */
  static async partialDecrypt(
    ciphertext: string,
    share: Share,
    keyGroup: KeyGroup
  ): Promise<PartialDecryptionResult> {
    const c = hexToBigInt(ciphertext);
    const rsaShare = decodeShare(share);
    const { n } = decodePublicKey(keyGroup.publicKey);
    const delta = hexToBigInt(keyGroup.delta);

    const partial = ThresholdRSA.partialDecrypt(c, rsaShare, n, delta);

    return {
      index: partial.index,
      partial: bigIntToHex(partial.value),
    };
  }

  /**
   * Combine partial decryptions to recover plaintext
   *
   * @param ciphertext - Original ciphertext (hex-encoded)
   * @param partials - Partial decryptions (need at least threshold)
   * @param keyGroup - Key group
   * @returns Hex-encoded plaintext
   */
  static async combineDecryptions(
    ciphertext: string,
    partials: PartialDecryptionResult[],
    keyGroup: KeyGroup
  ): Promise<string> {
    if (partials.length < keyGroup.threshold) {
      throw new Error(
        `Need ${keyGroup.threshold} partial decryptions, got ${partials.length}`
      );
    }

    const c = hexToBigInt(ciphertext);

    const partialDecs: PartialDecryption[] = partials.map(p => ({
      index: p.index,
      value: hexToBigInt(p.partial),
    }));

    const { n, e } = decodePublicKey(keyGroup.publicKey);
    const delta = hexToBigInt(keyGroup.delta);

    const plaintext = ThresholdRSA.combineDecryptions(
      c,
      partialDecs,
      keyGroup.threshold,
      n,
      e,
      delta
    );

    return bigIntToHex(plaintext);
  }

  // ===========================================================================
  // Deprecated methods (for backward compatibility)
  // ===========================================================================

  /**
   * @deprecated Use combineSignatures instead
   */
  static async combine(
    message: Uint8Array | string,
    partials: PartialSignatureResult[],
    keyGroup: KeyGroup
  ): Promise<string> {
    return VeilKey.combineSignatures(message, partials, keyGroup);
  }
}

// =============================================================================
// Helper Functions
// =============================================================================

function validateConfig(config: VeilKeyConfig): void {
  if (!Number.isInteger(config.threshold) || config.threshold < 1) {
    throw new Error('Threshold must be a positive integer');
  }
  if (!Number.isInteger(config.parties) || config.parties < 1) {
    throw new Error('Parties must be a positive integer');
  }
  if (config.threshold > config.parties) {
    throw new Error('Threshold cannot exceed number of parties');
  }
  if (config.algorithm !== 'RSA-2048' && config.algorithm !== 'RSA-4096') {
    throw new Error(`Unsupported algorithm: ${config.algorithm}`);
  }
}

function bigIntToHex(value: bigint): string {
  const hex = value.toString(16);
  return hex.length % 2 === 0 ? hex : '0' + hex;
}

function hexToBigInt(hex: string): bigint {
  if (!hex || hex.length === 0) {
    throw new Error('Invalid hex string: empty');
  }
  return BigInt('0x' + hex);
}

function decodePublicKey(encoded: string): { n: bigint; e: bigint } {
  const [nHex, eHex] = encoded.split(':');
  if (!nHex || !eHex) {
    throw new Error('Invalid public key format');
  }
  return { n: hexToBigInt(nHex), e: hexToBigInt(eHex) };
}

function decodeShare(share: Share): RSAShare {
  return {
    index: share.index,
    value: hexToBigInt(share.value),
    verificationKey: hexToBigInt(share.verificationKey),
  };
}

// =============================================================================
// Exports
// =============================================================================

export type {
  PartialSignatureResult as PartialSignResult,
  PartialDecryptionResult as PartialDecryptResult,
};

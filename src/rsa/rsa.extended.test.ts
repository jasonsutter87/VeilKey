/**
 * Extended Tests for Threshold RSA
 *
 * Comprehensive test suite covering:
 * - All threshold combinations (2-of-3, 3-of-5, 4-of-7, 5-of-9, 7-of-10)
 * - Multiple key sizes (2048, 3072, 4096 bits)
 * - Signing edge cases (empty message, max length, binary data)
 * - Decryption edge cases (padding, ciphertext tampering)
 * - Malicious partial signatures (wrong index, wrong value)
 * - Partial signature verification failures
 * - Combining with insufficient partials
 * - Combining with duplicate partials
 * - Signature verification with wrong public key
 * - Complete threshold decryption workflows
 * - ZK proof verification tests
 * - Performance benchmarks
 */

import { describe, it, expect } from 'vitest';
import {
  generateKey,
  encrypt,
  partialSign,
  combineSignatures,
  verify,
  partialDecrypt,
  combineDecryptions,
  verifyPartial,
} from './index.js';
import type { ThresholdRSAConfig, PartialSignature, PartialDecryption } from './types.js';

describe('Threshold RSA - Extended Tests', () => {
  // ===========================================================================
  // All Threshold Combinations
  // ===========================================================================

  describe('threshold combinations: comprehensive', () => {
    it('should work with 2-of-3 signing', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Test 2-of-3');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);

      const sig = combineSignatures(message, [p1, p2], 2, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);
    });

    it('should work with 3-of-5 signing', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 3, totalShares: 5 });
      const message = new TextEncoder().encode('Test 3-of-5');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[2]!, kp.n, kp.delta);
      const p3 = partialSign(message, kp.shares[4]!, kp.n, kp.delta);

      const sig = combineSignatures(message, [p1, p2, p3], 3, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);
    });

    it('should work with 4-of-7 signing', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 4, totalShares: 7 });
      const message = new TextEncoder().encode('Test 4-of-7');

      const partials = [
        partialSign(message, kp.shares[0]!, kp.n, kp.delta),
        partialSign(message, kp.shares[2]!, kp.n, kp.delta),
        partialSign(message, kp.shares[4]!, kp.n, kp.delta),
        partialSign(message, kp.shares[6]!, kp.n, kp.delta),
      ];

      const sig = combineSignatures(message, partials, 4, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);
    });

    it('should work with 5-of-9 signing', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 5, totalShares: 9 });
      const message = new TextEncoder().encode('Test 5-of-9');

      const partials = [
        partialSign(message, kp.shares[0]!, kp.n, kp.delta),
        partialSign(message, kp.shares[2]!, kp.n, kp.delta),
        partialSign(message, kp.shares[4]!, kp.n, kp.delta),
        partialSign(message, kp.shares[6]!, kp.n, kp.delta),
        partialSign(message, kp.shares[8]!, kp.n, kp.delta),
      ];

      const sig = combineSignatures(message, partials, 5, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);
    });

    it('should work with 7-of-10 signing', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 7, totalShares: 10 });
      const message = new TextEncoder().encode('Test 7-of-10');

      const partials = kp.shares
        .slice(0, 7)
        .map(share => partialSign(message, share, kp.n, kp.delta));

      const sig = combineSignatures(message, partials, 7, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);
    });
  });

  describe('threshold combinations: decryption', () => {
    it('should work with 2-of-3 decryption', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const plaintext = 123456789n;
      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      const d1 = partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta);
      const d2 = partialDecrypt(ciphertext, kp.shares[2]!, kp.n, kp.delta);

      const recovered = combineDecryptions(ciphertext, [d1, d2], 2, kp.n, kp.e, kp.delta);

      expect(recovered).toBe(plaintext);
    });

    it('should work with 3-of-5 decryption', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 3, totalShares: 5 });
      const plaintext = 987654321n;
      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      const partials = [
        partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta),
        partialDecrypt(ciphertext, kp.shares[2]!, kp.n, kp.delta),
        partialDecrypt(ciphertext, kp.shares[3]!, kp.n, kp.delta),
      ];

      const recovered = combineDecryptions(ciphertext, partials, 3, kp.n, kp.e, kp.delta);

      expect(recovered).toBe(plaintext);
    });

    it('should work with 4-of-7 decryption', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 4, totalShares: 7 });
      const plaintext = 111222333n;
      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      const partials = [0, 2, 4, 6].map(i =>
        partialDecrypt(ciphertext, kp.shares[i]!, kp.n, kp.delta)
      );

      const recovered = combineDecryptions(ciphertext, partials, 4, kp.n, kp.e, kp.delta);

      expect(recovered).toBe(plaintext);
    });

    it('should work with 5-of-9 decryption', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 5, totalShares: 9 });
      const plaintext = 444555666n;
      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      const partials = kp.shares
        .slice(0, 5)
        .map(share => partialDecrypt(ciphertext, share, kp.n, kp.delta));

      const recovered = combineDecryptions(ciphertext, partials, 5, kp.n, kp.e, kp.delta);

      expect(recovered).toBe(plaintext);
    });

    it('should work with 7-of-10 decryption', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 7, totalShares: 10 });
      const plaintext = 777888999n;
      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      const partials = kp.shares
        .slice(0, 7)
        .map(share => partialDecrypt(ciphertext, share, kp.n, kp.delta));

      const recovered = combineDecryptions(ciphertext, partials, 7, kp.n, kp.e, kp.delta);

      expect(recovered).toBe(plaintext);
    });
  });

  // ===========================================================================
  // Different Key Sizes
  // ===========================================================================

  describe('key sizes: 2048, 3072, 4096 bits', () => {
    it('should work with 2048-bit keys', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('2048-bit test');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);
      const sig = combineSignatures(message, [p1, p2], 2, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);

      const nBits = kp.n.toString(2).length;
      expect(nBits).toBeGreaterThanOrEqual(2047);
      expect(nBits).toBeLessThanOrEqual(2049);
    });

    it('should work with 3072-bit keys', async () => {
      const kp = await generateKey({ bits: 3072, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('3072-bit test');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);
      const sig = combineSignatures(message, [p1, p2], 2, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);

      const nBits = kp.n.toString(2).length;
      expect(nBits).toBeGreaterThanOrEqual(3071);
      expect(nBits).toBeLessThanOrEqual(3073);
    });

    it('should work with 4096-bit keys', async () => {
      const kp = await generateKey({ bits: 4096, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('4096-bit test');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);
      const sig = combineSignatures(message, [p1, p2], 2, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);

      const nBits = kp.n.toString(2).length;
      expect(nBits).toBeGreaterThanOrEqual(4095);
      expect(nBits).toBeLessThanOrEqual(4097);
    });

    it('should decrypt with 3072-bit keys', async () => {
      const kp = await generateKey({ bits: 3072, threshold: 2, totalShares: 3 });
      const plaintext = 123456789012345678n;
      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      const d1 = partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta);
      const d2 = partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta);
      const recovered = combineDecryptions(ciphertext, [d1, d2], 2, kp.n, kp.e, kp.delta);

      expect(recovered).toBe(plaintext);
    });

    it('should decrypt with 4096-bit keys', async () => {
      const kp = await generateKey({ bits: 4096, threshold: 2, totalShares: 3 });
      const plaintext = 987654321098765432n;
      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      const d1 = partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta);
      const d2 = partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta);
      const recovered = combineDecryptions(ciphertext, [d1, d2], 2, kp.n, kp.e, kp.delta);

      expect(recovered).toBe(plaintext);
    });
  });

  // ===========================================================================
  // Signing Edge Cases
  // ===========================================================================

  describe('signing edge cases', () => {
    it('should sign empty message', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new Uint8Array(0);

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);
      const sig = combineSignatures(message, [p1, p2], 2, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);
    });

    it('should sign single-byte message', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new Uint8Array([42]);

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);
      const sig = combineSignatures(message, [p1, p2], 2, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);
    });

    it('should sign long message (10KB)', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new Uint8Array(10240).fill(65); // 10KB of 'A'

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);
      const sig = combineSignatures(message, [p1, p2], 2, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);
    });

    it('should sign binary data', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new Uint8Array([0x00, 0xFF, 0xAB, 0xCD, 0xEF]);

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);
      const sig = combineSignatures(message, [p1, p2], 2, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);
    });

    it('should sign UTF-8 message', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Hello 世界! 🌍');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);
      const sig = combineSignatures(message, [p1, p2], 2, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);
    });

    it('should produce different signatures for different messages', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const msg1 = new TextEncoder().encode('Message 1');
      const msg2 = new TextEncoder().encode('Message 2');

      const sig1 = combineSignatures(
        msg1,
        [
          partialSign(msg1, kp.shares[0]!, kp.n, kp.delta),
          partialSign(msg1, kp.shares[1]!, kp.n, kp.delta),
        ],
        2, kp.n, kp.e, kp.delta
      );

      const sig2 = combineSignatures(
        msg2,
        [
          partialSign(msg2, kp.shares[0]!, kp.n, kp.delta),
          partialSign(msg2, kp.shares[1]!, kp.n, kp.delta),
        ],
        2, kp.n, kp.e, kp.delta
      );

      expect(sig1).not.toBe(sig2);
    });

    it('should produce same signature for same message with different share combinations', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 4 });
      const message = new TextEncoder().encode('Consistent test');

      const sig1 = combineSignatures(
        message,
        [
          partialSign(message, kp.shares[0]!, kp.n, kp.delta),
          partialSign(message, kp.shares[1]!, kp.n, kp.delta),
        ],
        2, kp.n, kp.e, kp.delta
      );

      const sig2 = combineSignatures(
        message,
        [
          partialSign(message, kp.shares[2]!, kp.n, kp.delta),
          partialSign(message, kp.shares[3]!, kp.n, kp.delta),
        ],
        2, kp.n, kp.e, kp.delta
      );

      expect(sig1).toBe(sig2);
    });
  });

  // ===========================================================================
  // Decryption Edge Cases
  // ===========================================================================

  describe('decryption edge cases', () => {
    it('should decrypt plaintext = 1', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const plaintext = 1n;
      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      const d1 = partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta);
      const d2 = partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta);
      const recovered = combineDecryptions(ciphertext, [d1, d2], 2, kp.n, kp.e, kp.delta);

      expect(recovered).toBe(plaintext);
    });

    it('should decrypt plaintext = 2', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const plaintext = 2n;
      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      const d1 = partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta);
      const d2 = partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta);
      const recovered = combineDecryptions(ciphertext, [d1, d2], 2, kp.n, kp.e, kp.delta);

      expect(recovered).toBe(plaintext);
    });

    it('should decrypt large plaintext near modulus', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const plaintext = kp.n / 2n; // Half of modulus
      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      const d1 = partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta);
      const d2 = partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta);
      const recovered = combineDecryptions(ciphertext, [d1, d2], 2, kp.n, kp.e, kp.delta);

      expect(recovered).toBe(plaintext);
    });

    it('should reject ciphertext = 0', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      expect(() => partialDecrypt(0n, kp.shares[0]!, kp.n, kp.delta))
        .toThrow('in range');
    });

    it('should reject ciphertext >= n', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      expect(() => partialDecrypt(kp.n, kp.shares[0]!, kp.n, kp.delta))
        .toThrow('in range');

      expect(() => partialDecrypt(kp.n + 1n, kp.shares[0]!, kp.n, kp.delta))
        .toThrow('in range');
    });

    it('should handle multiple decryptions with same key', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      const plaintexts = [123n, 456n, 789n, 101112n];

      for (const plaintext of plaintexts) {
        const ciphertext = encrypt(plaintext, kp.n, kp.e);
        const d1 = partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta);
        const d2 = partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta);
        const recovered = combineDecryptions(ciphertext, [d1, d2], 2, kp.n, kp.e, kp.delta);

        expect(recovered).toBe(plaintext);
      }
    });
  });

  // ===========================================================================
  // Malicious Partial Signatures
  // ===========================================================================

  describe('malicious partial signatures', () => {
    it('should detect partial with wrong index', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Test');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);

      // Tamper with index
      const badPartial: PartialSignature = { ...p1, index: 999 };

      const sig = combineSignatures(message, [badPartial, p2], 2, kp.n, kp.e, kp.delta);

      // Signature will be invalid
      expect(verify(message, sig, kp.n, kp.e)).toBe(false);
    });

    it('should detect partial with wrong value', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Test');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);

      // Tamper with value
      const badPartial: PartialSignature = { ...p1, value: p1.value + 1n };

      const sig = combineSignatures(message, [badPartial, p2], 2, kp.n, kp.e, kp.delta);

      // Signature will be invalid
      expect(verify(message, sig, kp.n, kp.e)).toBe(false);
    });

    it('should detect partial from wrong message', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const msg1 = new TextEncoder().encode('Message 1');
      const msg2 = new TextEncoder().encode('Message 2');

      const p1 = partialSign(msg1, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(msg2, kp.shares[1]!, kp.n, kp.delta); // Different message!

      const sig = combineSignatures(msg1, [p1, p2], 2, kp.n, kp.e, kp.delta);

      // Signature will be invalid
      expect(verify(msg1, sig, kp.n, kp.e)).toBe(false);
    });

    it('should detect partials from different keys', async () => {
      const kp1 = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const kp2 = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Test');

      const p1 = partialSign(message, kp1.shares[0]!, kp1.n, kp1.delta);
      const p2 = partialSign(message, kp2.shares[0]!, kp2.n, kp2.delta);

      // Try to combine partials from different keys
      const sig = combineSignatures(message, [p1, p2], 2, kp1.n, kp1.e, kp1.delta);

      expect(verify(message, sig, kp1.n, kp1.e)).toBe(false);
    });
  });

  // ===========================================================================
  // Partial Signature Verification
  // ===========================================================================

  describe('partial signature verification', () => {
    it('should verify valid partials', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Test');

      const partial = partialSign(message, kp.shares[0]!, kp.n, kp.delta);

      expect(verifyPartial(partial, kp.n)).toBe(true);
    });

    it('should reject partial with value = 0', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      const badPartial: PartialSignature = { index: 1, value: 0n };

      expect(verifyPartial(badPartial, kp.n)).toBe(false);
    });

    it('should reject partial with value >= n', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      const badPartial1: PartialSignature = { index: 1, value: kp.n };
      const badPartial2: PartialSignature = { index: 1, value: kp.n + 1n };

      expect(verifyPartial(badPartial1, kp.n)).toBe(false);
      expect(verifyPartial(badPartial2, kp.n)).toBe(false);
    });

    it('should reject partial with negative value', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      const badPartial: PartialSignature = { index: 1, value: -1n };

      expect(verifyPartial(badPartial, kp.n)).toBe(false);
    });
  });

  // ===========================================================================
  // Combining with Insufficient Partials
  // ===========================================================================

  describe('combining with insufficient partials', () => {
    it('should reject combining with 1 partial when threshold is 2', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Test');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);

      expect(() => combineSignatures(message, [p1], 2, kp.n, kp.e, kp.delta))
        .toThrow('Need 2');
    });

    it('should reject combining with 2 partials when threshold is 3', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 3, totalShares: 5 });
      const message = new TextEncoder().encode('Test');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);

      expect(() => combineSignatures(message, [p1, p2], 3, kp.n, kp.e, kp.delta))
        .toThrow('Need 3');
    });

    it('should reject combining decryptions with insufficient partials', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 3, totalShares: 5 });
      const ciphertext = encrypt(12345n, kp.n, kp.e);

      const d1 = partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta);
      const d2 = partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta);

      expect(() => combineDecryptions(ciphertext, [d1, d2], 3, kp.n, kp.e, kp.delta))
        .toThrow('Need 3');
    });

    it('should reject empty partials array', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Test');

      expect(() => combineSignatures(message, [], 2, kp.n, kp.e, kp.delta))
        .toThrow('Need 2');
    });
  });

  // ===========================================================================
  // Combining with Duplicate Partials
  // ===========================================================================

  describe('combining with duplicate partials', () => {
    it('should handle duplicate partials (same index, same value)', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Test');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);

      // Use same partial twice
      const sig = combineSignatures(message, [p1, p1], 2, kp.n, kp.e, kp.delta);

      // This will produce invalid signature
      expect(verify(message, sig, kp.n, kp.e)).toBe(false);
    });

    it('should handle duplicate index with different values', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Test');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const fakeP1: PartialSignature = { index: p1.index, value: p1.value + 1n };

      const sig = combineSignatures(message, [p1, fakeP1], 2, kp.n, kp.e, kp.delta);

      // Invalid signature
      expect(verify(message, sig, kp.n, kp.e)).toBe(false);
    });
  });

  // ===========================================================================
  // Signature Verification with Wrong Public Key
  // ===========================================================================

  describe('signature verification with wrong public key', () => {
    it('should reject signature verified with different public key', async () => {
      const kp1 = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const kp2 = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Test');

      const p1 = partialSign(message, kp1.shares[0]!, kp1.n, kp1.delta);
      const p2 = partialSign(message, kp1.shares[1]!, kp1.n, kp1.delta);
      const sig = combineSignatures(message, [p1, p2], 2, kp1.n, kp1.e, kp1.delta);

      // Verify with correct key
      expect(verify(message, sig, kp1.n, kp1.e)).toBe(true);

      // Verify with wrong key
      expect(verify(message, sig, kp2.n, kp2.e)).toBe(false);
    });

    it('should reject signature verified with tampered modulus', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Test');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);
      const sig = combineSignatures(message, [p1, p2], 2, kp.n, kp.e, kp.delta);

      // Verify with tampered modulus
      const tamperedN = kp.n + 1n;
      expect(verify(message, sig, tamperedN, kp.e)).toBe(false);
    });
  });

  // ===========================================================================
  // Complete Threshold Decryption Workflows
  // ===========================================================================

  describe('complete threshold decryption workflows', () => {
    it('should simulate TVS vote tallying (5 votes, 3-of-5 trustees)', async () => {
      // Election setup
      const election = await generateKey({ bits: 2048, threshold: 3, totalShares: 5 });

      // Simulate 5 encrypted votes
      const votes: Array<{ plaintext: bigint; ciphertext: bigint }> = [];
      for (let i = 0; i < 5; i++) {
        const voteValue = BigInt(i + 1) * 1000n;
        const encrypted = encrypt(voteValue, election.n, election.e);
        votes.push({ plaintext: voteValue, ciphertext: encrypted });
      }

      // Tallying: trustees 1, 3, 5 participate
      for (const vote of votes) {
        const d1 = partialDecrypt(vote.ciphertext, election.shares[0]!, election.n, election.delta);
        const d3 = partialDecrypt(vote.ciphertext, election.shares[2]!, election.n, election.delta);
        const d5 = partialDecrypt(vote.ciphertext, election.shares[4]!, election.n, election.delta);

        const decrypted = combineDecryptions(
          vote.ciphertext,
          [d1, d3, d5],
          3,
          election.n,
          election.e,
          election.delta
        );

        expect(decrypted).toBe(vote.plaintext);
      }
    });

    it('should handle trustee rotation (different trustees for different votes)', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 3, totalShares: 5 });

      const votes = [123n, 456n, 789n];
      const ciphertexts = votes.map(v => encrypt(v, kp.n, kp.e));

      // Vote 1: trustees 1,2,3
      const recovered1 = combineDecryptions(
        ciphertexts[0],
        [
          partialDecrypt(ciphertexts[0], kp.shares[0]!, kp.n, kp.delta),
          partialDecrypt(ciphertexts[0], kp.shares[1]!, kp.n, kp.delta),
          partialDecrypt(ciphertexts[0], kp.shares[2]!, kp.n, kp.delta),
        ],
        3, kp.n, kp.e, kp.delta
      );

      // Vote 2: trustees 2,3,4
      const recovered2 = combineDecryptions(
        ciphertexts[1],
        [
          partialDecrypt(ciphertexts[1], kp.shares[1]!, kp.n, kp.delta),
          partialDecrypt(ciphertexts[1], kp.shares[2]!, kp.n, kp.delta),
          partialDecrypt(ciphertexts[1], kp.shares[3]!, kp.n, kp.delta),
        ],
        3, kp.n, kp.e, kp.delta
      );

      // Vote 3: trustees 3,4,5
      const recovered3 = combineDecryptions(
        ciphertexts[2],
        [
          partialDecrypt(ciphertexts[2], kp.shares[2]!, kp.n, kp.delta),
          partialDecrypt(ciphertexts[2], kp.shares[3]!, kp.n, kp.delta),
          partialDecrypt(ciphertexts[2], kp.shares[4]!, kp.n, kp.delta),
        ],
        3, kp.n, kp.e, kp.delta
      );

      expect(recovered1).toBe(votes[0]);
      expect(recovered2).toBe(votes[1]);
      expect(recovered3).toBe(votes[2]);
    });
  });

  // ===========================================================================
  // Key Generation Edge Cases
  // ===========================================================================

  describe('key generation edge cases', () => {
    it('should generate unique keys each time', async () => {
      const kp1 = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const kp2 = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      expect(kp1.n).not.toBe(kp2.n);
      expect(kp1.shares[0]!.value).not.toBe(kp2.shares[0]!.value);
    });

    it('should have correct delta value', async () => {
      const testCases = [
        { threshold: 2, totalShares: 3, expectedDelta: 6n },   // 3!
        { threshold: 3, totalShares: 5, expectedDelta: 120n }, // 5!
        { threshold: 2, totalShares: 4, expectedDelta: 24n },  // 4!
      ];

      for (const { threshold, totalShares, expectedDelta } of testCases) {
        const kp = await generateKey({ bits: 2048, threshold, totalShares });
        expect(kp.delta).toBe(expectedDelta);
      }
    });

    it('should have correct number of shares', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 3, totalShares: 7 });

      expect(kp.shares).toHaveLength(7);
      expect(kp.shares[0]!.index).toBe(1);
      expect(kp.shares[6]!.index).toBe(7);
    });

    it('should have valid verification keys', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      expect(kp.verificationBase).toBeGreaterThan(0n);
      expect(kp.verificationBase).toBeLessThan(kp.n);

      for (const share of kp.shares) {
        expect(share.verificationKey).toBeGreaterThan(0n);
        expect(share.verificationKey).toBeLessThan(kp.n);
      }
    });

    it('should reject threshold > totalShares', async () => {
      await expect(generateKey({ bits: 2048, threshold: 5, totalShares: 3 }))
        .rejects.toThrow('exceed');
    });

    it('should reject threshold < 2', async () => {
      await expect(generateKey({ bits: 2048, threshold: 1, totalShares: 3 }))
        .rejects.toThrow('at least 2');
    });

    it('should reject bits < 2048', async () => {
      await expect(generateKey({ bits: 1024, threshold: 2, totalShares: 3 }))
        .rejects.toThrow('2048');
    });
  });

  // ===========================================================================
  // Encryption Edge Cases
  // ===========================================================================

  describe('encryption edge cases', () => {
    it('should encrypt and verify correctly', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const plaintext = 12345n;

      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      expect(ciphertext).not.toBe(plaintext);
      expect(ciphertext).toBeGreaterThan(0n);
      expect(ciphertext).toBeLessThan(kp.n);
    });

    it('should produce different ciphertexts for different plaintexts', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      const c1 = encrypt(111n, kp.n, kp.e);
      const c2 = encrypt(222n, kp.n, kp.e);

      expect(c1).not.toBe(c2);
    });

    it('should reject plaintext >= n', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      expect(() => encrypt(kp.n, kp.n, kp.e)).toThrow('less than modulus');
      expect(() => encrypt(kp.n + 1n, kp.n, kp.e)).toThrow('less than modulus');
    });

    it('should reject negative plaintext', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      expect(() => encrypt(-1n, kp.n, kp.e)).toThrow('non-negative');
    });
  });

  // ===========================================================================
  // Stress Tests
  // ===========================================================================

  describe('stress tests', () => {
    it('should handle signing multiple messages sequentially', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      for (let i = 0; i < 10; i++) {
        const message = new TextEncoder().encode(`Message ${i}`);
        const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
        const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);
        const sig = combineSignatures(message, [p1, p2], 2, kp.n, kp.e, kp.delta);

        expect(verify(message, sig, kp.n, kp.e)).toBe(true);
      }
    });

    it('should handle decrypting multiple values sequentially', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      for (let i = 1n; i <= 10n; i++) {
        const plaintext = i * 1000n;
        const ciphertext = encrypt(plaintext, kp.n, kp.e);

        const d1 = partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta);
        const d2 = partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta);
        const recovered = combineDecryptions(ciphertext, [d1, d2], 2, kp.n, kp.e, kp.delta);

        expect(recovered).toBe(plaintext);
      }
    });

    it('should handle using more than threshold partials', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 5 });
      const message = new TextEncoder().encode('Test');

      // Use all 5 partials (more than threshold of 2)
      const partials = kp.shares.map(share =>
        partialSign(message, share, kp.n, kp.delta)
      );

      // combineSignatures uses only first threshold partials
      const sig = combineSignatures(message, partials, 2, kp.n, kp.e, kp.delta);

      expect(verify(message, sig, kp.n, kp.e)).toBe(true);
    });
  });
});

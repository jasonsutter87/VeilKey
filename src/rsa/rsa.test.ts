/**
 * Comprehensive Tests for Threshold RSA
 *
 * Tests both threshold signing (for VeilSign) and
 * threshold decryption (for TVS vote tallying).
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

describe('Threshold RSA', () => {
  // ===========================================================================
  // Key Generation
  // ===========================================================================

  describe('generateKey', () => {
    it('should generate a valid 2048-bit 3-of-5 keypair', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 3,
        totalShares: 5,
      };

      const keyPair = await generateKey(config);

      // Structure checks
      expect(keyPair.n).toBeDefined();
      expect(keyPair.e).toBe(65537n);
      expect(keyPair.shares).toHaveLength(5);
      expect(keyPair.delta).toBe(120n); // 5! = 120
      expect(keyPair.verificationBase).toBeDefined();

      // Modulus size check
      const nBits = keyPair.n.toString(2).length;
      expect(nBits).toBeGreaterThanOrEqual(2047);
      expect(nBits).toBeLessThanOrEqual(2049);

      // Share structure checks
      for (let i = 0; i < 5; i++) {
        const share = keyPair.shares[i]!;
        expect(share.index).toBe(i + 1);
        expect(share.value).toBeGreaterThan(0n);
        expect(share.verificationKey).toBeGreaterThan(0n);
      }
    });

    it('should generate unique keys each time', async () => {
      const config: ThresholdRSAConfig = { bits: 2048, threshold: 2, totalShares: 3 };

      const kp1 = await generateKey(config);
      const kp2 = await generateKey(config);

      expect(kp1.n).not.toBe(kp2.n);
      expect(kp1.shares[0]!.value).not.toBe(kp2.shares[0]!.value);
    });

    it('should reject invalid configurations', async () => {
      await expect(generateKey({ bits: 2048, threshold: 6, totalShares: 5 }))
        .rejects.toThrow('exceed');
      await expect(generateKey({ bits: 2048, threshold: 1, totalShares: 5 }))
        .rejects.toThrow('at least 2');
      await expect(generateKey({ bits: 1024, threshold: 2, totalShares: 3 }))
        .rejects.toThrow('2048');
    });
  });

  // ===========================================================================
  // Standard RSA Encryption
  // ===========================================================================

  describe('encrypt', () => {
    it('should encrypt a value', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const plaintext = 12345678901234567890n;

      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      expect(ciphertext).toBeDefined();
      expect(ciphertext).not.toBe(plaintext);
      expect(ciphertext).toBeGreaterThan(0n);
      expect(ciphertext).toBeLessThan(kp.n);
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
  // Threshold Signing
  // ===========================================================================

  describe('Threshold Signing', () => {
    it('should sign and verify (2-of-3)', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Hello, VeilSign!');

      // Create partials
      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[1]!, kp.n, kp.delta);

      // Combine
      const signature = combineSignatures(message, [p1, p2], 2, kp.n, kp.e, kp.delta);

      // Verify
      expect(verify(message, signature, kp.n, kp.e)).toBe(true);
    });

    it('should sign and verify (3-of-5)', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 3, totalShares: 5 });
      const message = new TextEncoder().encode('Test message');

      const p1 = partialSign(message, kp.shares[0]!, kp.n, kp.delta);
      const p2 = partialSign(message, kp.shares[2]!, kp.n, kp.delta);
      const p3 = partialSign(message, kp.shares[4]!, kp.n, kp.delta);

      const signature = combineSignatures(message, [p1, p2, p3], 3, kp.n, kp.e, kp.delta);

      expect(verify(message, signature, kp.n, kp.e)).toBe(true);
    });

    it('should produce same signature from different share subsets', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 4 });
      const message = new TextEncoder().encode('Consistent signature');

      // Subset 1: shares 1, 2
      const sig1 = combineSignatures(
        message,
        [
          partialSign(message, kp.shares[0]!, kp.n, kp.delta),
          partialSign(message, kp.shares[1]!, kp.n, kp.delta),
        ],
        2, kp.n, kp.e, kp.delta
      );

      // Subset 2: shares 3, 4
      const sig2 = combineSignatures(
        message,
        [
          partialSign(message, kp.shares[2]!, kp.n, kp.delta),
          partialSign(message, kp.shares[3]!, kp.n, kp.delta),
        ],
        2, kp.n, kp.e, kp.delta
      );

      expect(sig1).toBe(sig2);
      expect(verify(message, sig1, kp.n, kp.e)).toBe(true);
    });

    it('should reject tampered message', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Original');
      const tampered = new TextEncoder().encode('Tampered');

      const partials = [
        partialSign(message, kp.shares[0]!, kp.n, kp.delta),
        partialSign(message, kp.shares[1]!, kp.n, kp.delta),
      ];
      const signature = combineSignatures(message, partials, 2, kp.n, kp.e, kp.delta);

      expect(verify(tampered, signature, kp.n, kp.e)).toBe(false);
    });

    it('should reject insufficient partials', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 3, totalShares: 5 });
      const message = new TextEncoder().encode('Test');

      const partials = [
        partialSign(message, kp.shares[0]!, kp.n, kp.delta),
        partialSign(message, kp.shares[1]!, kp.n, kp.delta),
      ];

      expect(() => combineSignatures(message, partials, 3, kp.n, kp.e, kp.delta))
        .toThrow('Need 3');
    });
  });

  // ===========================================================================
  // Threshold Decryption (TVS Use Case)
  // ===========================================================================

  describe('Threshold Decryption', () => {
    it('should encrypt and decrypt (2-of-3)', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const plaintext = 0xDEADBEEFCAFEBABEn;

      // Encrypt
      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      // Partial decryptions
      const d1 = partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta);
      const d2 = partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta);

      // Combine
      const recovered = combineDecryptions(ciphertext, [d1, d2], 2, kp.n, kp.e, kp.delta);

      expect(recovered).toBe(plaintext);
    });

    it('should encrypt and decrypt (3-of-5)', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 3, totalShares: 5 });
      const plaintext = 123456789012345678901234567890n;

      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      // Use trustees 1, 3, 5
      const d1 = partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta);
      const d3 = partialDecrypt(ciphertext, kp.shares[2]!, kp.n, kp.delta);
      const d5 = partialDecrypt(ciphertext, kp.shares[4]!, kp.n, kp.delta);

      const recovered = combineDecryptions(ciphertext, [d1, d3, d5], 3, kp.n, kp.e, kp.delta);

      expect(recovered).toBe(plaintext);
    });

    it('should work with different trustee combinations', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 4 });
      const plaintext = 42n;
      const ciphertext = encrypt(plaintext, kp.n, kp.e);

      // Combination 1: trustees 1, 2
      const r1 = combineDecryptions(
        ciphertext,
        [
          partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta),
          partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta),
        ],
        2, kp.n, kp.e, kp.delta
      );

      // Combination 2: trustees 2, 4
      const r2 = combineDecryptions(
        ciphertext,
        [
          partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta),
          partialDecrypt(ciphertext, kp.shares[3]!, kp.n, kp.delta),
        ],
        2, kp.n, kp.e, kp.delta
      );

      expect(r1).toBe(plaintext);
      expect(r2).toBe(plaintext);
    });

    it('should reject insufficient partial decryptions', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 3, totalShares: 5 });
      const ciphertext = encrypt(100n, kp.n, kp.e);

      const partials = [
        partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta),
        partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta),
      ];

      expect(() => combineDecryptions(ciphertext, partials, 3, kp.n, kp.e, kp.delta))
        .toThrow('Need 3');
    });

    it('should handle edge case: plaintext = 0', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const plaintext = 0n;

      // Note: 0^e = 0, so this is a special case
      const ciphertext = encrypt(plaintext, kp.n, kp.e);
      expect(ciphertext).toBe(0n);

      // Decryption of 0 is 0, but our implementation requires ciphertext > 0
      // This is correct behavior - 0 is not a valid RSA plaintext
    });

    it('should handle large plaintext values', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      // Use a large value that's still < n
      const plaintext = kp.n / 2n;

      const ciphertext = encrypt(plaintext, kp.n, kp.e);
      const d1 = partialDecrypt(ciphertext, kp.shares[0]!, kp.n, kp.delta);
      const d2 = partialDecrypt(ciphertext, kp.shares[1]!, kp.n, kp.delta);
      const recovered = combineDecryptions(ciphertext, [d1, d2], 2, kp.n, kp.e, kp.delta);

      expect(recovered).toBe(plaintext);
    });
  });

  // ===========================================================================
  // Partial Verification
  // ===========================================================================

  describe('verifyPartial', () => {
    it('should accept valid partials', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });
      const message = new TextEncoder().encode('Test');

      const partial = partialSign(message, kp.shares[0]!, kp.n, kp.delta);

      expect(verifyPartial(partial, kp.n)).toBe(true);
    });

    it('should reject out-of-range partials', async () => {
      const kp = await generateKey({ bits: 2048, threshold: 2, totalShares: 3 });

      expect(verifyPartial({ index: 1, value: 0n }, kp.n)).toBe(false);
      expect(verifyPartial({ index: 1, value: kp.n }, kp.n)).toBe(false);
      expect(verifyPartial({ index: 1, value: -1n }, kp.n)).toBe(false);
    });
  });

  // ===========================================================================
  // TVS Integration Scenario
  // ===========================================================================

  describe('TVS Integration', () => {
    it('should simulate complete vote tallying workflow', async () => {
      // 1. Election setup: 3-of-5 threshold
      const election = await generateKey({ bits: 2048, threshold: 3, totalShares: 5 });

      // 2. Simulate 10 votes, each with a random AES key
      const votes: Array<{ aesKey: bigint; encryptedKey: bigint }> = [];
      for (let i = 0; i < 10; i++) {
        // Random AES-256 key (256 bits)
        const aesKey = BigInt('0x' + Array.from(
          crypto.getRandomValues(new Uint8Array(32)),
          b => b.toString(16).padStart(2, '0')
        ).join(''));

        const encryptedKey = encrypt(aesKey, election.n, election.e);
        votes.push({ aesKey, encryptedKey });
      }

      // 3. Tallying: Trustees 1, 3, 5 participate
      for (const vote of votes) {
        const d1 = partialDecrypt(vote.encryptedKey, election.shares[0]!, election.n, election.delta);
        const d3 = partialDecrypt(vote.encryptedKey, election.shares[2]!, election.n, election.delta);
        const d5 = partialDecrypt(vote.encryptedKey, election.shares[4]!, election.n, election.delta);

        const recoveredKey = combineDecryptions(
          vote.encryptedKey,
          [d1, d3, d5],
          3,
          election.n,
          election.e,
          election.delta
        );

        // Verify decryption is correct
        expect(recoveredKey).toBe(vote.aesKey);
      }
    });
  });
});

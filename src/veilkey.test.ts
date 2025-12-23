/**
 * Comprehensive Tests for VeilKey API
 *
 * Tests the high-level API for:
 * - Key generation
 * - Threshold signing (VeilSign use case)
 * - Threshold decryption (TVS vote tallying use case)
 */

import { describe, it, expect } from 'vitest';
import { VeilKey } from './veilkey.js';
import type { VeilKeyConfig, KeyGroup } from './veilkey.js';

describe('VeilKey', () => {
  // ===========================================================================
  // Key Generation
  // ===========================================================================

  describe('generate', () => {
    it('should generate a 2-of-3 RSA-2048 key group', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      expect(keyGroup.id).toHaveLength(36); // UUID
      expect(keyGroup.publicKey).toContain(':');
      expect(keyGroup.algorithm).toBe('RSA-2048');
      expect(keyGroup.threshold).toBe(2);
      expect(keyGroup.parties).toBe(3);
      expect(keyGroup.shares).toHaveLength(3);
      expect(keyGroup.delta).toBe('06'); // 3! = 6
      expect(keyGroup.createdAt).toBeInstanceOf(Date);
    });

    it('should generate a 3-of-5 RSA-2048 key group', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 3,
        parties: 5,
        algorithm: 'RSA-2048',
      });

      expect(keyGroup.shares).toHaveLength(5);
      expect(keyGroup.threshold).toBe(3);
      expect(keyGroup.delta).toBe('78'); // 5! = 120
    });

    it('should reject invalid configurations', async () => {
      await expect(VeilKey.generate({ threshold: 5, parties: 3, algorithm: 'RSA-2048' }))
        .rejects.toThrow('exceed');

      await expect(VeilKey.generate({ threshold: 0, parties: 3, algorithm: 'RSA-2048' }))
        .rejects.toThrow('positive integer');

      await expect(VeilKey.generate({ threshold: 2, parties: 3, algorithm: 'INVALID' as 'RSA-2048' }))
        .rejects.toThrow('Unsupported');
    });
  });

  // ===========================================================================
  // Encryption
  // ===========================================================================

  describe('encrypt', () => {
    it('should encrypt a bigint value', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const plaintext = 0xDEADBEEFn;
      const ciphertext = await VeilKey.encrypt(plaintext, keyGroup);

      expect(ciphertext).toBeDefined();
      expect(ciphertext.length).toBeGreaterThan(10);
    });

    it('should encrypt a hex string value', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const ciphertext = await VeilKey.encrypt('deadbeef', keyGroup);

      expect(ciphertext).toBeDefined();
      expect(ciphertext.length).toBeGreaterThan(10);
    });
  });

  // ===========================================================================
  // Threshold Signing (VeilSign Use Case)
  // ===========================================================================

  describe('Threshold Signing', () => {
    it('should sign and verify (2-of-3)', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = 'Hello, VeilSign!';

      const p1 = await VeilKey.partialSign(message, keyGroup.shares[0]!, keyGroup);
      const p2 = await VeilKey.partialSign(message, keyGroup.shares[1]!, keyGroup);

      const signature = await VeilKey.combineSignatures(message, [p1, p2], keyGroup);
      const isValid = await VeilKey.verify(message, signature, keyGroup);

      expect(isValid).toBe(true);
    });

    it('should sign and verify with Uint8Array', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = new TextEncoder().encode('Binary message');

      const p1 = await VeilKey.partialSign(message, keyGroup.shares[0]!, keyGroup);
      const p2 = await VeilKey.partialSign(message, keyGroup.shares[2]!, keyGroup);

      const signature = await VeilKey.combineSignatures(message, [p1, p2], keyGroup);
      const isValid = await VeilKey.verify(message, signature, keyGroup);

      expect(isValid).toBe(true);
    });

    it('should reject tampered message', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const p1 = await VeilKey.partialSign('Original', keyGroup.shares[0]!, keyGroup);
      const p2 = await VeilKey.partialSign('Original', keyGroup.shares[1]!, keyGroup);

      const signature = await VeilKey.combineSignatures('Original', [p1, p2], keyGroup);

      expect(await VeilKey.verify('Tampered', signature, keyGroup)).toBe(false);
    });

    it('should reject insufficient partials', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 3,
        parties: 5,
        algorithm: 'RSA-2048',
      });

      const p1 = await VeilKey.partialSign('Test', keyGroup.shares[0]!, keyGroup);
      const p2 = await VeilKey.partialSign('Test', keyGroup.shares[1]!, keyGroup);

      await expect(VeilKey.combineSignatures('Test', [p1, p2], keyGroup))
        .rejects.toThrow('Need 3');
    });
  });

  // ===========================================================================
  // Threshold Decryption (TVS Use Case)
  // ===========================================================================

  describe('Threshold Decryption', () => {
    it('should encrypt and decrypt (2-of-3)', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const plaintext = 0xCAFEBABEDEADBEEFn;
      const ciphertext = await VeilKey.encrypt(plaintext, keyGroup);

      const d1 = await VeilKey.partialDecrypt(ciphertext, keyGroup.shares[0]!, keyGroup);
      const d2 = await VeilKey.partialDecrypt(ciphertext, keyGroup.shares[1]!, keyGroup);

      const recovered = await VeilKey.combineDecryptions(ciphertext, [d1, d2], keyGroup);

      // Compare as bigint
      expect(BigInt('0x' + recovered)).toBe(plaintext);
    });

    it('should encrypt and decrypt (3-of-5)', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 3,
        parties: 5,
        algorithm: 'RSA-2048',
      });

      const plaintext = 123456789n;
      const ciphertext = await VeilKey.encrypt(plaintext, keyGroup);

      // Trustees 1, 3, 5
      const d1 = await VeilKey.partialDecrypt(ciphertext, keyGroup.shares[0]!, keyGroup);
      const d3 = await VeilKey.partialDecrypt(ciphertext, keyGroup.shares[2]!, keyGroup);
      const d5 = await VeilKey.partialDecrypt(ciphertext, keyGroup.shares[4]!, keyGroup);

      const recovered = await VeilKey.combineDecryptions(ciphertext, [d1, d3, d5], keyGroup);

      expect(BigInt('0x' + recovered)).toBe(plaintext);
    });

    it('should reject insufficient partial decryptions', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 3,
        parties: 5,
        algorithm: 'RSA-2048',
      });

      const ciphertext = await VeilKey.encrypt(100n, keyGroup);

      const d1 = await VeilKey.partialDecrypt(ciphertext, keyGroup.shares[0]!, keyGroup);
      const d2 = await VeilKey.partialDecrypt(ciphertext, keyGroup.shares[1]!, keyGroup);

      await expect(VeilKey.combineDecryptions(ciphertext, [d1, d2], keyGroup))
        .rejects.toThrow('Need 3');
    });
  });

  // ===========================================================================
  // Serialization
  // ===========================================================================

  describe('Serialization', () => {
    it('should work after JSON round-trip', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      // Serialize and deserialize
      const json = JSON.stringify(keyGroup);
      const restored: KeyGroup = JSON.parse(json) as KeyGroup;
      restored.createdAt = new Date(restored.createdAt);

      // Test signing
      const message = 'Serialization test';
      const p1 = await VeilKey.partialSign(message, restored.shares[0]!, restored);
      const p2 = await VeilKey.partialSign(message, restored.shares[1]!, restored);
      const signature = await VeilKey.combineSignatures(message, [p1, p2], restored);

      expect(await VeilKey.verify(message, signature, restored)).toBe(true);

      // Test decryption
      const plaintext = 42n;
      const ciphertext = await VeilKey.encrypt(plaintext, restored);
      const d1 = await VeilKey.partialDecrypt(ciphertext, restored.shares[0]!, restored);
      const d2 = await VeilKey.partialDecrypt(ciphertext, restored.shares[1]!, restored);
      const recovered = await VeilKey.combineDecryptions(ciphertext, [d1, d2], restored);

      expect(BigInt('0x' + recovered)).toBe(plaintext);
    });
  });

  // ===========================================================================
  // TVS Complete Workflow
  // ===========================================================================

  describe('TVS Complete Workflow', () => {
    it('should simulate full election lifecycle', async () => {
      // ===== ELECTION SETUP =====
      // Election authority generates 3-of-5 threshold key
      const election = await VeilKey.generate({
        threshold: 3,
        parties: 5,
        algorithm: 'RSA-2048',
      });

      // Shares distributed to 5 trustees
      const trustee1Share = election.shares[0]!;
      const trustee2Share = election.shares[1]!;
      const trustee3Share = election.shares[2]!;
      const trustee4Share = election.shares[3]!;
      const trustee5Share = election.shares[4]!;

      // Public key published for voters
      const publicKey = election.publicKey;

      // ===== VOTING PHASE =====
      // Simulate 5 voters, each encrypting their AES key
      const votes: Array<{ voterId: string; aesKey: bigint; encryptedKey: string }> = [];

      for (let i = 0; i < 5; i++) {
        // Each vote uses a random AES key
        const aesKey = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER));
        const encryptedKey = await VeilKey.encrypt(aesKey, election);

        votes.push({
          voterId: `voter-${i + 1}`,
          aesKey,
          encryptedKey,
        });
      }

      // ===== TALLYING PHASE =====
      // Trustees 1, 3, 5 participate (any 3 of 5)
      for (const vote of votes) {
        // Each trustee computes their partial decryption
        const partial1 = await VeilKey.partialDecrypt(
          vote.encryptedKey,
          trustee1Share,
          election
        );
        const partial3 = await VeilKey.partialDecrypt(
          vote.encryptedKey,
          trustee3Share,
          election
        );
        const partial5 = await VeilKey.partialDecrypt(
          vote.encryptedKey,
          trustee5Share,
          election
        );

        // Combine partial decryptions
        const recoveredKeyHex = await VeilKey.combineDecryptions(
          vote.encryptedKey,
          [partial1, partial3, partial5],
          election
        );

        const recoveredKey = BigInt('0x' + recoveredKeyHex);

        // Verify decryption is correct
        expect(recoveredKey).toBe(vote.aesKey);
      }
    });

    it('should demonstrate t-1 trustees cannot decrypt', async () => {
      const election = await VeilKey.generate({
        threshold: 3,
        parties: 5,
        algorithm: 'RSA-2048',
      });

      const aesKey = 12345n;
      const encryptedKey = await VeilKey.encrypt(aesKey, election);

      // Only 2 trustees try to decrypt (need 3)
      const partial1 = await VeilKey.partialDecrypt(encryptedKey, election.shares[0]!, election);
      const partial2 = await VeilKey.partialDecrypt(encryptedKey, election.shares[1]!, election);

      // Should fail
      await expect(
        VeilKey.combineDecryptions(encryptedKey, [partial1, partial2], election)
      ).rejects.toThrow('Need 3');
    });
  });

  // ===========================================================================
  // Edge Cases
  // ===========================================================================

  describe('Edge Cases', () => {
    it('should handle empty string message for signing', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const p1 = await VeilKey.partialSign('', keyGroup.shares[0]!, keyGroup);
      const p2 = await VeilKey.partialSign('', keyGroup.shares[1]!, keyGroup);
      const signature = await VeilKey.combineSignatures('', [p1, p2], keyGroup);

      expect(await VeilKey.verify('', signature, keyGroup)).toBe(true);
    });

    it('should handle Unicode message for signing', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = '你好世界 🌍 مرحبا';

      const p1 = await VeilKey.partialSign(message, keyGroup.shares[0]!, keyGroup);
      const p2 = await VeilKey.partialSign(message, keyGroup.shares[1]!, keyGroup);
      const signature = await VeilKey.combineSignatures(message, [p1, p2], keyGroup);

      expect(await VeilKey.verify(message, signature, keyGroup)).toBe(true);
    });

    it('should handle small plaintext for decryption', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const plaintext = 1n;
      const ciphertext = await VeilKey.encrypt(plaintext, keyGroup);

      const d1 = await VeilKey.partialDecrypt(ciphertext, keyGroup.shares[0]!, keyGroup);
      const d2 = await VeilKey.partialDecrypt(ciphertext, keyGroup.shares[1]!, keyGroup);
      const recovered = await VeilKey.combineDecryptions(ciphertext, [d1, d2], keyGroup);

      expect(BigInt('0x' + recovered)).toBe(plaintext);
    });
  });
});

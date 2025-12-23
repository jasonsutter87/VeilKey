/**
 * Tests for VeilKey main API
 */

import { describe, it, expect } from 'vitest';
import { VeilKey } from './veilkey.js';
import type { VeilKeyConfig, KeyGroup, PartialSignatureResult } from './veilkey.js';

describe('VeilKey', () => {
  describe('generate', () => {
    it('should generate a 2-of-3 RSA-2048 key group', async () => {
      const config: VeilKeyConfig = {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      };

      const keyGroup = await VeilKey.generate(config);

      expect(keyGroup.id).toBeDefined();
      expect(keyGroup.id.length).toBe(36); // UUID format
      expect(keyGroup.publicKey).toBeDefined();
      expect(keyGroup.publicKey).toContain(':'); // n:e format
      expect(keyGroup.algorithm).toBe('RSA-2048');
      expect(keyGroup.threshold).toBe(2);
      expect(keyGroup.parties).toBe(3);
      expect(keyGroup.shares).toHaveLength(3);
      expect(keyGroup.delta).toBeDefined();
      expect(keyGroup.delta).toBe('06'); // 3! = 6
      expect(keyGroup.createdAt).toBeInstanceOf(Date);

      // Verify each share
      for (let i = 0; i < 3; i++) {
        const share = keyGroup.shares[i];
        expect(share).toBeDefined();
        expect(share!.index).toBe(i + 1);
        expect(share!.value).toBeDefined();
        expect(share!.value.length).toBeGreaterThan(0);
      }
    });

    it('should generate a 3-of-5 RSA-2048 key group', async () => {
      const config: VeilKeyConfig = {
        threshold: 3,
        parties: 5,
        algorithm: 'RSA-2048',
      };

      const keyGroup = await VeilKey.generate(config);

      expect(keyGroup.shares).toHaveLength(5);
      expect(keyGroup.threshold).toBe(3);
      expect(keyGroup.delta).toBe('78'); // 5! = 120 = 0x78
    });

    it('should generate unique IDs for each key group', async () => {
      const config: VeilKeyConfig = {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      };

      const keyGroup1 = await VeilKey.generate(config);
      const keyGroup2 = await VeilKey.generate(config);

      expect(keyGroup1.id).not.toBe(keyGroup2.id);
      expect(keyGroup1.publicKey).not.toBe(keyGroup2.publicKey);
    });

    it('should reject threshold greater than parties', async () => {
      await expect(
        VeilKey.generate({ threshold: 5, parties: 3, algorithm: 'RSA-2048' })
      ).rejects.toThrow('cannot exceed');
    });

    it('should reject invalid threshold', async () => {
      await expect(
        VeilKey.generate({ threshold: 0, parties: 3, algorithm: 'RSA-2048' })
      ).rejects.toThrow('positive integer');
    });

    it('should reject invalid algorithm', async () => {
      await expect(
        VeilKey.generate({ threshold: 2, parties: 3, algorithm: 'INVALID' as 'RSA-2048' })
      ).rejects.toThrow('Unsupported algorithm');
    });
  });

  describe('threshold signing workflow', () => {
    it('should sign and verify with Uint8Array message (2-of-3)', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = new TextEncoder().encode('Hello, VeilKey!');

      // Create partial signatures with 2 shares
      const partial1 = await VeilKey.partialSign(message, keyGroup.shares[0]!, keyGroup);
      const partial2 = await VeilKey.partialSign(message, keyGroup.shares[1]!, keyGroup);

      expect(partial1.index).toBe(1);
      expect(partial2.index).toBe(2);

      // Combine signatures
      const signature = await VeilKey.combine(message, [partial1, partial2], keyGroup);
      expect(signature).toBeDefined();
      expect(signature.length).toBeGreaterThan(0);

      // Verify
      const isValid = await VeilKey.verify(message, signature, keyGroup);
      expect(isValid).toBe(true);
    });

    it('should sign and verify with string message', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = 'Hello, VeilKey with string!';

      const partial1 = await VeilKey.partialSign(message, keyGroup.shares[0]!, keyGroup);
      const partial2 = await VeilKey.partialSign(message, keyGroup.shares[1]!, keyGroup);

      const signature = await VeilKey.combine(message, [partial1, partial2], keyGroup);
      const isValid = await VeilKey.verify(message, signature, keyGroup);

      expect(isValid).toBe(true);
    });

    it('should work with different share combinations', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = 'Testing different combinations';

      // Try shares 0 and 2 (skipping 1)
      const partial1 = await VeilKey.partialSign(message, keyGroup.shares[0]!, keyGroup);
      const partial3 = await VeilKey.partialSign(message, keyGroup.shares[2]!, keyGroup);

      const signature = await VeilKey.combine(message, [partial1, partial3], keyGroup);
      const isValid = await VeilKey.verify(message, signature, keyGroup);

      expect(isValid).toBe(true);
    });

    it('should work with 3-of-5 threshold', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 3,
        parties: 5,
        algorithm: 'RSA-2048',
      });

      const message = 'Testing 3-of-5 threshold';

      const partial1 = await VeilKey.partialSign(message, keyGroup.shares[0]!, keyGroup);
      const partial2 = await VeilKey.partialSign(message, keyGroup.shares[2]!, keyGroup);
      const partial3 = await VeilKey.partialSign(message, keyGroup.shares[4]!, keyGroup);

      const signature = await VeilKey.combine(message, [partial1, partial2, partial3], keyGroup);
      const isValid = await VeilKey.verify(message, signature, keyGroup);

      expect(isValid).toBe(true);
    });

    it('should reject wrong message during verification', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const originalMessage = 'Original message';
      const wrongMessage = 'Wrong message';

      const partial1 = await VeilKey.partialSign(originalMessage, keyGroup.shares[0]!, keyGroup);
      const partial2 = await VeilKey.partialSign(originalMessage, keyGroup.shares[1]!, keyGroup);

      const signature = await VeilKey.combine(originalMessage, [partial1, partial2], keyGroup);

      // Verify with wrong message should fail
      const isValid = await VeilKey.verify(wrongMessage, signature, keyGroup);
      expect(isValid).toBe(false);
    });
  });

  describe('error handling', () => {
    it('should reject insufficient partial signatures', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 3,
        parties: 5,
        algorithm: 'RSA-2048',
      });

      const message = 'Test message';

      // Only 2 partials when we need 3
      const partial1 = await VeilKey.partialSign(message, keyGroup.shares[0]!, keyGroup);
      const partial2 = await VeilKey.partialSign(message, keyGroup.shares[1]!, keyGroup);

      await expect(
        VeilKey.combine(message, [partial1, partial2], keyGroup)
      ).rejects.toThrow('Insufficient partial signatures');
    });
  });

  describe('serialization', () => {
    it('should work after JSON serialization/deserialization', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      // Serialize and deserialize
      const serialized = JSON.stringify(keyGroup);
      const deserialized: KeyGroup = JSON.parse(serialized) as KeyGroup;
      deserialized.createdAt = new Date(deserialized.createdAt);

      const message = 'Testing serialization';

      const partial1 = await VeilKey.partialSign(message, deserialized.shares[0]!, deserialized);
      const partial2 = await VeilKey.partialSign(message, deserialized.shares[1]!, deserialized);

      const signature = await VeilKey.combine(message, [partial1, partial2], deserialized);
      const isValid = await VeilKey.verify(message, signature, deserialized);

      expect(isValid).toBe(true);
    });

    it('should serialize partial signatures correctly', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = 'Partial serialization test';
      const partial = await VeilKey.partialSign(message, keyGroup.shares[0]!, keyGroup);

      // Serialize and deserialize partial
      const serialized = JSON.stringify(partial);
      const deserialized: PartialSignatureResult = JSON.parse(serialized) as PartialSignatureResult;

      expect(deserialized.index).toBe(partial.index);
      expect(deserialized.partial).toBe(partial.partial);
    });
  });

  describe('edge cases', () => {
    it('should handle empty messages', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = '';

      const partial1 = await VeilKey.partialSign(message, keyGroup.shares[0]!, keyGroup);
      const partial2 = await VeilKey.partialSign(message, keyGroup.shares[1]!, keyGroup);

      const signature = await VeilKey.combine(message, [partial1, partial2], keyGroup);
      const isValid = await VeilKey.verify(message, signature, keyGroup);

      expect(isValid).toBe(true);
    });

    it('should handle long messages', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = 'A'.repeat(10000);

      const partial1 = await VeilKey.partialSign(message, keyGroup.shares[0]!, keyGroup);
      const partial2 = await VeilKey.partialSign(message, keyGroup.shares[1]!, keyGroup);

      const signature = await VeilKey.combine(message, [partial1, partial2], keyGroup);
      const isValid = await VeilKey.verify(message, signature, keyGroup);

      expect(isValid).toBe(true);
    });

    it('should handle Unicode messages', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = '你好世界! 🌍 مرحبا';

      const partial1 = await VeilKey.partialSign(message, keyGroup.shares[0]!, keyGroup);
      const partial2 = await VeilKey.partialSign(message, keyGroup.shares[1]!, keyGroup);

      const signature = await VeilKey.combine(message, [partial1, partial2], keyGroup);
      const isValid = await VeilKey.verify(message, signature, keyGroup);

      expect(isValid).toBe(true);
    });
  });
});

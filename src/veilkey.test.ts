/**
 * End-to-end tests for VeilKey API
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

      // Verify structure
      expect(keyGroup).toBeDefined();
      expect(keyGroup.id).toBeDefined();
      expect(typeof keyGroup.id).toBe('string');
      expect(keyGroup.publicKey).toBeDefined();
      expect(typeof keyGroup.publicKey).toBe('string');
      expect(keyGroup.algorithm).toBe('RSA-2048');
      expect(keyGroup.threshold).toBe(2);
      expect(keyGroup.parties).toBe(3);
      expect(keyGroup.shares).toHaveLength(3);
      expect(keyGroup.createdAt).toBeInstanceOf(Date);

      // Verify each share
      keyGroup.shares.forEach((share, index) => {
        expect(share.index).toBe(index + 1); // Shares are 1-indexed
        expect(share.value).toBeDefined();
        expect(typeof share.value).toBe('string');
        expect(share.value.length).toBeGreaterThan(0);
      });

      // Verify public key format (should be "n:e")
      expect(keyGroup.publicKey).toContain(':');
      const [n, e] = keyGroup.publicKey.split(':');
      expect(n).toBeDefined();
      expect(e).toBeDefined();
      expect(n!.length).toBeGreaterThan(0);
      expect(e!.length).toBeGreaterThan(0);
    });

    it('should generate a 3-of-5 RSA-4096 key group', async () => {
      const config: VeilKeyConfig = {
        threshold: 3,
        parties: 5,
        algorithm: 'RSA-4096',
      };

      const keyGroup = await VeilKey.generate(config);

      expect(keyGroup.algorithm).toBe('RSA-4096');
      expect(keyGroup.threshold).toBe(3);
      expect(keyGroup.parties).toBe(5);
      expect(keyGroup.shares).toHaveLength(5);
    });

    it('should generate unique IDs for different key groups', async () => {
      const config: VeilKeyConfig = {
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      };

      const keyGroup1 = await VeilKey.generate(config);
      const keyGroup2 = await VeilKey.generate(config);

      expect(keyGroup1.id).not.toBe(keyGroup2.id);
    });

    describe('validation', () => {
      it('should reject threshold greater than parties', async () => {
        const config: VeilKeyConfig = {
          threshold: 5,
          parties: 3,
          algorithm: 'RSA-2048',
        };

        await expect(VeilKey.generate(config)).rejects.toThrow(
          'Threshold (5) cannot exceed number of parties (3)'
        );
      });

      it('should reject threshold less than 1', async () => {
        const config: VeilKeyConfig = {
          threshold: 0,
          parties: 3,
          algorithm: 'RSA-2048',
        };

        await expect(VeilKey.generate(config)).rejects.toThrow(
          'Threshold must be a positive integer'
        );
      });

      it('should reject parties less than 1', async () => {
        const config: VeilKeyConfig = {
          threshold: 2,
          parties: 0,
          algorithm: 'RSA-2048',
        };

        await expect(VeilKey.generate(config)).rejects.toThrow(
          'Parties must be a positive integer'
        );
      });

      it('should reject invalid algorithm', async () => {
        const config = {
          threshold: 2,
          parties: 3,
          algorithm: 'RSA-1024', // Invalid
        } as VeilKeyConfig;

        await expect(VeilKey.generate(config)).rejects.toThrow(
          'Unsupported algorithm'
        );
      });

      it('should reject non-integer threshold', async () => {
        const config = {
          threshold: 2.5,
          parties: 3,
          algorithm: 'RSA-2048',
        } as VeilKeyConfig;

        await expect(VeilKey.generate(config)).rejects.toThrow(
          'Threshold must be a positive integer'
        );
      });

      it('should reject non-integer parties', async () => {
        const config = {
          threshold: 2,
          parties: 3.7,
          algorithm: 'RSA-2048',
        } as VeilKeyConfig;

        await expect(VeilKey.generate(config)).rejects.toThrow(
          'Parties must be a positive integer'
        );
      });
    });
  });

  describe('end-to-end threshold signing', () => {
    it('should sign and verify with 2-of-3 threshold using Uint8Array message', async () => {
      // Generate key group
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      // Message to sign
      const message = new Uint8Array([1, 2, 3, 4, 5]);

      // Create partial signatures with first 2 shares
      const partial1 = await VeilKey.partialSign(
        message,
        keyGroup.shares[0]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      const partial2 = await VeilKey.partialSign(
        message,
        keyGroup.shares[1]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      // Verify partial signature structure
      expect(partial1.index).toBe(1);
      expect(partial1.partial).toBeDefined();
      expect(typeof partial1.partial).toBe('string');

      expect(partial2.index).toBe(2);
      expect(partial2.partial).toBeDefined();
      expect(typeof partial2.partial).toBe('string');

      // Combine partial signatures
      const signature = await VeilKey.combine(
        [partial1, partial2],
        keyGroup.publicKey,
        keyGroup.algorithm,
        keyGroup.threshold
      );

      expect(signature).toBeDefined();
      expect(typeof signature).toBe('string');
      expect(signature.length).toBeGreaterThan(0);

      // Verify signature
      const isValid = await VeilKey.verify(
        message,
        signature,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      expect(isValid).toBe(true);
    });

    it('should sign and verify with string message', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = 'Hello, VeilKey! Trust no single party.';

      // Create partial signatures
      const partial1 = await VeilKey.partialSign(
        message,
        keyGroup.shares[0]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      const partial2 = await VeilKey.partialSign(
        message,
        keyGroup.shares[1]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      // Combine and verify
      const signature = await VeilKey.combine(
        [partial1, partial2],
        keyGroup.publicKey,
        keyGroup.algorithm,
        keyGroup.threshold
      );

      const isValid = await VeilKey.verify(
        message,
        signature,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      expect(isValid).toBe(true);
    });

    it('should work with different share combinations (shares 0,1 vs 1,2)', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = 'Test message';

      // Combination 1: shares 0 and 1
      const partial1a = await VeilKey.partialSign(
        message,
        keyGroup.shares[0]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );
      const partial1b = await VeilKey.partialSign(
        message,
        keyGroup.shares[1]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );
      const signature1 = await VeilKey.combine(
        [partial1a, partial1b],
        keyGroup.publicKey,
        keyGroup.algorithm,
        keyGroup.threshold
      );

      // Combination 2: shares 1 and 2
      const partial2a = await VeilKey.partialSign(
        message,
        keyGroup.shares[1]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );
      const partial2b = await VeilKey.partialSign(
        message,
        keyGroup.shares[2]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );
      const signature2 = await VeilKey.combine(
        [partial2a, partial2b],
        keyGroup.publicKey,
        keyGroup.algorithm,
        keyGroup.threshold
      );

      // Both signatures should be valid
      expect(await VeilKey.verify(message, signature1, keyGroup.publicKey, keyGroup.algorithm)).toBe(true);
      expect(await VeilKey.verify(message, signature2, keyGroup.publicKey, keyGroup.algorithm)).toBe(true);
    });

    it('should reject signature with wrong message', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = 'Original message';
      const wrongMessage = 'Different message';

      // Sign with original message
      const partial1 = await VeilKey.partialSign(
        message,
        keyGroup.shares[0]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );
      const partial2 = await VeilKey.partialSign(
        message,
        keyGroup.shares[1]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );
      const signature = await VeilKey.combine(
        [partial1, partial2],
        keyGroup.publicKey,
        keyGroup.algorithm,
        keyGroup.threshold
      );

      // Verify with wrong message
      const isValid = await VeilKey.verify(
        wrongMessage,
        signature,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      expect(isValid).toBe(false);
    });

    it('should handle 3-of-5 threshold', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 3,
        parties: 5,
        algorithm: 'RSA-2048',
      });

      const message = 'Test with higher threshold';

      // Use shares 0, 2, and 4 (any 3 should work)
      const partial1 = await VeilKey.partialSign(
        message,
        keyGroup.shares[0]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );
      const partial2 = await VeilKey.partialSign(
        message,
        keyGroup.shares[2]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );
      const partial3 = await VeilKey.partialSign(
        message,
        keyGroup.shares[4]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      const signature = await VeilKey.combine(
        [partial1, partial2, partial3],
        keyGroup.publicKey,
        keyGroup.algorithm,
        keyGroup.threshold
      );

      const isValid = await VeilKey.verify(
        message,
        signature,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      expect(isValid).toBe(true);
    });
  });

  describe('error cases', () => {
    it('should reject combine with insufficient partial signatures', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = 'Test message';

      // Only create 1 partial signature when threshold is 2
      const partial1 = await VeilKey.partialSign(
        message,
        keyGroup.shares[0]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      await expect(
        VeilKey.combine(
          [partial1],
          keyGroup.publicKey,
          keyGroup.algorithm,
          keyGroup.threshold
        )
      ).rejects.toThrow('Insufficient partial signatures: need 2, got 1');
    });

    it('should handle empty message', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = new Uint8Array([]);

      const partial1 = await VeilKey.partialSign(
        message,
        keyGroup.shares[0]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );
      const partial2 = await VeilKey.partialSign(
        message,
        keyGroup.shares[1]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      const signature = await VeilKey.combine(
        [partial1, partial2],
        keyGroup.publicKey,
        keyGroup.algorithm,
        keyGroup.threshold
      );

      const isValid = await VeilKey.verify(
        message,
        signature,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      // Should still work with empty message
      expect(isValid).toBe(true);
    });

    it('should handle very long message', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      // Create a long message
      const longMessage = 'A'.repeat(10000);

      const partial1 = await VeilKey.partialSign(
        longMessage,
        keyGroup.shares[0]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );
      const partial2 = await VeilKey.partialSign(
        longMessage,
        keyGroup.shares[1]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      const signature = await VeilKey.combine(
        [partial1, partial2],
        keyGroup.publicKey,
        keyGroup.algorithm,
        keyGroup.threshold
      );

      const isValid = await VeilKey.verify(
        longMessage,
        signature,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      expect(isValid).toBe(true);
    });
  });

  describe('serialization and deserialization', () => {
    it('should maintain functionality after JSON serialization', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      // Serialize and deserialize
      const serialized = JSON.stringify(keyGroup);
      const deserialized: KeyGroup = JSON.parse(serialized);

      // Convert createdAt back to Date
      deserialized.createdAt = new Date(deserialized.createdAt);

      // Should still be able to use the deserialized key group
      const message = 'Test after serialization';

      const partial1 = await VeilKey.partialSign(
        message,
        deserialized.shares[0]!,
        deserialized.publicKey,
        deserialized.algorithm
      );
      const partial2 = await VeilKey.partialSign(
        message,
        deserialized.shares[1]!,
        deserialized.publicKey,
        deserialized.algorithm
      );

      const signature = await VeilKey.combine(
        [partial1, partial2],
        deserialized.publicKey,
        deserialized.algorithm,
        deserialized.threshold
      );

      const isValid = await VeilKey.verify(
        message,
        signature,
        deserialized.publicKey,
        deserialized.algorithm
      );

      expect(isValid).toBe(true);
    });

    it('should serialize partial signatures correctly', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      const message = 'Test partial serialization';

      const partial = await VeilKey.partialSign(
        message,
        keyGroup.shares[0]!,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      // Serialize and deserialize partial
      const serialized = JSON.stringify(partial);
      const deserialized: PartialSignatureResult = JSON.parse(serialized);

      expect(deserialized.index).toBe(partial.index);
      expect(deserialized.partial).toBe(partial.partial);
    });
  });

  describe('edge cases', () => {
    it('should reject 1-of-1 threshold (threshold must be at least 2)', async () => {
      // The RSA implementation requires threshold >= 2 for security
      await expect(
        VeilKey.generate({
          threshold: 1,
          parties: 1,
          algorithm: 'RSA-2048',
        })
      ).rejects.toThrow('Threshold must be at least 2');
    });

    it('should work with n-of-n threshold (all parties required)', async () => {
      const keyGroup = await VeilKey.generate({
        threshold: 5,
        parties: 5,
        algorithm: 'RSA-2048',
      });

      const message = 'All parties required';

      // Need all 5 shares
      const partials = await Promise.all(
        keyGroup.shares.map((share) =>
          VeilKey.partialSign(message, share, keyGroup.publicKey, keyGroup.algorithm)
        )
      );

      const signature = await VeilKey.combine(
        partials,
        keyGroup.publicKey,
        keyGroup.algorithm,
        keyGroup.threshold
      );

      const isValid = await VeilKey.verify(
        message,
        signature,
        keyGroup.publicKey,
        keyGroup.algorithm
      );

      expect(isValid).toBe(true);
    });
  });
});

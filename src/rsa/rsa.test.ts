/**
 * Tests for Threshold RSA (Shoup protocol)
 */

import { describe, it, expect } from 'vitest';
import {
  generateKey,
  partialSign,
  combineSignatures,
  verify,
  verifyPartialSignature,
} from './index.js';
import type { ThresholdRSAConfig, PartialSignature } from './types.js';

describe('Threshold RSA (Shoup Protocol)', () => {
  describe('generateKey', () => {
    it('should generate a valid 2048-bit threshold RSA keypair (3-of-5)', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 3,
        totalShares: 5,
      };

      const keyPair = await generateKey(config);

      // Verify structure
      expect(keyPair.n).toBeDefined();
      expect(keyPair.e).toBe(65537n);
      expect(keyPair.shares).toHaveLength(5);
      expect(keyPair.verificationBase).toBeDefined();
      expect(keyPair.config).toEqual(config);
      expect(keyPair.delta).toBeDefined();
      expect(keyPair.delta).toBe(120n); // 5! = 120

      // Verify n is approximately the right size
      const nBits = keyPair.n.toString(2).length;
      expect(nBits).toBeGreaterThanOrEqual(2047);
      expect(nBits).toBeLessThanOrEqual(2049);

      // Verify each share has correct structure
      for (let i = 0; i < 5; i++) {
        const share = keyPair.shares[i];
        expect(share).toBeDefined();
        expect(share!.index).toBe(i + 1);
        expect(share!.value).toBeDefined();
        expect(share!.value).toBeGreaterThan(0n);
        expect(share!.verificationKey).toBeDefined();
        expect(share!.verificationKey).toBeGreaterThan(0n);
      }
    });

    it('should generate different keys on each call', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 2,
        totalShares: 3,
      };

      const keyPair1 = await generateKey(config);
      const keyPair2 = await generateKey(config);

      // Keys should be different
      expect(keyPair1.n).not.toBe(keyPair2.n);
      expect(keyPair1.shares[0]!.value).not.toBe(keyPair2.shares[0]!.value);
    });

    it('should reject invalid configurations', async () => {
      // Threshold > total shares
      await expect(
        generateKey({ bits: 2048, threshold: 6, totalShares: 5 })
      ).rejects.toThrow('Threshold cannot be greater than total shares');

      // Threshold too small
      await expect(
        generateKey({ bits: 2048, threshold: 1, totalShares: 5 })
      ).rejects.toThrow('Threshold must be at least 2');

      // Key size too small
      await expect(
        generateKey({ bits: 1024, threshold: 2, totalShares: 3 })
      ).rejects.toThrow('Key size must be at least 2048 bits');
    });
  });

  describe('partialSign', () => {
    it('should create a valid partial signature', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 3,
        totalShares: 5,
      };

      const keyPair = await generateKey(config);
      const message = new TextEncoder().encode('Hello, Threshold RSA!');

      const partial = partialSign(message, keyPair.shares[0]!, keyPair.n, keyPair.delta);

      expect(partial.index).toBe(1);
      expect(partial.value).toBeDefined();
      expect(partial.value).toBeGreaterThan(0n);
      expect(partial.value).toBeLessThan(keyPair.n);
    });

    it('should create different partials for different shares', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 3,
        totalShares: 5,
      };

      const keyPair = await generateKey(config);
      const message = new TextEncoder().encode('Test message');

      const partial1 = partialSign(message, keyPair.shares[0]!, keyPair.n, keyPair.delta);
      const partial2 = partialSign(message, keyPair.shares[1]!, keyPair.n, keyPair.delta);

      expect(partial1.value).not.toBe(partial2.value);
      expect(partial1.index).toBe(1);
      expect(partial2.index).toBe(2);
    });

    it('should create different partials for different messages', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 2,
        totalShares: 3,
      };

      const keyPair = await generateKey(config);
      const message1 = new TextEncoder().encode('Message 1');
      const message2 = new TextEncoder().encode('Message 2');

      const partial1 = partialSign(message1, keyPair.shares[0]!, keyPair.n, keyPair.delta);
      const partial2 = partialSign(message2, keyPair.shares[0]!, keyPair.n, keyPair.delta);

      expect(partial1.value).not.toBe(partial2.value);
    });
  });

  describe('combineSignatures', () => {
    it('should combine partial signatures into a valid full signature (3-of-5)', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 3,
        totalShares: 5,
      };

      const keyPair = await generateKey(config);
      const message = new TextEncoder().encode('Threshold signing test');

      // Create 3 partial signatures
      const partials: PartialSignature[] = [
        partialSign(message, keyPair.shares[0]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[1]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[2]!, keyPair.n, keyPair.delta),
      ];

      // Combine them
      const signature = combineSignatures(
        message,
        partials,
        config.threshold,
        keyPair.n,
        keyPair.e,
        keyPair.delta
      );

      // Verify the signature
      const isValid = verify(message, signature, keyPair.n, keyPair.e);
      expect(isValid).toBe(true);
    });

    it('should work with different subsets of shares', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 3,
        totalShares: 5,
      };

      const keyPair = await generateKey(config);
      const message = new TextEncoder().encode('Another test message');

      // Test with shares 1, 2, 3
      const partials1: PartialSignature[] = [
        partialSign(message, keyPair.shares[0]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[1]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[2]!, keyPair.n, keyPair.delta),
      ];

      const signature1 = combineSignatures(
        message,
        partials1,
        config.threshold,
        keyPair.n,
        keyPair.e,
        keyPair.delta
      );

      // Test with shares 2, 3, 4
      const partials2: PartialSignature[] = [
        partialSign(message, keyPair.shares[1]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[2]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[3]!, keyPair.n, keyPair.delta),
      ];

      const signature2 = combineSignatures(
        message,
        partials2,
        config.threshold,
        keyPair.n,
        keyPair.e,
        keyPair.delta
      );

      // Both signatures should be valid
      expect(verify(message, signature1, keyPair.n, keyPair.e)).toBe(true);
      expect(verify(message, signature2, keyPair.n, keyPair.e)).toBe(true);

      // Both signatures should actually be the same (unique signature for message)
      expect(signature1).toBe(signature2);
    });

    it('should reject insufficient partial signatures', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 3,
        totalShares: 5,
      };

      const keyPair = await generateKey(config);
      const message = new TextEncoder().encode('Insufficient shares test');

      // Only create 2 partial signatures (need 3)
      const partials: PartialSignature[] = [
        partialSign(message, keyPair.shares[0]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[1]!, keyPair.n, keyPair.delta),
      ];

      // Should throw error
      expect(() => {
        combineSignatures(message, partials, config.threshold, keyPair.n, keyPair.e, keyPair.delta);
      }).toThrow('Not enough partial signatures');
    });

    it('should work with more than threshold shares', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 3,
        totalShares: 5,
      };

      const keyPair = await generateKey(config);
      const message = new TextEncoder().encode('Extra shares test');

      // Create 4 partial signatures (only need 3)
      const partials: PartialSignature[] = [
        partialSign(message, keyPair.shares[0]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[1]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[2]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[3]!, keyPair.n, keyPair.delta),
      ];

      // Should use only first 3
      const signature = combineSignatures(
        message,
        partials,
        config.threshold,
        keyPair.n,
        keyPair.e,
        keyPair.delta
      );

      // Verify the signature
      expect(verify(message, signature, keyPair.n, keyPair.e)).toBe(true);
    });
  });

  describe('verify', () => {
    it('should verify a valid signature', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 2,
        totalShares: 3,
      };

      const keyPair = await generateKey(config);
      const message = new TextEncoder().encode('Verification test');

      const partials: PartialSignature[] = [
        partialSign(message, keyPair.shares[0]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[1]!, keyPair.n, keyPair.delta),
      ];

      const signature = combineSignatures(
        message,
        partials,
        config.threshold,
        keyPair.n,
        keyPair.e,
        keyPair.delta
      );

      expect(verify(message, signature, keyPair.n, keyPair.e)).toBe(true);
    });

    it('should reject an invalid signature', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 2,
        totalShares: 3,
      };

      const keyPair = await generateKey(config);
      const message = new TextEncoder().encode('Original message');

      const partials: PartialSignature[] = [
        partialSign(message, keyPair.shares[0]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[1]!, keyPair.n, keyPair.delta),
      ];

      const signature = combineSignatures(
        message,
        partials,
        config.threshold,
        keyPair.n,
        keyPair.e,
        keyPair.delta
      );

      // Modify the message
      const tamperedMessage = new TextEncoder().encode('Tampered message');

      // Verification should fail
      expect(verify(tamperedMessage, signature, keyPair.n, keyPair.e)).toBe(
        false
      );
    });

    it('should reject a tampered signature', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 2,
        totalShares: 3,
      };

      const keyPair = await generateKey(config);
      const message = new TextEncoder().encode('Message to sign');

      const partials: PartialSignature[] = [
        partialSign(message, keyPair.shares[0]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[1]!, keyPair.n, keyPair.delta),
      ];

      const signature = combineSignatures(
        message,
        partials,
        config.threshold,
        keyPair.n,
        keyPair.e,
        keyPair.delta
      );

      // Tamper with signature
      const tamperedSignature = signature + 1n;

      // Verification should fail
      expect(verify(message, tamperedSignature, keyPair.n, keyPair.e)).toBe(
        false
      );
    });
  });

  describe('verifyPartialSignature', () => {
    it('should verify a valid partial signature', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 2,
        totalShares: 3,
      };

      const keyPair = await generateKey(config);
      const message = new TextEncoder().encode('Partial verification test');

      const partial = partialSign(message, keyPair.shares[0]!, keyPair.n, keyPair.delta);

      const isValid = verifyPartialSignature(
        message,
        partial,
        keyPair.shares[0]!.verificationKey,
        keyPair.verificationBase,
        keyPair.n,
        keyPair.delta
      );

      // Basic verification should pass
      expect(isValid).toBe(true);
    });
  });

  describe('Integration tests', () => {
    it('should handle complete threshold signing workflow (2-of-3)', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 2,
        totalShares: 3,
      };

      // Step 1: Generate keys
      const keyPair = await generateKey(config);
      expect(keyPair.shares).toHaveLength(3);

      // Step 2: Distribute shares to 3 parties (simulated)
      const party1Share = keyPair.shares[0]!;
      const party2Share = keyPair.shares[1]!;

      // Step 3: Message to sign
      const message = new TextEncoder().encode('Complete workflow test');

      // Step 4: Parties 1 and 2 create partial signatures
      const partial1 = partialSign(message, party1Share, keyPair.n, keyPair.delta);
      const partial2 = partialSign(message, party2Share, keyPair.n, keyPair.delta);

      // Step 5: Combine partial signatures
      const signature = combineSignatures(
        message,
        [partial1, partial2],
        config.threshold,
        keyPair.n,
        keyPair.e,
        keyPair.delta
      );

      // Step 6: Anyone can verify with public key (n, e)
      const isValid = verify(message, signature, keyPair.n, keyPair.e);
      expect(isValid).toBe(true);

      // Step 7: Verify that a different message fails
      const differentMessage = new TextEncoder().encode('Different message');
      const isInvalid = verify(differentMessage, signature, keyPair.n, keyPair.e);
      expect(isInvalid).toBe(false);
    });

    it('should demonstrate that t-1 shares cannot create a valid signature', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 3,
        totalShares: 5,
      };

      const keyPair = await generateKey(config);
      const message = new TextEncoder().encode('Insufficient shares test');

      // Only 2 parties sign (need 3)
      const partials: PartialSignature[] = [
        partialSign(message, keyPair.shares[0]!, keyPair.n, keyPair.delta),
        partialSign(message, keyPair.shares[1]!, keyPair.n, keyPair.delta),
      ];

      // Attempting to combine should fail
      expect(() => {
        combineSignatures(message, partials, config.threshold, keyPair.n, keyPair.e, keyPair.delta);
      }).toThrow('Not enough partial signatures');
    });

    it('should sign and verify multiple different messages', async () => {
      const config: ThresholdRSAConfig = {
        bits: 2048,
        threshold: 2,
        totalShares: 3,
      };

      const keyPair = await generateKey(config);

      const messages = [
        'First message',
        'Second message',
        'Third message',
        'Message with special chars: 你好世界!',
        'Empty after this:',
        '12345',
      ];

      for (const msgText of messages) {
        const message = new TextEncoder().encode(msgText);

        const partials: PartialSignature[] = [
          partialSign(message, keyPair.shares[0]!, keyPair.n, keyPair.delta),
          partialSign(message, keyPair.shares[1]!, keyPair.n, keyPair.delta),
        ];

        const signature = combineSignatures(
          message,
          partials,
          config.threshold,
          keyPair.n,
          keyPair.e,
          keyPair.delta
        );

        expect(verify(message, signature, keyPair.n, keyPair.e)).toBe(true);
      }
    });
  });
});

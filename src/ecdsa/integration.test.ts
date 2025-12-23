/**
 * Threshold ECDSA Integration Tests
 *
 * Tests integration with the main VeilKey API and cross-module compatibility.
 */

import { describe, it, expect } from 'vitest';
import { ThresholdECDSA } from '../index.js';
import type {
  ThresholdECDSAConfig,
  ECDSAShare,
  ECDSASignature,
} from '../index.js';

describe('ThresholdECDSA - Integration', () => {
  it('should export via main index', () => {
    expect(ThresholdECDSA).toBeDefined();
    expect(ThresholdECDSA.generateKey).toBeDefined();
    expect(ThresholdECDSA.verify).toBeDefined();
  });

  it('should work with imported types', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    };

    const keypair = await ThresholdECDSA.generateKey(config);

    // Type checking
    const share: ECDSAShare = keypair.shares[0];
    expect(share.index).toBe(1);

    const message = new TextEncoder().encode('Integration test');
    const presignature = ThresholdECDSA.generatePresignature('secp256k1', [1, 2]);

    const partials = [
      ThresholdECDSA.partialSign(message, keypair.shares[0], presignature),
      ThresholdECDSA.partialSign(message, keypair.shares[1], presignature),
    ];

    const signature: ECDSASignature = ThresholdECDSA.combineSignatures(
      partials,
      2,
      presignature
    );

    expect(signature.r).toBeGreaterThan(0n);
    expect(signature.s).toBeGreaterThan(0n);

    const result = ThresholdECDSA.verify(message, signature, keypair.publicKey);
    expect(result.valid).toBe(true);
  });

  it('should handle serialization round-trip', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    };

    const keypair = await ThresholdECDSA.generateKey(config);

    // Serialize share
    const shareJSON = JSON.stringify({
      index: keypair.shares[0].index,
      value: keypair.shares[0].value.toString(),
      verificationKey: keypair.shares[0].verificationKey,
    });

    // Deserialize
    const parsed = JSON.parse(shareJSON);
    const restoredShare: ECDSAShare = {
      index: parsed.index,
      value: BigInt(parsed.value),
      verificationKey: parsed.verificationKey,
    };

    // Verify restored share works
    expect(ThresholdECDSA.verifyShare(restoredShare)).toBe(true);

    const message = new TextEncoder().encode('Serialization test');
    const presignature = ThresholdECDSA.generatePresignature('secp256k1', [1, 2]);

    const partial = ThresholdECDSA.partialSign(message, restoredShare, presignature);
    expect(partial.value).toBeGreaterThan(0n);
  });

  it('should maintain compatibility across different threshold configurations', async () => {
    // Test that public keys are correctly computed for various configurations
    const configs: ThresholdECDSAConfig[] = [
      { curve: 'secp256k1', threshold: 2, totalShares: 3 },
      { curve: 'secp256k1', threshold: 3, totalShares: 5 },
      { curve: 'secp256k1', threshold: 5, totalShares: 7 },
      { curve: 'P-256', threshold: 2, totalShares: 3 },
      { curve: 'P-256', threshold: 3, totalShares: 5 },
    ];

    for (const config of configs) {
      const keypair = await ThresholdECDSA.generateKey(config);

      expect(keypair.shares).toHaveLength(config.totalShares);
      expect(ThresholdECDSA.verifyAllShares(keypair)).toBe(true);

      const message = new TextEncoder().encode('Compatibility test');
      const indices = Array.from({ length: config.threshold }, (_, i) => i + 1);
      const presignature = ThresholdECDSA.generatePresignature(config.curve, indices);

      const partials = indices.map(i =>
        ThresholdECDSA.partialSign(message, keypair.shares[i - 1], presignature)
      );

      const signature = ThresholdECDSA.combineSignatures(
        partials,
        config.threshold,
        presignature
      );

      const result = ThresholdECDSA.verify(message, signature, keypair.publicKey);
      expect(result.valid).toBe(true);
    }
  });

  it('should work with real-world message sizes', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    };

    const keypair = await ThresholdECDSA.generateKey(config);

    // Test various message sizes
    const messageSizes = [0, 32, 256, 1024, 10000];

    for (const size of messageSizes) {
      const message = new Uint8Array(size).fill(42);
      const presignature = ThresholdECDSA.generatePresignature('secp256k1', [1, 2]);

      const partials = [
        ThresholdECDSA.partialSign(message, keypair.shares[0], presignature),
        ThresholdECDSA.partialSign(message, keypair.shares[1], presignature),
      ];

      const signature = ThresholdECDSA.combineSignatures(partials, 2, presignature);
      const result = ThresholdECDSA.verify(message, signature, keypair.publicKey);

      expect(result.valid).toBe(true);
    }
  });
});

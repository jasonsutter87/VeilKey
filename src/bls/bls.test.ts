/**
 * Threshold BLS Tests
 *
 * Comprehensive tests for BLS12-381 threshold signatures.
 */

import { describe, it, expect } from 'vitest';
import {
  ThresholdBLS,
  generateKey,
  partialSign,
  combineSignatures,
  verify,
  verifyPartial,
  verifyShare,
  verifyAllShares,
  aggregateSignatures,
  aggregatePublicKeys,
  batchVerify,
} from './index.js';
import type {
  ThresholdBLSConfig,
  ThresholdBLSKeyPair,
  PartialBLSSignature,
} from './types.js';

// =============================================================================
// Test Helpers
// =============================================================================

function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

// =============================================================================
// Key Generation Tests
// =============================================================================

describe('Threshold BLS Key Generation', () => {
  describe('generateKey', () => {
    it('should generate a valid 2-of-3 keypair', async () => {
      const config: ThresholdBLSConfig = {
        threshold: 2,
        totalShares: 3,
      };

      const keypair = await generateKey(config);

      expect(keypair.publicKey).toBeDefined();
      expect(keypair.publicKey.group).toBe('G1'); // default short mode
      expect(keypair.shares).toHaveLength(3);
      expect(keypair.verificationKeys).toHaveLength(3);
      expect(keypair.config.threshold).toBe(2);
      expect(keypair.config.totalShares).toBe(3);
    });

    it('should generate a valid 3-of-5 keypair', async () => {
      const config: ThresholdBLSConfig = {
        threshold: 3,
        totalShares: 5,
      };

      const keypair = await generateKey(config);

      expect(keypair.shares).toHaveLength(5);
      expect(keypair.verificationKeys).toHaveLength(5);

      // All shares should have unique indices
      const indices = keypair.shares.map(s => s.index);
      expect(new Set(indices).size).toBe(5);
    });

    it('should generate unique keys each time', async () => {
      const config: ThresholdBLSConfig = {
        threshold: 2,
        totalShares: 3,
      };

      const keypair1 = await generateKey(config);
      const keypair2 = await generateKey(config);

      expect(keypair1.publicKey.value).not.toBe(keypair2.publicKey.value);
    });

    it('should support long signature mode', async () => {
      const config: ThresholdBLSConfig = {
        threshold: 2,
        totalShares: 3,
        mode: 'long',
      };

      const keypair = await generateKey(config);

      expect(keypair.publicKey.group).toBe('G2'); // long mode uses G2 for keys
      expect(keypair.shares[0]!.verificationKey.group).toBe('G2');
    });

    it('should reject invalid configurations', async () => {
      // Threshold > totalShares
      await expect(generateKey({ threshold: 5, totalShares: 3 })).rejects.toThrow(
        'Threshold cannot exceed total shares'
      );

      // Threshold < 2
      await expect(generateKey({ threshold: 1, totalShares: 3 })).rejects.toThrow(
        'Threshold must be at least 2'
      );

      // totalShares < 2 (but threshold > totalShares triggers first)
      await expect(generateKey({ threshold: 2, totalShares: 1 })).rejects.toThrow(
        'Threshold cannot exceed total shares'
      );
    });
  });
});

// =============================================================================
// Share Verification Tests
// =============================================================================

describe('Share Verification', () => {
  it('should verify valid shares', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });

    for (const share of keypair.shares) {
      expect(verifyShare(share, 'short')).toBe(true);
    }
  });

  it('should verify all shares in a keypair', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });
    expect(verifyAllShares(keypair)).toBe(true);
  });

  it('should detect tampered shares', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });

    // Tamper with share value
    const tamperedShare = {
      ...keypair.shares[0]!,
      value: keypair.shares[0]!.value + 1n,
    };

    expect(verifyShare(tamperedShare, 'short')).toBe(false);
  });
});

// =============================================================================
// Threshold Signing Tests
// =============================================================================

describe('Threshold Signing', () => {
  describe('2-of-3 signing', () => {
    let keypair: ThresholdBLSKeyPair;
    const message = stringToBytes('Hello VeilKey BLS!');

    beforeAll(async () => {
      keypair = await generateKey({ threshold: 2, totalShares: 3 });
    });

    it('should create valid partial signatures', () => {
      const partial = partialSign(message, keypair.shares[0]!, 'short');

      expect(partial.index).toBe(1);
      expect(partial.value.group).toBe('G2'); // short mode sigs in G2
      expect(partial.value.value).toBeDefined();
    });

    it('should sign and verify with threshold parties (2-of-3)', () => {
      // Create partials from shares 1 and 2
      const partial1 = partialSign(message, keypair.shares[0]!, 'short');
      const partial2 = partialSign(message, keypair.shares[1]!, 'short');

      // Combine
      const signature = combineSignatures([partial1, partial2], 2, 'short');

      expect(signature.participantIndices).toEqual([1, 2]);

      // Verify
      const result = verify(message, signature, keypair.publicKey);
      expect(result.valid).toBe(true);
    });

    it('should produce same signature from different share subsets', () => {
      // Shares 1 and 2
      const partial1a = partialSign(message, keypair.shares[0]!, 'short');
      const partial2a = partialSign(message, keypair.shares[1]!, 'short');
      const sig1 = combineSignatures([partial1a, partial2a], 2, 'short');

      // Shares 1 and 3
      const partial1b = partialSign(message, keypair.shares[0]!, 'short');
      const partial3 = partialSign(message, keypair.shares[2]!, 'short');
      const sig2 = combineSignatures([partial1b, partial3], 2, 'short');

      // Shares 2 and 3
      const partial2b = partialSign(message, keypair.shares[1]!, 'short');
      const partial3b = partialSign(message, keypair.shares[2]!, 'short');
      const sig3 = combineSignatures([partial2b, partial3b], 2, 'short');

      // All should produce the same signature
      expect(sig1.signature.value).toBe(sig2.signature.value);
      expect(sig2.signature.value).toBe(sig3.signature.value);
    });

    it('should reject tampered message', () => {
      const partial1 = partialSign(message, keypair.shares[0]!, 'short');
      const partial2 = partialSign(message, keypair.shares[1]!, 'short');
      const signature = combineSignatures([partial1, partial2], 2, 'short');

      // Verify with different message
      const wrongMessage = stringToBytes('Wrong message');
      const result = verify(wrongMessage, signature, keypair.publicKey);
      expect(result.valid).toBe(false);
    });

    it('should reject insufficient partials', () => {
      const partial1 = partialSign(message, keypair.shares[0]!, 'short');

      expect(() => combineSignatures([partial1], 2, 'short')).toThrow(
        'Need 2 partial signatures, got 1'
      );
    });
  });

  describe('3-of-5 signing', () => {
    it('should sign and verify with 3-of-5 threshold', async () => {
      const keypair = await generateKey({ threshold: 3, totalShares: 5 });
      const message = stringToBytes('Test 3-of-5 threshold BLS');

      // Create 3 partials
      const partials = [
        partialSign(message, keypair.shares[0]!, 'short'),
        partialSign(message, keypair.shares[2]!, 'short'),
        partialSign(message, keypair.shares[4]!, 'short'),
      ];

      const signature = combineSignatures(partials, 3, 'short');
      const result = verify(message, signature, keypair.publicKey);

      expect(result.valid).toBe(true);
    });
  });

  describe('Partial verification', () => {
    it('should verify partial signatures individually', async () => {
      const keypair = await generateKey({ threshold: 2, totalShares: 3 });
      const message = stringToBytes('Test partial verification');

      const partial = partialSign(message, keypair.shares[0]!, 'short');
      const result = verifyPartial(
        message,
        partial,
        keypair.shares[0]!.verificationKey,
        'short'
      );

      expect(result.valid).toBe(true);
    });

    it('should reject invalid partial signatures', async () => {
      const keypair = await generateKey({ threshold: 2, totalShares: 3 });
      const message = stringToBytes('Test partial verification');

      const partial = partialSign(message, keypair.shares[0]!, 'short');

      // Verify against wrong verification key
      const result = verifyPartial(
        message,
        partial,
        keypair.shares[1]!.verificationKey, // wrong key
        'short'
      );

      expect(result.valid).toBe(false);
    });
  });
});

// =============================================================================
// Signature Aggregation Tests
// =============================================================================

describe('Signature Aggregation', () => {
  it('should aggregate signatures from different signers', async () => {
    const message = stringToBytes('Same message for aggregation');

    // Generate 3 independent keypairs (not threshold)
    const keypair1 = await generateKey({ threshold: 2, totalShares: 2 });
    const keypair2 = await generateKey({ threshold: 2, totalShares: 2 });
    const keypair3 = await generateKey({ threshold: 2, totalShares: 2 });

    // Create full signatures from each
    const partials1 = keypair1.shares.map(s => partialSign(message, s, 'short'));
    const sig1 = combineSignatures(partials1, 2, 'short');

    const partials2 = keypair2.shares.map(s => partialSign(message, s, 'short'));
    const sig2 = combineSignatures(partials2, 2, 'short');

    const partials3 = keypair3.shares.map(s => partialSign(message, s, 'short'));
    const sig3 = combineSignatures(partials3, 2, 'short');

    // Aggregate signatures
    const aggregated = aggregateSignatures([sig1, sig2, sig3]);
    expect(aggregated.count).toBe(3);

    // Aggregate public keys
    const aggPubKey = aggregatePublicKeys([
      keypair1.publicKey,
      keypair2.publicKey,
      keypair3.publicKey,
    ]);

    // Verify aggregated signature against aggregated public key
    const result = verify(message, aggregated.signature, aggPubKey);
    expect(result.valid).toBe(true);
  });

  it('should reject aggregation of empty array', () => {
    expect(() => aggregateSignatures([])).toThrow('No signatures to aggregate');
    expect(() => aggregatePublicKeys([])).toThrow('No public keys to aggregate');
  });
});

// =============================================================================
// Batch Verification Tests
// =============================================================================

describe('Batch Verification', () => {
  it('should verify multiple signatures in batch', async () => {
    const messages = [
      stringToBytes('Message 1'),
      stringToBytes('Message 2'),
      stringToBytes('Message 3'),
    ];

    const keypairs = await Promise.all([
      generateKey({ threshold: 2, totalShares: 2 }),
      generateKey({ threshold: 2, totalShares: 2 }),
      generateKey({ threshold: 2, totalShares: 2 }),
    ]);

    const items = messages.map((msg, i) => {
      const keypair = keypairs[i]!;
      const partials = keypair.shares.map(s => partialSign(msg, s, 'short'));
      const sig = combineSignatures(partials, 2, 'short');
      return {
        message: msg,
        signature: sig.signature,
        publicKey: keypair.publicKey,
      };
    });

    const result = batchVerify(items);
    expect(result.valid).toBe(true);
  });

  it('should reject batch with one invalid signature', async () => {
    const messages = [
      stringToBytes('Message 1'),
      stringToBytes('Message 2'),
    ];

    const keypairs = await Promise.all([
      generateKey({ threshold: 2, totalShares: 2 }),
      generateKey({ threshold: 2, totalShares: 2 }),
    ]);

    // Create valid signature for first message
    const partials1 = keypairs[0]!.shares.map(s =>
      partialSign(messages[0]!, s, 'short')
    );
    const sig1 = combineSignatures(partials1, 2, 'short');

    // Create signature for second message with wrong key
    const partials2 = keypairs[1]!.shares.map(s =>
      partialSign(messages[1]!, s, 'short')
    );
    const sig2 = combineSignatures(partials2, 2, 'short');

    const items = [
      {
        message: messages[0]!,
        signature: sig1.signature,
        publicKey: keypairs[0]!.publicKey,
      },
      {
        message: messages[1]!,
        signature: sig2.signature,
        publicKey: keypairs[0]!.publicKey, // Wrong public key!
      },
    ];

    const result = batchVerify(items);
    expect(result.valid).toBe(false);
  });

  it('should handle empty batch', () => {
    const result = batchVerify([]);
    expect(result.valid).toBe(true);
  });
});

// =============================================================================
// Long Signature Mode Tests
// =============================================================================

describe('Long Signature Mode', () => {
  it('should generate and verify with long signatures', async () => {
    const keypair = await generateKey({
      threshold: 2,
      totalShares: 3,
      mode: 'long',
    });
    const message = stringToBytes('Test long signature mode');

    // Keys should be in G2, signatures in G1
    expect(keypair.publicKey.group).toBe('G2');

    const partial1 = partialSign(message, keypair.shares[0]!, 'long');
    const partial2 = partialSign(message, keypair.shares[1]!, 'long');

    expect(partial1.value.group).toBe('G1');

    const signature = combineSignatures([partial1, partial2], 2, 'long');
    const result = verify(message, signature, keypair.publicKey);

    expect(result.valid).toBe(true);
  });
});

// =============================================================================
// Edge Cases
// =============================================================================

describe('Edge Cases', () => {
  it('should handle empty message', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });
    const message = new Uint8Array(0);

    const partial1 = partialSign(message, keypair.shares[0]!, 'short');
    const partial2 = partialSign(message, keypair.shares[1]!, 'short');
    const signature = combineSignatures([partial1, partial2], 2, 'short');

    const result = verify(message, signature, keypair.publicKey);
    expect(result.valid).toBe(true);
  });

  it('should handle very long message', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });
    const message = new Uint8Array(10000).fill(0x42);

    const partial1 = partialSign(message, keypair.shares[0]!, 'short');
    const partial2 = partialSign(message, keypair.shares[1]!, 'short');
    const signature = combineSignatures([partial1, partial2], 2, 'short');

    const result = verify(message, signature, keypair.publicKey);
    expect(result.valid).toBe(true);
  });

  it('should handle threshold equal to totalShares', async () => {
    const keypair = await generateKey({ threshold: 3, totalShares: 3 });
    const message = stringToBytes('All parties must sign');

    // All 3 shares required
    const partials = keypair.shares.map(s => partialSign(message, s, 'short'));
    const signature = combineSignatures(partials, 3, 'short');

    const result = verify(message, signature, keypair.publicKey);
    expect(result.valid).toBe(true);
  });
});

// =============================================================================
// Namespace Export Tests
// =============================================================================

describe('ThresholdBLS Namespace', () => {
  it('should export all functions via namespace', () => {
    expect(ThresholdBLS.generateKey).toBeDefined();
    expect(ThresholdBLS.verifyShare).toBeDefined();
    expect(ThresholdBLS.verifyAllShares).toBeDefined();
    expect(ThresholdBLS.partialSign).toBeDefined();
    expect(ThresholdBLS.combineSignatures).toBeDefined();
    expect(ThresholdBLS.verify).toBeDefined();
    expect(ThresholdBLS.verifyPartial).toBeDefined();
    expect(ThresholdBLS.aggregateSignatures).toBeDefined();
    expect(ThresholdBLS.aggregatePublicKeys).toBeDefined();
    expect(ThresholdBLS.batchVerify).toBeDefined();
  });
});

/**
 * Threshold ECDSA Extended Tests
 *
 * Comprehensive extended test suite providing thorough coverage of:
 * - All threshold combinations (2-of-3 through 5-of-7)
 * - Both curves extensively (secp256k1 and P-256)
 * - Security properties and edge cases
 * - Error handling and validation
 *
 * Target: 60+ additional tests
 */

import { describe, it, expect } from 'vitest';
import {
  generateKey,
  verifyShare,
  verifyAllShares,
  generatePresignature,
  partialSign,
  combineSignatures,
  verify,
  verifyPartial,
  batchVerify,
} from './index.js';
import type {
  ThresholdECDSAConfig,
  ECDSACurve,
  PartialECDSASignature,
  ECDSASignature,
} from './types.js';

// =============================================================================
// Test Helpers
// =============================================================================

function createMessage(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

// =============================================================================
// Comprehensive Threshold Combinations
// =============================================================================

describe('ECDSA Extended - Threshold Combinations (secp256k1)', () => {
  it('should work with 2-of-4 threshold', async () => {
    const config: ThresholdECDSAConfig = { curve: 'secp256k1', threshold: 2, totalShares: 4 };
    const keypair = await generateKey(config);
    const message = createMessage('Test 2-of-4');
    const presignature = generatePresignature('secp256k1', [1, 2]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[1]!, presignature),
    ];

    const signature = combineSignatures(partials, 2, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 2-of-5 threshold', async () => {
    const config: ThresholdECDSAConfig = { curve: 'secp256k1', threshold: 2, totalShares: 5 };
    const keypair = await generateKey(config);
    const message = createMessage('Test 2-of-5');
    const presignature = generatePresignature('secp256k1', [1, 3]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[2]!, presignature),
    ];

    const signature = combineSignatures(partials, 2, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 3-of-4 threshold', async () => {
    const config: ThresholdECDSAConfig = { curve: 'secp256k1', threshold: 3, totalShares: 4 };
    const keypair = await generateKey(config);
    const message = createMessage('Test 3-of-4');
    const presignature = generatePresignature('secp256k1', [1, 2, 3]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[1]!, presignature),
      partialSign(message, keypair.shares[2]!, presignature),
    ];

    const signature = combineSignatures(partials, 3, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 3-of-6 threshold', async () => {
    const config: ThresholdECDSAConfig = { curve: 'secp256k1', threshold: 3, totalShares: 6 };
    const keypair = await generateKey(config);
    const message = createMessage('Test 3-of-6');
    const presignature = generatePresignature('secp256k1', [2, 4, 6]);

    const partials = [
      partialSign(message, keypair.shares[1]!, presignature),
      partialSign(message, keypair.shares[3]!, presignature),
      partialSign(message, keypair.shares[5]!, presignature),
    ];

    const signature = combineSignatures(partials, 3, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 4-of-5 threshold', async () => {
    const config: ThresholdECDSAConfig = { curve: 'secp256k1', threshold: 4, totalShares: 5 };
    const keypair = await generateKey(config);
    const message = createMessage('Test 4-of-5');
    const presignature = generatePresignature('secp256k1', [1, 2, 3, 4]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[1]!, presignature),
      partialSign(message, keypair.shares[2]!, presignature),
      partialSign(message, keypair.shares[3]!, presignature),
    ];

    const signature = combineSignatures(partials, 4, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 4-of-6 threshold', async () => {
    const config: ThresholdECDSAConfig = { curve: 'secp256k1', threshold: 4, totalShares: 6 };
    const keypair = await generateKey(config);
    const message = createMessage('Test 4-of-6');
    const presignature = generatePresignature('secp256k1', [1, 3, 4, 5]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[2]!, presignature),
      partialSign(message, keypair.shares[3]!, presignature),
      partialSign(message, keypair.shares[4]!, presignature),
    ];

    const signature = combineSignatures(partials, 4, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 4-of-7 threshold', async () => {
    const config: ThresholdECDSAConfig = { curve: 'secp256k1', threshold: 4, totalShares: 7 };
    const keypair = await generateKey(config);
    const message = createMessage('Test 4-of-7');
    const presignature = generatePresignature('secp256k1', [2, 3, 5, 7]);

    const partials = [
      partialSign(message, keypair.shares[1]!, presignature),
      partialSign(message, keypair.shares[2]!, presignature),
      partialSign(message, keypair.shares[4]!, presignature),
      partialSign(message, keypair.shares[6]!, presignature),
    ];

    const signature = combineSignatures(partials, 4, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 5-of-6 threshold', async () => {
    const config: ThresholdECDSAConfig = { curve: 'secp256k1', threshold: 5, totalShares: 6 };
    const keypair = await generateKey(config);
    const message = createMessage('Test 5-of-6');
    const presignature = generatePresignature('secp256k1', [1, 2, 3, 4, 5]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[1]!, presignature),
      partialSign(message, keypair.shares[2]!, presignature),
      partialSign(message, keypair.shares[3]!, presignature),
      partialSign(message, keypair.shares[4]!, presignature),
    ];

    const signature = combineSignatures(partials, 5, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });
});

describe('ECDSA Extended - Threshold Combinations (P-256)', () => {
  it('should work with 2-of-4 threshold on P-256', async () => {
    const config: ThresholdECDSAConfig = { curve: 'P-256', threshold: 2, totalShares: 4 };
    const keypair = await generateKey(config);
    const message = createMessage('P-256 test 2-of-4');
    const presignature = generatePresignature('P-256', [2, 4]);

    const partials = [
      partialSign(message, keypair.shares[1]!, presignature),
      partialSign(message, keypair.shares[3]!, presignature),
    ];

    const signature = combineSignatures(partials, 2, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 3-of-4 threshold on P-256', async () => {
    const config: ThresholdECDSAConfig = { curve: 'P-256', threshold: 3, totalShares: 4 };
    const keypair = await generateKey(config);
    const message = createMessage('P-256 test 3-of-4');
    const presignature = generatePresignature('P-256', [1, 2, 4]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[1]!, presignature),
      partialSign(message, keypair.shares[3]!, presignature),
    ];

    const signature = combineSignatures(partials, 3, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 4-of-6 threshold on P-256', async () => {
    const config: ThresholdECDSAConfig = { curve: 'P-256', threshold: 4, totalShares: 6 };
    const keypair = await generateKey(config);
    const message = createMessage('P-256 test 4-of-6');
    const presignature = generatePresignature('P-256', [1, 2, 5, 6]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[1]!, presignature),
      partialSign(message, keypair.shares[4]!, presignature),
      partialSign(message, keypair.shares[5]!, presignature),
    ];

    const signature = combineSignatures(partials, 4, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 5-of-7 threshold on P-256', async () => {
    const config: ThresholdECDSAConfig = { curve: 'P-256', threshold: 5, totalShares: 7 };
    const keypair = await generateKey(config);
    const message = createMessage('P-256 test 5-of-7');
    const presignature = generatePresignature('P-256', [1, 2, 3, 4, 5]);

    const partials = keypair.shares.slice(0, 5).map(share => partialSign(message, share, presignature));

    const signature = combineSignatures(partials, 5, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });
});

// =============================================================================
// Presignature Testing
// =============================================================================

describe('ECDSA Extended - Presignature Management', () => {
  it('should generate unique presignatures each time', () => {
    const presigs = Array.from({ length: 10 }, () =>
      generatePresignature('secp256k1', [1, 2, 3])
    );

    // All k values should be unique
    const kValues = presigs.map(p => p.k);
    const uniqueKValues = new Set(kValues);
    expect(uniqueKValues.size).toBe(10);

    // All r values should be unique
    const rValues = presigs.map(p => p.r);
    const uniqueRValues = new Set(rValues);
    expect(uniqueRValues.size).toBe(10);
  });

  it('should produce different signatures with different presignatures', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = createMessage('Same message');

    const presig1 = generatePresignature('secp256k1', [1, 2]);
    const sig1 = combineSignatures(
      [partialSign(message, keypair.shares[0]!, presig1), partialSign(message, keypair.shares[1]!, presig1)],
      2,
      presig1
    );

    const presig2 = generatePresignature('secp256k1', [1, 2]);
    const sig2 = combineSignatures(
      [partialSign(message, keypair.shares[0]!, presig2), partialSign(message, keypair.shares[1]!, presig2)],
      2,
      presig2
    );

    // Different presignatures should produce different r values
    expect(sig1.r).not.toBe(sig2.r);

    // But both should verify
    expect(verify(message, sig1, keypair.publicKey).valid).toBe(true);
    expect(verify(message, sig2, keypair.publicKey).valid).toBe(true);
  });

  it('should validate presignature curve consistency', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = createMessage('Test');
    const presignature = generatePresignature('secp256k1', [1, 2]);

    expect(presignature.curve).toBe('secp256k1');
    expect(presignature.R.curve).toBe('secp256k1');
  });

  it('should handle presignatures with different participant sets', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 5 });
    const message = createMessage('Test');

    // Different participant combinations
    const sets = [
      [1, 2],
      [1, 5],
      [2, 3],
      [3, 5],
    ];

    for (const indices of sets) {
      const presignature = generatePresignature('secp256k1', indices);
      const partials = indices.map(idx => partialSign(message, keypair.shares[idx - 1]!, presignature));
      const signature = combineSignatures(partials, 2, presignature);
      expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
    }
  });
});

// =============================================================================
// Message Edge Cases
// =============================================================================

describe('ECDSA Extended - Message Edge Cases', () => {
  it('should sign truly empty message (0 bytes)', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = new Uint8Array(0);
    const presignature = generatePresignature('secp256k1', [1, 2]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[1]!, presignature),
    ];

    const signature = combineSignatures(partials, 2, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should sign single byte message', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = new Uint8Array([42]);
    const presignature = generatePresignature('secp256k1', [1, 2]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[1]!, presignature),
    ];

    const signature = combineSignatures(partials, 2, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should sign maximum length message (100KB)', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = new Uint8Array(100000).fill(123);
    const presignature = generatePresignature('secp256k1', [1, 2]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[1]!, presignature),
    ];

    const signature = combineSignatures(partials, 2, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should sign unicode message correctly', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = createMessage('Hello 世界 🌍 مرحبا');
    const presignature = generatePresignature('secp256k1', [1, 2]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[1]!, presignature),
    ];

    const signature = combineSignatures(partials, 2, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should sign binary data (all byte values)', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      message[i] = i;
    }
    const presignature = generatePresignature('secp256k1', [1, 2]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[1]!, presignature),
    ];

    const signature = combineSignatures(partials, 2, presignature);
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should distinguish between similar messages', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const msg1 = createMessage('Message');
    const msg2 = createMessage('message'); // lowercase
    const msg3 = createMessage('Message '); // trailing space

    const presig1 = generatePresignature('secp256k1', [1, 2]);
    const sig1 = combineSignatures(
      [partialSign(msg1, keypair.shares[0]!, presig1), partialSign(msg1, keypair.shares[1]!, presig1)],
      2,
      presig1
    );

    expect(verify(msg1, sig1, keypair.publicKey).valid).toBe(true);
    expect(verify(msg2, sig1, keypair.publicKey).valid).toBe(false);
    expect(verify(msg3, sig1, keypair.publicKey).valid).toBe(false);
  });
});

// =============================================================================
// Partial Signature Validation
// =============================================================================

describe('ECDSA Extended - Partial Signature Validation', () => {
  it('should verify partial signatures are in valid range', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = createMessage('Test');
    const presignature = generatePresignature('secp256k1', [1, 2]);

    const partial = partialSign(message, keypair.shares[0]!, presignature);

    expect(verifyPartial(partial, 'secp256k1')).toBe(true);
    expect(partial.value).toBeGreaterThan(0n);
  });

  it('should reject partial with zero value', () => {
    const invalidPartial: PartialECDSASignature = { index: 1, value: 0n };
    expect(verifyPartial(invalidPartial, 'secp256k1')).toBe(false);
  });

  it('should reject partial with negative value', () => {
    const invalidPartial: PartialECDSASignature = { index: 1, value: -1n };
    expect(verifyPartial(invalidPartial, 'secp256k1')).toBe(false);
  });

  it('should verify partials from all shares', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 5 });
    const message = createMessage('Test all partials');
    const presignature = generatePresignature('secp256k1', [1, 2, 3, 4, 5]);

    for (const share of keypair.shares) {
      const partial = partialSign(message, share, presignature);
      expect(verifyPartial(partial, 'secp256k1')).toBe(true);
      expect(partial.index).toBe(share.index);
    }
  });
});

// =============================================================================
// Signature Malleability and Normalization
// =============================================================================

describe('ECDSA Extended - Signature Properties', () => {
  it('should produce low-S normalized signatures (malleability resistance)', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = createMessage('Test normalization');

    // Generate multiple signatures to test normalization
    for (let i = 0; i < 5; i++) {
      const presignature = generatePresignature('secp256k1', [1, 2]);
      const partials = [
        partialSign(message, keypair.shares[0]!, presignature),
        partialSign(message, keypair.shares[1]!, presignature),
      ];
      const signature = combineSignatures(partials, 2, presignature);

      // For secp256k1, curve order is known
      const secp256k1Order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
      const halfOrder = secp256k1Order >> 1n;

      // Signature should be normalized (low-S)
      expect(signature.s).toBeLessThanOrEqual(halfOrder);
    }
  });

  it('should produce valid r values in range', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = createMessage('Test r value');
    const presignature = generatePresignature('secp256k1', [1, 2]);

    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[1]!, presignature),
    ];
    const signature = combineSignatures(partials, 2, presignature);

    const secp256k1Order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    expect(signature.r).toBeGreaterThan(0n);
    expect(signature.r).toBeLessThan(secp256k1Order);
  });
});

// =============================================================================
// Different Participant Combinations
// =============================================================================

describe('ECDSA Extended - Participant Combinations', () => {
  it('should allow all possible 2-of-5 combinations', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 5 });
    const message = createMessage('Test all combinations');

    // All possible 2-of-5 combinations
    const combinations = [
      [1, 2], [1, 3], [1, 4], [1, 5],
      [2, 3], [2, 4], [2, 5],
      [3, 4], [3, 5],
      [4, 5],
    ];

    for (const indices of combinations) {
      const presignature = generatePresignature('secp256k1', indices);
      const partials = indices.map(idx => partialSign(message, keypair.shares[idx - 1]!, presignature));
      const signature = combineSignatures(partials, 2, presignature);
      expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
    }
  });

  it('should track participant indices in signature', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 5 });
    const message = createMessage('Test participant tracking');
    const presignature = generatePresignature('secp256k1', [2, 4]);

    const partials = [
      partialSign(message, keypair.shares[1]!, presignature),
      partialSign(message, keypair.shares[3]!, presignature),
    ];

    const signature = combineSignatures(partials, 2, presignature);
    expect(signature.participantIndices).toEqual([2, 4]);
  });
});

// =============================================================================
// Share Verification Edge Cases
// =============================================================================

describe('ECDSA Extended - Share Verification', () => {
  it('should detect share with wrong curve', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });

    // Tamper with verification key curve
    const tamperedShare = {
      ...keypair.shares[0]!,
      verificationKey: { ...keypair.shares[0]!.verificationKey, curve: 'P-256' as ECDSACurve },
    };

    expect(verifyShare(tamperedShare)).toBe(false);
  });

  it('should detect incrementally tampered share values', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });

    for (let i = 1; i <= 10; i++) {
      const tamperedShare = {
        ...keypair.shares[0]!,
        value: keypair.shares[0]!.value + BigInt(i),
      };
      expect(verifyShare(tamperedShare)).toBe(false);
    }
  });

  it('should verify all shares independently', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 3, totalShares: 7 });

    for (let i = 0; i < keypair.shares.length; i++) {
      expect(verifyShare(keypair.shares[i]!)).toBe(true);
    }
  });
});

// =============================================================================
// Batch Verification Extended
// =============================================================================

describe('ECDSA Extended - Batch Verification', () => {
  it('should verify batch of 10 signatures', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });

    const items = [];
    for (let i = 0; i < 10; i++) {
      const message = createMessage(`Batch message ${i}`);
      const presignature = generatePresignature('secp256k1', [1, 2]);
      const partials = [
        partialSign(message, keypair.shares[0]!, presignature),
        partialSign(message, keypair.shares[1]!, presignature),
      ];
      const signature = combineSignatures(partials, 2, presignature);
      items.push({ message, signature, publicKey: keypair.publicKey });
    }

    expect(batchVerify(items).valid).toBe(true);
  });

  it('should detect single invalid signature in batch of 10', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });

    const items = [];
    for (let i = 0; i < 10; i++) {
      const message = createMessage(`Batch message ${i}`);
      const presignature = generatePresignature('secp256k1', [1, 2]);
      const partials = [
        partialSign(message, keypair.shares[0]!, presignature),
        partialSign(message, keypair.shares[1]!, presignature),
      ];
      let signature = combineSignatures(partials, 2, presignature);

      // Tamper with signature at index 5
      if (i === 5) {
        signature = { ...signature, s: signature.s + 1n };
      }

      items.push({ message, signature, publicKey: keypair.publicKey });
    }

    expect(batchVerify(items).valid).toBe(false);
  });

  it('should handle batch with mixed curves (verify independently)', async () => {
    const secp256k1Keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const p256Keypair = await generateKey({ curve: 'P-256', threshold: 2, totalShares: 3 });

    const items = [];

    // Add secp256k1 signatures
    for (let i = 0; i < 3; i++) {
      const message = createMessage(`secp256k1 message ${i}`);
      const presignature = generatePresignature('secp256k1', [1, 2]);
      const partials = [
        partialSign(message, secp256k1Keypair.shares[0]!, presignature),
        partialSign(message, secp256k1Keypair.shares[1]!, presignature),
      ];
      const signature = combineSignatures(partials, 2, presignature);
      items.push({ message, signature, publicKey: secp256k1Keypair.publicKey });
    }

    // Add P-256 signatures
    for (let i = 0; i < 3; i++) {
      const message = createMessage(`P-256 message ${i}`);
      const presignature = generatePresignature('P-256', [1, 2]);
      const partials = [
        partialSign(message, p256Keypair.shares[0]!, presignature),
        partialSign(message, p256Keypair.shares[1]!, presignature),
      ];
      const signature = combineSignatures(partials, 2, presignature);
      items.push({ message, signature, publicKey: p256Keypair.publicKey });
    }

    expect(batchVerify(items).valid).toBe(true);
  });
});

// =============================================================================
// Error Handling and Validation
// =============================================================================

describe('ECDSA Extended - Error Handling', () => {
  it('should reject threshold of 0', async () => {
    await expect(
      generateKey({ curve: 'secp256k1', threshold: 0, totalShares: 3 })
    ).rejects.toThrow();
  });

  it('should reject negative threshold', async () => {
    await expect(
      generateKey({ curve: 'secp256k1', threshold: -1, totalShares: 3 })
    ).rejects.toThrow();
  });

  it('should reject total shares of 0', async () => {
    await expect(
      generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 0 })
    ).rejects.toThrow();
  });

  it('should reject combining with 0 partials', async () => {
    const presignature = generatePresignature('secp256k1', [1, 2]);
    expect(() => combineSignatures([], 2, presignature)).toThrow();
  });

  it('should reject signature with r >= curve order', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = createMessage('Test');
    const secp256k1Order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

    const invalidSig: ECDSASignature = {
      r: secp256k1Order, // At boundary
      s: 1n,
    };

    expect(verify(message, invalidSig, keypair.publicKey).valid).toBe(false);
  });

  it('should reject signature with s >= curve order', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = createMessage('Test');
    const secp256k1Order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

    const invalidSig: ECDSASignature = {
      r: 1n,
      s: secp256k1Order, // At boundary
    };

    expect(verify(message, invalidSig, keypair.publicKey).valid).toBe(false);
  });
});

// =============================================================================
// Cross-Curve Validation
// =============================================================================

describe('ECDSA Extended - Cross-Curve Prevention', () => {
  it('should not verify secp256k1 signature with P-256 public key', async () => {
    const secp256k1Keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const p256Keypair = await generateKey({ curve: 'P-256', threshold: 2, totalShares: 3 });

    const message = createMessage('Cross-curve test');
    const presignature = generatePresignature('secp256k1', [1, 2]);
    const partials = [
      partialSign(message, secp256k1Keypair.shares[0]!, presignature),
      partialSign(message, secp256k1Keypair.shares[1]!, presignature),
    ];
    const signature = combineSignatures(partials, 2, presignature);

    // Should fail to verify with wrong curve public key
    const result = verify(message, signature, p256Keypair.publicKey);
    expect(result.valid).toBe(false);
  });

  it('should maintain curve consistency throughout signing', async () => {
    const curves: ECDSACurve[] = ['secp256k1', 'P-256'];

    for (const curve of curves) {
      const keypair = await generateKey({ curve, threshold: 2, totalShares: 3 });
      const message = createMessage(`Test ${curve}`);
      const presignature = generatePresignature(curve, [1, 2]);

      expect(keypair.publicKey.curve).toBe(curve);
      expect(presignature.curve).toBe(curve);
      expect(presignature.R.curve).toBe(curve);

      for (const share of keypair.shares) {
        expect(share.verificationKey.curve).toBe(curve);
      }
    }
  });
});

// =============================================================================
// Determinism and Uniqueness
// =============================================================================

describe('ECDSA Extended - Determinism', () => {
  it('should produce different signatures for same message with different presignatures', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = createMessage('Same message');

    const signatures: ECDSASignature[] = [];
    for (let i = 0; i < 5; i++) {
      const presignature = generatePresignature('secp256k1', [1, 2]);
      const partials = [
        partialSign(message, keypair.shares[0]!, presignature),
        partialSign(message, keypair.shares[1]!, presignature),
      ];
      const signature = combineSignatures(partials, 2, presignature);
      signatures.push(signature);
    }

    // All signatures should be different (different r values)
    const rValues = signatures.map(s => s.r);
    const uniqueRValues = new Set(rValues);
    expect(uniqueRValues.size).toBe(5);

    // But all should verify
    for (const sig of signatures) {
      expect(verify(message, sig, keypair.publicKey).valid).toBe(true);
    }
  });

  it('should produce identical signature with same presignature and shares', async () => {
    const keypair = await generateKey({ curve: 'secp256k1', threshold: 2, totalShares: 3 });
    const message = createMessage('Same everything');
    const presignature = generatePresignature('secp256k1', [1, 2]);

    const sig1 = combineSignatures(
      [
        partialSign(message, keypair.shares[0]!, presignature),
        partialSign(message, keypair.shares[1]!, presignature),
      ],
      2,
      presignature
    );

    const sig2 = combineSignatures(
      [
        partialSign(message, keypair.shares[0]!, presignature),
        partialSign(message, keypair.shares[1]!, presignature),
      ],
      2,
      presignature
    );

    expect(sig1.r).toBe(sig2.r);
    expect(sig1.s).toBe(sig2.s);
  });
});

// =============================================================================
// Additional P-256 Coverage
// =============================================================================

describe('ECDSA Extended - P-256 Specific', () => {
  it('should handle P-256 with maximum threshold (7-of-7)', async () => {
    const keypair = await generateKey({ curve: 'P-256', threshold: 7, totalShares: 7 });
    const message = createMessage('Max P-256 threshold');
    const presignature = generatePresignature('P-256', [1, 2, 3, 4, 5, 6, 7]);

    const partials = keypair.shares.map(share => partialSign(message, share, presignature));
    const signature = combineSignatures(partials, 7, presignature);

    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should verify P-256 signatures are normalized', async () => {
    const keypair = await generateKey({ curve: 'P-256', threshold: 2, totalShares: 3 });
    const message = createMessage('P-256 normalization');

    // P-256 order
    const p256Order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const halfOrder = p256Order >> 1n;

    for (let i = 0; i < 5; i++) {
      const presignature = generatePresignature('P-256', [1, 2]);
      const partials = [
        partialSign(message, keypair.shares[0]!, presignature),
        partialSign(message, keypair.shares[1]!, presignature),
      ];
      const signature = combineSignatures(partials, 2, presignature);

      expect(signature.s).toBeLessThanOrEqual(halfOrder);
    }
  });
});

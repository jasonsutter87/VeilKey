/**
 * Threshold BLS Extended Tests
 *
 * Comprehensive extended test suite providing thorough coverage of:
 * - All threshold combinations
 * - Signature aggregation at scale
 * - Security properties (rogue key attacks, etc.)
 * - Batch verification edge cases
 * - Short vs long signature modes
 *
 * Target: 49+ additional tests
 */

import { describe, it, expect } from 'vitest';
import {
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
  BLSSignature,
} from './types.js';

// =============================================================================
// Test Helpers
// =============================================================================

function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

// =============================================================================
// Extended Threshold Combinations
// =============================================================================

describe('BLS Extended - Threshold Combinations', () => {
  it('should work with 2-of-4 threshold', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 4 });
    const message = stringToBytes('Test 2-of-4');

    const partials = [
      partialSign(message, keypair.shares[0]!, 'short'),
      partialSign(message, keypair.shares[1]!, 'short'),
    ];

    const signature = combineSignatures(partials, 2, 'short');
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 2-of-6 threshold', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 6 });
    const message = stringToBytes('Test 2-of-6');

    const partials = [
      partialSign(message, keypair.shares[2]!, 'short'),
      partialSign(message, keypair.shares[5]!, 'short'),
    ];

    const signature = combineSignatures(partials, 2, 'short');
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 3-of-4 threshold', async () => {
    const keypair = await generateKey({ threshold: 3, totalShares: 4 });
    const message = stringToBytes('Test 3-of-4');

    const partials = [
      partialSign(message, keypair.shares[0]!, 'short'),
      partialSign(message, keypair.shares[1]!, 'short'),
      partialSign(message, keypair.shares[2]!, 'short'),
    ];

    const signature = combineSignatures(partials, 3, 'short');
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 3-of-6 threshold', async () => {
    const keypair = await generateKey({ threshold: 3, totalShares: 6 });
    const message = stringToBytes('Test 3-of-6');

    const partials = [
      partialSign(message, keypair.shares[1]!, 'short'),
      partialSign(message, keypair.shares[3]!, 'short'),
      partialSign(message, keypair.shares[5]!, 'short'),
    ];

    const signature = combineSignatures(partials, 3, 'short');
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 4-of-7 threshold', async () => {
    const keypair = await generateKey({ threshold: 4, totalShares: 7 });
    const message = stringToBytes('Test 4-of-7');

    const partials = [
      partialSign(message, keypair.shares[0]!, 'short'),
      partialSign(message, keypair.shares[2]!, 'short'),
      partialSign(message, keypair.shares[4]!, 'short'),
      partialSign(message, keypair.shares[6]!, 'short'),
    ];

    const signature = combineSignatures(partials, 4, 'short');
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 5-of-7 threshold', async () => {
    const keypair = await generateKey({ threshold: 5, totalShares: 7 });
    const message = stringToBytes('Test 5-of-7');

    const partials = keypair.shares.slice(0, 5).map(s => partialSign(message, s, 'short'));
    const signature = combineSignatures(partials, 5, 'short');
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 6-of-7 threshold', async () => {
    const keypair = await generateKey({ threshold: 6, totalShares: 7 });
    const message = stringToBytes('Test 6-of-7');

    const partials = keypair.shares.slice(0, 6).map(s => partialSign(message, s, 'short'));
    const signature = combineSignatures(partials, 6, 'short');
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should work with 7-of-7 threshold (n-of-n)', async () => {
    const keypair = await generateKey({ threshold: 7, totalShares: 7 });
    const message = stringToBytes('Test 7-of-7');

    const partials = keypair.shares.map(s => partialSign(message, s, 'short'));
    const signature = combineSignatures(partials, 7, 'short');
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });
});

// =============================================================================
// Signature Aggregation at Scale
// =============================================================================

describe('BLS Extended - Large-Scale Aggregation', () => {
  it('should aggregate 10 signatures', async () => {
    const message = stringToBytes('Aggregate 10 signatures');
    const keypairs: ThresholdBLSKeyPair[] = [];
    const signatures: BLSSignature[] = [];

    // Generate 10 independent keypairs and signatures
    for (let i = 0; i < 10; i++) {
      const keypair = await generateKey({ threshold: 2, totalShares: 2 });
      keypairs.push(keypair);

      const partials = keypair.shares.map(s => partialSign(message, s, 'short'));
      const sig = combineSignatures(partials, 2, 'short');
      signatures.push(sig);
    }

    // Aggregate signatures
    const aggregated = aggregateSignatures(signatures);
    expect(aggregated.count).toBe(10);

    // Aggregate public keys
    const aggPubKey = aggregatePublicKeys(keypairs.map(kp => kp.publicKey));

    // Verify
    expect(verify(message, aggregated.signature, aggPubKey).valid).toBe(true);
  });

  it('should aggregate 50 signatures', async () => {
    const message = stringToBytes('Aggregate 50 signatures');
    const keypairs: ThresholdBLSKeyPair[] = [];
    const signatures: BLSSignature[] = [];

    for (let i = 0; i < 50; i++) {
      const keypair = await generateKey({ threshold: 2, totalShares: 2 });
      keypairs.push(keypair);

      const partials = keypair.shares.map(s => partialSign(message, s, 'short'));
      const sig = combineSignatures(partials, 2, 'short');
      signatures.push(sig);
    }

    const aggregated = aggregateSignatures(signatures);
    expect(aggregated.count).toBe(50);

    const aggPubKey = aggregatePublicKeys(keypairs.map(kp => kp.publicKey));
    expect(verify(message, aggregated.signature, aggPubKey).valid).toBe(true);
  });

  it('should aggregate 100 signatures', async () => {
    const message = stringToBytes('Aggregate 100 signatures');
    const keypairs: ThresholdBLSKeyPair[] = [];
    const signatures: BLSSignature[] = [];

    for (let i = 0; i < 100; i++) {
      const keypair = await generateKey({ threshold: 2, totalShares: 2 });
      keypairs.push(keypair);

      const partials = keypair.shares.map(s => partialSign(message, s, 'short'));
      const sig = combineSignatures(partials, 2, 'short');
      signatures.push(sig);
    }

    const aggregated = aggregateSignatures(signatures);
    expect(aggregated.count).toBe(100);

    const aggPubKey = aggregatePublicKeys(keypairs.map(kp => kp.publicKey));
    expect(verify(message, aggregated.signature, aggPubKey).valid).toBe(true);
  });

  it('should reject aggregating signatures from different groups', async () => {
    const keypair1 = await generateKey({ threshold: 2, totalShares: 2, mode: 'short' });
    const keypair2 = await generateKey({ threshold: 2, totalShares: 2, mode: 'long' });

    const message = stringToBytes('Mixed groups');

    const partials1 = keypair1.shares.map(s => partialSign(message, s, 'short'));
    const sig1 = combineSignatures(partials1, 2, 'short');

    const partials2 = keypair2.shares.map(s => partialSign(message, s, 'long'));
    const sig2 = combineSignatures(partials2, 2, 'long');

    expect(() => aggregateSignatures([sig1, sig2])).toThrow('same group');
  });

  it('should reject aggregating public keys from different groups', async () => {
    const keypair1 = await generateKey({ threshold: 2, totalShares: 2, mode: 'short' });
    const keypair2 = await generateKey({ threshold: 2, totalShares: 2, mode: 'long' });

    expect(() => aggregatePublicKeys([keypair1.publicKey, keypair2.publicKey])).toThrow('same group');
  });
});

// =============================================================================
// Rogue Key Attack Prevention
// =============================================================================

describe('BLS Extended - Rogue Key Attack Prevention', () => {
  it('should detect invalid aggregated signature (rogue key scenario)', async () => {
    // In a real rogue key attack, attacker would manipulate their public key
    // Here we simulate by creating mismatched signature
    const message = stringToBytes('Rogue key test');

    const honest1 = await generateKey({ threshold: 2, totalShares: 2 });
    const honest2 = await generateKey({ threshold: 2, totalShares: 2 });
    const attacker = await generateKey({ threshold: 2, totalShares: 2 });

    // Honest parties sign
    const sig1 = combineSignatures(
      honest1.shares.map(s => partialSign(message, s, 'short')),
      2,
      'short'
    );
    const sig2 = combineSignatures(
      honest2.shares.map(s => partialSign(message, s, 'short')),
      2,
      'short'
    );

    // Attacker signs different message
    const wrongMessage = stringToBytes('Different message');
    const attackerSig = combineSignatures(
      attacker.shares.map(s => partialSign(wrongMessage, s, 'short')),
      2,
      'short'
    );

    // Try to aggregate
    const aggregated = aggregateSignatures([sig1, sig2, attackerSig]);
    const aggPubKey = aggregatePublicKeys([honest1.publicKey, honest2.publicKey, attacker.publicKey]);

    // Should fail verification
    expect(verify(message, aggregated.signature, aggPubKey).valid).toBe(false);
  });
});

// =============================================================================
// Batch Verification Edge Cases
// =============================================================================

describe('BLS Extended - Batch Verification', () => {
  it('should batch verify 20 signatures', async () => {
    const items = [];

    for (let i = 0; i < 20; i++) {
      const keypair = await generateKey({ threshold: 2, totalShares: 2 });
      const message = stringToBytes(`Batch message ${i}`);
      const partials = keypair.shares.map(s => partialSign(message, s, 'short'));
      const sig = combineSignatures(partials, 2, 'short');

      items.push({
        message,
        signature: sig.signature,
        publicKey: keypair.publicKey,
      });
    }

    expect(batchVerify(items).valid).toBe(true);
  });

  it('should detect invalid signature in batch of 20', async () => {
    const items = [];

    for (let i = 0; i < 20; i++) {
      const keypair = await generateKey({ threshold: 2, totalShares: 2 });
      const message = stringToBytes(`Batch message ${i}`);
      const partials = keypair.shares.map(s => partialSign(message, s, 'short'));
      const sig = combineSignatures(partials, 2, 'short');

      // Corrupt signature at index 10
      const signature = i === 10 ? sig.signature : sig.signature;
      const actualMessage = i === 10 ? stringToBytes('Wrong message') : message;

      items.push({
        message: actualMessage,
        signature,
        publicKey: keypair.publicKey,
      });
    }

    expect(batchVerify(items).valid).toBe(false);
  });

  it('should handle batch with single item', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 2 });
    const message = stringToBytes('Single item batch');
    const partials = keypair.shares.map(s => partialSign(message, s, 'short'));
    const sig = combineSignatures(partials, 2, 'short');

    const items = [{
      message,
      signature: sig.signature,
      publicKey: keypair.publicKey,
    }];

    expect(batchVerify(items).valid).toBe(true);
  });
});

// =============================================================================
// Message Edge Cases
// =============================================================================

describe('BLS Extended - Message Edge Cases', () => {
  it('should sign single byte message', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });
    const message = new Uint8Array([0x42]);

    const partials = [
      partialSign(message, keypair.shares[0]!, 'short'),
      partialSign(message, keypair.shares[1]!, 'short'),
    ];

    const signature = combineSignatures(partials, 2, 'short');
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should sign very long message (1MB)', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });
    const message = new Uint8Array(1024 * 1024).fill(0xAB);

    const partials = [
      partialSign(message, keypair.shares[0]!, 'short'),
      partialSign(message, keypair.shares[1]!, 'short'),
    ];

    const signature = combineSignatures(partials, 2, 'short');
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should sign binary data with all byte values', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });
    const message = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      message[i] = i;
    }

    const partials = [
      partialSign(message, keypair.shares[0]!, 'short'),
      partialSign(message, keypair.shares[1]!, 'short'),
    ];

    const signature = combineSignatures(partials, 2, 'short');
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should produce different signatures for similar messages', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });

    const messages = [
      stringToBytes('Message'),
      stringToBytes('message'),
      stringToBytes('Message '),
      stringToBytes(' Message'),
    ];

    const signatures = messages.map(msg => {
      const partials = [
        partialSign(msg, keypair.shares[0]!, 'short'),
        partialSign(msg, keypair.shares[1]!, 'short'),
      ];
      return combineSignatures(partials, 2, 'short');
    });

    // All signatures should verify with their respective messages
    for (let i = 0; i < messages.length; i++) {
      expect(verify(messages[i]!, signatures[i]!, keypair.publicKey).valid).toBe(true);
    }

    // Should not cross-verify
    expect(verify(messages[0]!, signatures[1]!, keypair.publicKey).valid).toBe(false);
    expect(verify(messages[1]!, signatures[0]!, keypair.publicKey).valid).toBe(false);
  });

  it('should handle unicode and emoji messages', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });
    const message = stringToBytes('Hello 世界 🌍 مرحبا שלום');

    const partials = [
      partialSign(message, keypair.shares[0]!, 'short'),
      partialSign(message, keypair.shares[1]!, 'short'),
    ];

    const signature = combineSignatures(partials, 2, 'short');
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });
});

// =============================================================================
// Short vs Long Signature Mode
// =============================================================================

describe('BLS Extended - Signature Modes', () => {
  it('should verify short mode has correct group assignments', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3, mode: 'short' });
    const message = stringToBytes('Short mode test');

    expect(keypair.publicKey.group).toBe('G1');

    const partial = partialSign(message, keypair.shares[0]!, 'short');
    expect(partial.value.group).toBe('G2');
  });

  it('should verify long mode has correct group assignments', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3, mode: 'long' });
    const message = stringToBytes('Long mode test');

    expect(keypair.publicKey.group).toBe('G2');

    const partial = partialSign(message, keypair.shares[0]!, 'long');
    expect(partial.value.group).toBe('G1');
  });

  it('should sign and verify with long mode', async () => {
    const keypair = await generateKey({ threshold: 3, totalShares: 5, mode: 'long' });
    const message = stringToBytes('Long mode signing');

    const partials = [
      partialSign(message, keypair.shares[0]!, 'long'),
      partialSign(message, keypair.shares[2]!, 'long'),
      partialSign(message, keypair.shares[4]!, 'long'),
    ];

    const signature = combineSignatures(partials, 3, 'long');
    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should aggregate long mode signatures', async () => {
    const message = stringToBytes('Long mode aggregation');
    const keypairs: ThresholdBLSKeyPair[] = [];
    const signatures: BLSSignature[] = [];

    for (let i = 0; i < 5; i++) {
      const keypair = await generateKey({ threshold: 2, totalShares: 2, mode: 'long' });
      keypairs.push(keypair);

      const partials = keypair.shares.map(s => partialSign(message, s, 'long'));
      const sig = combineSignatures(partials, 2, 'long');
      signatures.push(sig);
    }

    const aggregated = aggregateSignatures(signatures);
    const aggPubKey = aggregatePublicKeys(keypairs.map(kp => kp.publicKey));

    expect(verify(message, aggregated.signature, aggPubKey).valid).toBe(true);
  });
});

// =============================================================================
// Partial Signature Verification
// =============================================================================

describe('BLS Extended - Partial Verification', () => {
  it('should verify all partials individually', async () => {
    const keypair = await generateKey({ threshold: 3, totalShares: 5 });
    const message = stringToBytes('Verify all partials');

    for (const share of keypair.shares) {
      const partial = partialSign(message, share, 'short');
      const result = verifyPartial(message, partial, share.verificationKey, 'short');
      expect(result.valid).toBe(true);
    }
  });

  it('should detect partial signed with wrong share', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });
    const message = stringToBytes('Wrong share test');

    const partial = partialSign(message, keypair.shares[0]!, 'short');

    // Verify against wrong verification key
    const result = verifyPartial(message, partial, keypair.shares[1]!.verificationKey, 'short');
    expect(result.valid).toBe(false);
  });

  it('should verify partial signatures in long mode', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3, mode: 'long' });
    const message = stringToBytes('Long mode partial verification');

    for (const share of keypair.shares) {
      const partial = partialSign(message, share, 'long');
      const result = verifyPartial(message, partial, share.verificationKey, 'long');
      expect(result.valid).toBe(true);
    }
  });
});

// =============================================================================
// Share Verification Extended
// =============================================================================

describe('BLS Extended - Share Verification', () => {
  it('should verify shares in short mode', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 5, mode: 'short' });

    for (const share of keypair.shares) {
      expect(verifyShare(share, 'short')).toBe(true);
    }
  });

  it('should verify shares in long mode', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 5, mode: 'long' });

    for (const share of keypair.shares) {
      expect(verifyShare(share, 'long')).toBe(true);
    }
  });

  it('should detect tampered share value', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });

    const tamperedShare = {
      ...keypair.shares[0]!,
      value: keypair.shares[0]!.value + 1n,
    };

    expect(verifyShare(tamperedShare, 'short')).toBe(false);
  });

  it('should verify all shares in large keypair', async () => {
    const keypair = await generateKey({ threshold: 5, totalShares: 10 });
    expect(verifyAllShares(keypair)).toBe(true);
  });
});

// =============================================================================
// Signature Uniqueness
// =============================================================================

describe('BLS Extended - Signature Uniqueness', () => {
  it('should produce identical signatures from same shares and message', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });
    const message = stringToBytes('Deterministic test');

    const sig1 = combineSignatures(
      [
        partialSign(message, keypair.shares[0]!, 'short'),
        partialSign(message, keypair.shares[1]!, 'short'),
      ],
      2,
      'short'
    );

    const sig2 = combineSignatures(
      [
        partialSign(message, keypair.shares[0]!, 'short'),
        partialSign(message, keypair.shares[1]!, 'short'),
      ],
      2,
      'short'
    );

    expect(sig1.signature.value).toBe(sig2.signature.value);
  });

  it('should produce identical signatures from different share combinations', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 4 });
    const message = stringToBytes('Share combination test');

    const sig1 = combineSignatures(
      [
        partialSign(message, keypair.shares[0]!, 'short'),
        partialSign(message, keypair.shares[1]!, 'short'),
      ],
      2,
      'short'
    );

    const sig2 = combineSignatures(
      [
        partialSign(message, keypair.shares[2]!, 'short'),
        partialSign(message, keypair.shares[3]!, 'short'),
      ],
      2,
      'short'
    );

    // Different share combinations should produce same signature
    expect(sig1.signature.value).toBe(sig2.signature.value);
  });
});

// =============================================================================
// Participant Combinations
// =============================================================================

describe('BLS Extended - Participant Combinations', () => {
  it('should work with all 2-of-5 combinations', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 5 });
    const message = stringToBytes('All combinations');

    const combinations = [
      [0, 1], [0, 2], [0, 3], [0, 4],
      [1, 2], [1, 3], [1, 4],
      [2, 3], [2, 4],
      [3, 4],
    ];

    for (const [i, j] of combinations) {
      const partials = [
        partialSign(message, keypair.shares[i]!, 'short'),
        partialSign(message, keypair.shares[j]!, 'short'),
      ];
      const signature = combineSignatures(partials, 2, 'short');
      expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
    }
  });

  it('should track participant indices correctly', async () => {
    const keypair = await generateKey({ threshold: 3, totalShares: 5 });
    const message = stringToBytes('Participant tracking');

    const partials = [
      partialSign(message, keypair.shares[1]!, 'short'), // index 2
      partialSign(message, keypair.shares[2]!, 'short'), // index 3
      partialSign(message, keypair.shares[4]!, 'short'), // index 5
    ];

    const signature = combineSignatures(partials, 3, 'short');
    expect(signature.participantIndices).toEqual([2, 3, 5]);
  });
});

// =============================================================================
// Error Handling
// =============================================================================

describe('BLS Extended - Error Handling', () => {
  it('should reject threshold of 0', async () => {
    await expect(
      generateKey({ threshold: 0, totalShares: 3 })
    ).rejects.toThrow();
  });

  it('should reject threshold of 1', async () => {
    await expect(
      generateKey({ threshold: 1, totalShares: 3 })
    ).rejects.toThrow('at least 2');
  });

  it('should reject negative threshold', async () => {
    await expect(
      generateKey({ threshold: -1, totalShares: 3 })
    ).rejects.toThrow();
  });

  it('should reject totalShares of 0', async () => {
    await expect(
      generateKey({ threshold: 2, totalShares: 0 })
    ).rejects.toThrow();
  });

  it('should reject threshold exceeding totalShares', async () => {
    await expect(
      generateKey({ threshold: 5, totalShares: 3 })
    ).rejects.toThrow('cannot exceed');
  });

  it('should reject combining with insufficient partials', async () => {
    const keypair = await generateKey({ threshold: 3, totalShares: 5 });
    const message = stringToBytes('Insufficient partials');

    const partials = [
      partialSign(message, keypair.shares[0]!, 'short'),
      partialSign(message, keypair.shares[1]!, 'short'),
    ];

    expect(() => combineSignatures(partials, 3, 'short')).toThrow('Need 3');
  });

  it('should reject aggregating empty signature array', () => {
    expect(() => aggregateSignatures([])).toThrow('No signatures');
  });

  it('should reject aggregating empty public key array', () => {
    expect(() => aggregatePublicKeys([])).toThrow('No public keys');
  });
});

// =============================================================================
// Key Generation Properties
// =============================================================================

describe('BLS Extended - Key Generation', () => {
  it('should generate unique keys each time', async () => {
    const keypairs = await Promise.all([
      generateKey({ threshold: 2, totalShares: 3 }),
      generateKey({ threshold: 2, totalShares: 3 }),
      generateKey({ threshold: 2, totalShares: 3 }),
    ]);

    const pubKeys = keypairs.map(kp => kp.publicKey.value);
    const uniquePubKeys = new Set(pubKeys);
    expect(uniquePubKeys.size).toBe(3);
  });

  it('should generate shares with sequential indices', async () => {
    const keypair = await generateKey({ threshold: 3, totalShares: 7 });

    const indices = keypair.shares.map(s => s.index);
    expect(indices).toEqual([1, 2, 3, 4, 5, 6, 7]);
  });

  it('should generate verification keys for all shares', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 5 });

    expect(keypair.verificationKeys).toHaveLength(5);
    for (let i = 0; i < 5; i++) {
      expect(keypair.shares[i]!.verificationKey).toEqual(keypair.verificationKeys[i]);
    }
  });
});

// =============================================================================
// Aggregated Public Key Properties
// =============================================================================

describe('BLS Extended - Aggregated Public Keys', () => {
  it('should create valid aggregated public key from 10 keys', async () => {
    const keypairs = await Promise.all(
      Array.from({ length: 10 }, () => generateKey({ threshold: 2, totalShares: 2 }))
    );

    const aggPubKey = aggregatePublicKeys(keypairs.map(kp => kp.publicKey));
    expect(aggPubKey.group).toBe('G1'); // Default short mode
    expect(aggPubKey.value).toBeDefined();
  });

  it('should maintain group consistency in aggregation', async () => {
    const keypairs = await Promise.all([
      generateKey({ threshold: 2, totalShares: 2, mode: 'short' }),
      generateKey({ threshold: 2, totalShares: 2, mode: 'short' }),
      generateKey({ threshold: 2, totalShares: 2, mode: 'short' }),
    ]);

    const aggPubKey = aggregatePublicKeys(keypairs.map(kp => kp.publicKey));
    expect(aggPubKey.group).toBe('G1');
  });
});

// =============================================================================
// Performance and Stress Tests
// =============================================================================

describe('BLS Extended - Stress Tests', () => {
  it('should handle maximum participants (10-of-10)', async () => {
    const keypair = await generateKey({ threshold: 10, totalShares: 10 });
    const message = stringToBytes('Max participants');

    const partials = keypair.shares.map(s => partialSign(message, s, 'short'));
    const signature = combineSignatures(partials, 10, 'short');

    expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
  });

  it('should handle signing 100 different messages', async () => {
    const keypair = await generateKey({ threshold: 2, totalShares: 3 });

    for (let i = 0; i < 100; i++) {
      const message = stringToBytes(`Message ${i}`);
      const partials = [
        partialSign(message, keypair.shares[0]!, 'short'),
        partialSign(message, keypair.shares[1]!, 'short'),
      ];
      const signature = combineSignatures(partials, 2, 'short');
      expect(verify(message, signature, keypair.publicKey).valid).toBe(true);
    }
  });
});

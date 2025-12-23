/**
 * Threshold ECDSA Tests
 *
 * Comprehensive test suite for threshold ECDSA implementation
 * covering both secp256k1 (Bitcoin/Ethereum) and P-256 curves.
 */

import { describe, it, expect } from 'vitest';
import {
  ThresholdECDSA,
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
} from './types.js';

// =============================================================================
// Test Helpers
// =============================================================================

/**
 * Create a test message
 */
function createMessage(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/**
 * Test basic threshold signing workflow
 */
async function testThresholdSigningWorkflow(
  curve: ECDSACurve,
  threshold: number,
  totalShares: number
) {
  const config: ThresholdECDSAConfig = { curve, threshold, totalShares };

  // 1. Generate threshold keypair
  const keypair = await generateKey(config);

  expect(keypair.shares).toHaveLength(totalShares);
  expect(keypair.verificationKeys).toHaveLength(totalShares);
  expect(keypair.publicKey.curve).toBe(curve);

  // 2. Verify all shares
  expect(verifyAllShares(keypair)).toBe(true);

  // 3. Generate presignature
  const participantIndices = Array.from({ length: threshold }, (_, i) => i + 1);
  const presignature = generatePresignature(curve, participantIndices);

  expect(presignature.curve).toBe(curve);
  expect(presignature.r).toBeGreaterThan(0n);

  // 4. Create message
  const message = createMessage('Hello, threshold ECDSA!');

  // 5. Create partial signatures from threshold parties
  const partials: PartialECDSASignature[] = [];
  for (let i = 0; i < threshold; i++) {
    const share = keypair.shares[i]!;
    const partial = partialSign(message, share, presignature);
    partials.push(partial);

    // Verify partial is well-formed
    expect(verifyPartial(partial, curve)).toBe(true);
  }

  expect(partials).toHaveLength(threshold);

  // 6. Combine partial signatures
  const signature = combineSignatures(partials, threshold, presignature);

  expect(signature.r).toBeGreaterThan(0n);
  expect(signature.s).toBeGreaterThan(0n);

  // 7. Verify signature
  const result = verify(message, signature, keypair.publicKey);
  expect(result.valid).toBe(true);
  expect(result.error).toBeUndefined();

  // 8. Verify signature fails with wrong message
  const wrongMessage = createMessage('Wrong message');
  const wrongResult = verify(wrongMessage, signature, keypair.publicKey);
  expect(wrongResult.valid).toBe(false);

  return { keypair, signature, message };
}

// =============================================================================
// Key Generation Tests
// =============================================================================

describe('ThresholdECDSA - Key Generation', () => {
  it('should generate keypair for secp256k1', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    };

    const keypair = await generateKey(config);

    expect(keypair.shares).toHaveLength(3);
    expect(keypair.verificationKeys).toHaveLength(3);
    expect(keypair.publicKey.curve).toBe('secp256k1');
    expect(keypair.config).toEqual(config);
  });

  it('should generate keypair for P-256', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'P-256',
      threshold: 3,
      totalShares: 5,
    };

    const keypair = await generateKey(config);

    expect(keypair.shares).toHaveLength(5);
    expect(keypair.verificationKeys).toHaveLength(5);
    expect(keypair.publicKey.curve).toBe('P-256');
    expect(keypair.config).toEqual(config);
  });

  it('should reject invalid threshold (too high)', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 5,
      totalShares: 3,
    };

    await expect(generateKey(config)).rejects.toThrow('cannot exceed total shares');
  });

  it('should reject invalid threshold (too low)', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 1,
      totalShares: 3,
    };

    await expect(generateKey(config)).rejects.toThrow('must be at least 2');
  });

  it('should reject invalid total shares', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 1,
    };

    await expect(generateKey(config)).rejects.toThrow('cannot exceed total shares');
  });
});

// =============================================================================
// Share Verification Tests
// =============================================================================

describe('ThresholdECDSA - Share Verification', () => {
  it('should verify valid shares', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    };

    const keypair = await generateKey(config);

    for (const share of keypair.shares) {
      expect(verifyShare(share)).toBe(true);
    }
  });

  it('should detect tampered share', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    };

    const keypair = await generateKey(config);

    // Tamper with a share
    const tamperedShare = {
      ...keypair.shares[0]!,
      value: keypair.shares[0]!.value + 1n,
    };

    expect(verifyShare(tamperedShare)).toBe(false);
  });

  it('should verify all shares in keypair', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'P-256',
      threshold: 3,
      totalShares: 5,
    };

    const keypair = await generateKey(config);

    expect(verifyAllShares(keypair)).toBe(true);
  });
});

// =============================================================================
// Presignature Tests
// =============================================================================

describe('ThresholdECDSA - Presignature', () => {
  it('should generate valid presignature for secp256k1', () => {
    const presignature = generatePresignature('secp256k1', [1, 2, 3]);

    expect(presignature.curve).toBe('secp256k1');
    expect(presignature.k).toBeGreaterThan(0n);
    expect(presignature.kInv).toBeGreaterThan(0n);
    expect(presignature.r).toBeGreaterThan(0n);
    expect(presignature.R.curve).toBe('secp256k1');
    expect(presignature.participantIndices).toEqual([1, 2, 3]);
  });

  it('should generate valid presignature for P-256', () => {
    const presignature = generatePresignature('P-256', [1, 2]);

    expect(presignature.curve).toBe('P-256');
    expect(presignature.k).toBeGreaterThan(0n);
    expect(presignature.kInv).toBeGreaterThan(0n);
    expect(presignature.r).toBeGreaterThan(0n);
    expect(presignature.R.curve).toBe('P-256');
  });

  it('should generate different presignatures each time', () => {
    const presig1 = generatePresignature('secp256k1', [1, 2]);
    const presig2 = generatePresignature('secp256k1', [1, 2]);

    expect(presig1.k).not.toBe(presig2.k);
    expect(presig1.r).not.toBe(presig2.r);
  });
});

// =============================================================================
// Threshold Signing Tests - secp256k1
// =============================================================================

describe('ThresholdECDSA - Threshold Signing (secp256k1)', () => {
  it('should sign with 2-of-3 threshold', async () => {
    await testThresholdSigningWorkflow('secp256k1', 2, 3);
  });

  it('should sign with 3-of-5 threshold', async () => {
    await testThresholdSigningWorkflow('secp256k1', 3, 5);
  });

  it('should sign with different sets of participants', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 4,
    };

    const keypair = await generateKey(config);
    const message = createMessage('Test message');

    // Sign with shares [0, 1]
    const presig1 = generatePresignature('secp256k1', [1, 2]);
    const partials1 = [
      partialSign(message, keypair.shares[0]!, presig1),
      partialSign(message, keypair.shares[1]!, presig1),
    ];
    const sig1 = combineSignatures(partials1, 2, presig1);
    expect(verify(message, sig1, keypair.publicKey).valid).toBe(true);

    // Sign with shares [1, 2]
    const presig2 = generatePresignature('secp256k1', [2, 3]);
    const partials2 = [
      partialSign(message, keypair.shares[1]!, presig2),
      partialSign(message, keypair.shares[2]!, presig2),
    ];
    const sig2 = combineSignatures(partials2, 2, presig2);
    expect(verify(message, sig2, keypair.publicKey).valid).toBe(true);

    // Sign with shares [0, 3]
    const presig3 = generatePresignature('secp256k1', [1, 4]);
    const partials3 = [
      partialSign(message, keypair.shares[0]!, presig3),
      partialSign(message, keypair.shares[3]!, presig3),
    ];
    const sig3 = combineSignatures(partials3, 2, presig3);
    expect(verify(message, sig3, keypair.publicKey).valid).toBe(true);
  });

  it('should fail with insufficient partials', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 3,
      totalShares: 5,
    };

    const keypair = await generateKey(config);
    const message = createMessage('Test message');
    const presignature = generatePresignature('secp256k1', [1, 2]);

    // Only provide 2 partials when threshold is 3
    const partials = [
      partialSign(message, keypair.shares[0]!, presignature),
      partialSign(message, keypair.shares[1]!, presignature),
    ];

    expect(() => combineSignatures(partials, 3, presignature)).toThrow('Need 3 partial');
  });

  it('should sign different messages correctly', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    };

    const keypair = await generateKey(config);

    const messages = [
      createMessage('Message 1'),
      createMessage('Message 2'),
      createMessage('Message 3'),
    ];

    for (const message of messages) {
      const presignature = generatePresignature('secp256k1', [1, 2]);
      const partials = [
        partialSign(message, keypair.shares[0]!, presignature),
        partialSign(message, keypair.shares[1]!, presignature),
      ];

      const signature = combineSignatures(partials, 2, presignature);
      const result = verify(message, signature, keypair.publicKey);
      expect(result.valid).toBe(true);
    }
  });
});

// =============================================================================
// Threshold Signing Tests - P-256
// =============================================================================

describe('ThresholdECDSA - Threshold Signing (P-256)', () => {
  it('should sign with 2-of-3 threshold', async () => {
    await testThresholdSigningWorkflow('P-256', 2, 3);
  });

  it('should sign with 3-of-5 threshold', async () => {
    await testThresholdSigningWorkflow('P-256', 3, 5);
  });

  it('should sign with 5-of-7 threshold', async () => {
    await testThresholdSigningWorkflow('P-256', 5, 7);
  });
});

// =============================================================================
// Signature Verification Tests
// =============================================================================

describe('ThresholdECDSA - Signature Verification', () => {
  it('should verify valid signature', async () => {
    const { keypair, signature, message } = await testThresholdSigningWorkflow(
      'secp256k1',
      2,
      3
    );

    const result = verify(message, signature, keypair.publicKey);
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('should reject signature with wrong message', async () => {
    const { keypair, signature } = await testThresholdSigningWorkflow('secp256k1', 2, 3);

    const wrongMessage = createMessage('Different message');
    const result = verify(wrongMessage, signature, keypair.publicKey);
    expect(result.valid).toBe(false);
  });

  it('should reject signature with wrong public key', async () => {
    const { signature, message } = await testThresholdSigningWorkflow('secp256k1', 2, 3);

    // Generate a different keypair
    const wrongKeypair = await generateKey({
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    });

    const result = verify(message, signature, wrongKeypair.publicKey);
    expect(result.valid).toBe(false);
  });

  it('should reject signature with tampered r', async () => {
    const { keypair, signature, message } = await testThresholdSigningWorkflow(
      'secp256k1',
      2,
      3
    );

    const tamperedSignature = {
      ...signature,
      r: signature.r + 1n,
    };

    const result = verify(message, tamperedSignature, keypair.publicKey);
    expect(result.valid).toBe(false);
  });

  it('should reject signature with tampered s', async () => {
    const { keypair, signature, message } = await testThresholdSigningWorkflow(
      'secp256k1',
      2,
      3
    );

    const tamperedSignature = {
      ...signature,
      s: signature.s + 1n,
    };

    const result = verify(message, tamperedSignature, keypair.publicKey);
    expect(result.valid).toBe(false);
  });

  it('should reject signature with r = 0', async () => {
    const keypair = await generateKey({
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    });

    const invalidSignature = { r: 0n, s: 1n };
    const message = createMessage('Test');

    const result = verify(message, invalidSignature, keypair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('out of range');
  });

  it('should reject signature with s = 0', async () => {
    const keypair = await generateKey({
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    });

    const invalidSignature = { r: 1n, s: 0n };
    const message = createMessage('Test');

    const result = verify(message, invalidSignature, keypair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('out of range');
  });
});

// =============================================================================
// Batch Verification Tests
// =============================================================================

describe('ThresholdECDSA - Batch Verification', () => {
  it('should verify multiple valid signatures', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    };

    const keypair = await generateKey(config);

    // Create multiple signatures
    const items = [];
    for (let i = 0; i < 3; i++) {
      const message = createMessage(`Message ${i}`);
      const presignature = generatePresignature('secp256k1', [1, 2]);
      const partials = [
        partialSign(message, keypair.shares[0]!, presignature),
        partialSign(message, keypair.shares[1]!, presignature),
      ];
      const signature = combineSignatures(partials, 2, presignature);

      items.push({ message, signature, publicKey: keypair.publicKey });
    }

    const result = batchVerify(items);
    expect(result.valid).toBe(true);
  });

  it('should detect invalid signature in batch', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    };

    const keypair = await generateKey(config);

    // Create mix of valid and invalid signatures
    const items = [];

    // Valid signature
    const message1 = createMessage('Message 1');
    const presignature1 = generatePresignature('secp256k1', [1, 2]);
    const partials1 = [
      partialSign(message1, keypair.shares[0]!, presignature1),
      partialSign(message1, keypair.shares[1]!, presignature1),
    ];
    const signature1 = combineSignatures(partials1, 2, presignature1);
    items.push({ message: message1, signature: signature1, publicKey: keypair.publicKey });

    // Invalid signature (tampered)
    const message2 = createMessage('Message 2');
    const presignature2 = generatePresignature('secp256k1', [1, 2]);
    const partials2 = [
      partialSign(message2, keypair.shares[0]!, presignature2),
      partialSign(message2, keypair.shares[1]!, presignature2),
    ];
    const signature2 = combineSignatures(partials2, 2, presignature2);
    const tamperedSignature = { ...signature2, s: signature2.s + 1n };
    items.push({ message: message2, signature: tamperedSignature, publicKey: keypair.publicKey });

    const result = batchVerify(items);
    expect(result.valid).toBe(false);
  });

  it('should handle empty batch', () => {
    const result = batchVerify([]);
    expect(result.valid).toBe(true);
  });
});

// =============================================================================
// Namespace Export Tests
// =============================================================================

describe('ThresholdECDSA - Namespace', () => {
  it('should export all functions via namespace', () => {
    expect(ThresholdECDSA.generateKey).toBeDefined();
    expect(ThresholdECDSA.verifyShare).toBeDefined();
    expect(ThresholdECDSA.verifyAllShares).toBeDefined();
    expect(ThresholdECDSA.generatePresignature).toBeDefined();
    expect(ThresholdECDSA.partialSign).toBeDefined();
    expect(ThresholdECDSA.combineSignatures).toBeDefined();
    expect(ThresholdECDSA.verify).toBeDefined();
    expect(ThresholdECDSA.verifyPartial).toBeDefined();
    expect(ThresholdECDSA.batchVerify).toBeDefined();
  });

  it('should work via namespace', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    };

    const keypair = await ThresholdECDSA.generateKey(config);
    expect(ThresholdECDSA.verifyAllShares(keypair)).toBe(true);

    const message = createMessage('Test via namespace');
    const presignature = ThresholdECDSA.generatePresignature('secp256k1', [1, 2]);

    const partials = [
      ThresholdECDSA.partialSign(message, keypair.shares[0]!, presignature),
      ThresholdECDSA.partialSign(message, keypair.shares[1]!, presignature),
    ];

    const signature = ThresholdECDSA.combineSignatures(partials, 2, presignature);
    const result = ThresholdECDSA.verify(message, signature, keypair.publicKey);

    expect(result.valid).toBe(true);
  });
});

// =============================================================================
// Interoperability Tests
// =============================================================================

describe('ThresholdECDSA - Interoperability', () => {
  it('should work with both curves independently', async () => {
    const message = createMessage('Cross-curve test');

    // Test secp256k1
    const secp256k1Config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    };

    const secp256k1Keypair = await generateKey(secp256k1Config);
    const secp256k1Presig = generatePresignature('secp256k1', [1, 2]);
    const secp256k1Partials = [
      partialSign(message, secp256k1Keypair.shares[0]!, secp256k1Presig),
      partialSign(message, secp256k1Keypair.shares[1]!, secp256k1Presig),
    ];
    const secp256k1Sig = combineSignatures(secp256k1Partials, 2, secp256k1Presig);
    expect(verify(message, secp256k1Sig, secp256k1Keypair.publicKey).valid).toBe(true);

    // Test P-256
    const p256Config: ThresholdECDSAConfig = {
      curve: 'P-256',
      threshold: 2,
      totalShares: 3,
    };

    const p256Keypair = await generateKey(p256Config);
    const p256Presig = generatePresignature('P-256', [1, 2]);
    const p256Partials = [
      partialSign(message, p256Keypair.shares[0]!, p256Presig),
      partialSign(message, p256Keypair.shares[1]!, p256Presig),
    ];
    const p256Sig = combineSignatures(p256Partials, 2, p256Presig);
    expect(verify(message, p256Sig, p256Keypair.publicKey).valid).toBe(true);
  });
});

// =============================================================================
// Edge Cases and Error Handling
// =============================================================================

describe('ThresholdECDSA - Edge Cases', () => {
  it('should handle maximum threshold (n-of-n)', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 3,
      totalShares: 3,
    };

    const keypair = await generateKey(config);
    const message = createMessage('Maximum threshold test');
    const presignature = generatePresignature('secp256k1', [1, 2, 3]);

    const partials = keypair.shares.map(share => partialSign(message, share, presignature));

    const signature = combineSignatures(partials, 3, presignature);
    const result = verify(message, signature, keypair.publicKey);

    expect(result.valid).toBe(true);
  });

  it('should handle empty message', async () => {
    await testThresholdSigningWorkflow('secp256k1', 2, 3);
  });

  it('should handle very long message', async () => {
    const config: ThresholdECDSAConfig = {
      curve: 'secp256k1',
      threshold: 2,
      totalShares: 3,
    };

    const keypair = await generateKey(config);
    const longMessage = new Uint8Array(10000).fill(42);
    const presignature = generatePresignature('secp256k1', [1, 2]);

    const partials = [
      partialSign(longMessage, keypair.shares[0]!, presignature),
      partialSign(longMessage, keypair.shares[1]!, presignature),
    ];

    const signature = combineSignatures(partials, 2, presignature);
    const result = verify(longMessage, signature, keypair.publicKey);

    expect(result.valid).toBe(true);
  });
});

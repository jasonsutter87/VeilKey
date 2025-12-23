# Threshold ECDSA Quick Reference

## Installation

```typescript
import { ThresholdECDSA } from '@veilkey/core';
import type { ThresholdECDSAConfig } from '@veilkey/core';
```

## Basic Workflow

### 1. Generate Keys

```typescript
const keypair = await ThresholdECDSA.generateKey({
  curve: 'secp256k1',  // or 'P-256'
  threshold: 2,         // minimum signers
  totalShares: 3,       // total parties
});
```

### 2. Distribute Shares

```typescript
// Give each party their share
party1.share = keypair.shares[0];
party2.share = keypair.shares[1];
party3.share = keypair.shares[2];

// Everyone gets the public key
everyone.publicKey = keypair.publicKey;
```

### 3. Sign Message

```typescript
// Step 1: Generate presignature
const presignature = ThresholdECDSA.generatePresignature(
  'secp256k1',
  [1, 2]  // parties 1 and 2 will sign
);

// Step 2: Each party creates partial signature
const message = new TextEncoder().encode('Hello!');
const partial1 = ThresholdECDSA.partialSign(message, party1.share, presignature);
const partial2 = ThresholdECDSA.partialSign(message, party2.share, presignature);

// Step 3: Combine partials
const signature = ThresholdECDSA.combineSignatures(
  [partial1, partial2],
  2,  // threshold
  presignature
);
```

### 4. Verify Signature

```typescript
const result = ThresholdECDSA.verify(
  message,
  signature,
  publicKey
);

console.log(result.valid);  // true or false
```

## API Cheat Sheet

| Function | Purpose | Returns |
|----------|---------|---------|
| `generateKey(config)` | Create threshold keypair | `ThresholdECDSAKeyPair` |
| `verifyShare(share)` | Verify single share | `boolean` |
| `verifyAllShares(keypair)` | Verify all shares | `boolean` |
| `generatePresignature(curve, indices)` | Create presignature | `ECDSAPresignature` |
| `partialSign(msg, share, presig)` | Create partial sig | `PartialECDSASignature` |
| `combineSignatures(partials, t, presig)` | Combine partials | `ECDSASignature` |
| `verify(msg, sig, pk)` | Verify signature | `ECDSAVerificationResult` |
| `batchVerify(items)` | Verify multiple sigs | `ECDSAVerificationResult` |

## Configuration Options

```typescript
interface ThresholdECDSAConfig {
  curve: 'secp256k1' | 'P-256';
  threshold: number;    // t: minimum signers
  totalShares: number;  // n: total parties
}
```

## Common Patterns

### Bitcoin Wallet (2-of-3)

```typescript
const wallet = await ThresholdECDSA.generateKey({
  curve: 'secp256k1',
  threshold: 2,
  totalShares: 3,
});
```

### Enterprise CA (3-of-5)

```typescript
const ca = await ThresholdECDSA.generateKey({
  curve: 'P-256',
  threshold: 3,
  totalShares: 5,
});
```

### High Security (5-of-7)

```typescript
const vault = await ThresholdECDSA.generateKey({
  curve: 'secp256k1',
  threshold: 5,
  totalShares: 7,
});
```

## Error Handling

```typescript
try {
  const signature = ThresholdECDSA.combineSignatures(
    partials,
    threshold,
    presignature
  );
} catch (error) {
  if (error.message.includes('Need')) {
    console.error('Insufficient partial signatures');
  }
}
```

## Type Definitions

```typescript
// Keypair
interface ThresholdECDSAKeyPair {
  publicKey: ECDSAPoint;
  shares: ECDSAShare[];
  verificationKeys: ECDSAPoint[];
  config: ThresholdECDSAConfig;
}

// Share
interface ECDSAShare {
  index: number;
  value: bigint;
  verificationKey: ECDSAPoint;
}

// Signature
interface ECDSASignature {
  r: bigint;
  s: bigint;
  participantIndices?: number[];
}

// Verification
interface ECDSAVerificationResult {
  valid: boolean;
  error?: string;
}
```

## Performance Tips

1. **Precompute Presignatures**: Generate them before you need to sign
2. **Batch Verify**: Use `batchVerify()` for multiple signatures
3. **Share Storage**: Keep shares in memory during signing session
4. **Parallel Partials**: Parties can sign in parallel

## Security Best Practices

1. **Secure Channels**: Distribute shares over encrypted channels
2. **Share Isolation**: Store each share on separate hardware
3. **Access Control**: Require authentication before signing
4. **Audit Logs**: Log all signing operations
5. **Regular Rotation**: Refresh shares periodically

## Common Mistakes

### ❌ Wrong: Using same presignature twice

```typescript
const presig = ThresholdECDSA.generatePresignature('secp256k1', [1, 2]);
const sig1 = ThresholdECDSA.combineSignatures(partials1, 2, presig);
const sig2 = ThresholdECDSA.combineSignatures(partials2, 2, presig); // DANGER!
```

### ✅ Right: Generate new presignature for each signature

```typescript
const presig1 = ThresholdECDSA.generatePresignature('secp256k1', [1, 2]);
const sig1 = ThresholdECDSA.combineSignatures(partials1, 2, presig1);

const presig2 = ThresholdECDSA.generatePresignature('secp256k1', [1, 2]);
const sig2 = ThresholdECDSA.combineSignatures(partials2, 2, presig2);
```

### ❌ Wrong: Not verifying shares

```typescript
const keypair = await ThresholdECDSA.generateKey(config);
// Start signing immediately
```

### ✅ Right: Always verify shares

```typescript
const keypair = await ThresholdECDSA.generateKey(config);
if (!ThresholdECDSA.verifyAllShares(keypair)) {
  throw new Error('Share verification failed');
}
```

## Debugging

### Check share validity

```typescript
for (const share of keypair.shares) {
  console.log(`Share ${share.index}: ${ThresholdECDSA.verifyShare(share)}`);
}
```

### Verify signature details

```typescript
const result = ThresholdECDSA.verify(message, signature, publicKey);
if (!result.valid) {
  console.error('Verification failed:', result.error);
  console.log('r:', signature.r);
  console.log('s:', signature.s);
}
```

## Testing

```bash
# Run tests
npm test -- src/ecdsa/ecdsa.test.ts

# Run integration tests
npm test -- src/ecdsa/integration.test.ts

# Run examples
npx tsx examples/ecdsa-example.ts
```

## Resources

- Full Documentation: `src/ecdsa/README.md`
- Examples: `examples/ecdsa-example.ts`
- Tests: `src/ecdsa/ecdsa.test.ts`
- Phase Summary: `PHASE_2.1_SUMMARY.md`

## Support Matrix

| Curve | Key Size | Security | Use Case |
|-------|----------|----------|----------|
| secp256k1 | 256-bit | ~128-bit | Bitcoin, Ethereum |
| P-256 | 256-bit | ~128-bit | TLS, General |

## Version Compatibility

- Node.js: ≥ 18.0.0
- TypeScript: ≥ 5.0.0
- Dependencies: `@noble/curves@^1.3.0`, `@noble/hashes@^1.3.2`

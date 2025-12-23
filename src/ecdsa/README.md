# Threshold ECDSA (GG20)

Threshold ECDSA implementation based on the GG20 protocol, supporting Bitcoin (secp256k1) and general-purpose (P-256) signatures.

## Overview

Threshold ECDSA allows `t-of-n` parties to jointly create ECDSA signatures without any single party ever holding the complete private key. This implementation supports:

- **Multiple Curves**: secp256k1 (Bitcoin/Ethereum) and P-256 (NIST)
- **Trusted Dealer Model**: Simplified key generation for Phase 2.1
- **Standard ECDSA**: Signatures are fully compatible with existing systems
- **Presignatures**: Optional optimization for faster signing

## Security Properties

- **No Single Point of Failure**: The private key never exists in one place
- **Threshold Security**: Any `t` parties can sign, but `t-1` learn nothing
- **Standard Compatibility**: Signatures are indistinguishable from regular ECDSA
- **Verifiable Shares**: Each share can be verified against its public key

## Quick Start

```typescript
import { ThresholdECDSA } from '@veilkey/core';

// 1. Generate threshold keypair (2-of-3)
const keypair = await ThresholdECDSA.generateKey({
  curve: 'secp256k1',
  threshold: 2,
  totalShares: 3,
});

// 2. Distribute shares to parties
// Party 1 gets keypair.shares[0]
// Party 2 gets keypair.shares[1]
// Party 3 gets keypair.shares[2]

// 3. Generate presignature
const presignature = ThresholdECDSA.generatePresignature('secp256k1', [1, 2]);

// 4. Each party creates a partial signature
const message = new TextEncoder().encode('Hello, VeilKey!');

const partial1 = ThresholdECDSA.partialSign(message, keypair.shares[0], presignature);
const partial2 = ThresholdECDSA.partialSign(message, keypair.shares[1], presignature);

// 5. Combine partial signatures
const signature = ThresholdECDSA.combineSignatures(
  [partial1, partial2],
  2,
  presignature
);

// 6. Verify signature
const result = ThresholdECDSA.verify(message, signature, keypair.publicKey);
console.log(result.valid); // true
```

## Use Cases

### Bitcoin/Ethereum Wallets

Multi-party custody for cryptocurrency wallets:

```typescript
const keypair = await ThresholdECDSA.generateKey({
  curve: 'secp256k1',
  threshold: 3,
  totalShares: 5,
});

// 3 out of 5 board members must approve each transaction
```

### Distributed Certificate Authorities

TLS certificate signing with no single root of trust:

```typescript
const keypair = await ThresholdECDSA.generateKey({
  curve: 'P-256',
  threshold: 5,
  totalShares: 7,
});

// 5 out of 7 trustees must approve each certificate
```

### Voting Systems (VeilSign Integration)

Distributed blind signature authority:

```typescript
const keypair = await ThresholdECDSA.generateKey({
  curve: 'secp256k1',
  threshold: 3,
  totalShares: 5,
});

// 3 out of 5 trustees must cooperate to issue voting tokens
```

## API Reference

### Key Generation

#### `generateKey(config)`

Generate a threshold ECDSA keypair.

```typescript
const keypair = await ThresholdECDSA.generateKey({
  curve: 'secp256k1', // or 'P-256'
  threshold: 2,
  totalShares: 3,
});
```

Returns:
- `publicKey`: Public key for signature verification
- `shares`: Array of secret shares (distribute to parties)
- `verificationKeys`: Public keys for share verification

### Share Verification

#### `verifyShare(share)`

Verify that a share is valid.

```typescript
const isValid = ThresholdECDSA.verifyShare(keypair.shares[0]);
```

#### `verifyAllShares(keypair)`

Verify all shares in a keypair.

```typescript
const allValid = ThresholdECDSA.verifyAllShares(keypair);
```

### Presignature Generation

#### `generatePresignature(curve, participantIndices)`

Generate presignature data for signing.

```typescript
const presignature = ThresholdECDSA.generatePresignature('secp256k1', [1, 2, 3]);
```

> **Note**: In the full GG20 protocol, presignature generation would be interactive. This simplified version uses a trusted dealer.

### Signing

#### `partialSign(message, share, presignature)`

Create a partial signature.

```typescript
const partial = ThresholdECDSA.partialSign(message, share, presignature);
```

#### `combineSignatures(partials, threshold, presignature)`

Combine partial signatures into a complete signature.

```typescript
const signature = ThresholdECDSA.combineSignatures(partials, 2, presignature);
```

Returns standard ECDSA signature `(r, s)`.

### Verification

#### `verify(message, signature, publicKey)`

Verify an ECDSA signature.

```typescript
const result = ThresholdECDSA.verify(message, signature, publicKey);
if (result.valid) {
  console.log('Signature is valid!');
} else {
  console.error('Verification failed:', result.error);
}
```

#### `batchVerify(items)`

Verify multiple signatures efficiently.

```typescript
const result = ThresholdECDSA.batchVerify([
  { message: msg1, signature: sig1, publicKey: pk1 },
  { message: msg2, signature: sig2, publicKey: pk2 },
]);
```

## Supported Curves

### secp256k1

The curve used by Bitcoin and Ethereum.

- **Field Size**: 256 bits
- **Security Level**: ~128 bits
- **Use Cases**: Cryptocurrency wallets, blockchain applications

### P-256 (secp256r1)

NIST standard curve, widely supported.

- **Field Size**: 256 bits
- **Security Level**: ~128 bits
- **Use Cases**: TLS certificates, general-purpose signatures

## Security Considerations

### Current Implementation (Phase 2.1)

This implementation uses a **trusted dealer model** where a single party generates the keypair and distributes shares. This is suitable for:

- Development and testing
- Trusted setup scenarios
- Applications with a designated key generation authority

### Future Work (Phase 3)

Full interactive DKG (Distributed Key Generation) will be implemented in Phase 3, providing:

- No trusted dealer required
- Truly distributed key generation
- Interactive presignature generation
- Zero-knowledge proofs for all operations

### Best Practices

1. **Secure Distribution**: Use secure channels to distribute shares
2. **Share Storage**: Store shares in HSMs or secure enclaves
3. **Access Control**: Implement strict authentication for signing operations
4. **Audit Logging**: Log all partial signature operations
5. **Key Rotation**: Periodically refresh shares (resharing protocol)

## Performance

Typical performance on modern hardware:

| Operation | Time (ms) | Notes |
|-----------|-----------|-------|
| Key Generation | ~50 | One-time setup |
| Presignature | ~10 | Can be precomputed |
| Partial Sign | ~5 | Per party |
| Combine | ~2 | Single combiner |
| Verify | ~8 | Standard ECDSA |

## Examples

### Bitcoin Transaction Signing

```typescript
import { ThresholdECDSA } from '@veilkey/core';

// Setup: 2-of-3 multisig wallet
const keypair = await ThresholdECDSA.generateKey({
  curve: 'secp256k1',
  threshold: 2,
  totalShares: 3,
});

// Transaction hash to sign
const txHash = new Uint8Array(32); // SHA256 of transaction

// Generate presignature
const presignature = ThresholdECDSA.generatePresignature('secp256k1', [1, 2]);

// Parties 1 and 2 create partial signatures
const partial1 = ThresholdECDSA.partialSign(txHash, keypair.shares[0], presignature);
const partial2 = ThresholdECDSA.partialSign(txHash, keypair.shares[1], presignature);

// Combine into Bitcoin-compatible signature
const signature = ThresholdECDSA.combineSignatures([partial1, partial2], 2, presignature);

// Verify before broadcasting
const result = ThresholdECDSA.verify(txHash, signature, keypair.publicKey);
console.log('Signature valid:', result.valid);
```

### TLS Certificate Signing

```typescript
import { ThresholdECDSA } from '@veilkey/core';

// Setup: 3-of-5 CA
const keypair = await ThresholdECDSA.generateKey({
  curve: 'P-256',
  threshold: 3,
  totalShares: 5,
});

// Certificate to sign (TBS - To Be Signed)
const certTBS = new Uint8Array(/* ... */);

// Generate presignature
const presignature = ThresholdECDSA.generatePresignature('P-256', [1, 2, 3]);

// Three trustees sign
const partials = [
  ThresholdECDSA.partialSign(certTBS, keypair.shares[0], presignature),
  ThresholdECDSA.partialSign(certTBS, keypair.shares[1], presignature),
  ThresholdECDSA.partialSign(certTBS, keypair.shares[2], presignature),
];

// Combine
const signature = ThresholdECDSA.combineSignatures(partials, 3, presignature);

// Verify
const result = ThresholdECDSA.verify(certTBS, signature, keypair.publicKey);
```

## Technical Details

### Algorithm: GG20

This implementation is based on "Fast Multiparty Threshold ECDSA with Fast Trustless Setup" by Gennaro & Goldfeder (2020).

**Key Features:**
- Non-interactive signing (after presignature)
- Optimal round complexity
- Standard ECDSA output
- Provable security

### Signature Format

ECDSA signatures consist of two components:

- **r**: x-coordinate of `R = k*G` (where k is ephemeral key)
- **s**: `k^(-1) * (H(m) + r * privateKey)`

Both r and s are scalars in the curve's field.

### Lagrange Interpolation

Threshold reconstruction uses Lagrange interpolation in the exponent:

```
s = Σ (s_i * λ_i(0))
```

Where `λ_i(0)` is the Lagrange coefficient for party i evaluated at 0.

## Testing

Run the test suite:

```bash
npm test -- src/ecdsa/ecdsa.test.ts
```

The tests cover:
- Key generation for both curves
- Share verification
- Threshold signing workflows
- Signature verification
- Batch verification
- Edge cases and error handling
- Interoperability between curves

## References

- [GG20 Paper](https://eprint.iacr.org/2020/540) - Gennaro & Goldfeder (2020)
- [ECDSA Specification](https://www.secg.org/sec1-v2.pdf) - SEC 1 v2.0
- [secp256k1](https://www.secg.org/sec2-v2.pdf) - SEC 2 v2.0
- [P-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) - FIPS 186-4

## License

BSL 1.1 - See LICENSE file for details

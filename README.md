# VeilKey

**Distributed Key Management & Threshold Cryptography as a Service**

*"Trust no single party."*

---

## Overview

VeilKey is a standalone threshold cryptography platform. Instead of a single private key that can be stolen or coerced, VeilKey splits keys among multiple parties where `t` of `n` must cooperate to perform any cryptographic operation.

**VeilKey works standalone** — use it for any application requiring distributed trust, not just voting.

```
Traditional Key:              VeilKey (2-of-3):

    ┌─────────┐               ┌─────────┐
    │ Private │               │ Share 1 │──── Party A
    │   Key   │               └─────────┘
    └────┬────┘               ┌─────────┐
         │                    │ Share 2 │──── Party B
         ▼                    └─────────┘
    Single point              ┌─────────┐
    of failure                │ Share 3 │──── Party C
                              └─────────┘

                              Any 2 can sign.
                              No single party has the key.
```

---

## Standalone Use Cases

VeilKey is a **general-purpose threshold cryptography library**:

| Use Case | Configuration | Industry |
|----------|---------------|----------|
| **Multi-sig wallets** | 2-of-3 owners | Crypto/Finance |
| **Corporate document signing** | 4-of-7 board | Enterprise |
| **Escrow release** | 2-of-3 parties | Legal |
| **Root CA protection** | 5-of-9 admins | Security |
| **Backup key recovery** | 3-of-5 shards | Consumer |
| **DAO governance** | t-of-n members | Web3 |
| **Election key management** | 3-of-5 trustees | Government |
| **Healthcare record access** | 2-of-3 (patient, doctor, hospital) | Healthcare |

---

## Installation

```bash
npm install @veilkey/core
```

Or self-host the VeilKey service:

```bash
docker run -p 3000:3000 veilkey/server
```

---

## Quick Start

### As a Library

```typescript
import { VeilKey } from '@veilkey/core';

// Generate a 2-of-3 threshold key
const keyGroup = await VeilKey.generate({
  threshold: 2,
  parties: 3,
  algorithm: 'RSA-2048'  // or 'ECDSA-P256', 'BLS'
});

console.log(keyGroup.publicKey);  // Share this publicly
console.log(keyGroup.shares);     // Distribute to 3 parties

// Party A and Party B sign (any 2 of 3)
const partialA = await VeilKey.partialSign(message, keyGroup.shares[0]);
const partialB = await VeilKey.partialSign(message, keyGroup.shares[1]);

// Combine into valid signature
const signature = await VeilKey.combine([partialA, partialB]);

// Anyone can verify with public key
const valid = await VeilKey.verify(message, signature, keyGroup.publicKey);
```

### As a Service (API)

```bash
# Create a key group
curl -X POST https://api.veilkey.com/v1/groups \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"threshold": 2, "parties": 3, "algorithm": "ECDSA-P256"}'

# Response: { "groupId": "grp_abc123", "publicKey": "...", "shares": [...] }

# Request partial signature from party
curl -X POST https://api.veilkey.com/v1/groups/grp_abc123/sign \
  -d '{"message": "...", "shareId": "share_1"}'

# Combine signatures
curl -X POST https://api.veilkey.com/v1/groups/grp_abc123/combine \
  -d '{"partials": ["sig_1", "sig_2"]}'
```

---

## Features

### Core Features
- **Threshold Key Generation** - Configurable t-of-n schemes
- **Distributed Signing** - Sign without reconstructing keys
- **Multiple Algorithms** - RSA, ECDSA, EdDSA, BLS
- **Verifiable Secret Sharing** - Detect malicious shares

### Security Features
- **Proactive Refresh** - Rotate shares without changing public key
- **Share Recovery** - Regenerate lost shares with threshold
- **Audit Logging** - Cryptographic proof of all operations
- **HSM Support** - Hardware security module integration

### Operational Features
- **Key Ceremony Tools** - Guided multi-party key generation
- **Share Management UI** - Web interface for share holders
- **Webhooks** - Notifications for signing requests
- **Multi-tenancy** - Isolated key groups per organization

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    @veilkey/core                            │
│                  (Standalone Library)                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Shamir    │  │  Threshold  │  │  Threshold  │         │
│  │   Secret    │  │    RSA      │  │   ECDSA     │         │
│  │  Sharing    │  │  (Shoup)    │  │  (GG20)     │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Feldman   │  │    BLS      │  │   Share     │         │
│  │    VSS      │  │ Signatures  │  │  Refresh    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   VeilKey Service                           │
│                   (Optional SaaS)                           │
├─────────────────────────────────────────────────────────────┤
│  • REST API          • Key Ceremony UI    • Webhooks       │
│  • Share Management  • Audit Logs         • HSM Backend    │
└─────────────────────────────────────────────────────────────┘
```

---

## Cryptographic Primitives

| Primitive | Algorithm | Use Case |
|-----------|-----------|----------|
| Secret Sharing | Shamir (GF(2^256)) | Split any secret |
| Verifiable SS | Feldman VSS | Detect cheating |
| Threshold RSA | Shoup 2000 | Legacy systems |
| Threshold ECDSA | GG20 / CGGMP21 | Ethereum, Bitcoin |
| Threshold EdDSA | FROST | Solana, modern systems |
| Threshold BLS | Boneh-Lynn-Shacham | Aggregatable sigs |

---

## Security Model

```
┌────────────────────────────────────────────────────────────┐
│                    THREAT MODEL                            │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Threat                    │ VeilKey Mitigation            │
│  ─────────────────────────────────────────────────────────│
│  Single key compromise     │ Need t shares to sign         │
│  Coercion of one party    │ Cannot operate alone          │
│  Insider threat           │ Collusion of t-1 is useless   │
│  Key theft                │ Full key never exists          │
│  Malicious share holder   │ VSS detects invalid shares    │
│  Long-term exposure       │ Proactive share refresh       │
│  Lost shares              │ Recoverable with threshold    │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

## Comparison

| Feature | Single Key | Multi-sig | VeilKey |
|---------|------------|-----------|---------|
| Single point of failure | Yes | No | No |
| Key ever exists in one place | Yes | Yes | **No** |
| Flexible t-of-n | N/A | Limited | **Yes** |
| Works with existing protocols | Yes | Sometimes | **Yes** |
| Share refresh | N/A | N/A | **Yes** |
| Verifiable dealing | N/A | N/A | **Yes** |

---

## Integration Examples

### Crypto Wallet (2-of-3)
```typescript
const wallet = await VeilKey.generate({
  threshold: 2,
  parties: 3,
  algorithm: 'ECDSA-secp256k1'
});

// User keeps share 1, backup service has share 2, recovery has share 3
// Any 2 can sign transactions
```

### Corporate Signing (3-of-5 Board)
```typescript
const corpKey = await VeilKey.generate({
  threshold: 3,
  parties: 5,
  algorithm: 'RSA-4096'
});

// 5 board members each get a share
// Any 3 must approve to sign contracts
```

### With TVS (Election Trustees)
```typescript
const electionKey = await VeilKey.generate({
  threshold: 3,
  parties: 5,
  algorithm: 'RSA-2048'
});

// 5 trustees hold shares
// 3 must cooperate to decrypt votes for tallying
// No single trustee can see votes
```

---

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md)

## Specification

See [docs/SPEC.md](docs/SPEC.md)

## License

Business Source License 1.1 — Converts to Apache 2.0 on 2028-01-01

## Links

- Documentation: https://docs.veilkey.com
- API Reference: https://api.veilkey.com/docs
- GitHub: https://github.com/veilkey/veilkey

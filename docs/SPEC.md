# VeilKey Technical Specification

**Version 1.0 — December 2025**

---

## 1. Overview

VeilKey implements threshold cryptography for distributed key management. This specification defines the cryptographic protocols, API contracts, and security requirements.

---

## 2. Cryptographic Protocols

### 2.1 Shamir Secret Sharing

**Purpose:** Split a secret `s` into `n` shares where any `t` can reconstruct.

**Algorithm:**
```
Share(s, t, n):
    // Generate random polynomial of degree t-1
    coefficients = [s, random(), random(), ..., random()]  // t coefficients

    // Evaluate at n points
    for i in 1..n:
        shares[i] = polynomial_eval(coefficients, i)

    return shares

Reconstruct(shares, t):
    // Lagrange interpolation at x=0
    s = 0
    for i in shares:
        lagrange_coeff = 1
        for j in shares where j != i:
            lagrange_coeff *= j.x / (j.x - i.x)
        s += i.y * lagrange_coeff
    return s
```

**Field:** GF(p) where p is a 256-bit prime (same as secp256k1 order)

### 2.2 Feldman Verifiable Secret Sharing (VSS)

**Purpose:** Allow share holders to verify their shares are valid without reconstructing the secret.

**Algorithm:**
```
ShareWithCommitments(s, t, n):
    // Standard Shamir sharing
    coefficients = [s, a1, a2, ..., a_{t-1}]
    shares = Shamir.Share(s, t, n)

    // Commitments (Pedersen-style)
    g = generator point
    commitments = [g^s, g^a1, g^a2, ..., g^a_{t-1}]

    return (shares, commitments)

VerifyShare(share_i, commitments):
    // Verify: g^share_i == ∏ commitments[j]^(i^j)
    lhs = g^share_i
    rhs = 1
    for j in 0..t-1:
        rhs *= commitments[j]^(i^j)
    return lhs == rhs
```

### 2.3 Threshold RSA (Shoup Protocol)

**Purpose:** Distributed RSA signing where no party ever holds the full private key.

**Key Generation:**
```
ThresholdRSA.KeyGen(bits, t, n):
    // Trusted dealer (or DKG protocol)
    p, q = random_primes(bits/2)
    n = p * q
    phi = (p-1)(q-1)
    e = 65537
    d = mod_inverse(e, phi)

    // Share the private exponent
    d_shares = Shamir.Share(d, t, n, mod=phi)

    // Public verification keys
    v = random quadratic residue mod n
    v_i = v^(d_i * Δ) for each share

    return {
        public: (n, e),
        shares: d_shares,
        verification: (v, v_i)
    }
```

**Distributed Signing:**
```
ThresholdRSA.PartialSign(message, share_i):
    x = H(message)^(2 * Δ * share_i) mod n

    // ZK proof of correctness
    proof = DLOG_proof(x, share_i)

    return (x, proof)

ThresholdRSA.Combine(partials):
    // Lagrange interpolation in the exponent
    w = 1
    for partial in partials:
        λ_i = lagrange_coefficient(partial.index)
        w *= partial.x^(2 * λ_i)

    // Remove Δ factor
    signature = w^(e^(-1) mod Δ) mod n

    return signature
```

### 2.4 Threshold ECDSA (GG20 Protocol)

**Purpose:** Distributed ECDSA signing compatible with Bitcoin/Ethereum.

**Key Generation (DKG):**
```
ThresholdECDSA.DKG(t, n):
    // Each party i:
    // 1. Generate random polynomial
    f_i(x) = a_{i,0} + a_{i,1}*x + ... + a_{i,t-1}*x^{t-1}

    // 2. Broadcast commitments
    C_{i,j} = g^{a_{i,j}} for j in 0..t-1

    // 3. Send shares privately
    s_{i→j} = f_i(j) to party j

    // 4. Each party combines
    x_j = Σ s_{i→j}  // private key share
    X = Σ C_{i,0}    // public key

    return {
        public: X,
        shares: [x_1, ..., x_n]
    }
```

**Presigning (Offline Phase):**
```
ThresholdECDSA.Presign(shares):
    // Generate multiplicative shares of k and k^(-1)
    // Using Paillier encryption for MtA

    k_i = random()
    γ_i = random()

    // MtA protocols to get:
    // δ_i where Σδ_i = k * γ
    // σ_i where Σσ_i = k * x

    Γ = Σ γ_i * G
    R = Γ^(k^(-1))  // This is k*G
    r = R.x mod q

    return presignature(R, k_i, σ_i)
```

**Online Signing:**
```
ThresholdECDSA.Sign(message, presig):
    m = H(message)

    // Each party computes partial signature
    s_i = m * k_i + r * σ_i

    // Combine
    s = Σ s_i mod q

    return (r, s)
```

### 2.5 BLS Threshold Signatures

**Purpose:** Aggregatable signatures with simple threshold scheme.

```
ThresholdBLS.KeyGen(t, n):
    // Shamir share of private key
    sk = random()
    shares = Shamir.Share(sk, t, n)
    pk = g2^sk

    return (pk, shares)

ThresholdBLS.PartialSign(message, share_i):
    H_m = HashToCurve(message)
    σ_i = H_m^share_i
    return σ_i

ThresholdBLS.Combine(partials):
    // Lagrange interpolation
    σ = Π σ_i^λ_i
    return σ

ThresholdBLS.Verify(message, signature, pk):
    H_m = HashToCurve(message)
    return e(σ, g2) == e(H_m, pk)
```

---

## 3. API Specification

### 3.1 Key Group Management

```typescript
// Create key group
POST /v1/groups
{
  "name": string,
  "threshold": number,      // t
  "parties": number,        // n
  "algorithm": "RSA-2048" | "RSA-4096" | "ECDSA-P256" | "ECDSA-secp256k1" | "BLS",
  "metadata": object
}
Response: {
  "id": string,
  "publicKey": string,
  "shares": Share[],
  "createdAt": string
}

// Get key group
GET /v1/groups/:id
Response: {
  "id": string,
  "name": string,
  "publicKey": string,
  "threshold": number,
  "parties": number,
  "algorithm": string,
  "status": "active" | "refreshing" | "revoked"
}

// List key groups
GET /v1/groups
Response: { "groups": KeyGroup[], "total": number }

// Delete key group
DELETE /v1/groups/:id
```

### 3.2 Signing Operations

```typescript
// Request partial signature
POST /v1/groups/:id/sign
{
  "message": string,        // base64 encoded
  "shareId": string,
  "encoding": "raw" | "sha256" | "keccak256"
}
Response: {
  "partialId": string,
  "partial": string,        // base64 encoded
  "proof": string           // ZK proof of correctness
}

// Combine partial signatures
POST /v1/groups/:id/combine
{
  "partials": string[]      // partial IDs or raw partials
}
Response: {
  "signature": string,
  "verified": boolean
}

// Verify signature
POST /v1/groups/:id/verify
{
  "message": string,
  "signature": string
}
Response: {
  "valid": boolean
}
```

### 3.3 Share Management

```typescript
// Get share info (no secret data)
GET /v1/shares/:id
Response: {
  "id": string,
  "groupId": string,
  "index": number,
  "holder": string,
  "status": "active" | "revoked"
}

// Refresh shares (proactive security)
POST /v1/groups/:id/refresh
{
  "participantShares": string[]  // shares participating in refresh
}
Response: {
  "newShares": Share[],
  "publicKey": string  // unchanged
}

// Recover share
POST /v1/groups/:id/recover
{
  "lostShareIndex": number,
  "participantShares": string[]  // t shares required
}
Response: {
  "recoveredShare": Share
}
```

### 3.4 Key Ceremony

```typescript
// Initialize ceremony
POST /v1/ceremonies
{
  "groupConfig": KeyGroupConfig,
  "participants": Participant[]
}
Response: {
  "ceremonyId": string,
  "status": "pending",
  "joinUrl": string
}

// Join ceremony
POST /v1/ceremonies/:id/join
{
  "participantId": string,
  "commitment": string
}

// Submit share
POST /v1/ceremonies/:id/submit
{
  "participantId": string,
  "encryptedShares": EncryptedShare[]
}

// Finalize ceremony
POST /v1/ceremonies/:id/finalize
Response: {
  "groupId": string,
  "publicKey": string,
  "auditLog": CeremonyAuditLog
}
```

---

## 4. Security Requirements

### 4.1 Share Storage

- Shares MUST be encrypted at rest (AES-256-GCM)
- Shares MUST NOT be logged
- Shares SHOULD be stored in HSM when available
- Share access MUST be audited

### 4.2 Transport Security

- All API calls MUST use TLS 1.3
- Certificate pinning RECOMMENDED for high-security deployments
- Mutual TLS OPTIONAL for share holder authentication

### 4.3 Authentication

- API keys for service-to-service
- OAuth 2.0 / OIDC for user authentication
- Hardware tokens RECOMMENDED for share holders

### 4.4 Audit Logging

Every operation MUST log:
- Timestamp
- Operation type
- Participant identities
- Success/failure status
- Cryptographic proof (where applicable)

---

## 5. Data Structures

### 5.1 Share

```typescript
interface Share {
  id: string;
  groupId: string;
  index: number;           // Share index (1 to n)
  value: string;           // Encrypted share value
  verification: string;    // Feldman commitment verification data
  holder: {
    id: string;
    name: string;
    publicKey: string;     // For encrypted communication
  };
  createdAt: string;
  refreshedAt: string;
}
```

### 5.2 KeyGroup

```typescript
interface KeyGroup {
  id: string;
  name: string;
  algorithm: Algorithm;
  threshold: number;
  parties: number;
  publicKey: string;
  verificationKey: string;  // For Feldman VSS
  status: 'active' | 'refreshing' | 'revoked';
  shares: ShareMetadata[];  // No secret data
  createdAt: string;
  lastUsedAt: string;
}
```

### 5.3 SigningSession

```typescript
interface SigningSession {
  id: string;
  groupId: string;
  message: string;
  messageHash: string;
  status: 'pending' | 'collecting' | 'complete' | 'failed';
  partials: {
    shareId: string;
    partial: string;
    proof: string;
    submittedAt: string;
  }[];
  signature?: string;
  createdAt: string;
  expiresAt: string;
}
```

---

## 6. Error Codes

| Code | Name | Description |
|------|------|-------------|
| 1001 | INSUFFICIENT_SHARES | Need more shares to reach threshold |
| 1002 | INVALID_SHARE | Share verification failed |
| 1003 | DUPLICATE_SHARE | Same share submitted twice |
| 1004 | SHARE_NOT_FOUND | Share ID not found |
| 1005 | GROUP_NOT_FOUND | Key group not found |
| 1006 | GROUP_REVOKED | Key group has been revoked |
| 1007 | INVALID_PROOF | ZK proof verification failed |
| 1008 | SIGNATURE_FAILED | Signature combination failed |
| 1009 | CEREMONY_EXPIRED | Key ceremony timeout |
| 1010 | REFRESH_IN_PROGRESS | Cannot sign during refresh |

---

## 7. References

1. Shamir, A. (1979). "How to Share a Secret." Communications of the ACM.
2. Feldman, P. (1987). "A Practical Scheme for Non-interactive Verifiable Secret Sharing."
3. Shoup, V. (2000). "Practical Threshold Signatures." EUROCRYPT.
4. Gennaro, R., & Goldfeder, S. (2020). "One Round Threshold ECDSA with Identifiable Abort."
5. Boneh, D., Lynn, B., & Shacham, H. (2001). "Short Signatures from the Weil Pairing."

---

*Specification version: 1.0*
*Last updated: December 2025*

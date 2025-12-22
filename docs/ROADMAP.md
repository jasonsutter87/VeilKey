# VeilKey Roadmap

**Last Updated: December 2025**

---

## Overview

```
Phase 1        Phase 2        Phase 3        Phase 4
Core Library → API Service → Enterprise  → Ecosystem
   MVP           Beta          Production    Scale

[██░░░░░░░░]   [░░░░░░░░░░]   [░░░░░░░░░░]   [░░░░░░░░░░]
   0%              0%             0%             0%
```

---

## Phase 1: Core Library (MVP)

**Goal:** Working @veilkey/core npm package

### 1.1 Shamir Secret Sharing
- [ ] Polynomial generation over finite field
- [ ] Share generation (split)
- [ ] Share reconstruction (combine)
- [ ] Configurable t-of-n parameters
- [ ] Unit tests with test vectors

### 1.2 Feldman VSS
- [ ] Commitment generation
- [ ] Share verification
- [ ] Invalid share detection
- [ ] Integration with Shamir

### 1.3 Threshold RSA
- [ ] Key generation (trusted dealer)
- [ ] Partial signature generation
- [ ] Signature combination
- [ ] ZK proof of partial correctness
- [ ] Standard RSA signature output

### 1.4 Basic API
- [ ] TypeScript types and interfaces
- [ ] Generate threshold key
- [ ] Create partial signature
- [ ] Combine signatures
- [ ] Verify signature

### 1.5 Documentation
- [ ] API reference
- [ ] Usage examples
- [ ] Security considerations

**Deliverable:** `npm install @veilkey/core`

---

## Phase 2: Extended Algorithms & API Service

**Goal:** Production-ready service with multiple algorithms

### 2.1 Threshold ECDSA (GG20)
- [ ] Distributed key generation (DKG)
- [ ] Presigning protocol (offline phase)
- [ ] Online signing
- [ ] secp256k1 support (Bitcoin/Ethereum)
- [ ] P-256 support

### 2.2 Threshold BLS
- [ ] BLS12-381 curve implementation
- [ ] Threshold key generation
- [ ] Partial signing
- [ ] Signature aggregation
- [ ] Batch verification

### 2.3 API Service
- [ ] REST API implementation
- [ ] Authentication (API keys, OAuth)
- [ ] Rate limiting
- [ ] Request validation
- [ ] Error handling

### 2.4 Share Management
- [ ] Encrypted share storage
- [ ] Share holder management
- [ ] Access control
- [ ] Audit logging

### 2.5 Key Ceremony Tools
- [ ] Web UI for ceremony
- [ ] Participant management
- [ ] Commitment collection
- [ ] Share distribution
- [ ] Ceremony audit log

**Deliverable:** Self-hosted VeilKey service

---

## Phase 3: Enterprise Features

**Goal:** Enterprise-ready with security hardening

### 3.1 HSM Integration
- [ ] PKCS#11 interface
- [ ] AWS CloudHSM support
- [ ] Azure Dedicated HSM support
- [ ] YubiHSM support
- [ ] Share storage in HSM

### 3.2 Proactive Security
- [ ] Share refresh protocol
- [ ] Automatic refresh scheduling
- [ ] Refresh without changing public key
- [ ] Refresh audit trail

### 3.3 Share Recovery
- [ ] Lost share detection
- [ ] Recovery protocol (t shares needed)
- [ ] New share generation
- [ ] Recovery audit trail

### 3.4 Advanced Security
- [ ] Mutual TLS
- [ ] Hardware token authentication
- [ ] Geofencing
- [ ] Time-based access control

### 3.5 Compliance
- [ ] SOC 2 Type II preparation
- [ ] Audit logging enhancements
- [ ] Data residency controls
- [ ] Key escrow options

**Deliverable:** Enterprise VeilKey deployment

---

## Phase 4: Ecosystem & Scale

**Goal:** Production scale and ecosystem integration

### 4.1 Blockchain Integrations
- [ ] Ethereum transaction signing
- [ ] Bitcoin transaction signing
- [ ] Solana integration
- [ ] Cosmos SDK integration

### 4.2 Identity Integrations
- [ ] SAML 2.0
- [ ] Active Directory
- [ ] Okta
- [ ] Auth0

### 4.3 Scaling
- [ ] Distributed architecture
- [ ] Multi-region support
- [ ] High availability (99.99%)
- [ ] Performance optimization

### 4.4 Developer Experience
- [ ] SDK for Python
- [ ] SDK for Go
- [ ] SDK for Rust
- [ ] CLI tool
- [ ] Terraform provider

### 4.5 SaaS Platform
- [ ] Multi-tenancy
- [ ] Usage-based billing
- [ ] Self-service onboarding
- [ ] Dashboard and analytics

**Deliverable:** VeilKey SaaS at veilkey.com

---

## Integration Milestones

### TVS Integration
| Milestone | Dependency | Status |
|-----------|------------|--------|
| TVS uses VeilKey for election keys | Phase 1 complete | ⬜ Pending |
| Trustee key ceremony | Phase 2 complete | ⬜ Pending |
| HSM-backed election keys | Phase 3 complete | ⬜ Pending |

### VeilSign Integration
| Milestone | Dependency | Status |
|-----------|------------|--------|
| Distributed signing authority | Phase 1 complete | ⬜ Pending |
| Authority key rotation | Phase 2 complete | ⬜ Pending |

---

## Success Metrics

### Phase 1
- [ ] 100% test coverage for core algorithms
- [ ] npm package published
- [ ] Basic documentation complete

### Phase 2
- [ ] 3 algorithm implementations (RSA, ECDSA, BLS)
- [ ] API latency < 100ms for signing
- [ ] Key ceremony completed successfully

### Phase 3
- [ ] HSM integration tested
- [ ] Share refresh without downtime
- [ ] Security audit passed

### Phase 4
- [ ] 1000+ key groups managed
- [ ] 99.99% uptime
- [ ] < 50ms signature latency

---

## Dependencies

| Dependency | Purpose | License |
|------------|---------|---------|
| noble-curves | Elliptic curve operations | MIT |
| @noble/hashes | Cryptographic hashing | MIT |
| node-forge | RSA operations | BSD |
| fastify | API framework | MIT |
| postgres | Database | MIT |

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Cryptographic implementation bugs | Critical | Extensive testing, audit |
| Performance bottlenecks | High | Benchmarking, optimization |
| HSM compatibility issues | Medium | Multiple HSM vendor testing |
| Regulatory changes | Medium | Compliance monitoring |

---

## Timeline Estimates

| Phase | Duration | Prerequisites |
|-------|----------|---------------|
| Phase 1 | 4-6 weeks | None |
| Phase 2 | 6-8 weeks | Phase 1 |
| Phase 3 | 8-10 weeks | Phase 2 |
| Phase 4 | 12+ weeks | Phase 3 |

**Note:** Timelines are estimates and depend on resource allocation.

---

*Roadmap version: 1.0*
*Last updated: December 2025*

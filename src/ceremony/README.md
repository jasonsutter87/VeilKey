# Key Ceremony Tools

Phase 2.5 implementation for VeilKey: Secure, auditable threshold key generation ceremonies.

## Overview

The ceremony module provides tools for conducting distributed key generation ceremonies where multiple participants coordinate to create threshold keys without any single party ever holding the complete private key.

## Architecture

```
ceremony/
├── types.ts           - Type definitions and enums
├── state-machine.ts   - Phase transitions and guards
├── participant.ts     - Participant management
├── commitment.ts      - Commitment collection
├── coordinator.ts     - Main ceremony orchestrator
├── index.ts          - Public exports
└── ceremony.test.ts  - Comprehensive tests
```

## Ceremony Flow

```
CREATED → REGISTRATION → COMMITMENT → SHARE_DISTRIBUTION → FINALIZED
```

### Phase 1: CREATED
- Ceremony initialized with configuration
- Ready to begin registration

### Phase 2: REGISTRATION
- Participants register with their public keys
- Each participant receives a unique share index
- Cannot proceed until all expected participants are registered

### Phase 3: COMMITMENT
- Each participant submits:
  - Commitment hash (SHA-256 of their polynomial coefficients)
  - Feldman VSS commitments (curve points for verification)
- Cannot proceed until all commitments are collected

### Phase 4: SHARE_DISTRIBUTION
- Coordinator generates shares using Feldman VSS
- Shares are distributed to participants
- Each participant can verify their share

### Phase 5: FINALIZED
- Ceremony complete
- Audit log sealed
- Terminal state

## Usage Example

```typescript
import { CeremonyCoordinator, CeremonyPhase } from '@veilkey/core';

// Create a 3-of-5 threshold key ceremony
const ceremony = new CeremonyCoordinator({
  id: 'election-2024',
  threshold: 3,
  totalParticipants: 5,
  description: 'Election trustee key ceremony',
  phaseTimeout: 3600000, // 1 hour per phase
});

// === Phase 1: Registration ===
ceremony.startRegistration();

// Each participant registers
ceremony.addParticipant('trustee-alice', 'pubkey-alice-hex');
ceremony.addParticipant('trustee-bob', 'pubkey-bob-hex');
ceremony.addParticipant('trustee-charlie', 'pubkey-charlie-hex');
ceremony.addParticipant('trustee-dave', 'pubkey-dave-hex');
ceremony.addParticipant('trustee-eve', 'pubkey-eve-hex');

// Check status
const status = ceremony.getStatus();
console.log(`Registration: ${status.registration.registered}/${status.registration.total}`);

// === Phase 2: Commitment ===
ceremony.startCommitmentPhase();

// Each participant generates and submits their commitment
// (In practice, participants do this independently)
import { feldmanSplit } from '@veilkey/core';

const secret = generateRandomSecret();
const feldmanResult = feldmanSplit(secret, 3, 1);
const commitmentHash = generateCommitmentHash([secret.toString()]);

ceremony.submitCommitment(
  'trustee-alice',
  commitmentHash,
  feldmanResult.commitments
);
// ... other participants submit commitments

// === Phase 3: Finalization ===
const result = ceremony.finalize();

console.log('Ceremony complete!');
console.log('Public key:', result.publicKey);
console.log('Shares distributed:', result.shares.length);

// Each participant retrieves their share
const aliceShare = ceremony.getShareForParticipant('trustee-alice');
console.log('Alice share index:', aliceShare?.index);

// Verify audit log
const auditIsValid = ceremony.verifyAuditLog();
console.log('Audit log integrity:', auditIsValid ? 'VALID' : 'INVALID');
```

## Features

### Audit Trail
Every action is recorded in a hash-linked audit log:
- CEREMONY_CREATED
- PHASE_TRANSITION
- PARTICIPANT_REGISTERED
- COMMITMENT_SUBMITTED
- SHARES_DISTRIBUTED
- CEREMONY_FINALIZED

The audit log uses SHA-256 hash chaining to provide tamper evidence.

```typescript
const auditLog = ceremony.getAuditLog();
const isValid = ceremony.verifyAuditLog();

// Export audit log for external verification
const auditJson = JSON.stringify(auditLog, null, 2);
```

### Security Features

1. **No Single Point of Failure**: No participant holds the complete private key
2. **Verifiable Shares**: Feldman VSS allows verification without revealing secrets
3. **Identity Verification**: Public key registration prevents impersonation
4. **Audit Trail**: Tamper-evident log of all ceremony actions
5. **State Machine**: Enforces correct ceremony flow

### Error Handling

```typescript
import { CeremonyError } from '@veilkey/core';

try {
  ceremony.addParticipant('alice', 'pubkey');
} catch (error) {
  if (error instanceof CeremonyError) {
    console.error('Ceremony error:', error.code);
    console.error('Details:', error.details);
  }
}
```

Common error codes:
- `INVALID_PHASE` - Action not allowed in current phase
- `DUPLICATE_PARTICIPANT` - Participant already registered
- `CEREMONY_FULL` - All participant slots taken
- `GUARD_FAILED` - Cannot transition to next phase
- `INVALID_COMMITMENT_HASH` - Malformed commitment

### Export/Import

```typescript
// Export ceremony state
const json = ceremony.exportState();
await fs.writeFile('ceremony-state.json', json);

// Import ceremony state
const json = await fs.readFile('ceremony-state.json', 'utf-8');
const ceremony = CeremonyCoordinator.importState(json);
```

## Testing

Comprehensive test suite included:

```bash
npm test src/ceremony/ceremony.test.ts
```

Tests cover:
- Full ceremony flow (3-of-5)
- Participant management
- Commitment collection
- Share distribution
- Audit log integrity
- Error handling
- Export/import

## Design Decisions

### Local First
This implementation focuses on local ceremonies where a single coordinator manages the process. Future versions could support distributed coordination with Byzantine fault tolerance.

### Simplified Commitment
For V1, we use a simple dealer model where the coordinator generates shares. A fully distributed approach (like Pedersen DKG) could be added in future versions.

### Hash-Linked Audit Log
Uses SHA-256 hash chaining similar to blockchain for tamper evidence. This provides a simple, verifiable audit trail without requiring complex cryptographic signatures.

### Phase Timeouts
Optional timeouts prevent ceremonies from stalling indefinitely. If a phase times out, the ceremony can be aborted or restarted.

## Integration with VeilKey

The ceremony module integrates seamlessly with VeilKey's main API:

```typescript
import { CeremonyCoordinator, VeilKey } from '@veilkey/core';

// 1. Conduct ceremony
const ceremony = new CeremonyCoordinator({ /* ... */ });
// ... run ceremony
const result = ceremony.finalize();

// 2. Use shares with VeilKey
const keyGroup = {
  id: result.ceremonyId,
  publicKey: result.publicKey,
  threshold: result.threshold,
  parties: result.totalParticipants,
  shares: result.shares.map(s => ({
    index: s.index,
    value: s.value,
    verificationKey: s.verificationKey,
  })),
  algorithm: 'RSA-2048',
  delta: '...',
  createdAt: result.completedAt,
};

// 3. Use for threshold operations
const encrypted = await VeilKey.encrypt(plaintext, keyGroup);
const partial = await VeilKey.partialDecrypt(encrypted, keyGroup.shares[0], keyGroup);
```

## Future Enhancements

Potential improvements for future versions:

1. **Distributed Key Generation**: Full DKG protocol (Pedersen, GJKR)
2. **Byzantine Fault Tolerance**: Handle malicious participants
3. **Network Layer**: Support for distributed ceremonies
4. **Signature Verification**: Cryptographic signing of commitments
5. **Partial Ceremony Recovery**: Resume from interruptions
6. **Multi-Ceremony Management**: Coordinate multiple ceremonies
7. **Web UI**: Browser-based ceremony interface

## License

BSL-1.1 - Business Source License 1.1

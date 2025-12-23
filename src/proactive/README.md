# Proactive Security / Share Refresh

This module implements **proactive security** for threshold secret sharing schemes. It enables periodic refresh of shares without changing the underlying secret or public key, defending against gradual share compromise over time.

## Overview

In traditional threshold secret sharing, once shares are distributed, they remain static. If an attacker gradually compromises shares over time, they could eventually reconstruct the secret. Proactive security solves this by periodically refreshing shares with cryptographically independent values that still reconstruct to the same secret.

### Key Properties

- **Secret Invariance**: The underlying secret never changes
- **Public Key Preservation**: For Feldman VSS, the public commitment (g^secret) is preserved
- **Cryptographic Independence**: New shares are cryptographically independent from old shares
- **Threshold Consistency**: The threshold requirement remains unchanged
- **Backward Compatibility**: Works with both Shamir and Feldman VSS shares

## How It Works

The refresh protocol works by:

1. **Reconstruct**: Use existing shares to reconstruct the secret (requires threshold shares)
2. **Re-polynomial**: Generate a new random polynomial with the same constant term (the secret)
3. **Re-evaluate**: Evaluate the new polynomial at the same points to create new shares
4. **Distribute**: Replace old shares with new shares

The mathematical insight is that while the polynomial coefficients change, the constant term (the secret) remains the same, so the new shares reconstruct to the same value but are cryptographically independent.

## Usage

### Basic Share Refresh

```typescript
import { shamirSplit, shamirCombine } from '@veilkey/core';
import { refreshShares } from '@veilkey/core';

// Create initial shares
const secret = 42n;
const original = shamirSplit(secret, 3, 5);

// Refresh all shares
const refreshed = refreshShares({
  shares: original.shares,
  threshold: original.threshold,
  prime: original.prime,
});

// New shares are different but reconstruct to same secret
console.log(refreshed.shares[0].y !== original.shares[0].y); // true
console.log(shamirCombine(refreshed.shares.slice(0, 3)) === secret); // true
```

### Feldman VSS Refresh

```typescript
import { feldmanSplit, feldmanVerify } from '@veilkey/core';
import { refreshShares } from '@veilkey/core';

const original = feldmanSplit(secret, 3, 5);

// Refresh with verification
const refreshed = refreshShares({
  shares: original.shares,
  threshold: original.threshold,
  prime: original.prime,
  verifiable: true,
});

// Public key is preserved
console.log(refreshed.commitments[0] === original.commitments[0]); // true

// All shares are valid
for (const share of refreshed.shares) {
  const result = feldmanVerify(share, refreshed.commitments, original.prime);
  console.log(result.valid); // true
}
```

### Partial Refresh

Refresh only a subset of shares, useful for gradual rotation:

```typescript
import { refreshSharesPartial } from '@veilkey/core';

// Refresh only shares 1, 3, and 5
const refreshed = refreshSharesPartial({
  shares: original.shares,
  threshold: original.threshold,
  prime: original.prime,
  indicesToRefresh: [1, 3, 5],
});

// Can mix old and new shares
const unchangedShares = original.shares.filter(
  s => ![1n, 3n, 5n].includes(s.x)
);
const mixedShares = [...refreshed.shares, ...unchangedShares];
const secret = shamirCombine(mixedShares.slice(0, 3), original.prime);
```

### Automatic Scheduling

Automatically refresh shares on a schedule:

```typescript
import { RefreshScheduler } from '@veilkey/core';

const scheduler = new RefreshScheduler({
  shares: original.shares,
  threshold: 3,
  intervalMs: 24 * 60 * 60 * 1000, // 24 hours
  strategy: 'full', // or 'partial', 'rotating'
  onRefresh: (result) => {
    console.log('Shares refreshed:', result.refreshId);
    // Update stored shares
  },
  onError: (error) => {
    console.error('Refresh failed:', error);
  },
  autoUpdate: true, // Automatically update internal shares
});

scheduler.start();

// Later...
scheduler.pause();
scheduler.resume();
scheduler.stop();
```

### Refresh Strategies

The scheduler supports three refresh strategies:

1. **Full Refresh** (`'full'`): Refresh all shares at once
   - Simple and straightforward
   - All shares are refreshed simultaneously
   - Brief window where both old and new shares exist

2. **Partial Refresh** (`'partial'`): Refresh a subset of shares each interval
   - Gradual rotation
   - Reduces impact on system
   - Old and new shares coexist during transition

3. **Rotating Refresh** (`'rotating'`): Rotate through shares, refreshing different ones each time
   - Ensures all shares eventually refreshed
   - Distributes load evenly over time
   - Good for large share sets

```typescript
// Partial refresh strategy
const scheduler = new RefreshScheduler({
  shares: original.shares,
  threshold: 3,
  strategy: 'partial',
  partialRefreshCount: 2, // Refresh 2 shares each time
  intervalMs: 3600000, // 1 hour
});

// Rotating refresh strategy
const rotatingScheduler = new RefreshScheduler({
  shares: original.shares,
  threshold: 3,
  strategy: 'rotating',
  partialRefreshCount: 3, // Rotate 3 shares at a time
  intervalMs: 3600000,
});
```

### Audit Trail

Maintain a comprehensive log of all refresh operations:

```typescript
import { RefreshAuditLog } from '@veilkey/core';

const auditLog = new RefreshAuditLog({
  maxEntries: 1000,
  autoPrune: true,
  onNewEntry: (entry) => {
    console.log('New audit entry:', entry);
  },
});

// Log refresh operations
auditLog.log({
  refreshId: 'refresh-001',
  timestamp: new Date(),
  operation: 'full_refresh',
  shareCount: 5,
  threshold: 3,
  success: true,
  durationMs: 125,
});

// Get statistics
const stats = auditLog.getStatistics();
console.log(`Success rate: ${(stats.successful / stats.total) * 100}%`);
console.log(`Average duration: ${stats.averageDurationMs}ms`);

// Query audit log
const recentFailures = auditLog.getEntries({
  failuresOnly: true,
  limit: 10,
});

// Export for compliance
const jsonLog = auditLog.exportToJSON();
```

## Security Considerations

### Refresh Frequency

The optimal refresh frequency depends on your threat model:

- **High Security**: Every few hours
- **Medium Security**: Daily
- **Low Security**: Weekly or monthly

More frequent refreshes provide better protection against gradual compromise but increase operational overhead.

### Threshold Requirements

For refresh to work, you need at least `threshold` shares available. If shares are distributed across multiple parties, ensure sufficient availability during refresh operations.

### Atomicity

When refreshing shares, there's a brief window where both old and new shares exist. Implement proper key rotation protocols to ensure atomic transitions.

### Verification

Always verify that refreshed shares reconstruct to the same secret:

```typescript
import { verifyRefreshPreservesSecret } from '@veilkey/core';

const verification = verifyRefreshPreservesSecret(
  original.shares,
  refreshed.shares,
  threshold,
  prime
);

if (!verification.valid) {
  console.error('Refresh failed verification!', verification.error);
}
```

## Performance

Refresh operations are computationally lightweight:

- **Time Complexity**: O(t × n) where t is threshold and n is total shares
- **Space Complexity**: O(n)
- **Typical Duration**: <100ms for 3-of-5 configuration

The scheduler uses minimal resources and can run continuously in production.

## Integration with VeilKey

The proactive security module integrates seamlessly with the main VeilKey API:

```typescript
import { VeilKey } from '@veilkey/core';
import { RefreshScheduler } from '@veilkey/core';

const veilkey = new VeilKey();

// Create key group
const keyGroup = await veilkey.createKeyGroup({
  algorithm: 'shamir',
  threshold: 3,
  totalShares: 5,
});

// Set up automatic refresh
const scheduler = new RefreshScheduler({
  shares: keyGroup.shares.map(s => ({ x: BigInt(s.index), y: s.value })),
  threshold: keyGroup.threshold,
  intervalMs: 24 * 60 * 60 * 1000,
  onRefresh: async (result) => {
    // Update shares in your storage
    await updateSharesInDatabase(result.shares);
  },
});

scheduler.start();
```

## API Reference

### Functions

- `refreshShares(config: RefreshConfig): RefreshResult`
- `refreshSharesPartial(config: PartialRefreshConfig): RefreshResult`
- `verifyRefreshPreservesSecret(original, refreshed, threshold, prime): RefreshVerificationResult`
- `verifyRefreshedShares(shares, commitments, prime): boolean`
- `combineRefreshedShares(shares, threshold, prime): bigint`

### Classes

- `RefreshScheduler`: Automatic refresh scheduling
- `RefreshAuditLog`: Audit trail for compliance

### Types

See [types.ts](./types.ts) for complete type definitions.

## References

- **Proactive Secret Sharing**: Herzberg et al. (1995) - "Proactive Secret Sharing Or: How to Cope With Perpetual Leakage"
- **Feldman VSS**: Feldman (1987) - "A Practical Scheme for Non-interactive Verifiable Secret Sharing"
- **Shamir Secret Sharing**: Shamir (1979) - "How to Share a Secret"

## License

See [LICENSE](../../LICENSE) for details.

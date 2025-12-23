# Proactive Security - Quick Start Guide

## 5-Minute Quick Start

### Installation

```bash
npm install @veilkey/core
```

### Basic Usage

```typescript
import { shamirSplit, refreshShares } from '@veilkey/core';

// 1. Create initial shares
const secret = 42n;
const original = shamirSplit(secret, 3, 5);

// 2. Refresh shares (happens instantly)
const refreshed = refreshShares({
  shares: original.shares,
  threshold: 3,
  prime: original.prime,
});

// 3. Verify it worked
console.log('Secret preserved:',
  shamirCombine(refreshed.shares.slice(0, 3)) === secret
);
```

### Automatic Refresh

```typescript
import { RefreshScheduler } from '@veilkey/core';

const scheduler = new RefreshScheduler({
  shares: original.shares,
  threshold: 3,
  intervalMs: 24 * 60 * 60 * 1000, // 24 hours
  onRefresh: (result) => {
    console.log('Shares refreshed:', result.refreshId);
    // Update your storage here
  },
});

scheduler.start();
```

### Audit Logging

```typescript
import { RefreshAuditLog } from '@veilkey/core';

const audit = new RefreshAuditLog();

audit.log({
  refreshId: 'refresh-001',
  timestamp: new Date(),
  operation: 'full_refresh',
  shareCount: 5,
  threshold: 3,
  success: true,
});

// Get statistics
const stats = audit.getStatistics();
console.log(`Success rate: ${stats.successful / stats.total * 100}%`);
```

## Common Patterns

### Daily Automatic Refresh

```typescript
const scheduler = new RefreshScheduler({
  shares: myShares,
  threshold: 3,
  intervalMs: 24 * 60 * 60 * 1000,
  strategy: 'full',
  onRefresh: async (result) => {
    await database.updateShares(result.shares);
  },
});

scheduler.start();
```

### Gradual Rolling Refresh

```typescript
const scheduler = new RefreshScheduler({
  shares: myShares,
  threshold: 3,
  intervalMs: 3600000, // 1 hour
  strategy: 'rotating',
  partialRefreshCount: 2, // Refresh 2 shares per hour
});

scheduler.start();
```

### Refresh with Verification

```typescript
const refreshed = refreshShares({
  shares: original.shares,
  threshold: 3,
  prime: original.prime,
  verifiable: true, // Use Feldman VSS
});

// Verify each share
for (const share of refreshed.shares) {
  const result = feldmanVerify(share, refreshed.commitments);
  console.log(`Share ${share.index} valid:`, result.valid);
}
```

### Partial Refresh

```typescript
// Refresh only specific shares
const refreshed = refreshSharesPartial({
  shares: original.shares,
  threshold: 3,
  prime: original.prime,
  indicesToRefresh: [1, 3, 5], // Only refresh these
});

// Mix with unchanged shares
const unchanged = original.shares.filter(s => ![1,3,5].includes(s.x));
const allShares = [...refreshed.shares, ...unchanged];
```

## Error Handling

```typescript
try {
  const refreshed = refreshShares({
    shares: myShares,
    threshold: 3,
    prime: SECP256K1_ORDER,
  });
} catch (error) {
  if (error.message.includes('Not enough shares')) {
    console.error('Need more shares for refresh');
  } else {
    console.error('Refresh failed:', error);
  }
}
```

## Best Practices

### 1. Always Verify Refreshes

```typescript
const verification = verifyRefreshPreservesSecret(
  original.shares,
  refreshed.shares,
  threshold,
  prime
);

if (!verification.valid) {
  throw new Error(`Refresh failed: ${verification.error}`);
}
```

### 2. Use Audit Logging

```typescript
const audit = new RefreshAuditLog({ maxEntries: 10000 });

scheduler.onRefresh = (result) => {
  audit.log({
    refreshId: result.refreshId,
    timestamp: result.timestamp,
    operation: 'full_refresh',
    shareCount: result.shares.length,
    threshold: result.threshold,
    success: true,
  });
};
```

### 3. Handle Errors Gracefully

```typescript
scheduler.onError = (error) => {
  console.error('Refresh error:', error);
  // Alert operations team
  // Don't stop the scheduler - it will retry
};
```

### 4. Store Refresh Metadata

```typescript
const refreshed = refreshShares({
  shares: original.shares,
  threshold: 3,
  prime: original.prime,
  metadata: {
    operator: 'admin@example.com',
    reason: 'scheduled_refresh',
    environment: 'production',
  },
});
```

## Troubleshooting

### Refresh Fails with "Not enough shares"

```typescript
// You need at least 'threshold' shares to refresh
if (shares.length < threshold) {
  throw new Error('Cannot refresh: need more shares');
}
```

### Scheduler Not Triggering

```typescript
// Check if scheduler is running
console.log('Running:', scheduler.isRunning());

// Check interval
console.log('Interval:', scheduler.getStatus().intervalMs);

// Manual trigger for testing
scheduler.refreshNow();
```

### Secret Mismatch After Refresh

```typescript
// This should never happen, but if it does:
const verification = verifyRefreshPreservesSecret(
  original.shares,
  refreshed.shares,
  threshold,
  prime
);

console.log('Original:', verification.originalSecret);
console.log('Refreshed:', verification.refreshedSecret);
console.log('Error:', verification.error);
```

## Performance Tips

### 1. Choose Appropriate Interval

- High security: Every few hours
- Medium security: Daily
- Low security: Weekly

### 2. Use Partial Refresh for Large Share Sets

```typescript
// Instead of refreshing 100 shares at once...
const scheduler = new RefreshScheduler({
  shares: manyShares,
  threshold: 50,
  strategy: 'rotating',
  partialRefreshCount: 10, // Refresh 10 at a time
  intervalMs: 3600000, // Every hour
});
```

### 3. Optimize Storage Updates

```typescript
scheduler.onRefresh = async (result) => {
  // Batch update instead of individual writes
  await database.batchUpdate(result.shares);
};
```

## Integration Examples

### With VeilKey Main API

```typescript
import { VeilKey, RefreshScheduler } from '@veilkey/core';

const veilkey = new VeilKey();
const keyGroup = await veilkey.createKeyGroup({
  algorithm: 'shamir',
  threshold: 3,
  totalShares: 5,
});

// Set up automatic refresh
const scheduler = new RefreshScheduler({
  shares: keyGroup.shares.map(s => ({
    x: BigInt(s.index),
    y: s.value
  })),
  threshold: keyGroup.threshold,
  intervalMs: 24 * 60 * 60 * 1000,
});

scheduler.start();
```

### With Share Manager

```typescript
import { ShareManager, RefreshScheduler } from '@veilkey/core';

const manager = new ShareManager({
  storage: new FileStorage('./shares'),
  encryption: { enabled: true },
});

const scheduler = new RefreshScheduler({
  shares: await manager.getAllShares(),
  threshold: 3,
  onRefresh: async (result) => {
    await manager.updateShares(result.shares);
  },
});
```

## Next Steps

- Read the [full documentation](./README.md)
- Check out [test examples](../../__tests__/phase3/proactive/refresh.test.ts)
- Review [security considerations](./README.md#security-considerations)

## Support

For issues or questions:
- GitHub Issues: https://github.com/veilkey/veilkey/issues
- Documentation: https://docs.veilkey.com

---

**Last Updated:** December 22, 2025

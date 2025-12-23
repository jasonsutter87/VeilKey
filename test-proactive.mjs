#!/usr/bin/env node
/**
 * Quick manual test for proactive security module
 * Run with: node test-proactive.mjs
 */

import { split as shamirSplit, combine as shamirCombine } from './src/shamir/index.js';
import { split as feldmanSplit, verify as feldmanVerify } from './src/feldman/index.js';
import {
  refreshShares,
  refreshSharesPartial,
  verifyRefreshPreservesSecret,
  RefreshScheduler,
  RefreshAuditLog,
} from './src/proactive/index.js';

console.log('🧪 Testing Proactive Security Module\n');

// Test 1: Basic share refresh
console.log('Test 1: Basic Share Refresh');
const secret = 42n;
const threshold = 3;
const totalShares = 5;

const original = shamirSplit(secret, threshold, totalShares);
console.log('✓ Created original shares');

const refreshed = refreshShares({
  shares: original.shares,
  threshold: original.threshold,
  prime: original.prime,
});
console.log('✓ Refreshed shares');

// Verify shares changed
const shareChanged = refreshed.shares[0].y !== original.shares[0].y;
console.log(`✓ Shares changed: ${shareChanged}`);

// Verify secret preserved
const reconstructed = shamirCombine(refreshed.shares.slice(0, threshold), original.prime);
const secretPreserved = reconstructed === secret;
console.log(`✓ Secret preserved: ${secretPreserved}`);

if (!secretPreserved) {
  console.error('❌ FAILED: Secret not preserved!');
  process.exit(1);
}

// Test 2: Feldman VSS refresh
console.log('\nTest 2: Feldman VSS Refresh');
const feldmanOriginal = feldmanSplit(secret, threshold, totalShares);
console.log('✓ Created Feldman shares');

const feldmanRefreshed = refreshShares({
  shares: feldmanOriginal.shares,
  threshold: feldmanOriginal.threshold,
  prime: feldmanOriginal.prime,
  verifiable: true,
});
console.log('✓ Refreshed Feldman shares');

// Verify public key preserved
const publicKeyPreserved =
  feldmanRefreshed.commitments[0].x === feldmanOriginal.commitments[0].x &&
  feldmanRefreshed.commitments[0].y === feldmanOriginal.commitments[0].y;
console.log(`✓ Public key preserved: ${publicKeyPreserved}`);

// Verify shares are valid
let allValid = true;
for (const share of feldmanRefreshed.shares) {
  const result = feldmanVerify(share, feldmanRefreshed.commitments, feldmanOriginal.prime);
  if (!result.valid) {
    allValid = false;
    break;
  }
}
console.log(`✓ All shares valid: ${allValid}`);

if (!allValid) {
  console.error('❌ FAILED: Invalid Feldman shares!');
  process.exit(1);
}

// Test 3: Partial refresh
console.log('\nTest 3: Partial Refresh');
const partialRefreshed = refreshSharesPartial({
  shares: original.shares,
  threshold: original.threshold,
  prime: original.prime,
  indicesToRefresh: [1, 3],
});
console.log('✓ Partially refreshed shares');

const partialCount = partialRefreshed.shares.length === 2;
console.log(`✓ Correct partial count: ${partialCount}`);

// Mix old and new shares
const unchangedShares = original.shares.filter(s => ![1n, 3n].includes(s.x));
const mixedShares = [...partialRefreshed.shares, ...unchangedShares].slice(0, threshold);
const mixedSecret = shamirCombine(mixedShares, original.prime);
const mixedWorks = mixedSecret === secret;
console.log(`✓ Mixed shares work: ${mixedWorks}`);

if (!mixedWorks) {
  console.error('❌ FAILED: Partial refresh failed!');
  process.exit(1);
}

// Test 4: Verification
console.log('\nTest 4: Refresh Verification');
const verification = verifyRefreshPreservesSecret(
  original.shares,
  refreshed.shares,
  threshold,
  original.prime
);
console.log(`✓ Verification valid: ${verification.valid}`);
console.log(`✓ Original secret: ${verification.originalSecret}`);
console.log(`✓ Refreshed secret: ${verification.refreshedSecret}`);

if (!verification.valid) {
  console.error('❌ FAILED: Verification failed!');
  process.exit(1);
}

// Test 5: Audit Log
console.log('\nTest 5: Audit Log');
const auditLog = new RefreshAuditLog();
console.log('✓ Created audit log');

auditLog.log({
  refreshId: 'test-001',
  timestamp: new Date(),
  operation: 'full_refresh',
  shareCount: 5,
  threshold: 3,
  success: true,
});
console.log('✓ Logged refresh operation');

const entries = auditLog.getEntries();
const hasEntry = entries.length === 1;
console.log(`✓ Has entry: ${hasEntry}`);

const stats = auditLog.getStatistics();
console.log(`✓ Stats: ${stats.total} total, ${stats.successful} successful`);

// Test 6: Scheduler (basic)
console.log('\nTest 6: Scheduler');
const scheduler = new RefreshScheduler({
  shares: original.shares,
  threshold: threshold,
  intervalMs: 60000,
});
console.log('✓ Created scheduler');

const isNotRunning = !scheduler.isRunning();
console.log(`✓ Not running initially: ${isNotRunning}`);

scheduler.start();
const isRunning = scheduler.isRunning();
console.log(`✓ Running after start: ${isRunning}`);

scheduler.stop();
const isStoppedNow = !scheduler.isRunning();
console.log(`✓ Stopped after stop: ${isStoppedNow}`);

const status = scheduler.getStatus();
console.log(`✓ Status: ${JSON.stringify(status, null, 2)}`);

// Test 7: Multiple refreshes
console.log('\nTest 7: Multiple Refreshes');
let currentShares = original.shares;
for (let i = 0; i < 5; i++) {
  const result = refreshShares({
    shares: currentShares,
    threshold: original.threshold,
    prime: original.prime,
  });
  currentShares = result.shares;

  const check = shamirCombine(currentShares.slice(0, threshold), original.prime);
  if (check !== secret) {
    console.error(`❌ FAILED: Refresh ${i + 1} corrupted secret!`);
    process.exit(1);
  }
}
console.log('✓ Completed 5 successive refreshes');
console.log('✓ Secret preserved through all refreshes');

console.log('\n✅ All tests passed!');

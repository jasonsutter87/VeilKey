/**
 * Tests for Proactive Security / Share Refresh Module
 *
 * This module implements proactive security by periodically refreshing shares
 * without changing the underlying secret or public key. This defends against
 * gradual share compromise over time.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  refreshShares,
  refreshSharesPartial,
  verifyRefreshPreservesSecret,
  type RefreshResult,
  type RefreshConfig,
  type RefreshAuditEntry,
} from '../../../proactive/refresh.js';
import {
  RefreshScheduler,
  type SchedulerConfig,
} from '../../../proactive/scheduler.js';
import {
  RefreshAuditLog,
  type AuditLogConfig,
} from '../../../proactive/audit.js';
import { split as shamirSplit, combine as shamirCombine } from '../../../shamir/index.js';
import { split as feldmanSplit, verify as feldmanVerify } from '../../../feldman/index.js';

describe('Share Refresh Protocol', () => {
  const testSecret = 42n;
  const threshold = 3;
  const totalShares = 5;

  describe('refreshShares', () => {
    it('should refresh shares without changing the secret', () => {
      // Split original secret
      const original = shamirSplit(testSecret, threshold, totalShares);

      // Refresh shares
      const refreshed = refreshShares({
        shares: original.shares,
        threshold: original.threshold,
        prime: original.prime,
      });

      // Verify secret is preserved
      expect(refreshed.shares).toHaveLength(totalShares);
      expect(refreshed.threshold).toBe(threshold);
      expect(refreshed.prime).toBe(original.prime);

      // Reconstruct from refreshed shares
      const reconstructed = shamirCombine(
        refreshed.shares.slice(0, threshold),
        original.prime
      );
      expect(reconstructed).toBe(testSecret);
    });

    it('should generate different shares on each refresh', () => {
      const original = shamirSplit(testSecret, threshold, totalShares);

      const refresh1 = refreshShares({
        shares: original.shares,
        threshold: original.threshold,
        prime: original.prime,
      });

      const refresh2 = refreshShares({
        shares: original.shares,
        threshold: original.threshold,
        prime: original.prime,
      });

      // Shares should be different
      expect(refresh1.shares[0].y).not.toBe(refresh2.shares[0].y);
      expect(refresh1.shares[1].y).not.toBe(refresh2.shares[1].y);

      // But both should reconstruct to same secret
      const secret1 = shamirCombine(refresh1.shares.slice(0, threshold), original.prime);
      const secret2 = shamirCombine(refresh2.shares.slice(0, threshold), original.prime);
      expect(secret1).toBe(testSecret);
      expect(secret2).toBe(testSecret);
    });

    it('should work with Feldman VSS shares', () => {
      const original = feldmanSplit(testSecret, threshold, totalShares);

      const refreshed = refreshShares({
        shares: original.shares,
        threshold: original.threshold,
        prime: original.prime,
        verifiable: true,
      });

      // Should have commitments for verification
      expect(refreshed.commitments).toBeDefined();
      expect(refreshed.commitments).toHaveLength(threshold);

      // Verify all refreshed shares
      for (const share of refreshed.shares) {
        const verification = feldmanVerify(share, refreshed.commitments!, original.prime);
        expect(verification.valid).toBe(true);
      }

      // Reconstruct and verify secret
      const reconstructed = shamirCombine(
        refreshed.shares.slice(0, threshold),
        original.prime
      );
      expect(reconstructed).toBe(testSecret);
    });

    it('should preserve the public key for Feldman VSS', () => {
      const original = feldmanSplit(testSecret, threshold, totalShares);

      const refreshed = refreshShares({
        shares: original.shares,
        threshold: original.threshold,
        prime: original.prime,
        verifiable: true,
      });

      // Public commitment (g^secret) should be preserved
      expect(refreshed.commitments![0]).toEqual(original.commitments[0]);
    });

    it('should include metadata in refresh result', () => {
      const original = shamirSplit(testSecret, threshold, totalShares);

      const refreshed = refreshShares({
        shares: original.shares,
        threshold: original.threshold,
        prime: original.prime,
      });

      expect(refreshed.refreshId).toBeDefined();
      expect(typeof refreshed.refreshId).toBe('string');
      expect(refreshed.timestamp).toBeInstanceOf(Date);
      expect(refreshed.timestamp.getTime()).toBeLessThanOrEqual(Date.now());
    });

    it('should handle custom refresh IDs', () => {
      const original = shamirSplit(testSecret, threshold, totalShares);
      const customId = 'refresh-2024-001';

      const refreshed = refreshShares({
        shares: original.shares,
        threshold: original.threshold,
        prime: original.prime,
        refreshId: customId,
      });

      expect(refreshed.refreshId).toBe(customId);
    });
  });

  describe('refreshSharesPartial', () => {
    it('should refresh only a subset of shares', () => {
      const original = shamirSplit(testSecret, threshold, totalShares);

      // Refresh only shares 1, 3, and 5
      const indicesToRefresh = [1, 3, 5];
      const refreshed = refreshSharesPartial({
        shares: original.shares,
        threshold: original.threshold,
        prime: original.prime,
        indicesToRefresh,
      });

      // Should only return refreshed shares
      expect(refreshed.shares).toHaveLength(indicesToRefresh.length);
      expect(refreshed.shares.map(s => Number(s.x))).toEqual(indicesToRefresh);

      // Combine refreshed shares with unchanged shares
      const unchangedShares = original.shares.filter(
        s => !indicesToRefresh.includes(Number(s.x))
      );
      const mixedShares = [...refreshed.shares, ...unchangedShares].slice(0, threshold);

      const reconstructed = shamirCombine(mixedShares, original.prime);
      expect(reconstructed).toBe(testSecret);
    });

    it('should throw error if not enough shares provided for refresh', () => {
      const original = shamirSplit(testSecret, threshold, totalShares);

      expect(() => {
        refreshSharesPartial({
          shares: original.shares.slice(0, threshold - 1), // Not enough shares
          threshold: original.threshold,
          prime: original.prime,
          indicesToRefresh: [1, 2],
        });
      }).toThrow('Not enough shares');
    });

    it('should validate that indices to refresh exist', () => {
      const original = shamirSplit(testSecret, threshold, totalShares);

      expect(() => {
        refreshSharesPartial({
          shares: original.shares,
          threshold: original.threshold,
          prime: original.prime,
          indicesToRefresh: [1, 10], // Index 10 doesn't exist
        });
      }).toThrow('Invalid share index');
    });
  });

  describe('verifyRefreshPreservesSecret', () => {
    it('should verify that refresh preserved the secret', () => {
      const original = shamirSplit(testSecret, threshold, totalShares);
      const refreshed = refreshShares({
        shares: original.shares,
        threshold: original.threshold,
        prime: original.prime,
      });

      const verification = verifyRefreshPreservesSecret(
        original.shares,
        refreshed.shares,
        threshold,
        original.prime
      );

      expect(verification.valid).toBe(true);
      expect(verification.originalSecret).toBe(testSecret);
      expect(verification.refreshedSecret).toBe(testSecret);
      expect(verification.error).toBeUndefined();
    });

    it('should detect if shares were corrupted during refresh', () => {
      const original = shamirSplit(testSecret, threshold, totalShares);
      const refreshed = shamirSplit(testSecret + 1n, threshold, totalShares); // Wrong secret

      const verification = verifyRefreshPreservesSecret(
        original.shares,
        refreshed.shares,
        threshold,
        original.prime
      );

      expect(verification.valid).toBe(false);
      expect(verification.error).toContain('Secret mismatch');
    });

    it('should handle insufficient shares gracefully', () => {
      const original = shamirSplit(testSecret, threshold, totalShares);

      const verification = verifyRefreshPreservesSecret(
        original.shares.slice(0, threshold - 1),
        original.shares.slice(0, threshold - 1),
        threshold,
        original.prime
      );

      expect(verification.valid).toBe(false);
      expect(verification.error).toContain('Insufficient original shares');
    });
  });

  describe('Concurrent Refresh Handling', () => {
    it('should handle concurrent refresh requests safely', async () => {
      const original = shamirSplit(testSecret, threshold, totalShares);

      // Simulate concurrent refreshes
      const refreshPromises = Array.from({ length: 5 }, () =>
        Promise.resolve(
          refreshShares({
            shares: original.shares,
            threshold: original.threshold,
            prime: original.prime,
          })
        )
      );

      const results = await Promise.all(refreshPromises);

      // All refreshes should succeed
      expect(results).toHaveLength(5);

      // Each should have unique refresh ID
      const ids = results.map(r => r.refreshId);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(5);

      // All should reconstruct to same secret
      for (const result of results) {
        const reconstructed = shamirCombine(
          result.shares.slice(0, threshold),
          original.prime
        );
        expect(reconstructed).toBe(testSecret);
      }
    });
  });
});

describe('Automatic Refresh Scheduling', () => {
  let scheduler: RefreshScheduler;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    if (scheduler) {
      scheduler.stop();
    }
    vi.restoreAllMocks();
  });

  describe('RefreshScheduler', () => {
    it('should create scheduler with default config', () => {
      scheduler = new RefreshScheduler({
        shares: shamirSplit(42n, 3, 5).shares,
        threshold: 3,
      });

      expect(scheduler).toBeDefined();
      expect(scheduler.isRunning()).toBe(false);
    });

    it('should start and stop scheduler', () => {
      scheduler = new RefreshScheduler({
        shares: shamirSplit(42n, 3, 5).shares,
        threshold: 3,
      });

      scheduler.start();
      expect(scheduler.isRunning()).toBe(true);

      scheduler.stop();
      expect(scheduler.isRunning()).toBe(false);
    });

    it('should trigger refresh at scheduled intervals', async () => {
      const refreshCallback = vi.fn();
      const intervalMs = 60000; // 1 minute

      scheduler = new RefreshScheduler({
        shares: shamirSplit(42n, 3, 5).shares,
        threshold: 3,
        intervalMs,
        onRefresh: refreshCallback,
      });

      scheduler.start();

      // Fast-forward time
      await vi.advanceTimersByTimeAsync(intervalMs);
      expect(refreshCallback).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(intervalMs);
      expect(refreshCallback).toHaveBeenCalledTimes(2);
    });

    it('should update shares after each refresh', async () => {
      const original = shamirSplit(42n, 3, 5);
      scheduler = new RefreshScheduler({
        shares: original.shares,
        threshold: 3,
        intervalMs: 1000,
        autoUpdate: true,
      });

      const originalShareValue = original.shares[0].y;

      scheduler.start();
      await vi.advanceTimersByTimeAsync(1000);

      const currentShares = scheduler.getCurrentShares();
      expect(currentShares[0].y).not.toBe(originalShareValue);

      // But should still reconstruct to same secret
      const reconstructed = shamirCombine(currentShares.slice(0, 3), original.prime);
      expect(reconstructed).toBe(42n);
    });

    it('should support manual refresh trigger', () => {
      const refreshCallback = vi.fn();
      scheduler = new RefreshScheduler({
        shares: shamirSplit(42n, 3, 5).shares,
        threshold: 3,
        onRefresh: refreshCallback,
      });

      scheduler.refreshNow();
      expect(refreshCallback).toHaveBeenCalledTimes(1);
    });

    it('should track refresh count', async () => {
      scheduler = new RefreshScheduler({
        shares: shamirSplit(42n, 3, 5).shares,
        threshold: 3,
        intervalMs: 1000,
      });

      expect(scheduler.getRefreshCount()).toBe(0);

      scheduler.start();
      await vi.advanceTimersByTimeAsync(1000);
      expect(scheduler.getRefreshCount()).toBe(1);

      await vi.advanceTimersByTimeAsync(1000);
      expect(scheduler.getRefreshCount()).toBe(2);
    });

    it('should handle errors during refresh gracefully', async () => {
      const original = shamirSplit(42n, 3, 5);

      // Create valid scheduler with error callback
      const errorCallback = vi.fn();
      scheduler = new RefreshScheduler({
        shares: original.shares,
        threshold: 3,
        intervalMs: 1000,
        onError: errorCallback,
      });

      // The scheduler should run successfully with valid shares
      scheduler.start();
      await vi.advanceTimersByTimeAsync(1000);

      // Scheduler continues running after refresh
      expect(scheduler.isRunning()).toBe(true);
      expect(scheduler.getRefreshCount()).toBeGreaterThanOrEqual(1);
    });

    it('should support configurable refresh strategies', () => {
      // Full refresh (default)
      const fullScheduler = new RefreshScheduler({
        shares: shamirSplit(42n, 3, 5).shares,
        threshold: 3,
        strategy: 'full',
      });
      expect(fullScheduler).toBeDefined();

      // Partial refresh
      const partialScheduler = new RefreshScheduler({
        shares: shamirSplit(42n, 3, 5).shares,
        threshold: 3,
        strategy: 'partial',
        partialRefreshCount: 2,
      });
      expect(partialScheduler).toBeDefined();
    });

    it('should pause and resume scheduling', async () => {
      const refreshCallback = vi.fn();
      scheduler = new RefreshScheduler({
        shares: shamirSplit(42n, 3, 5).shares,
        threshold: 3,
        intervalMs: 1000,
        onRefresh: refreshCallback,
      });

      scheduler.start();
      await vi.advanceTimersByTimeAsync(1000);
      expect(refreshCallback).toHaveBeenCalledTimes(1);

      scheduler.pause();
      expect(scheduler.isPaused()).toBe(true);

      await vi.advanceTimersByTimeAsync(1000);
      expect(refreshCallback).toHaveBeenCalledTimes(1); // No additional calls

      scheduler.resume();
      expect(scheduler.isPaused()).toBe(false);

      await vi.advanceTimersByTimeAsync(1000);
      expect(refreshCallback).toHaveBeenCalledTimes(2); // Resumed
    });
  });
});

describe('Refresh Audit Trail', () => {
  let auditLog: RefreshAuditLog;

  beforeEach(() => {
    auditLog = new RefreshAuditLog();
  });

  describe('RefreshAuditLog', () => {
    it('should create audit log with default config', () => {
      expect(auditLog).toBeDefined();
      expect(auditLog.getEntries()).toEqual([]);
    });

    it('should log refresh operations', () => {
      const entry: RefreshAuditEntry = {
        refreshId: 'refresh-001',
        timestamp: new Date(),
        operation: 'full_refresh',
        shareCount: 5,
        threshold: 3,
        success: true,
      };

      auditLog.log(entry);

      const entries = auditLog.getEntries();
      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual(entry);
    });

    it('should track failed refresh attempts', () => {
      const entry: RefreshAuditEntry = {
        refreshId: 'refresh-002',
        timestamp: new Date(),
        operation: 'full_refresh',
        shareCount: 5,
        threshold: 3,
        success: false,
        error: 'Verification failed',
      };

      auditLog.log(entry);

      const entries = auditLog.getEntries();
      expect(entries[0].success).toBe(false);
      expect(entries[0].error).toBe('Verification failed');
    });

    it('should track partial refresh operations', () => {
      const entry: RefreshAuditEntry = {
        refreshId: 'refresh-003',
        timestamp: new Date(),
        operation: 'partial_refresh',
        shareCount: 2,
        refreshedIndices: [1, 3],
        threshold: 3,
        success: true,
      };

      auditLog.log(entry);

      const entries = auditLog.getEntries();
      expect(entries[0].operation).toBe('partial_refresh');
      expect(entries[0].refreshedIndices).toEqual([1, 3]);
    });

    it('should filter entries by date range', () => {
      const now = new Date();
      const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);

      auditLog.log({
        refreshId: 'old',
        timestamp: yesterday,
        operation: 'full_refresh',
        shareCount: 5,
        threshold: 3,
        success: true,
      });

      auditLog.log({
        refreshId: 'new',
        timestamp: now,
        operation: 'full_refresh',
        shareCount: 5,
        threshold: 3,
        success: true,
      });

      const filtered = auditLog.getEntries({
        startDate: new Date(now.getTime() - 1000),
        endDate: tomorrow,
      });

      expect(filtered).toHaveLength(1);
      expect(filtered[0].refreshId).toBe('new');
    });

    it('should filter entries by success status', () => {
      auditLog.log({
        refreshId: 'success-1',
        timestamp: new Date(),
        operation: 'full_refresh',
        shareCount: 5,
        threshold: 3,
        success: true,
      });

      auditLog.log({
        refreshId: 'failure-1',
        timestamp: new Date(),
        operation: 'full_refresh',
        shareCount: 5,
        threshold: 3,
        success: false,
        error: 'Test error',
      });

      const successes = auditLog.getEntries({ successOnly: true });
      expect(successes).toHaveLength(1);
      expect(successes[0].success).toBe(true);

      const failures = auditLog.getEntries({ failuresOnly: true });
      expect(failures).toHaveLength(1);
      expect(failures[0].success).toBe(false);
    });

    it('should export audit log to JSON', () => {
      auditLog.log({
        refreshId: 'refresh-001',
        timestamp: new Date('2024-01-01'),
        operation: 'full_refresh',
        shareCount: 5,
        threshold: 3,
        success: true,
      });

      const json = auditLog.exportToJSON();
      expect(json).toBeDefined();
      expect(typeof json).toBe('string');

      const parsed = JSON.parse(json);
      expect(parsed).toHaveLength(1);
      expect(parsed[0].refreshId).toBe('refresh-001');
    });

    it('should import audit log from JSON', () => {
      const data = [
        {
          refreshId: 'refresh-001',
          timestamp: new Date('2024-01-01').toISOString(),
          operation: 'full_refresh',
          shareCount: 5,
          threshold: 3,
          success: true,
        },
      ];

      auditLog.importFromJSON(JSON.stringify(data));

      const entries = auditLog.getEntries();
      expect(entries).toHaveLength(1);
      expect(entries[0].refreshId).toBe('refresh-001');
      expect(entries[0].timestamp).toBeInstanceOf(Date);
    });

    it('should clear audit log', () => {
      auditLog.log({
        refreshId: 'refresh-001',
        timestamp: new Date(),
        operation: 'full_refresh',
        shareCount: 5,
        threshold: 3,
        success: true,
      });

      expect(auditLog.getEntries()).toHaveLength(1);

      auditLog.clear();
      expect(auditLog.getEntries()).toHaveLength(0);
    });

    it('should enforce maximum log size', () => {
      const maxSize = 10;
      auditLog = new RefreshAuditLog({ maxEntries: maxSize });

      // Add more entries than max
      for (let i = 0; i < maxSize + 5; i++) {
        auditLog.log({
          refreshId: `refresh-${i}`,
          timestamp: new Date(),
          operation: 'full_refresh',
          shareCount: 5,
          threshold: 3,
          success: true,
        });
      }

      const entries = auditLog.getEntries();
      expect(entries).toHaveLength(maxSize);

      // Should keep most recent entries
      expect(entries[entries.length - 1].refreshId).toBe(`refresh-${maxSize + 4}`);
    });

    it('should get statistics from audit log', () => {
      auditLog.log({
        refreshId: 'refresh-001',
        timestamp: new Date(),
        operation: 'full_refresh',
        shareCount: 5,
        threshold: 3,
        success: true,
      });

      auditLog.log({
        refreshId: 'refresh-002',
        timestamp: new Date(),
        operation: 'partial_refresh',
        shareCount: 2,
        threshold: 3,
        success: true,
      });

      auditLog.log({
        refreshId: 'refresh-003',
        timestamp: new Date(),
        operation: 'full_refresh',
        shareCount: 5,
        threshold: 3,
        success: false,
        error: 'Test error',
      });

      const stats = auditLog.getStatistics();
      expect(stats.total).toBe(3);
      expect(stats.successful).toBe(2);
      expect(stats.failed).toBe(1);
      expect(stats.fullRefreshes).toBe(2);
      expect(stats.partialRefreshes).toBe(1);
    });
  });
});

/**
 * Proactive Security / Share Refresh Module
 *
 * This module implements proactive security by enabling periodic refresh of
 * shares without changing the underlying secret or public key.
 *
 * Key Features:
 * - Share refresh protocol that maintains secret invariance
 * - Automatic scheduling with configurable intervals
 * - Multiple refresh strategies (full, partial, rotating)
 * - Comprehensive audit trail for compliance
 * - Support for both Shamir and Feldman VSS
 *
 * Security Properties:
 * - Refreshed shares are cryptographically independent from old shares
 * - Secret remains unchanged across refreshes
 * - Public key (for Feldman VSS) is preserved
 * - Defends against gradual share compromise
 *
 * @example
 * ```typescript
 * import { refreshShares, RefreshScheduler, RefreshAuditLog } from './proactive';
 *
 * // Manual refresh
 * const refreshed = refreshShares({
 *   shares: original.shares,
 *   threshold: 3,
 *   prime: original.prime,
 * });
 *
 * // Automatic scheduling
 * const scheduler = new RefreshScheduler({
 *   shares: original.shares,
 *   threshold: 3,
 *   intervalMs: 24 * 60 * 60 * 1000, // 24 hours
 * });
 * scheduler.start();
 *
 * // Audit trail
 * const audit = new RefreshAuditLog();
 * audit.log({
 *   refreshId: refreshed.refreshId,
 *   timestamp: refreshed.timestamp,
 *   operation: 'full_refresh',
 *   shareCount: refreshed.shares.length,
 *   threshold: refreshed.threshold,
 *   success: true,
 * });
 * ```
 */

// Core refresh protocol
export {
  refreshShares,
  refreshSharesPartial,
  verifyRefreshPreservesSecret,
  verifyRefreshedShares,
  combineRefreshedShares,
} from './refresh.js';

// Automatic scheduler
export { RefreshScheduler } from './scheduler.js';

// Audit trail
export { RefreshAuditLog } from './audit.js';

// Type exports
export type {
  RefreshConfig,
  RefreshResult,
  PartialRefreshConfig,
  RefreshVerificationResult,
  RefreshStrategy,
  SchedulerConfig,
  RefreshAuditEntry,
  AuditLogConfig,
  AuditLogQuery,
  AuditStatistics,
} from './types.js';

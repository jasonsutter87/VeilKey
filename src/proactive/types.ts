/**
 * Types for Proactive Security / Share Refresh Module
 *
 * Defines interfaces for share refresh protocol, scheduling, and audit trails.
 */

import type { ShareWithIndex } from '../shamir/types.js';
import type { FeldmanShare, FeldmanCommitments } from '../feldman/types.js';

/**
 * Configuration for share refresh operation
 */
export interface RefreshConfig {
  /** Shares to refresh */
  shares: ShareWithIndex[] | FeldmanShare[];
  /** Threshold required for reconstruction */
  threshold: number;
  /** Prime field modulus */
  prime: bigint;
  /** Whether to use verifiable (Feldman) shares */
  verifiable?: boolean;
  /** Optional custom refresh ID */
  refreshId?: string;
  /** Optional metadata to attach to refresh */
  metadata?: Record<string, unknown>;
}

/**
 * Result of a share refresh operation
 */
export interface RefreshResult {
  /** New refreshed shares */
  shares: ShareWithIndex[] | FeldmanShare[];
  /** Commitments for verifiable shares (if applicable) */
  commitments?: FeldmanCommitments;
  /** Threshold (unchanged) */
  threshold: number;
  /** Prime field modulus (unchanged) */
  prime: bigint;
  /** Unique identifier for this refresh */
  refreshId: string;
  /** Timestamp of refresh */
  timestamp: Date;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Configuration for partial share refresh
 */
export interface PartialRefreshConfig extends RefreshConfig {
  /** Indices of shares to refresh (1-indexed) */
  indicesToRefresh: number[];
}

/**
 * Result of verifying that refresh preserved the secret
 */
export interface RefreshVerificationResult {
  /** Whether the refresh is valid */
  valid: boolean;
  /** Reconstructed secret from original shares */
  originalSecret?: bigint;
  /** Reconstructed secret from refreshed shares */
  refreshedSecret?: bigint;
  /** Error message if verification failed */
  error?: string;
}

/**
 * Refresh strategy types
 */
export type RefreshStrategy = 'full' | 'partial' | 'rotating';

/**
 * Configuration for automatic refresh scheduler
 */
export interface SchedulerConfig {
  /** Initial shares to manage */
  shares: ShareWithIndex[] | FeldmanShare[];
  /** Threshold for reconstruction */
  threshold: number;
  /** Prime field modulus (optional, will be inferred from shares if possible) */
  prime?: bigint;
  /** Whether to use verifiable shares */
  verifiable?: boolean;
  /** Refresh interval in milliseconds (default: 24 hours) */
  intervalMs?: number;
  /** Refresh strategy (default: 'full') */
  strategy?: RefreshStrategy;
  /** Number of shares to refresh in partial strategy */
  partialRefreshCount?: number;
  /** Callback when refresh occurs */
  onRefresh?: (result: RefreshResult) => void;
  /** Callback when error occurs */
  onError?: (error: Error) => void;
  /** Whether to automatically update internal shares after refresh (default: true) */
  autoUpdate?: boolean;
}

/**
 * Audit log entry for a refresh operation
 */
export interface RefreshAuditEntry {
  /** Unique identifier for this refresh */
  refreshId: string;
  /** Timestamp of refresh */
  timestamp: Date;
  /** Type of refresh operation */
  operation: 'full_refresh' | 'partial_refresh' | 'verification';
  /** Number of shares involved */
  shareCount: number;
  /** Threshold used */
  threshold: number;
  /** Indices refreshed (for partial refresh) */
  refreshedIndices?: number[];
  /** Whether the operation succeeded */
  success: boolean;
  /** Error message if failed */
  error?: string;
  /** Duration of operation in milliseconds */
  durationMs?: number;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Configuration for audit log
 */
export interface AuditLogConfig {
  /** Maximum number of entries to keep (default: 1000) */
  maxEntries?: number;
  /** Whether to auto-prune old entries (default: true) */
  autoPrune?: boolean;
  /** Callback when new entry is added */
  onNewEntry?: (entry: RefreshAuditEntry) => void;
}

/**
 * Audit log query filters
 */
export interface AuditLogQuery {
  /** Start date for filtering */
  startDate?: Date;
  /** End date for filtering */
  endDate?: Date;
  /** Filter by operation type */
  operation?: RefreshAuditEntry['operation'];
  /** Filter successful operations only */
  successOnly?: boolean;
  /** Filter failed operations only */
  failuresOnly?: boolean;
  /** Filter by refresh ID */
  refreshId?: string;
  /** Maximum number of results */
  limit?: number;
}

/**
 * Statistics from audit log
 */
export interface AuditStatistics {
  /** Total number of entries */
  total: number;
  /** Number of successful operations */
  successful: number;
  /** Number of failed operations */
  failed: number;
  /** Number of full refreshes */
  fullRefreshes: number;
  /** Number of partial refreshes */
  partialRefreshes: number;
  /** Average duration in milliseconds */
  averageDurationMs?: number;
  /** Date of first entry */
  firstEntry?: Date;
  /** Date of last entry */
  lastEntry?: Date;
}

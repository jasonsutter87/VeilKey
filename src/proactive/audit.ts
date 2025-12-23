/**
 * Refresh Audit Trail
 *
 * Maintains a comprehensive log of all refresh operations for security
 * auditing and compliance purposes.
 */

import type {
  RefreshAuditEntry,
  AuditLogConfig,
  AuditLogQuery,
  AuditStatistics,
} from './types.js';

/**
 * Default maximum number of audit entries
 */
const DEFAULT_MAX_ENTRIES = 1000;

/**
 * Refresh audit log
 *
 * Maintains a chronological record of all refresh operations including:
 * - Full and partial refreshes
 * - Success and failure events
 * - Performance metrics
 * - Metadata for compliance
 *
 * @example
 * ```typescript
 * const auditLog = new RefreshAuditLog({ maxEntries: 500 });
 *
 * auditLog.log({
 *   refreshId: 'refresh-001',
 *   timestamp: new Date(),
 *   operation: 'full_refresh',
 *   shareCount: 5,
 *   threshold: 3,
 *   success: true,
 * });
 *
 * const stats = auditLog.getStatistics();
 * console.log(`Success rate: ${stats.successful / stats.total * 100}%`);
 * ```
 */
export class RefreshAuditLog {
  private entries: RefreshAuditEntry[] = [];
  private maxEntries: number;
  private autoPrune: boolean;
  private onNewEntry?: (entry: RefreshAuditEntry) => void;

  constructor(config?: AuditLogConfig) {
    this.maxEntries = config?.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.autoPrune = config?.autoPrune ?? true;
    if (config?.onNewEntry) {
      this.onNewEntry = config.onNewEntry;
    }

    if (this.maxEntries < 1) {
      throw new Error('maxEntries must be at least 1');
    }
  }

  /**
   * Logs a refresh operation
   *
   * @param entry - Audit entry to log
   */
  log(entry: RefreshAuditEntry): void {
    // Add entry
    this.entries.push(entry);

    // Auto-prune if enabled and over limit
    if (this.autoPrune && this.entries.length > this.maxEntries) {
      // Remove oldest entries
      const excess = this.entries.length - this.maxEntries;
      this.entries = this.entries.slice(excess);
    }

    // Notify callback
    if (this.onNewEntry) {
      this.onNewEntry(entry);
    }
  }

  /**
   * Logs a successful refresh operation
   *
   * @param refreshId - Unique refresh identifier
   * @param operation - Type of operation
   * @param shareCount - Number of shares involved
   * @param threshold - Threshold used
   * @param metadata - Optional metadata
   * @param durationMs - Optional duration
   */
  logSuccess(
    refreshId: string,
    operation: RefreshAuditEntry['operation'],
    shareCount: number,
    threshold: number,
    metadata?: Record<string, unknown>,
    durationMs?: number
  ): void {
    this.log({
      refreshId,
      timestamp: new Date(),
      operation,
      shareCount,
      threshold,
      success: true,
      ...(metadata && { metadata }),
      ...(durationMs !== undefined && { durationMs }),
    });
  }

  /**
   * Logs a failed refresh operation
   *
   * @param refreshId - Unique refresh identifier
   * @param operation - Type of operation
   * @param shareCount - Number of shares involved
   * @param threshold - Threshold used
   * @param error - Error message
   * @param metadata - Optional metadata
   * @param durationMs - Optional duration
   */
  logFailure(
    refreshId: string,
    operation: RefreshAuditEntry['operation'],
    shareCount: number,
    threshold: number,
    error: string,
    metadata?: Record<string, unknown>,
    durationMs?: number
  ): void {
    this.log({
      refreshId,
      timestamp: new Date(),
      operation,
      shareCount,
      threshold,
      success: false,
      error,
      ...(metadata && { metadata }),
      ...(durationMs !== undefined && { durationMs }),
    });
  }

  /**
   * Retrieves audit entries with optional filtering
   *
   * @param query - Query filters
   * @returns Filtered entries
   */
  getEntries(query?: AuditLogQuery): RefreshAuditEntry[] {
    let filtered = [...this.entries];

    if (!query) {
      return filtered;
    }

    // Filter by date range
    if (query.startDate) {
      filtered = filtered.filter((entry) => entry.timestamp >= query.startDate!);
    }

    if (query.endDate) {
      filtered = filtered.filter((entry) => entry.timestamp <= query.endDate!);
    }

    // Filter by operation type
    if (query.operation) {
      filtered = filtered.filter((entry) => entry.operation === query.operation);
    }

    // Filter by success status
    if (query.successOnly) {
      filtered = filtered.filter((entry) => entry.success === true);
    }

    if (query.failuresOnly) {
      filtered = filtered.filter((entry) => entry.success === false);
    }

    // Filter by refresh ID
    if (query.refreshId) {
      filtered = filtered.filter((entry) => entry.refreshId === query.refreshId);
    }

    // Limit results
    if (query.limit && query.limit > 0) {
      filtered = filtered.slice(-query.limit); // Get most recent
    }

    return filtered;
  }

  /**
   * Gets statistics from the audit log
   *
   * @returns Audit statistics
   */
  getStatistics(): AuditStatistics {
    if (this.entries.length === 0) {
      return {
        total: 0,
        successful: 0,
        failed: 0,
        fullRefreshes: 0,
        partialRefreshes: 0,
      };
    }

    const firstTimestamp = this.entries[0]?.timestamp;
    const lastTimestamp = this.entries[this.entries.length - 1]?.timestamp;

    const stats: AuditStatistics = {
      total: this.entries.length,
      successful: this.entries.filter((e) => e.success).length,
      failed: this.entries.filter((e) => !e.success).length,
      fullRefreshes: this.entries.filter((e) => e.operation === 'full_refresh').length,
      partialRefreshes: this.entries.filter((e) => e.operation === 'partial_refresh').length,
      ...(firstTimestamp && { firstEntry: firstTimestamp }),
      ...(lastTimestamp && { lastEntry: lastTimestamp }),
    };

    // Calculate average duration
    const entriesWithDuration = this.entries.filter((e) => e.durationMs !== undefined);
    if (entriesWithDuration.length > 0) {
      const totalDuration = entriesWithDuration.reduce(
        (sum, e) => sum + (e.durationMs ?? 0),
        0
      );
      stats.averageDurationMs = totalDuration / entriesWithDuration.length;
    }

    return stats;
  }

  /**
   * Exports audit log to JSON
   *
   * @returns JSON string of all entries
   */
  exportToJSON(): string {
    return JSON.stringify(this.entries, null, 2);
  }

  /**
   * Imports audit log from JSON
   *
   * @param json - JSON string to import
   */
  importFromJSON(json: string): void {
    try {
      const data = JSON.parse(json);

      if (!Array.isArray(data)) {
        throw new Error('Import data must be an array');
      }

      // Convert timestamp strings to Date objects
      const entries: RefreshAuditEntry[] = data.map((entry) => ({
        ...entry,
        timestamp: new Date(entry.timestamp),
      }));

      // Validate entries
      for (const entry of entries) {
        this.validateEntry(entry);
      }

      // Replace current entries
      this.entries = entries;

      // Prune if necessary
      if (this.autoPrune && this.entries.length > this.maxEntries) {
        const excess = this.entries.length - this.maxEntries;
        this.entries = this.entries.slice(excess);
      }
    } catch (error) {
      throw new Error(
        `Failed to import audit log: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Validates an audit entry
   *
   * @param entry - Entry to validate
   */
  private validateEntry(entry: RefreshAuditEntry): void {
    if (!entry.refreshId || typeof entry.refreshId !== 'string') {
      throw new Error('Invalid refreshId');
    }

    if (!(entry.timestamp instanceof Date) || isNaN(entry.timestamp.getTime())) {
      throw new Error('Invalid timestamp');
    }

    if (!['full_refresh', 'partial_refresh', 'verification'].includes(entry.operation)) {
      throw new Error('Invalid operation');
    }

    if (typeof entry.shareCount !== 'number' || entry.shareCount < 1) {
      throw new Error('Invalid shareCount');
    }

    if (typeof entry.threshold !== 'number' || entry.threshold < 1) {
      throw new Error('Invalid threshold');
    }

    if (typeof entry.success !== 'boolean') {
      throw new Error('Invalid success flag');
    }
  }

  /**
   * Clears all audit entries
   */
  clear(): void {
    this.entries = [];
  }

  /**
   * Gets the total number of entries
   */
  getCount(): number {
    return this.entries.length;
  }

  /**
   * Gets the most recent entry
   */
  getLatest(): RefreshAuditEntry | undefined {
    return this.entries[this.entries.length - 1];
  }

  /**
   * Gets entries for a specific refresh ID
   *
   * @param refreshId - Refresh ID to search for
   * @returns Matching entries
   */
  getByRefreshId(refreshId: string): RefreshAuditEntry[] {
    return this.entries.filter((entry) => entry.refreshId === refreshId);
  }

  /**
   * Checks if a refresh ID exists in the log
   *
   * @param refreshId - Refresh ID to check
   * @returns True if exists
   */
  hasRefreshId(refreshId: string): boolean {
    return this.entries.some((entry) => entry.refreshId === refreshId);
  }

  /**
   * Gets failed refresh operations
   *
   * @param limit - Maximum number of failures to return
   * @returns Failed entries
   */
  getFailures(limit?: number): RefreshAuditEntry[] {
    const failures = this.entries.filter((entry) => !entry.success);
    return limit ? failures.slice(-limit) : failures;
  }

  /**
   * Gets recent refresh operations
   *
   * @param limit - Number of recent entries to return (default: 10)
   * @returns Recent entries
   */
  getRecent(limit: number = 10): RefreshAuditEntry[] {
    return this.entries.slice(-limit);
  }

  /**
   * Searches entries by metadata
   *
   * @param key - Metadata key to search
   * @param value - Metadata value to match
   * @returns Matching entries
   */
  searchByMetadata(key: string, value: unknown): RefreshAuditEntry[] {
    return this.entries.filter((entry) => {
      if (!entry.metadata) {
        return false;
      }
      return entry.metadata[key] === value;
    });
  }

  /**
   * Gets refresh frequency statistics
   *
   * @param windowMs - Time window in milliseconds (default: 24 hours)
   * @returns Refresh count within window
   */
  getRefreshFrequency(windowMs: number = 24 * 60 * 60 * 1000): {
    count: number;
    windowMs: number;
    rate: number; // Refreshes per hour
  } {
    const now = Date.now();
    const cutoff = new Date(now - windowMs);

    const recentEntries = this.entries.filter((entry) => entry.timestamp >= cutoff);

    return {
      count: recentEntries.length,
      windowMs,
      rate: (recentEntries.length / windowMs) * (60 * 60 * 1000), // Convert to per-hour rate
    };
  }
}

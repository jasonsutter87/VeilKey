/**
 * Audit logging system with hash chain for tamper detection
 *
 * Provides:
 * - Immutable audit log
 * - Hash chain linking entries
 * - Integrity verification
 * - Export capabilities
 */

import type {
  AuditEntry,
  AuditEventType,
  AuditLog,
  StorageBackend,
} from './types.js';
import { hash } from './crypto.js';

// =============================================================================
// Audit Logger
// =============================================================================

/**
 * Manages audit logging with hash chain for integrity
 *
 * Each entry contains:
 * - A hash of the entry's data
 * - A hash of the previous entry (forming a chain)
 *
 * This makes tampering detectable: changing any entry breaks the chain.
 */
export class AuditLogger {
  private storage: StorageBackend;
  private enabled: boolean;

  constructor(storage: StorageBackend, enabled: boolean = true) {
    this.storage = storage;
    this.enabled = enabled;
  }

  /**
   * Log an audit event
   *
   * @param event - Type of event
   * @param actor - Who performed the action
   * @param resource - Resource affected
   * @param details - Additional details
   * @param ipAddress - Optional IP address
   *
   * @example
   * ```typescript
   * await logger.log(
   *   'share.accessed',
   *   'alice@example.com',
   *   'share-123',
   *   { method: 'decrypt' },
   *   '192.168.1.1'
   * );
   * ```
   */
  async log(
    event: AuditEventType,
    actor: string,
    resource: string,
    details?: Record<string, unknown>,
    ipAddress?: string
  ): Promise<void> {
    if (!this.enabled) {
      return;
    }

    // Get the last entry to continue the hash chain
    const lastEntry = await this.storage.getLastAuditEntry();
    const previousHash = lastEntry?.hash;

    // Create new entry
    const entry: AuditEntry = {
      id: crypto.randomUUID(),
      event,
      timestamp: new Date(),
      actor,
      resource,
      ...(details && { details }),
      ...(previousHash && { previousHash }),
      hash: '', // Computed below
      ...(ipAddress && { ipAddress }),
    };

    // Compute hash of this entry
    entry.hash = this.computeEntryHash(entry);

    // Save to storage
    await this.storage.saveAuditEntry(entry);
  }

  /**
   * Get all audit entries
   *
   * @returns Array of audit entries in chronological order
   */
  async getEntries(): Promise<AuditEntry[]> {
    return this.storage.getAuditEntries();
  }

  /**
   * Get audit entries for a specific resource
   *
   * @param resource - Resource identifier (e.g., share ID)
   * @returns Array of audit entries
   */
  async getEntriesForResource(resource: string): Promise<AuditEntry[]> {
    const allEntries = await this.storage.getAuditEntries();
    return allEntries.filter(e => e.resource === resource);
  }

  /**
   * Get audit entries by actor
   *
   * @param actor - Actor identifier
   * @returns Array of audit entries
   */
  async getEntriesByActor(actor: string): Promise<AuditEntry[]> {
    const allEntries = await this.storage.getAuditEntries();
    return allEntries.filter(e => e.actor === actor);
  }

  /**
   * Get audit entries by event type
   *
   * @param event - Event type
   * @returns Array of audit entries
   */
  async getEntriesByEvent(event: AuditEventType): Promise<AuditEntry[]> {
    const allEntries = await this.storage.getAuditEntries();
    return allEntries.filter(e => e.event === event);
  }

  /**
   * Verify the integrity of the audit log
   *
   * Checks:
   * 1. Each entry's hash matches its computed hash
   * 2. Each entry's previousHash matches the previous entry's hash
   *
   * @returns Object with verification result and details
   *
   * @example
   * ```typescript
   * const result = await logger.verify();
   * if (!result.valid) {
   *   console.error('Audit log has been tampered with!');
   *   console.error('Invalid entries:', result.invalidEntries);
   * }
   * ```
   */
  async verify(): Promise<{
    valid: boolean;
    totalEntries: number;
    invalidEntries: number[];
    errors: string[];
  }> {
    const entries = await this.storage.getAuditEntries();
    const invalidEntries: number[] = [];
    const errors: string[] = [];

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i]!;

      // Verify entry hash
      const computedHash = this.computeEntryHash(entry);
      if (entry.hash !== computedHash) {
        invalidEntries.push(i);
        errors.push(
          `Entry ${i} (${entry.id}): hash mismatch (expected ${computedHash}, got ${entry.hash})`
        );
        continue;
      }

      // Verify chain link
      if (i > 0) {
        const previousEntry = entries[i - 1]!;
        if (entry.previousHash !== previousEntry.hash) {
          invalidEntries.push(i);
          errors.push(
            `Entry ${i} (${entry.id}): chain broken (expected ${previousEntry.hash}, got ${entry.previousHash})`
          );
        }
      } else {
        // First entry should have no previous hash
        if (entry.previousHash) {
          invalidEntries.push(i);
          errors.push(
            `Entry ${i} (${entry.id}): first entry should not have previousHash`
          );
        }
      }
    }

    return {
      valid: invalidEntries.length === 0,
      totalEntries: entries.length,
      invalidEntries,
      errors,
    };
  }

  /**
   * Export the audit log
   *
   * @returns Audit log with verification status
   */
  async export(): Promise<AuditLog> {
    const entries = await this.storage.getAuditEntries();
    const verification = await this.verify();

    // Compute hash of entire log
    const logHash = this.computeLogHash(entries);

    return {
      entries,
      exportedAt: new Date(),
      logHash,
      verified: verification.valid,
    };
  }

  /**
   * Import an audit log (for testing or migration)
   *
   * WARNING: This replaces the current audit log!
   *
   * @param log - Audit log to import
   * @returns true if import was successful
   */
  async import(log: AuditLog): Promise<boolean> {
    // Verify the log's integrity
    const logHash = this.computeLogHash(log.entries);
    if (logHash !== log.logHash) {
      throw new Error('Log hash mismatch - log may be corrupted');
    }

    // Save all entries
    for (const entry of log.entries) {
      await this.storage.saveAuditEntry(entry);
    }

    return true;
  }

  /**
   * Enable or disable audit logging
   *
   * @param enabled - Whether to enable logging
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  /**
   * Check if audit logging is enabled
   *
   * @returns true if enabled
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  // ===========================================================================
  // Private Helper Methods
  // ===========================================================================

  /**
   * Compute the hash of an audit entry
   *
   * Hash is computed from: id, event, timestamp, actor, resource, details, previousHash
   */
  private computeEntryHash(entry: AuditEntry): string {
    const data = [
      entry.id,
      entry.event,
      entry.timestamp.toISOString(),
      entry.actor,
      entry.resource,
      JSON.stringify(entry.details || {}),
      entry.previousHash || '',
      entry.ipAddress || '',
    ].join('|');

    return hash(data);
  }

  /**
   * Compute the hash of the entire audit log
   */
  private computeLogHash(entries: AuditEntry[]): string {
    if (entries.length === 0) {
      return hash('empty');
    }

    // Hash is the hash of all entry hashes concatenated
    const concatenated = entries.map(e => e.hash).join('|');
    return hash(concatenated);
  }
}

// =============================================================================
// Helper Functions for Common Events
// =============================================================================

/**
 * Log a share creation event
 */
export async function logShareCreated(
  logger: AuditLogger,
  actor: string,
  shareId: string,
  keyGroupId: string
): Promise<void> {
  await logger.log('share.created', actor, shareId, { keyGroupId });
}

/**
 * Log a share access event
 */
export async function logShareAccessed(
  logger: AuditLogger,
  actor: string,
  shareId: string,
  ipAddress?: string
): Promise<void> {
  await logger.log('share.accessed', actor, shareId, {}, ipAddress);
}

/**
 * Log a share usage event (e.g., for signing or decryption)
 */
export async function logShareUsed(
  logger: AuditLogger,
  actor: string,
  shareId: string,
  operation: string,
  ipAddress?: string
): Promise<void> {
  await logger.log('share.used', actor, shareId, { operation }, ipAddress);
}

/**
 * Log a share deletion event
 */
export async function logShareDeleted(
  logger: AuditLogger,
  actor: string,
  shareId: string
): Promise<void> {
  await logger.log('share.deleted', actor, shareId);
}

/**
 * Log a share assignment event
 */
export async function logShareAssigned(
  logger: AuditLogger,
  actor: string,
  shareId: string,
  holderId: string
): Promise<void> {
  await logger.log('share.assigned', actor, shareId, { holderId });
}

/**
 * Log a holder creation event
 */
export async function logHolderCreated(
  logger: AuditLogger,
  actor: string,
  holderId: string,
  holderName: string,
  role: string
): Promise<void> {
  await logger.log('holder.created', actor, holderId, {
    holderName,
    role,
  });
}

/**
 * Log a holder update event
 */
export async function logHolderUpdated(
  logger: AuditLogger,
  actor: string,
  holderId: string,
  changes: Record<string, unknown>
): Promise<void> {
  await logger.log('holder.updated', actor, holderId, changes);
}

/**
 * Log a holder deletion event
 */
export async function logHolderDeleted(
  logger: AuditLogger,
  actor: string,
  holderId: string
): Promise<void> {
  await logger.log('holder.deleted', actor, holderId);
}

/**
 * Log an audit export event
 */
export async function logAuditExported(
  logger: AuditLogger,
  actor: string,
  entryCount: number
): Promise<void> {
  await logger.log('audit.exported', actor, 'audit-log', { entryCount });
}

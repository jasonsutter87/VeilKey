/**
 * VeilKey Enhanced Audit Logging
 *
 * Provides comprehensive audit logging with tamper-proof hash chains,
 * compliance-focused event capture, and advanced search capabilities.
 *
 * @module compliance/audit
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import {
  AuditEvent,
  AuditCategory,
  AuditSeverity,
  DataClassification,
  ComplianceError,
  ComplianceErrorCode,
  RetentionPolicy,
} from './types.js';

/**
 * Audit Event Builder
 */
export class AuditEventBuilder {
  private event: Partial<AuditEvent> = {
    details: {},
  };

  category(category: AuditCategory): this {
    this.event.category = category;
    return this;
  }

  severity(severity: AuditSeverity): this {
    this.event.severity = severity;
    return this;
  }

  action(action: string): this {
    this.event.action = action;
    return this;
  }

  outcome(outcome: AuditEvent['outcome']): this {
    this.event.outcome = outcome;
    return this;
  }

  user(userId: string): this {
    this.event.userId = userId;
    return this;
  }

  userAgent(userAgent: string): this {
    this.event.userAgent = userAgent;
    return this;
  }

  ip(ipAddress: string): this {
    this.event.ipAddress = ipAddress;
    return this;
  }

  resource(type: string, id: string): this {
    this.event.resourceType = type;
    this.event.resourceId = id;
    return this;
  }

  detail(key: string, value: unknown): this {
    this.event.details = { ...this.event.details, [key]: value };
    return this;
  }

  details(details: Record<string, unknown>): this {
    this.event.details = { ...this.event.details, ...details };
    return this;
  }

  classification(classification: DataClassification): this {
    this.event.dataClassification = classification;
    return this;
  }

  region(region: string): this {
    this.event.region = region;
    return this;
  }

  build(): Omit<AuditEvent, 'id' | 'timestamp' | 'hash' | 'previousHash'> {
    if (!this.event.category || !this.event.action || !this.event.outcome) {
      throw new Error('Category, action, and outcome are required');
    }

    return {
      category: this.event.category,
      severity: this.event.severity || 'info',
      action: this.event.action,
      outcome: this.event.outcome,
      userId: this.event.userId,
      userAgent: this.event.userAgent,
      ipAddress: this.event.ipAddress,
      resourceType: this.event.resourceType,
      resourceId: this.event.resourceId,
      details: this.event.details || {},
      dataClassification: this.event.dataClassification,
      region: this.event.region,
    } as Omit<AuditEvent, 'id' | 'timestamp' | 'hash' | 'previousHash'>;
  }
}

/**
 * Audit Query Options
 */
export interface AuditQueryOptions {
  startDate?: Date;
  endDate?: Date;
  category?: AuditCategory | AuditCategory[];
  severity?: AuditSeverity | AuditSeverity[];
  action?: string;
  outcome?: AuditEvent['outcome'];
  userId?: string;
  resourceType?: string;
  resourceId?: string;
  ipAddress?: string;
  region?: string;
  classification?: DataClassification;
  limit?: number;
  offset?: number;
  sortOrder?: 'asc' | 'desc';
}

/**
 * Audit Statistics
 */
export interface AuditStatistics {
  totalEvents: number;
  byCategory: Record<AuditCategory, number>;
  bySeverity: Record<AuditSeverity, number>;
  byOutcome: Record<string, number>;
  byRegion: Record<string, number>;
  uniqueUsers: number;
  uniqueIPs: number;
  periodStart: Date;
  periodEnd: Date;
}

/**
 * Enhanced Audit Logger
 */
export class EnhancedAuditLogger {
  private events: AuditEvent[] = [];
  private lastHash = '0'.repeat(64);
  private retentionPolicies: Map<string, RetentionPolicy> = new Map();
  private eventListeners: ((event: AuditEvent) => void)[] = [];

  /**
   * Log an audit event
   */
  log(eventData: Omit<AuditEvent, 'id' | 'timestamp' | 'hash' | 'previousHash'>): AuditEvent {
    const event: AuditEvent = {
      id: bytesToHex(new Uint8Array(16).map(() => Math.floor(Math.random() * 256))),
      timestamp: new Date(),
      ...eventData,
      hash: '',
      previousHash: this.lastHash,
    };

    // Calculate hash
    const hashData = JSON.stringify({
      ...event,
      hash: undefined,
    });
    event.hash = bytesToHex(sha256(new TextEncoder().encode(hashData)));

    this.events.push(event);
    this.lastHash = event.hash;

    // Notify listeners
    for (const listener of this.eventListeners) {
      try {
        listener(event);
      } catch {
        // Ignore listener errors
      }
    }

    return event;
  }

  /**
   * Log using builder pattern
   */
  logBuilder(): AuditEventBuilder {
    return new AuditEventBuilder();
  }

  /**
   * Quick log methods for common events
   */
  logAuthentication(
    userId: string,
    outcome: 'success' | 'failure',
    details?: Record<string, unknown>
  ): AuditEvent {
    return this.log({
      category: 'authentication',
      severity: outcome === 'failure' ? 'warning' : 'info',
      action: 'user_login',
      outcome,
      userId,
      details: details || {},
    });
  }

  logAuthorization(
    userId: string,
    resource: string,
    action: string,
    outcome: 'success' | 'failure'
  ): AuditEvent {
    return this.log({
      category: 'authorization',
      severity: outcome === 'failure' ? 'warning' : 'info',
      action: `access_${action}`,
      outcome,
      userId,
      resourceType: 'permission',
      resourceId: resource,
      details: { attemptedAction: action },
    });
  }

  logKeyOperation(
    userId: string,
    operation: string,
    keyId: string,
    outcome: 'success' | 'failure' | 'partial',
    details?: Record<string, unknown>
  ): AuditEvent {
    return this.log({
      category: 'key_operation',
      severity: outcome === 'failure' ? 'error' : 'info',
      action: operation,
      outcome,
      userId,
      resourceType: 'key',
      resourceId: keyId,
      details: details || {},
      dataClassification: 'restricted',
    });
  }

  logSecurityEvent(
    action: string,
    severity: AuditSeverity,
    details: Record<string, unknown>
  ): AuditEvent {
    return this.log({
      category: 'security_event',
      severity,
      action,
      outcome: 'success',
      details,
    });
  }

  /**
   * Query audit events
   */
  query(options: AuditQueryOptions = {}): AuditEvent[] {
    let result = [...this.events];

    // Apply filters
    if (options.startDate) {
      result = result.filter(e => e.timestamp >= options.startDate!);
    }

    if (options.endDate) {
      result = result.filter(e => e.timestamp <= options.endDate!);
    }

    if (options.category) {
      const categories = Array.isArray(options.category) ? options.category : [options.category];
      result = result.filter(e => categories.includes(e.category));
    }

    if (options.severity) {
      const severities = Array.isArray(options.severity) ? options.severity : [options.severity];
      result = result.filter(e => severities.includes(e.severity));
    }

    if (options.action) {
      result = result.filter(e => e.action === options.action);
    }

    if (options.outcome) {
      result = result.filter(e => e.outcome === options.outcome);
    }

    if (options.userId) {
      result = result.filter(e => e.userId === options.userId);
    }

    if (options.resourceType) {
      result = result.filter(e => e.resourceType === options.resourceType);
    }

    if (options.resourceId) {
      result = result.filter(e => e.resourceId === options.resourceId);
    }

    if (options.ipAddress) {
      result = result.filter(e => e.ipAddress === options.ipAddress);
    }

    if (options.region) {
      result = result.filter(e => e.region === options.region);
    }

    if (options.classification) {
      result = result.filter(e => e.dataClassification === options.classification);
    }

    // Sort
    const sortOrder = options.sortOrder || 'desc';
    result.sort((a, b) => {
      const diff = a.timestamp.getTime() - b.timestamp.getTime();
      return sortOrder === 'asc' ? diff : -diff;
    });

    // Pagination
    if (options.offset) {
      result = result.slice(options.offset);
    }

    if (options.limit) {
      result = result.slice(0, options.limit);
    }

    return result;
  }

  /**
   * Get event by ID
   */
  getEvent(eventId: string): AuditEvent | undefined {
    return this.events.find(e => e.id === eventId);
  }

  /**
   * Get recent events
   */
  getRecent(count = 100): AuditEvent[] {
    return this.query({ limit: count, sortOrder: 'desc' });
  }

  /**
   * Calculate statistics
   */
  getStatistics(startDate?: Date, endDate?: Date): AuditStatistics {
    let events = this.events;

    if (startDate) {
      events = events.filter(e => e.timestamp >= startDate);
    }

    if (endDate) {
      events = events.filter(e => e.timestamp <= endDate);
    }

    const byCategory: Record<AuditCategory, number> = {
      authentication: 0,
      authorization: 0,
      key_operation: 0,
      share_operation: 0,
      configuration: 0,
      access_control: 0,
      data_access: 0,
      admin_action: 0,
      system_event: 0,
      security_event: 0,
    };

    const bySeverity: Record<AuditSeverity, number> = {
      debug: 0,
      info: 0,
      warning: 0,
      error: 0,
      critical: 0,
    };

    const byOutcome: Record<string, number> = {
      success: 0,
      failure: 0,
      partial: 0,
    };

    const byRegion: Record<string, number> = {};
    const uniqueUsers = new Set<string>();
    const uniqueIPs = new Set<string>();

    for (const event of events) {
      byCategory[event.category]++;
      bySeverity[event.severity]++;
      byOutcome[event.outcome]++;

      if (event.region) {
        byRegion[event.region] = (byRegion[event.region] || 0) + 1;
      }

      if (event.userId) {
        uniqueUsers.add(event.userId);
      }

      if (event.ipAddress) {
        uniqueIPs.add(event.ipAddress);
      }
    }

    return {
      totalEvents: events.length,
      byCategory,
      bySeverity,
      byOutcome,
      byRegion,
      uniqueUsers: uniqueUsers.size,
      uniqueIPs: uniqueIPs.size,
      periodStart: startDate || (events[0]?.timestamp ?? new Date()),
      periodEnd: endDate || new Date(),
    };
  }

  /**
   * Verify audit log integrity
   */
  verifyIntegrity(): { valid: boolean; invalidEventIds: string[]; brokenChainAt?: string } {
    const invalidEventIds: string[] = [];
    let previousHash = '0'.repeat(64);
    let brokenChainAt: string | undefined;

    for (const event of this.events) {
      // Verify hash chain
      if (event.previousHash !== previousHash && !brokenChainAt) {
        brokenChainAt = event.id;
      }

      // Verify event hash
      const hashData = JSON.stringify({
        ...event,
        hash: undefined,
      });
      const expectedHash = bytesToHex(sha256(new TextEncoder().encode(hashData)));

      if (event.hash !== expectedHash) {
        invalidEventIds.push(event.id);
      }

      previousHash = event.hash;
    }

    return {
      valid: invalidEventIds.length === 0 && !brokenChainAt,
      invalidEventIds,
      brokenChainAt,
    };
  }

  /**
   * Add retention policy
   */
  addRetentionPolicy(policy: RetentionPolicy): void {
    this.retentionPolicies.set(policy.id, policy);
  }

  /**
   * Apply retention policies
   */
  applyRetentionPolicies(): { deleted: number; archived: number } {
    let deleted = 0;
    let archived = 0;
    const now = new Date();

    for (const policy of this.retentionPolicies.values()) {
      if (!policy.enabled) continue;

      const deleteCutoff = new Date(now.getTime() - policy.retentionDays * 24 * 60 * 60 * 1000);
      const archiveCutoff = policy.archiveAfterDays
        ? new Date(now.getTime() - policy.archiveAfterDays * 24 * 60 * 60 * 1000)
        : null;

      const eventsToProcess = this.events.filter(e => {
        if (!e.resourceType) return false;
        return policy.resourceTypes.includes(e.resourceType);
      });

      for (const event of eventsToProcess) {
        if (event.timestamp < deleteCutoff && policy.deleteAfterArchive) {
          const index = this.events.indexOf(event);
          if (index > -1) {
            this.events.splice(index, 1);
            deleted++;
          }
        } else if (archiveCutoff && event.timestamp < archiveCutoff) {
          // In a real implementation, this would move to archive storage
          archived++;
        }
      }
    }

    return { deleted, archived };
  }

  /**
   * Add event listener
   */
  addListener(listener: (event: AuditEvent) => void): void {
    this.eventListeners.push(listener);
  }

  /**
   * Remove event listener
   */
  removeListener(listener: (event: AuditEvent) => void): void {
    const index = this.eventListeners.indexOf(listener);
    if (index > -1) {
      this.eventListeners.splice(index, 1);
    }
  }

  /**
   * Export events as JSON
   */
  export(options: AuditQueryOptions = {}): string {
    const events = this.query(options);
    return JSON.stringify(events, null, 2);
  }

  /**
   * Export events as CSV
   */
  exportCSV(options: AuditQueryOptions = {}): string {
    const events = this.query(options);

    const headers = [
      'id',
      'timestamp',
      'category',
      'severity',
      'action',
      'outcome',
      'userId',
      'ipAddress',
      'resourceType',
      'resourceId',
      'region',
      'classification',
    ];

    const rows = events.map(e => [
      e.id,
      e.timestamp.toISOString(),
      e.category,
      e.severity,
      e.action,
      e.outcome,
      e.userId || '',
      e.ipAddress || '',
      e.resourceType || '',
      e.resourceId || '',
      e.region || '',
      e.dataClassification || '',
    ]);

    return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  }

  /**
   * Get total event count
   */
  count(): number {
    return this.events.length;
  }

  /**
   * Clear all events (for testing)
   */
  clear(): void {
    this.events = [];
    this.lastHash = '0'.repeat(64);
  }
}

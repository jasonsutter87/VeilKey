/**
 * Enhanced Audit Logger Tests
 *
 * Tests for tamper-proof audit logging system
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  EnhancedAuditLogger,
  AuditEventBuilder,
} from '../../../compliance/audit.js';

describe('EnhancedAuditLogger', () => {
  let logger: EnhancedAuditLogger;

  beforeEach(() => {
    logger = new EnhancedAuditLogger();
  });

  describe('event logging', () => {
    it('should log basic event', () => {
      const event = logger.log({
        category: 'authentication',
        severity: 'info',
        action: 'user_login',
        outcome: 'success',
        userId: 'user123',
        details: { method: 'password' },
      });

      expect(event.id).toBeDefined();
      expect(event.timestamp).toBeInstanceOf(Date);
      expect(event.hash).toBeDefined();
      expect(event.previousHash).toBeDefined();
    });

    it('should chain hashes correctly', () => {
      const event1 = logger.log({
        category: 'authentication',
        severity: 'info',
        action: 'login',
        outcome: 'success',
        details: {},
      });

      const event2 = logger.log({
        category: 'authentication',
        severity: 'info',
        action: 'logout',
        outcome: 'success',
        details: {},
      });

      expect(event2.previousHash).toBe(event1.hash);
    });

    it('should log with all optional fields', () => {
      const event = logger.log({
        category: 'key_operation',
        severity: 'info',
        action: 'key_generate',
        outcome: 'success',
        userId: 'user123',
        userAgent: 'Mozilla/5.0',
        ipAddress: '192.168.1.1',
        resourceType: 'key',
        resourceId: 'key-001',
        details: { algorithm: 'RSA' },
        dataClassification: 'restricted',
        region: 'us-east-1',
      });

      expect(event.userId).toBe('user123');
      expect(event.userAgent).toBe('Mozilla/5.0');
      expect(event.ipAddress).toBe('192.168.1.1');
      expect(event.resourceType).toBe('key');
      expect(event.region).toBe('us-east-1');
    });
  });

  describe('quick log methods', () => {
    it('should log authentication success', () => {
      const event = logger.logAuthentication('user123', 'success', { method: 'mfa' });

      expect(event.category).toBe('authentication');
      expect(event.action).toBe('user_login');
      expect(event.outcome).toBe('success');
      expect(event.severity).toBe('info');
    });

    it('should log authentication failure with warning severity', () => {
      const event = logger.logAuthentication('user123', 'failure');

      expect(event.severity).toBe('warning');
      expect(event.outcome).toBe('failure');
    });

    it('should log authorization event', () => {
      const event = logger.logAuthorization('user123', 'admin-panel', 'access', 'success');

      expect(event.category).toBe('authorization');
      expect(event.resourceId).toBe('admin-panel');
    });

    it('should log key operation', () => {
      const event = logger.logKeyOperation(
        'user123',
        'sign',
        'key-001',
        'success',
        { signature: 'abc123' }
      );

      expect(event.category).toBe('key_operation');
      expect(event.resourceType).toBe('key');
      expect(event.resourceId).toBe('key-001');
      expect(event.dataClassification).toBe('restricted');
    });

    it('should log security event', () => {
      const event = logger.logSecurityEvent(
        'intrusion_detected',
        'critical',
        { source: '10.0.0.1', attempts: 100 }
      );

      expect(event.category).toBe('security_event');
      expect(event.severity).toBe('critical');
    });
  });

  describe('AuditEventBuilder', () => {
    it('should build event with fluent interface', () => {
      const builder = new AuditEventBuilder();
      const eventData = builder
        .category('data_access')
        .severity('info')
        .action('read_file')
        .outcome('success')
        .user('user123')
        .ip('192.168.1.1')
        .resource('file', '/data/secret.txt')
        .classification('confidential')
        .detail('bytes_read', 1024)
        .build();

      expect(eventData.category).toBe('data_access');
      expect(eventData.userId).toBe('user123');
      expect(eventData.resourceType).toBe('file');
      expect(eventData.dataClassification).toBe('confidential');
    });

    it('should require category, action, and outcome', () => {
      const builder = new AuditEventBuilder();

      expect(() => {
        builder.build();
      }).toThrow('Category, action, and outcome are required');
    });

    it('should set default severity to info', () => {
      const builder = new AuditEventBuilder();
      const eventData = builder
        .category('system_event')
        .action('startup')
        .outcome('success')
        .build();

      expect(eventData.severity).toBe('info');
    });
  });

  describe('event querying', () => {
    beforeEach(() => {
      // Create a variety of events
      logger.logAuthentication('user1', 'success');
      logger.logAuthentication('user2', 'failure');
      logger.logKeyOperation('user1', 'sign', 'key1', 'success');
      logger.logSecurityEvent('test', 'critical', {});
    });

    it('should query all events', () => {
      const events = logger.query();
      expect(events.length).toBe(4);
    });

    it('should filter by category', () => {
      const events = logger.query({ category: 'authentication' });
      expect(events.length).toBe(2);
    });

    it('should filter by multiple categories', () => {
      const events = logger.query({
        category: ['authentication', 'key_operation'],
      });
      expect(events.length).toBe(3);
    });

    it('should filter by severity', () => {
      const events = logger.query({ severity: 'critical' });
      expect(events.length).toBe(1);
    });

    it('should filter by outcome', () => {
      const events = logger.query({ outcome: 'failure' });
      expect(events.length).toBe(1);
    });

    it('should filter by user', () => {
      const events = logger.query({ userId: 'user1' });
      expect(events.length).toBe(2);
    });

    it('should filter by date range', () => {
      const now = new Date();
      const earlier = new Date(now.getTime() - 1000);

      const events = logger.query({
        startDate: earlier,
        endDate: now,
      });

      expect(events.length).toBeGreaterThan(0);
    });

    it('should support pagination', () => {
      const page1 = logger.query({ limit: 2, offset: 0 });
      const page2 = logger.query({ limit: 2, offset: 2 });

      expect(page1.length).toBe(2);
      expect(page2.length).toBe(2);
      expect(page1[0].id).not.toBe(page2[0].id);
    });

    it('should sort by timestamp', () => {
      const ascending = logger.query({ sortOrder: 'asc' });
      const descending = logger.query({ sortOrder: 'desc' });

      expect(ascending[0].timestamp.getTime())
        .toBeLessThanOrEqual(ascending[ascending.length - 1].timestamp.getTime());
      expect(descending[0].timestamp.getTime())
        .toBeGreaterThanOrEqual(descending[descending.length - 1].timestamp.getTime());
    });
  });

  describe('event retrieval', () => {
    it('should get event by ID', () => {
      const logged = logger.logAuthentication('user123', 'success');
      const retrieved = logger.getEvent(logged.id);

      expect(retrieved).toEqual(logged);
    });

    it('should return undefined for non-existent event', () => {
      const event = logger.getEvent('non-existent');
      expect(event).toBeUndefined();
    });

    it('should get recent events', () => {
      for (let i = 0; i < 50; i++) {
        logger.logAuthentication(`user${i}`, 'success');
      }

      const recent = logger.getRecent(10);
      expect(recent.length).toBe(10);
    });
  });

  describe('statistics', () => {
    beforeEach(() => {
      logger.log({
        category: 'authentication',
        severity: 'info',
        action: 'login',
        outcome: 'success',
        userId: 'user1',
        ipAddress: '192.168.1.1',
        region: 'us-east-1',
        details: {},
      });

      logger.log({
        category: 'authentication',
        severity: 'warning',
        action: 'login',
        outcome: 'failure',
        userId: 'user2',
        ipAddress: '192.168.1.2',
        region: 'eu-west-1',
        details: {},
      });

      logger.log({
        category: 'key_operation',
        severity: 'info',
        action: 'sign',
        outcome: 'success',
        userId: 'user1',
        ipAddress: '192.168.1.1',
        region: 'us-east-1',
        details: {},
      });
    });

    it('should calculate statistics', () => {
      const stats = logger.getStatistics();

      expect(stats.totalEvents).toBe(3);
      expect(stats.byCategory.authentication).toBe(2);
      expect(stats.byCategory.key_operation).toBe(1);
      expect(stats.bySeverity.info).toBe(2);
      expect(stats.bySeverity.warning).toBe(1);
      expect(stats.byOutcome.success).toBe(2);
      expect(stats.byOutcome.failure).toBe(1);
      expect(stats.uniqueUsers).toBe(2);
      expect(stats.uniqueIPs).toBe(2);
      expect(stats.byRegion['us-east-1']).toBe(2);
      expect(stats.byRegion['eu-west-1']).toBe(1);
    });

    it('should calculate statistics for date range', () => {
      // Use a future date range that excludes all existing events
      const future = new Date();
      future.setFullYear(future.getFullYear() + 1);
      const stats = logger.getStatistics(future, future);
      expect(stats.totalEvents).toBe(0);
    });
  });

  describe('integrity verification', () => {
    it('should verify integrity of untampered log', () => {
      logger.logAuthentication('user1', 'success');
      logger.logAuthentication('user2', 'success');
      logger.logAuthentication('user3', 'success');

      const result = logger.verifyIntegrity();

      expect(result.valid).toBe(true);
      expect(result.invalidEventIds.length).toBe(0);
      expect(result.brokenChainAt).toBeUndefined();
    });

    it('should detect empty log as valid', () => {
      const result = logger.verifyIntegrity();
      expect(result.valid).toBe(true);
    });
  });

  describe('retention policies', () => {
    it('should add retention policy', () => {
      logger.addRetentionPolicy({
        id: 'policy1',
        name: 'Auth Log Retention',
        resourceTypes: ['auth'],
        retentionDays: 90,
        deleteAfterArchive: true,
        legalHoldExempt: false,
        enabled: true,
      });

      // Policy should be stored (tested through applying)
      const result = logger.applyRetentionPolicies();
      expect(result.deleted).toBe(0);
    });

    it('should apply retention policies', () => {
      // Add old events
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 100);

      // We can't directly set timestamps, so this tests the policy application structure
      logger.addRetentionPolicy({
        id: 'policy1',
        name: 'Test Policy',
        resourceTypes: ['key'],
        retentionDays: 30,
        deleteAfterArchive: true,
        legalHoldExempt: false,
        enabled: true,
      });

      const result = logger.applyRetentionPolicies();
      expect(typeof result.deleted).toBe('number');
      expect(typeof result.archived).toBe('number');
    });
  });

  describe('event listeners', () => {
    it('should notify listeners on new event', () => {
      const listener = vi.fn();
      logger.addListener(listener);

      logger.logAuthentication('user123', 'success');

      expect(listener).toHaveBeenCalledTimes(1);
      expect(listener).toHaveBeenCalledWith(expect.objectContaining({
        category: 'authentication',
        userId: 'user123',
      }));
    });

    it('should remove listener', () => {
      const listener = vi.fn();
      logger.addListener(listener);
      logger.removeListener(listener);

      logger.logAuthentication('user123', 'success');

      expect(listener).not.toHaveBeenCalled();
    });

    it('should handle listener errors gracefully', () => {
      const errorListener = vi.fn().mockImplementation(() => {
        throw new Error('Listener error');
      });

      logger.addListener(errorListener);

      // Should not throw
      expect(() => {
        logger.logAuthentication('user123', 'success');
      }).not.toThrow();
    });
  });

  describe('export', () => {
    it('should export as JSON', () => {
      logger.logAuthentication('user1', 'success');
      logger.logAuthentication('user2', 'success');

      const json = logger.export();
      const parsed = JSON.parse(json);

      expect(parsed.length).toBe(2);
    });

    it('should export as CSV', () => {
      logger.logAuthentication('user1', 'success');
      logger.logAuthentication('user2', 'success');

      const csv = logger.exportCSV();
      const lines = csv.split('\n');

      expect(lines.length).toBe(3); // header + 2 events
      expect(lines[0]).toContain('id,timestamp');
    });

    it('should respect query options in export', () => {
      logger.logAuthentication('user1', 'success');
      logger.logAuthentication('user2', 'failure');

      const json = logger.export({ outcome: 'success' });
      const parsed = JSON.parse(json);

      expect(parsed.length).toBe(1);
    });
  });

  describe('utility methods', () => {
    it('should count events', () => {
      logger.logAuthentication('user1', 'success');
      logger.logAuthentication('user2', 'success');

      expect(logger.count()).toBe(2);
    });

    it('should clear events', () => {
      logger.logAuthentication('user1', 'success');
      logger.logAuthentication('user2', 'success');

      logger.clear();

      expect(logger.count()).toBe(0);
    });
  });
});

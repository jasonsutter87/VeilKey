/**
 * Time-Based Access Control Tests
 *
 * Tests for time-based restrictions
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  TimeAccessManager,
  TimeAccessError,
  TimeAccessErrorCode,
  TimeWindow,
  DateRange,
  MaintenanceWindow,
  Holiday,
  TimeAccessPolicy,
  TimeAccessRule,
} from '../../../security/time-access.js';

describe('TimeAccessManager', () => {
  let manager: TimeAccessManager;

  beforeEach(() => {
    manager = new TimeAccessManager();
  });

  describe('Time Windows', () => {
    it('should add a time window', () => {
      const window: TimeWindow = {
        id: 'business-hours',
        name: 'Business Hours',
        days: [1, 2, 3, 4, 5], // Mon-Fri
        startTime: '09:00',
        endTime: '17:00',
        timezone: 'America/New_York',
        enabled: true,
      };

      manager.addTimeWindow(window);
      expect(manager.getTimeWindow('business-hours')).toEqual(window);
    });

    it('should reject invalid time format', () => {
      const window: TimeWindow = {
        id: 'invalid',
        name: 'Invalid',
        days: [1],
        startTime: '25:00', // Invalid
        endTime: '17:00',
        timezone: 'UTC',
        enabled: true,
      };

      expect(() => manager.addTimeWindow(window)).toThrow(TimeAccessError);
    });

    it('should detect time within window', () => {
      const window: TimeWindow = {
        id: 'work',
        name: 'Work Hours',
        days: [1, 2, 3, 4, 5],
        startTime: '09:00',
        endTime: '17:00',
        timezone: 'UTC',
        enabled: true,
      };

      manager.addTimeWindow(window);

      // Wednesday at 12:00 UTC
      const wednesday = new Date('2024-01-10T12:00:00Z');
      const context = manager.getTimeContext('UTC', wednesday);

      expect(manager.isInTimeWindow('work', context)).toBe(true);
    });

    it('should detect time outside window', () => {
      const window: TimeWindow = {
        id: 'work',
        name: 'Work Hours',
        days: [1, 2, 3, 4, 5],
        startTime: '09:00',
        endTime: '17:00',
        timezone: 'UTC',
        enabled: true,
      };

      manager.addTimeWindow(window);

      // Wednesday at 20:00 UTC
      const evening = new Date('2024-01-10T20:00:00Z');
      const context = manager.getTimeContext('UTC', evening);

      expect(manager.isInTimeWindow('work', context)).toBe(false);
    });

    it('should handle overnight windows', () => {
      const window: TimeWindow = {
        id: 'night-shift',
        name: 'Night Shift',
        days: [0, 1, 2, 3, 4, 5, 6],
        startTime: '22:00',
        endTime: '06:00',
        timezone: 'UTC',
        enabled: true,
      };

      manager.addTimeWindow(window);

      // 23:00 should be in window
      const lateNight = new Date('2024-01-10T23:00:00Z');
      const context1 = manager.getTimeContext('UTC', lateNight);
      expect(manager.isInTimeWindow('night-shift', context1)).toBe(true);

      // 03:00 should be in window
      const earlyMorning = new Date('2024-01-10T03:00:00Z');
      const context2 = manager.getTimeContext('UTC', earlyMorning);
      expect(manager.isInTimeWindow('night-shift', context2)).toBe(true);

      // 12:00 should be outside window
      const noon = new Date('2024-01-10T12:00:00Z');
      const context3 = manager.getTimeContext('UTC', noon);
      expect(manager.isInTimeWindow('night-shift', context3)).toBe(false);
    });

    it('should respect day of week restrictions', () => {
      const window: TimeWindow = {
        id: 'weekdays',
        name: 'Weekdays Only',
        days: [1, 2, 3, 4, 5], // Mon-Fri
        startTime: '00:00',
        endTime: '23:59',
        timezone: 'UTC',
        enabled: true,
      };

      manager.addTimeWindow(window);

      // Saturday
      const saturday = new Date('2024-01-13T12:00:00Z');
      const satContext = manager.getTimeContext('UTC', saturday);
      expect(manager.isInTimeWindow('weekdays', satContext)).toBe(false);

      // Wednesday
      const wednesday = new Date('2024-01-10T12:00:00Z');
      const wedContext = manager.getTimeContext('UTC', wednesday);
      expect(manager.isInTimeWindow('weekdays', wedContext)).toBe(true);
    });

    it('should respect enabled flag', () => {
      const window: TimeWindow = {
        id: 'disabled',
        name: 'Disabled Window',
        days: [0, 1, 2, 3, 4, 5, 6],
        startTime: '00:00',
        endTime: '23:59',
        timezone: 'UTC',
        enabled: false,
      };

      manager.addTimeWindow(window);
      expect(manager.isInTimeWindow('disabled')).toBe(false);
    });
  });

  describe('Date Ranges', () => {
    it('should add a date range', () => {
      const range: DateRange = {
        id: 'q1-2024',
        name: 'Q1 2024',
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-03-31'),
        enabled: true,
      };

      manager.addDateRange(range);
      expect(manager.getDateRange('q1-2024')).toEqual(range);
    });

    it('should reject invalid date range', () => {
      const range: DateRange = {
        id: 'invalid',
        name: 'Invalid',
        startDate: new Date('2024-03-31'),
        endDate: new Date('2024-01-01'), // Before start
        enabled: true,
      };

      expect(() => manager.addDateRange(range)).toThrow(TimeAccessError);
    });

    it('should detect date within range', () => {
      const range: DateRange = {
        id: 'q1-2024',
        name: 'Q1 2024',
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-03-31'),
        enabled: true,
      };

      manager.addDateRange(range);

      expect(manager.isInDateRange('q1-2024', new Date('2024-02-15'))).toBe(true);
      expect(manager.isInDateRange('q1-2024', new Date('2024-04-15'))).toBe(false);
    });
  });

  describe('Maintenance Windows', () => {
    it('should add a maintenance window', () => {
      const window: MaintenanceWindow = {
        id: 'maint-1',
        name: 'Scheduled Maintenance',
        startTime: new Date('2024-01-15T02:00:00Z'),
        endTime: new Date('2024-01-15T06:00:00Z'),
        reason: 'Database upgrade',
        allowEmergencyAccess: true,
        notifyBefore: 60,
        enabled: true,
      };

      manager.addMaintenanceWindow(window);
      expect(manager.getMaintenanceWindow('maint-1')).toEqual(window);
    });

    it('should detect active maintenance', () => {
      const window: MaintenanceWindow = {
        id: 'maint-1',
        name: 'Maintenance',
        startTime: new Date('2024-01-15T02:00:00Z'),
        endTime: new Date('2024-01-15T06:00:00Z'),
        reason: 'Upgrade',
        allowEmergencyAccess: true,
        notifyBefore: 60,
        enabled: true,
      };

      manager.addMaintenanceWindow(window);

      const during = manager.isInMaintenanceWindow(new Date('2024-01-15T04:00:00Z'));
      expect(during.isMaintenance).toBe(true);
      expect(during.window?.reason).toBe('Upgrade');

      const before = manager.isInMaintenanceWindow(new Date('2024-01-15T01:00:00Z'));
      expect(before.isMaintenance).toBe(false);
    });

    it('should get upcoming maintenance', () => {
      const now = new Date();

      manager.addMaintenanceWindow({
        id: 'upcoming-1',
        name: 'Soon',
        startTime: new Date(now.getTime() + 2 * 60 * 60 * 1000), // 2 hours from now
        endTime: new Date(now.getTime() + 4 * 60 * 60 * 1000),
        reason: 'Patch',
        allowEmergencyAccess: false,
        notifyBefore: 30,
        enabled: true,
      });

      manager.addMaintenanceWindow({
        id: 'far-future',
        name: 'Far Future',
        startTime: new Date(now.getTime() + 48 * 60 * 60 * 1000), // 48 hours from now
        endTime: new Date(now.getTime() + 50 * 60 * 60 * 1000),
        reason: 'Major upgrade',
        allowEmergencyAccess: false,
        notifyBefore: 120,
        enabled: true,
      });

      const upcoming = manager.getUpcomingMaintenance(24);
      expect(upcoming).toHaveLength(1);
      expect(upcoming[0].id).toBe('upcoming-1');
    });
  });

  describe('Holidays', () => {
    it('should add a holiday', () => {
      const holiday: Holiday = {
        id: 'christmas',
        name: 'Christmas',
        date: new Date('2024-12-25'),
        recurring: true,
        enabled: true,
      };

      manager.addHoliday(holiday);
      expect(manager.getHoliday('christmas')).toEqual(holiday);
    });

    it('should detect recurring holiday', () => {
      manager.addHoliday({
        id: 'christmas',
        name: 'Christmas',
        date: new Date('2024-12-25'),
        recurring: true,
        enabled: true,
      });

      // Same day in different year
      const context = manager.getTimeContext('UTC', new Date('2025-12-25T12:00:00Z'));
      expect(context.isHoliday).toBe(true);
      expect(context.holidayName).toBe('Christmas');
    });

    it('should detect non-recurring holiday', () => {
      manager.addHoliday({
        id: 'special-day',
        name: 'Special Day',
        date: new Date('2024-06-15'),
        recurring: false,
        enabled: true,
      });

      // Exact date
      const context1 = manager.getTimeContext('UTC', new Date('2024-06-15T12:00:00Z'));
      expect(context1.isHoliday).toBe(true);

      // Same day next year (should not match)
      const context2 = manager.getTimeContext('UTC', new Date('2025-06-15T12:00:00Z'));
      expect(context2.isHoliday).toBe(false);
    });
  });

  describe('Policy Evaluation', () => {
    beforeEach(() => {
      // Business hours window
      manager.addTimeWindow({
        id: 'business-hours',
        name: 'Business Hours',
        days: [1, 2, 3, 4, 5],
        startTime: '09:00',
        endTime: '17:00',
        timezone: 'UTC',
        enabled: true,
      });

      // After hours window
      manager.addTimeWindow({
        id: 'after-hours',
        name: 'After Hours',
        days: [1, 2, 3, 4, 5],
        startTime: '17:00',
        endTime: '09:00',
        timezone: 'UTC',
        enabled: true,
      });

      // Weekend window
      manager.addTimeWindow({
        id: 'weekend',
        name: 'Weekend',
        days: [0, 6],
        startTime: '00:00',
        endTime: '23:59',
        timezone: 'UTC',
        enabled: true,
      });
    });

    it('should allow access during business hours', () => {
      const policy: TimeAccessPolicy = {
        id: 'office-policy',
        name: 'Office Policy',
        defaultAction: 'deny',
        rules: [
          {
            id: 'allow-business',
            name: 'Allow Business Hours',
            priority: 1,
            action: 'allow',
            timeWindows: ['business-hours'],
            enabled: true,
          },
        ],
        defaultTimezone: 'UTC',
        enabled: true,
      };

      manager.createPolicy(policy);

      // Wednesday at 12:00 UTC
      const result = manager.evaluatePolicy('office-policy', {
        timestamp: new Date('2024-01-10T12:00:00Z'),
      });

      expect(result.allowed).toBe(true);
      expect(result.action).toBe('allow');
      expect(result.matchedRules).toContain('allow-business');
    });

    it('should deny access after hours', () => {
      const policy: TimeAccessPolicy = {
        id: 'office-policy',
        name: 'Office Policy',
        defaultAction: 'deny',
        rules: [
          {
            id: 'allow-business',
            name: 'Allow Business Hours',
            priority: 1,
            action: 'allow',
            timeWindows: ['business-hours'],
            enabled: true,
          },
        ],
        defaultTimezone: 'UTC',
        enabled: true,
      };

      manager.createPolicy(policy);

      // Wednesday at 20:00 UTC
      const result = manager.evaluatePolicy('office-policy', {
        timestamp: new Date('2024-01-10T20:00:00Z'),
      });

      expect(result.allowed).toBe(false);
      expect(result.action).toBe('deny');
    });

    it('should require MFA after hours', () => {
      const policy: TimeAccessPolicy = {
        id: 'mfa-policy',
        name: 'MFA After Hours',
        defaultAction: 'deny',
        rules: [
          {
            id: 'allow-business',
            name: 'Allow Business Hours',
            priority: 1,
            action: 'allow',
            timeWindows: ['business-hours'],
            enabled: true,
          },
          {
            id: 'mfa-after-hours',
            name: 'MFA After Hours',
            priority: 2,
            action: 'mfa_required',
            timeWindows: ['after-hours'],
            enabled: true,
          },
        ],
        defaultTimezone: 'UTC',
        enabled: true,
      };

      manager.createPolicy(policy);

      // Wednesday at 20:00 UTC
      const result = manager.evaluatePolicy('mfa-policy', {
        timestamp: new Date('2024-01-10T20:00:00Z'),
      });

      expect(result.allowed).toBe(false);
      expect(result.action).toBe('mfa_required');
    });

    it('should use default action when no rules match', () => {
      const policy: TimeAccessPolicy = {
        id: 'default-allow',
        name: 'Default Allow',
        defaultAction: 'allow',
        rules: [],
        defaultTimezone: 'UTC',
        enabled: true,
      };

      manager.createPolicy(policy);

      const result = manager.evaluatePolicy('default-allow');
      expect(result.allowed).toBe(true);
      expect(result.action).toBe('allow');
    });

    it('should skip disabled rules', () => {
      const policy: TimeAccessPolicy = {
        id: 'skip-disabled',
        name: 'Skip Disabled',
        defaultAction: 'allow',
        rules: [
          {
            id: 'disabled-deny',
            name: 'Disabled Deny',
            priority: 1,
            action: 'deny',
            enabled: false,
          },
        ],
        defaultTimezone: 'UTC',
        enabled: true,
      };

      manager.createPolicy(policy);

      const result = manager.evaluatePolicy('skip-disabled');
      expect(result.allowed).toBe(true);
    });

    it('should filter by user', () => {
      const policy: TimeAccessPolicy = {
        id: 'user-policy',
        name: 'User Policy',
        defaultAction: 'allow',
        rules: [
          {
            id: 'deny-user-123',
            name: 'Deny User 123',
            priority: 1,
            action: 'deny',
            users: ['user-123'],
            enabled: true,
          },
        ],
        defaultTimezone: 'UTC',
        enabled: true,
      };

      manager.createPolicy(policy);

      // User 123 should be denied
      const result1 = manager.evaluatePolicy('user-policy', { userId: 'user-123' });
      expect(result1.allowed).toBe(false);

      // User 456 should be allowed
      const result2 = manager.evaluatePolicy('user-policy', { userId: 'user-456' });
      expect(result2.allowed).toBe(true);
    });

    it('should filter by role', () => {
      const policy: TimeAccessPolicy = {
        id: 'role-policy',
        name: 'Role Policy',
        defaultAction: 'deny',
        rules: [
          {
            id: 'allow-admin',
            name: 'Allow Admins',
            priority: 1,
            action: 'allow',
            roles: ['admin'],
            enabled: true,
          },
        ],
        defaultTimezone: 'UTC',
        enabled: true,
      };

      manager.createPolicy(policy);

      // Admin should be allowed
      const result1 = manager.evaluatePolicy('role-policy', { userRoles: ['admin'] });
      expect(result1.allowed).toBe(true);

      // User should be denied
      const result2 = manager.evaluatePolicy('role-policy', { userRoles: ['user'] });
      expect(result2.allowed).toBe(false);
    });

    it('should filter by operation', () => {
      const policy: TimeAccessPolicy = {
        id: 'op-policy',
        name: 'Operation Policy',
        defaultAction: 'allow',
        rules: [
          {
            id: 'deny-sign-weekend',
            name: 'Deny Sign on Weekend',
            priority: 1,
            action: 'deny',
            operations: ['sign'],
            timeWindows: ['weekend'],
            enabled: true,
          },
        ],
        defaultTimezone: 'UTC',
        enabled: true,
      };

      manager.createPolicy(policy);

      // Sign on Saturday
      const result1 = manager.evaluatePolicy('op-policy', {
        operation: 'sign',
        timestamp: new Date('2024-01-13T12:00:00Z'), // Saturday
      });
      expect(result1.allowed).toBe(false);

      // Verify on Saturday (different operation)
      const result2 = manager.evaluatePolicy('op-policy', {
        operation: 'verify',
        timestamp: new Date('2024-01-13T12:00:00Z'),
      });
      expect(result2.allowed).toBe(true);
    });

    it('should return error for non-existent policy', () => {
      const result = manager.evaluatePolicy('non-existent');
      expect(result.allowed).toBe(false);
      expect(result.reasons).toContain('Policy not found');
    });

    it('should allow when policy is disabled', () => {
      const policy: TimeAccessPolicy = {
        id: 'disabled',
        name: 'Disabled',
        defaultAction: 'deny',
        rules: [],
        defaultTimezone: 'UTC',
        enabled: false,
      };

      manager.createPolicy(policy);

      const result = manager.evaluatePolicy('disabled');
      expect(result.allowed).toBe(true);
      expect(result.reasons).toContain('Policy disabled');
    });
  });

  describe('Rate Limiting', () => {
    it('should allow requests within limit', () => {
      const result = manager.checkRateLimit('user-1', 'sign', 10, 60);

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(9);
    });

    it('should deny requests exceeding limit', () => {
      // Exhaust the limit
      for (let i = 0; i < 5; i++) {
        manager.checkRateLimit('user-1', 'sign', 5, 60);
      }

      // Next request should be denied
      const result = manager.checkRateLimit('user-1', 'sign', 5, 60);

      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });

    it('should reset rate limit', () => {
      // Use some requests
      manager.checkRateLimit('user-1', 'sign', 5, 60);
      manager.checkRateLimit('user-1', 'sign', 5, 60);

      // Reset
      manager.resetRateLimit('user-1', 'sign');

      // Should have full limit again
      const result = manager.checkRateLimit('user-1', 'sign', 5, 60);
      expect(result.remaining).toBe(4);
    });

    it('should track different operations separately', () => {
      manager.checkRateLimit('user-1', 'sign', 2, 60);
      manager.checkRateLimit('user-1', 'sign', 2, 60);

      // Sign is exhausted
      const signResult = manager.checkRateLimit('user-1', 'sign', 2, 60);
      expect(signResult.allowed).toBe(false);

      // Verify has full limit
      const verifyResult = manager.checkRateLimit('user-1', 'verify', 2, 60);
      expect(verifyResult.allowed).toBe(true);
      expect(verifyResult.remaining).toBe(1);
    });
  });

  describe('Time Context', () => {
    it('should get current time context', () => {
      const context = manager.getTimeContext('UTC');

      expect(context.timestamp).toBeInstanceOf(Date);
      expect(context.timezone).toBe('UTC');
      expect(context.dayOfWeek).toBeGreaterThanOrEqual(0);
      expect(context.dayOfWeek).toBeLessThanOrEqual(6);
      expect(context.timeOfDay).toMatch(/^\d{2}:\d{2}$/);
    });

    it('should include holiday info in context', () => {
      manager.addHoliday({
        id: 'test-day',
        name: 'Test Day',
        date: new Date('2024-07-04'),
        recurring: true,
        enabled: true,
      });

      const context = manager.getTimeContext('UTC', new Date('2024-07-04T12:00:00Z'));

      expect(context.isHoliday).toBe(true);
      expect(context.holidayName).toBe('Test Day');
    });

    it('should include maintenance info in context', () => {
      manager.addMaintenanceWindow({
        id: 'maint',
        name: 'Maintenance',
        startTime: new Date('2024-01-15T02:00:00Z'),
        endTime: new Date('2024-01-15T06:00:00Z'),
        reason: 'Upgrade',
        allowEmergencyAccess: false,
        notifyBefore: 60,
        enabled: true,
      });

      const context = manager.getTimeContext('UTC', new Date('2024-01-15T04:00:00Z'));

      expect(context.isMaintenanceWindow).toBe(true);
      expect(context.maintenanceReason).toBe('Upgrade');
    });
  });

  describe('Audit Logging', () => {
    it('should record audit entries', () => {
      const context = manager.getTimeContext();
      const result = manager.evaluatePolicy('test', { timestamp: new Date() });

      const entry = manager.recordAudit('user-1', 'sign', context, result);

      expect(entry.userId).toBe('user-1');
      expect(entry.operation).toBe('sign');
      expect(entry.hash.length).toBe(64);
    });

    it('should filter audit log', () => {
      const context = manager.getTimeContext();
      const result = manager.evaluatePolicy('test', { timestamp: new Date() });

      manager.recordAudit('user-1', 'sign', context, result);
      manager.recordAudit('user-1', 'verify', context, result);
      manager.recordAudit('user-2', 'sign', context, result);

      const user1Entries = manager.getAuditLog({ userId: 'user-1' });
      expect(user1Entries).toHaveLength(2);

      const signEntries = manager.getAuditLog({ operation: 'sign' });
      expect(signEntries).toHaveLength(2);
    });
  });

  describe('Resource Management', () => {
    it('should list all time windows', () => {
      manager.addTimeWindow({
        id: 'tw1',
        name: 'TW1',
        days: [1],
        startTime: '09:00',
        endTime: '17:00',
        timezone: 'UTC',
        enabled: true,
      });

      manager.addTimeWindow({
        id: 'tw2',
        name: 'TW2',
        days: [2],
        startTime: '09:00',
        endTime: '17:00',
        timezone: 'UTC',
        enabled: true,
      });

      expect(manager.listTimeWindows()).toHaveLength(2);
    });

    it('should remove resources', () => {
      manager.addTimeWindow({
        id: 'tw1',
        name: 'TW1',
        days: [1],
        startTime: '09:00',
        endTime: '17:00',
        timezone: 'UTC',
        enabled: true,
      });

      expect(manager.getTimeWindow('tw1')).toBeDefined();
      manager.removeTimeWindow('tw1');
      expect(manager.getTimeWindow('tw1')).toBeUndefined();
    });

    it('should list all policies', () => {
      manager.createPolicy({
        id: 'p1',
        name: 'P1',
        defaultAction: 'allow',
        rules: [],
        defaultTimezone: 'UTC',
        enabled: true,
      });

      manager.createPolicy({
        id: 'p2',
        name: 'P2',
        defaultAction: 'deny',
        rules: [],
        defaultTimezone: 'UTC',
        enabled: true,
      });

      expect(manager.listPolicies()).toHaveLength(2);
    });
  });

  describe('Error Codes', () => {
    it('should have correct error codes', () => {
      expect(TimeAccessErrorCode.OUTSIDE_TIME_WINDOW).toBe('OUTSIDE_TIME_WINDOW');
      expect(TimeAccessErrorCode.MAINTENANCE_PERIOD).toBe('MAINTENANCE_PERIOD');
      expect(TimeAccessErrorCode.HOLIDAY_RESTRICTION).toBe('HOLIDAY_RESTRICTION');
      expect(TimeAccessErrorCode.DATE_RANGE_EXPIRED).toBe('DATE_RANGE_EXPIRED');
      expect(TimeAccessErrorCode.RATE_LIMIT_EXCEEDED).toBe('RATE_LIMIT_EXCEEDED');
      expect(TimeAccessErrorCode.INVALID_TIME_FORMAT).toBe('INVALID_TIME_FORMAT');
      expect(TimeAccessErrorCode.INVALID_TIMEZONE).toBe('INVALID_TIMEZONE');
      expect(TimeAccessErrorCode.POLICY_NOT_FOUND).toBe('POLICY_NOT_FOUND');
    });

    it('should create TimeAccessError with properties', () => {
      const context = manager.getTimeContext();
      const error = new TimeAccessError(
        'Test error',
        TimeAccessErrorCode.OUTSIDE_TIME_WINDOW,
        context
      );

      expect(error.message).toBe('Test error');
      expect(error.code).toBe(TimeAccessErrorCode.OUTSIDE_TIME_WINDOW);
      expect(error.context).toBe(context);
      expect(error.name).toBe('TimeAccessError');
    });
  });

  describe('Holiday Exclusions', () => {
    it('should skip rules on excluded holidays', () => {
      manager.addHoliday({
        id: 'christmas',
        name: 'Christmas',
        date: new Date('2024-12-25'),
        recurring: true,
        enabled: true,
      });

      manager.addTimeWindow({
        id: 'all-day',
        name: 'All Day',
        days: [0, 1, 2, 3, 4, 5, 6],
        startTime: '00:00',
        endTime: '23:59',
        timezone: 'UTC',
        enabled: true,
      });

      const policy: TimeAccessPolicy = {
        id: 'holiday-policy',
        name: 'Holiday Policy',
        defaultAction: 'allow',
        rules: [
          {
            id: 'deny-all',
            name: 'Deny All',
            priority: 1,
            action: 'deny',
            timeWindows: ['all-day'],
            excludeHolidays: ['christmas'], // Don't apply on Christmas
            enabled: true,
          },
        ],
        defaultTimezone: 'UTC',
        enabled: true,
      };

      manager.createPolicy(policy);

      // Regular day - should be denied
      const regularResult = manager.evaluatePolicy('holiday-policy', {
        timestamp: new Date('2024-12-20T12:00:00Z'),
      });
      expect(regularResult.allowed).toBe(false);

      // Christmas - rule skipped, default allow
      const christmasResult = manager.evaluatePolicy('holiday-policy', {
        timestamp: new Date('2024-12-25T12:00:00Z'),
      });
      expect(christmasResult.allowed).toBe(true);
    });
  });

  describe('Maintenance Window Exclusions', () => {
    it('should skip rules during maintenance', () => {
      manager.addMaintenanceWindow({
        id: 'maint',
        name: 'Maintenance',
        startTime: new Date('2024-01-15T02:00:00Z'),
        endTime: new Date('2024-01-15T06:00:00Z'),
        reason: 'Upgrade',
        allowEmergencyAccess: false,
        notifyBefore: 60,
        enabled: true,
      });

      const policy: TimeAccessPolicy = {
        id: 'maint-policy',
        name: 'Maintenance Policy',
        defaultAction: 'deny',
        rules: [
          {
            id: 'allow-all',
            name: 'Allow All',
            priority: 1,
            action: 'allow',
            excludeMaintenanceWindows: true,
            enabled: true,
          },
        ],
        defaultTimezone: 'UTC',
        enabled: true,
      };

      manager.createPolicy(policy);

      // During maintenance - rule skipped, default deny
      const maintResult = manager.evaluatePolicy('maint-policy', {
        timestamp: new Date('2024-01-15T04:00:00Z'),
      });
      expect(maintResult.allowed).toBe(false);

      // Outside maintenance - rule applies, allow
      const normalResult = manager.evaluatePolicy('maint-policy', {
        timestamp: new Date('2024-01-15T12:00:00Z'),
      });
      expect(normalResult.allowed).toBe(true);
    });
  });
});

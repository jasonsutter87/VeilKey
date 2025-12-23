/**
 * VeilKey Time-Based Access Control
 *
 * Provides time-based restrictions for threshold cryptography operations.
 * Supports schedules, time windows, maintenance periods, and temporal policies.
 *
 * @module security/time-access
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

/**
 * Day of week (0 = Sunday, 6 = Saturday)
 */
export type DayOfWeek = 0 | 1 | 2 | 3 | 4 | 5 | 6;

/**
 * Time of day in HH:MM format (24-hour)
 */
export type TimeOfDay = string;

/**
 * Time Window - a recurring time slot
 */
export interface TimeWindow {
  id: string;
  name: string;
  days: DayOfWeek[];
  startTime: TimeOfDay; // HH:MM
  endTime: TimeOfDay; // HH:MM
  timezone: string; // IANA timezone
  enabled: boolean;
}

/**
 * Date Range - a specific date range
 */
export interface DateRange {
  id: string;
  name: string;
  startDate: Date;
  endDate: Date;
  enabled: boolean;
}

/**
 * Maintenance Window
 */
export interface MaintenanceWindow {
  id: string;
  name: string;
  startTime: Date;
  endTime: Date;
  reason: string;
  allowEmergencyAccess: boolean;
  notifyBefore: number; // minutes
  enabled: boolean;
}

/**
 * Holiday Definition
 */
export interface Holiday {
  id: string;
  name: string;
  date: Date;
  recurring: boolean; // true = same date every year
  enabled: boolean;
}

/**
 * Time-Based Rule Action
 */
export type TimeAction = 'allow' | 'deny' | 'mfa_required' | 'notify' | 'rate_limit';

/**
 * Time-Based Access Rule
 */
export interface TimeAccessRule {
  id: string;
  name: string;
  priority: number;
  action: TimeAction;
  timeWindows?: string[]; // TimeWindow IDs
  dateRanges?: string[]; // DateRange IDs
  excludeHolidays?: string[]; // Holiday IDs to exclude
  excludeMaintenanceWindows?: boolean;
  operations?: string[]; // Operations this applies to
  users?: string[]; // User IDs this applies to (empty = all)
  roles?: string[]; // Role names this applies to
  enabled: boolean;
}

/**
 * Time Access Policy
 */
export interface TimeAccessPolicy {
  id: string;
  name: string;
  defaultAction: TimeAction;
  rules: TimeAccessRule[];
  defaultTimezone: string;
  enabled: boolean;
}

/**
 * Time Context - current time information
 */
export interface TimeContext {
  timestamp: Date;
  timezone: string;
  dayOfWeek: DayOfWeek;
  timeOfDay: TimeOfDay;
  isHoliday: boolean;
  isMaintenanceWindow: boolean;
  holidayName?: string;
  maintenanceReason?: string;
}

/**
 * Time Access Evaluation Result
 */
export interface TimeAccessResult {
  allowed: boolean;
  action: TimeAction;
  matchedRules: string[];
  context: TimeContext;
  reasons: string[];
  nextAllowedTime?: Date;
  timestamp: Date;
}

/**
 * Rate Limit State
 */
export interface RateLimitState {
  userId: string;
  operation: string;
  windowStart: Date;
  count: number;
  limit: number;
  windowSeconds: number;
}

/**
 * Time Access Audit Entry
 */
export interface TimeAccessAuditEntry {
  id: string;
  userId: string;
  operation: string;
  context: TimeContext;
  result: TimeAccessResult;
  timestamp: Date;
  hash: string;
  previousHash: string;
}

/**
 * Time Access Error
 */
export class TimeAccessError extends Error {
  constructor(
    message: string,
    public readonly code: TimeAccessErrorCode,
    public readonly context?: TimeContext
  ) {
    super(message);
    this.name = 'TimeAccessError';
  }
}

/**
 * Error Codes
 */
export enum TimeAccessErrorCode {
  OUTSIDE_TIME_WINDOW = 'OUTSIDE_TIME_WINDOW',
  MAINTENANCE_PERIOD = 'MAINTENANCE_PERIOD',
  HOLIDAY_RESTRICTION = 'HOLIDAY_RESTRICTION',
  DATE_RANGE_EXPIRED = 'DATE_RANGE_EXPIRED',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  INVALID_TIME_FORMAT = 'INVALID_TIME_FORMAT',
  INVALID_TIMEZONE = 'INVALID_TIMEZONE',
  POLICY_NOT_FOUND = 'POLICY_NOT_FOUND',
}

/**
 * Time-Based Access Manager
 */
export class TimeAccessManager {
  private timeWindows: Map<string, TimeWindow> = new Map();
  private dateRanges: Map<string, DateRange> = new Map();
  private maintenanceWindows: Map<string, MaintenanceWindow> = new Map();
  private holidays: Map<string, Holiday> = new Map();
  private policies: Map<string, TimeAccessPolicy> = new Map();
  private rateLimits: Map<string, RateLimitState> = new Map();
  private auditLog: TimeAccessAuditEntry[] = [];
  private lastAuditHash = '0'.repeat(64);

  /**
   * Add a recurring time window
   */
  addTimeWindow(window: TimeWindow): void {
    this.validateTimeFormat(window.startTime);
    this.validateTimeFormat(window.endTime);
    this.timeWindows.set(window.id, window);
  }

  /**
   * Add a date range
   */
  addDateRange(range: DateRange): void {
    if (range.endDate <= range.startDate) {
      throw new TimeAccessError(
        'End date must be after start date',
        TimeAccessErrorCode.INVALID_TIME_FORMAT
      );
    }
    this.dateRanges.set(range.id, range);
  }

  /**
   * Add a maintenance window
   */
  addMaintenanceWindow(window: MaintenanceWindow): void {
    if (window.endTime <= window.startTime) {
      throw new TimeAccessError(
        'End time must be after start time',
        TimeAccessErrorCode.INVALID_TIME_FORMAT
      );
    }
    this.maintenanceWindows.set(window.id, window);
  }

  /**
   * Add a holiday
   */
  addHoliday(holiday: Holiday): void {
    this.holidays.set(holiday.id, holiday);
  }

  /**
   * Create a time access policy
   */
  createPolicy(policy: TimeAccessPolicy): void {
    policy.rules.sort((a, b) => a.priority - b.priority);
    this.policies.set(policy.id, policy);
  }

  /**
   * Get current time context
   */
  getTimeContext(timezone?: string, timestamp?: Date): TimeContext {
    const now = timestamp || new Date();
    const tz = timezone || 'UTC';

    // Get time in specified timezone
    const options: Intl.DateTimeFormatOptions = {
      timeZone: tz,
      weekday: 'short',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    };

    const formatter = new Intl.DateTimeFormat('en-US', options);
    const parts = formatter.formatToParts(now);

    const weekdayMap: Record<string, DayOfWeek> = {
      Sun: 0,
      Mon: 1,
      Tue: 2,
      Wed: 3,
      Thu: 4,
      Fri: 5,
      Sat: 6,
    };

    let dayOfWeek: DayOfWeek = 0;
    let hour = '00';
    let minute = '00';

    for (const part of parts) {
      if (part.type === 'weekday') {
        dayOfWeek = weekdayMap[part.value] ?? 0;
      } else if (part.type === 'hour') {
        hour = part.value.padStart(2, '0');
      } else if (part.type === 'minute') {
        minute = part.value.padStart(2, '0');
      }
    }

    const timeOfDay = `${hour}:${minute}`;

    // Check for holidays
    const { isHoliday, holidayName } = this.checkHoliday(now);

    // Check for maintenance windows
    const { isMaintenance, maintenanceReason } = this.checkMaintenanceWindow(now);

    return {
      timestamp: now,
      timezone: tz,
      dayOfWeek,
      timeOfDay,
      isHoliday,
      isMaintenanceWindow: isMaintenance,
      holidayName,
      maintenanceReason,
    };
  }

  /**
   * Evaluate access against a policy
   */
  evaluatePolicy(
    policyId: string,
    options?: {
      userId?: string;
      userRoles?: string[];
      operation?: string;
      timezone?: string;
      timestamp?: Date;
    }
  ): TimeAccessResult {
    const policy = this.policies.get(policyId);

    if (!policy) {
      const context = this.getTimeContext(options?.timezone, options?.timestamp);
      return {
        allowed: false,
        action: 'deny',
        matchedRules: [],
        context,
        reasons: ['Policy not found'],
        timestamp: new Date(),
      };
    }

    if (!policy.enabled) {
      const context = this.getTimeContext(options?.timezone, options?.timestamp);
      return {
        allowed: true,
        action: 'allow',
        matchedRules: [],
        context,
        reasons: ['Policy disabled'],
        timestamp: new Date(),
      };
    }

    const context = this.getTimeContext(
      options?.timezone || policy.defaultTimezone,
      options?.timestamp
    );

    // Evaluate rules in priority order
    for (const rule of policy.rules) {
      if (!rule.enabled) continue;

      // Check user filter
      if (rule.users && rule.users.length > 0 && options?.userId) {
        if (!rule.users.includes(options.userId)) continue;
      }

      // Check role filter
      if (rule.roles && rule.roles.length > 0 && options?.userRoles) {
        if (!rule.roles.some(r => options.userRoles!.includes(r))) continue;
      }

      // Check operation filter
      if (rule.operations && rule.operations.length > 0 && options?.operation) {
        if (!rule.operations.includes(options.operation)) continue;
      }

      // Check holiday exclusion
      if (rule.excludeHolidays && context.isHoliday) {
        const holiday = this.findHolidayByName(context.holidayName || '');
        if (holiday && rule.excludeHolidays.includes(holiday.id)) {
          continue; // Skip this rule on excluded holidays
        }
      }

      // Check maintenance exclusion
      if (rule.excludeMaintenanceWindows && context.isMaintenanceWindow) {
        continue;
      }

      // Check if rule matches current time
      const ruleMatch = this.checkRuleMatch(rule, context);

      if (ruleMatch.matched) {
        const allowed = rule.action === 'allow';
        return {
          allowed,
          action: rule.action,
          matchedRules: [rule.id],
          context,
          reasons: ruleMatch.reasons,
          nextAllowedTime: !allowed ? this.calculateNextAllowedTime(rule, context) : undefined,
          timestamp: new Date(),
        };
      }
    }

    // No rules matched, use default
    const allowed = policy.defaultAction === 'allow';
    return {
      allowed,
      action: policy.defaultAction,
      matchedRules: [],
      context,
      reasons: ['No matching rules, using default action'],
      timestamp: new Date(),
    };
  }

  /**
   * Check if current time is within a time window
   */
  isInTimeWindow(windowId: string, context?: TimeContext): boolean {
    const window = this.timeWindows.get(windowId);
    if (!window || !window.enabled) return false;

    const ctx = context || this.getTimeContext(window.timezone);

    // Check day of week
    if (!window.days.includes(ctx.dayOfWeek)) return false;

    // Check time of day
    return this.isTimeInRange(ctx.timeOfDay, window.startTime, window.endTime);
  }

  /**
   * Check if current date is within a date range
   */
  isInDateRange(rangeId: string, timestamp?: Date): boolean {
    const range = this.dateRanges.get(rangeId);
    if (!range || !range.enabled) return false;

    const now = timestamp || new Date();
    return now >= range.startDate && now <= range.endDate;
  }

  /**
   * Check if current time is in maintenance window
   */
  isInMaintenanceWindow(timestamp?: Date): { isMaintenance: boolean; window?: MaintenanceWindow } {
    const now = timestamp || new Date();

    for (const window of this.maintenanceWindows.values()) {
      if (!window.enabled) continue;
      if (now >= window.startTime && now <= window.endTime) {
        return { isMaintenance: true, window };
      }
    }

    return { isMaintenance: false };
  }

  /**
   * Get upcoming maintenance windows
   */
  getUpcomingMaintenance(withinHours = 24): MaintenanceWindow[] {
    const now = new Date();
    const future = new Date(now.getTime() + withinHours * 60 * 60 * 1000);

    const upcoming: MaintenanceWindow[] = [];

    for (const window of this.maintenanceWindows.values()) {
      if (!window.enabled) continue;
      if (window.startTime > now && window.startTime <= future) {
        upcoming.push(window);
      }
    }

    return upcoming.sort((a, b) => a.startTime.getTime() - b.startTime.getTime());
  }

  /**
   * Check rate limit
   */
  checkRateLimit(
    userId: string,
    operation: string,
    limit: number,
    windowSeconds: number
  ): { allowed: boolean; remaining: number; resetAt: Date } {
    const key = `${userId}:${operation}`;
    const now = new Date();
    let state = this.rateLimits.get(key);

    // Check if window has expired
    if (state) {
      const windowEnd = new Date(state.windowStart.getTime() + state.windowSeconds * 1000);
      if (now > windowEnd) {
        state = undefined;
      }
    }

    // Create new window if needed
    if (!state) {
      state = {
        userId,
        operation,
        windowStart: now,
        count: 0,
        limit,
        windowSeconds,
      };
    }

    // Check if within limit
    const allowed = state.count < limit;
    if (allowed) {
      state.count++;
    }

    this.rateLimits.set(key, state);

    const resetAt = new Date(state.windowStart.getTime() + windowSeconds * 1000);
    return {
      allowed,
      remaining: Math.max(0, limit - state.count),
      resetAt,
    };
  }

  /**
   * Reset rate limit for a user/operation
   */
  resetRateLimit(userId: string, operation: string): void {
    const key = `${userId}:${operation}`;
    this.rateLimits.delete(key);
  }

  /**
   * Record audit entry
   */
  recordAudit(
    userId: string,
    operation: string,
    context: TimeContext,
    result: TimeAccessResult
  ): TimeAccessAuditEntry {
    const entry: TimeAccessAuditEntry = {
      id: bytesToHex(new Uint8Array(16).map(() => Math.floor(Math.random() * 256))),
      userId,
      operation,
      context,
      result,
      timestamp: new Date(),
      hash: '',
      previousHash: this.lastAuditHash,
    };

    const dataToHash = JSON.stringify({
      ...entry,
      hash: undefined,
    });
    entry.hash = bytesToHex(sha256(new TextEncoder().encode(dataToHash)));

    this.auditLog.push(entry);
    this.lastAuditHash = entry.hash;

    return entry;
  }

  /**
   * Get audit log
   */
  getAuditLog(
    filters?: {
      userId?: string;
      operation?: string;
      startDate?: Date;
      endDate?: Date;
    },
    limit = 100
  ): TimeAccessAuditEntry[] {
    let entries = [...this.auditLog];

    if (filters) {
      if (filters.userId) {
        entries = entries.filter(e => e.userId === filters.userId);
      }
      if (filters.operation) {
        entries = entries.filter(e => e.operation === filters.operation);
      }
      if (filters.startDate) {
        entries = entries.filter(e => e.timestamp >= filters.startDate!);
      }
      if (filters.endDate) {
        entries = entries.filter(e => e.timestamp <= filters.endDate!);
      }
    }

    return entries.slice(-limit);
  }

  /**
   * Get time window by ID
   */
  getTimeWindow(id: string): TimeWindow | undefined {
    return this.timeWindows.get(id);
  }

  /**
   * Get date range by ID
   */
  getDateRange(id: string): DateRange | undefined {
    return this.dateRanges.get(id);
  }

  /**
   * Get maintenance window by ID
   */
  getMaintenanceWindow(id: string): MaintenanceWindow | undefined {
    return this.maintenanceWindows.get(id);
  }

  /**
   * Get holiday by ID
   */
  getHoliday(id: string): Holiday | undefined {
    return this.holidays.get(id);
  }

  /**
   * Get policy by ID
   */
  getPolicy(id: string): TimeAccessPolicy | undefined {
    return this.policies.get(id);
  }

  /**
   * Remove time window
   */
  removeTimeWindow(id: string): boolean {
    return this.timeWindows.delete(id);
  }

  /**
   * Remove date range
   */
  removeDateRange(id: string): boolean {
    return this.dateRanges.delete(id);
  }

  /**
   * Remove maintenance window
   */
  removeMaintenanceWindow(id: string): boolean {
    return this.maintenanceWindows.delete(id);
  }

  /**
   * Remove holiday
   */
  removeHoliday(id: string): boolean {
    return this.holidays.delete(id);
  }

  /**
   * Remove policy
   */
  removePolicy(id: string): boolean {
    return this.policies.delete(id);
  }

  /**
   * List all time windows
   */
  listTimeWindows(): TimeWindow[] {
    return Array.from(this.timeWindows.values());
  }

  /**
   * List all date ranges
   */
  listDateRanges(): DateRange[] {
    return Array.from(this.dateRanges.values());
  }

  /**
   * List all maintenance windows
   */
  listMaintenanceWindows(): MaintenanceWindow[] {
    return Array.from(this.maintenanceWindows.values());
  }

  /**
   * List all holidays
   */
  listHolidays(): Holiday[] {
    return Array.from(this.holidays.values());
  }

  /**
   * List all policies
   */
  listPolicies(): TimeAccessPolicy[] {
    return Array.from(this.policies.values());
  }

  // Private helper methods

  private validateTimeFormat(time: TimeOfDay): void {
    const regex = /^([01]\d|2[0-3]):([0-5]\d)$/;
    if (!regex.test(time)) {
      throw new TimeAccessError(
        `Invalid time format: ${time}. Expected HH:MM (24-hour)`,
        TimeAccessErrorCode.INVALID_TIME_FORMAT
      );
    }
  }

  private isTimeInRange(current: TimeOfDay, start: TimeOfDay, end: TimeOfDay): boolean {
    const currentMinutes = this.timeToMinutes(current);
    const startMinutes = this.timeToMinutes(start);
    const endMinutes = this.timeToMinutes(end);

    // Handle overnight ranges (e.g., 22:00 - 06:00)
    if (endMinutes < startMinutes) {
      return currentMinutes >= startMinutes || currentMinutes <= endMinutes;
    }

    return currentMinutes >= startMinutes && currentMinutes <= endMinutes;
  }

  private timeToMinutes(time: TimeOfDay): number {
    const [hours, minutes] = time.split(':').map(Number);
    return hours * 60 + minutes;
  }

  private checkHoliday(timestamp: Date): { isHoliday: boolean; holidayName?: string } {
    for (const holiday of this.holidays.values()) {
      if (!holiday.enabled) continue;

      if (holiday.recurring) {
        // Check if same day and month (using UTC to avoid timezone issues)
        if (
          holiday.date.getUTCMonth() === timestamp.getUTCMonth() &&
          holiday.date.getUTCDate() === timestamp.getUTCDate()
        ) {
          return { isHoliday: true, holidayName: holiday.name };
        }
      } else {
        // Check exact date (using UTC)
        if (
          holiday.date.getUTCFullYear() === timestamp.getUTCFullYear() &&
          holiday.date.getUTCMonth() === timestamp.getUTCMonth() &&
          holiday.date.getUTCDate() === timestamp.getUTCDate()
        ) {
          return { isHoliday: true, holidayName: holiday.name };
        }
      }
    }

    return { isHoliday: false };
  }

  private checkMaintenanceWindow(
    timestamp: Date
  ): { isMaintenance: boolean; maintenanceReason?: string } {
    const result = this.isInMaintenanceWindow(timestamp);
    return {
      isMaintenance: result.isMaintenance,
      maintenanceReason: result.window?.reason,
    };
  }

  private findHolidayByName(name: string): Holiday | undefined {
    for (const holiday of this.holidays.values()) {
      if (holiday.name === name) return holiday;
    }
    return undefined;
  }

  private checkRuleMatch(
    rule: TimeAccessRule,
    context: TimeContext
  ): { matched: boolean; reasons: string[] } {
    const reasons: string[] = [];
    let hasAnyCriteria = false;
    let anyMatch = false;

    // Check time windows
    if (rule.timeWindows && rule.timeWindows.length > 0) {
      hasAnyCriteria = true;
      for (const windowId of rule.timeWindows) {
        if (this.isInTimeWindow(windowId, context)) {
          anyMatch = true;
          const window = this.timeWindows.get(windowId);
          reasons.push(`Within time window: ${window?.name || windowId}`);
        }
      }
    }

    // Check date ranges
    if (rule.dateRanges && rule.dateRanges.length > 0) {
      hasAnyCriteria = true;
      for (const rangeId of rule.dateRanges) {
        if (this.isInDateRange(rangeId, context.timestamp)) {
          anyMatch = true;
          const range = this.dateRanges.get(rangeId);
          reasons.push(`Within date range: ${range?.name || rangeId}`);
        }
      }
    }

    // If no criteria, rule matches all times
    if (!hasAnyCriteria) {
      return { matched: true, reasons: ['Rule matches all times'] };
    }

    return { matched: anyMatch, reasons };
  }

  private calculateNextAllowedTime(rule: TimeAccessRule, context: TimeContext): Date | undefined {
    // Find the next time this rule would allow access
    if (!rule.timeWindows || rule.timeWindows.length === 0) return undefined;

    const now = context.timestamp;
    let earliest: Date | undefined;

    for (const windowId of rule.timeWindows) {
      const window = this.timeWindows.get(windowId);
      if (!window || !window.enabled) continue;

      const next = this.getNextWindowStart(window, now);
      if (!earliest || (next && next < earliest)) {
        earliest = next;
      }
    }

    return earliest;
  }

  private getNextWindowStart(window: TimeWindow, from: Date): Date | undefined {
    // Get day/time in window's timezone
    const options: Intl.DateTimeFormatOptions = {
      timeZone: window.timezone,
      weekday: 'short',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    };

    const formatter = new Intl.DateTimeFormat('en-US', options);
    const parts = formatter.formatToParts(from);

    const weekdayMap: Record<string, DayOfWeek> = {
      Sun: 0,
      Mon: 1,
      Tue: 2,
      Wed: 3,
      Thu: 4,
      Fri: 5,
      Sat: 6,
    };

    let currentDay: DayOfWeek = 0;
    for (const part of parts) {
      if (part.type === 'weekday') {
        currentDay = weekdayMap[part.value] ?? 0;
      }
    }

    // Find next valid day
    for (let i = 0; i < 7; i++) {
      const checkDay = ((currentDay + i) % 7) as DayOfWeek;
      if (window.days.includes(checkDay)) {
        const nextDate = new Date(from);
        nextDate.setDate(nextDate.getDate() + i);

        // Set to window start time
        const [hours, minutes] = window.startTime.split(':').map(Number);
        nextDate.setHours(hours, minutes, 0, 0);

        if (nextDate > from) {
          return nextDate;
        }
      }
    }

    return undefined;
  }
}

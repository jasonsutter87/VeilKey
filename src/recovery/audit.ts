/**
 * Recovery audit service
 *
 * Provides:
 * - Audit logging for recovery operations
 * - Compliance reporting
 * - Hash chain for tamper detection
 */

import type {
  RecoveryInitiationEvent,
  ParticipantConsentEvent,
  ShareDistributionEvent,
  AuditRecord,
  ReportFilter,
  ComplianceReport,
  ComplianceCheck,
  RecoveryStorage,
} from './types.js';
import { createHash } from 'crypto';

export class RecoveryAuditServiceImpl {
  private storage: RecoveryStorage;

  constructor(storage: RecoveryStorage) {
    this.storage = storage;
  }

  async logRecoveryInitiation(event: RecoveryInitiationEvent): Promise<AuditRecord> {
    const lastRecord = await this.storage.getLastAuditRecord();

    const record: AuditRecord = {
      id: crypto.randomUUID(),
      eventType: 'initiation',
      recoveryId: event.recoveryId,
      timestamp: event.timestamp,
      actor: event.initiatedBy,
      action: 'initiate_recovery',
      details: {
        lostShareHolderId: event.lostShareHolderId,
        reason: event.reason,
        detectionMethod: event.detectionMethod,
        approvalRequired: event.approvalRequired,
      },
      previousRecordHash: lastRecord?.recordHash,
      recordHash: '', // Will be computed below
    };

    record.recordHash = this.computeRecordHash(record);
    await this.storage.saveAuditRecord(record);

    return record;
  }

  async logParticipantConsent(event: ParticipantConsentEvent): Promise<AuditRecord> {
    const lastRecord = await this.storage.getLastAuditRecord();

    const record: AuditRecord = {
      id: crypto.randomUUID(),
      eventType: 'consent',
      recoveryId: event.recoveryId,
      timestamp: event.timestamp,
      actor: event.participantId,
      action: event.consentGiven ? 'consent_given' : 'consent_denied',
      details: {
        participantId: event.participantId,
        consentGiven: event.consentGiven,
        signature: event.signature,
        conditions: event.conditions,
      },
      previousRecordHash: lastRecord?.recordHash,
      recordHash: '',
    };

    record.recordHash = this.computeRecordHash(record);
    await this.storage.saveAuditRecord(record);

    return record;
  }

  async logShareDistribution(event: ShareDistributionEvent): Promise<AuditRecord> {
    const lastRecord = await this.storage.getLastAuditRecord();

    const record: AuditRecord = {
      id: crypto.randomUUID(),
      eventType: 'distribution',
      recoveryId: event.recoveryId,
      timestamp: event.distributedAt,
      actor: 'system',
      action: 'distribute_share',
      details: {
        newShareHolderId: event.newShareHolderId,
        shareIndex: event.shareIndex,
        deliveryMethod: event.deliveryMethod,
        confirmationReceived: event.confirmationReceived,
        confirmationTimestamp: event.confirmationTimestamp,
      },
      previousRecordHash: lastRecord?.recordHash,
      recordHash: '',
    };

    record.recordHash = this.computeRecordHash(record);
    await this.storage.saveAuditRecord(record);

    return record;
  }

  async generateComplianceReport(filter: ReportFilter): Promise<ComplianceReport> {
    const records = await this.storage.getAuditRecords(filter);

    // Calculate statistics
    const recoveryIds = new Set(records.map(r => r.recoveryId));
    const totalRecoveries = recoveryIds.size;

    // Count by status (based on event types)
    const initiations = records.filter(r => r.eventType === 'initiation');
    const completions = records.filter(r => r.eventType === 'completion');
    const failures = records.filter(r => r.eventType === 'failure');

    const successfulRecoveries = completions.length;
    const failedRecoveries = failures.length;
    const pendingRecoveries = totalRecoveries - successfulRecoveries - failedRecoveries;

    // Calculate average recovery time
    const recoveryTimes: number[] = [];
    for (const recoveryId of recoveryIds) {
      const recoveryRecords = records.filter(r => r.recoveryId === recoveryId);
      const initiation = recoveryRecords.find(r => r.eventType === 'initiation');
      const completion = recoveryRecords.find(r => r.eventType === 'completion');

      if (initiation && completion) {
        const time = completion.timestamp.getTime() - initiation.timestamp.getTime();
        recoveryTimes.push(time);
      }
    }

    const averageRecoveryTime =
      recoveryTimes.length > 0
        ? recoveryTimes.reduce((a, b) => a + b, 0) / recoveryTimes.length
        : 0;

    // Calculate participation rate
    const consentRecords = records.filter(r => r.eventType === 'consent');
    const consentGiven = consentRecords.filter(r => r.details.consentGiven === true).length;
    const consentDenied = consentRecords.filter(r => r.details.consentGiven === false).length;

    // Perform compliance checks
    const complianceChecks: ComplianceCheck[] = [];

    // Check 1: Verify audit trail integrity
    const integrityValid = await this.verifyAuditIntegrity(records);
    complianceChecks.push({
      checkType: 'audit_integrity',
      passed: integrityValid,
      details: integrityValid
        ? 'Audit trail hash chain is intact'
        : 'Audit trail has been tampered with',
      timestamp: new Date(),
    });

    // Check 2: Verify all recoveries have proper authorization
    const unauthorizedRecoveries = initiations.filter(
      r => r.details.approvalRequired && !r.details.authorized
    );
    complianceChecks.push({
      checkType: 'authorization_required',
      passed: unauthorizedRecoveries.length === 0,
      details: `${unauthorizedRecoveries.length} unauthorized recovery attempts found`,
      timestamp: new Date(),
    });

    // Generate report
    const report: ComplianceReport = {
      id: crypto.randomUUID(),
      generatedAt: new Date(),
      reportPeriod: {
        startDate: filter.startDate || new Date(0),
        endDate: filter.endDate || new Date(),
      },
      totalRecoveries,
      successfulRecoveries,
      failedRecoveries,
      pendingRecoveries,
      averageRecoveryTime,
      participationRate: {
        totalParticipants: consentRecords.length,
        consentGiven,
        consentDenied,
      },
      auditRecords: records,
      complianceChecks,
      recommendations: this.generateRecommendations(complianceChecks),
    };

    return report;
  }

  async getAuditTrail(recoveryId: string): Promise<AuditRecord[]> {
    return this.storage.getAuditRecords({ recoveryId });
  }

  async verifyAuditIntegrity(records: AuditRecord[]): Promise<boolean> {
    if (records.length === 0) {
      return true;
    }

    for (let i = 0; i < records.length; i++) {
      const record = records[i]!;

      // Verify record hash
      const computedHash = this.computeRecordHash(record);
      if (record.recordHash !== computedHash) {
        return false;
      }

      // Verify chain link
      if (i > 0) {
        const previousRecord = records[i - 1]!;
        if (record.previousRecordHash !== previousRecord.recordHash) {
          return false;
        }
      } else {
        // First record should have no previous hash
        if (record.previousRecordHash) {
          return false;
        }
      }
    }

    return true;
  }

  async exportAuditLog(
    format: 'json' | 'csv' | 'pdf',
    filter?: ReportFilter
  ): Promise<string> {
    const records = await this.storage.getAuditRecords(filter);

    switch (format) {
      case 'json':
        return JSON.stringify(records, null, 2);

      case 'csv':
        return this.exportToCsv(records);

      case 'pdf':
        // Mock PDF export - would use a PDF library in production
        return `PDF Export (${records.length} records)`;

      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  // Private helper methods

  private computeRecordHash(record: AuditRecord): string {
    const data = [
      record.id,
      record.eventType,
      record.recoveryId,
      record.timestamp.toISOString(),
      record.actor,
      record.action,
      JSON.stringify(record.details),
      record.previousRecordHash || '',
    ].join('|');

    const hash = createHash('sha256');
    hash.update(data);
    return hash.digest('hex');
  }

  private exportToCsv(records: AuditRecord[]): string {
    const headers = ['ID', 'Event Type', 'Recovery ID', 'Timestamp', 'Actor', 'Action', 'Hash'];
    const rows = records.map(r => [
      r.id,
      r.eventType,
      r.recoveryId,
      r.timestamp.toISOString(),
      r.actor,
      r.action,
      r.recordHash,
    ]);

    const csv = [headers, ...rows].map(row => row.join(',')).join('\n');
    return csv;
  }

  private generateRecommendations(checks: ComplianceCheck[]): string[] {
    const recommendations: string[] = [];

    const failedChecks = checks.filter(c => !c.passed);

    if (failedChecks.length > 0) {
      recommendations.push(
        'Review and address failed compliance checks immediately'
      );
    }

    if (failedChecks.some(c => c.checkType === 'audit_integrity')) {
      recommendations.push(
        'Investigate potential tampering of audit records'
      );
    }

    if (failedChecks.some(c => c.checkType === 'authorization_required')) {
      recommendations.push(
        'Enforce authorization requirements for all recovery operations'
      );
    }

    if (recommendations.length === 0) {
      recommendations.push('All compliance checks passed - continue current practices');
    }

    return recommendations;
  }
}

// Export interface for test compatibility
export interface RecoveryAuditService {
  logRecoveryInitiation(event: RecoveryInitiationEvent): Promise<AuditRecord>;
  logParticipantConsent(event: ParticipantConsentEvent): Promise<AuditRecord>;
  logShareDistribution(event: ShareDistributionEvent): Promise<AuditRecord>;
  generateComplianceReport(filter: ReportFilter): Promise<ComplianceReport>;
  getAuditTrail(recoveryId: string): Promise<AuditRecord[]>;
  verifyAuditIntegrity(records: AuditRecord[]): Promise<boolean>;
  exportAuditLog(format: 'json' | 'csv' | 'pdf', filter?: ReportFilter): Promise<string>;
}

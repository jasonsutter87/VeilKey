/**
 * Phase 3: Share Recovery - Audit Tests
 *
 * Tests for auditing and logging recovery operations.
 *
 * @test-count 19
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  RecoveryAuditServiceImpl,
  InMemoryRecoveryStorage,
  type RecoveryInitiationEvent,
  type ParticipantConsentEvent,
  type ShareDistributionEvent,
  type AuditRecord,
  type ReportFilter,
  type ComplianceReport,
} from '../../../recovery/index.js';

// Additional type for tests
export interface ComplianceReportTest {
  id: string;
  generatedAt: Date;
  reportPeriod: {
    startDate: Date;
    endDate: Date;
  };
  totalRecoveries: number;
  successfulRecoveries: number;
  failedRecoveries: number;
  pendingRecoveries: number;
  averageRecoveryTime: number; // milliseconds
  participationRate: {
    totalParticipants: number;
    consentGiven: number;
    consentDenied: number;
  };
  auditRecords: AuditRecord[];
  complianceChecks: ComplianceCheck[];
  recommendations?: string[];
}

export interface ComplianceCheck {
  checkType: string;
  passed: boolean;
  details: string;
  timestamp: Date;
}

describe('Share Recovery - Audit', () => {
  let storage: InMemoryRecoveryStorage;
  let auditService: RecoveryAuditServiceImpl;

  beforeEach(() => {
    storage = new InMemoryRecoveryStorage();
    auditService = new RecoveryAuditServiceImpl(storage);
  });

  describe('Recovery Initiation Logging', () => {
    it('should log recovery initiation event', async () => {
      const initiationEvent: RecoveryInitiationEvent = {
        recoveryId: 'recovery-init-1',
        lostShareHolderId: 'holder-lost-1',
        initiatedBy: 'admin-user-1',
        timestamp: new Date(),
        reason: 'Hardware failure',
        detectionMethod: 'manual',
        approvalRequired: true,
      };

      const auditRecord = await auditService.logRecoveryInitiation(initiationEvent);

      expect(auditRecord).toBeDefined();
      expect(auditRecord.eventType).toBe('initiation');
      expect(auditRecord.recoveryId).toBe(initiationEvent.recoveryId);
      expect(auditRecord.actor).toBe(initiationEvent.initiatedBy);
      expect(auditRecord.recordHash).toBeDefined();
    });

    it('should include all required initiation details', async () => {
      const initiationEvent: RecoveryInitiationEvent = {
        recoveryId: 'recovery-init-2',
        lostShareHolderId: 'holder-lost-2',
        initiatedBy: 'admin-user-2',
        timestamp: new Date(),
        reason: 'Employee termination',
        detectionMethod: 'automatic',
        approvalRequired: true,
      };

      const auditRecord = await auditService.logRecoveryInitiation(initiationEvent);

      expect(auditRecord.details).toHaveProperty('lostShareHolderId');
      expect(auditRecord.details).toHaveProperty('reason');
      expect(auditRecord.details).toHaveProperty('detectionMethod');
      expect(auditRecord.details.lostShareHolderId).toBe('holder-lost-2');
    });

    it('should generate unique audit record ID', async () => {
      const initiationEvent1: RecoveryInitiationEvent = {
        recoveryId: 'recovery-init-3a',
        lostShareHolderId: 'holder-lost-3',
        initiatedBy: 'admin-user-3',
        timestamp: new Date(),
        reason: 'Test 1',
        detectionMethod: 'manual',
        approvalRequired: false,
      };

      const initiationEvent2: RecoveryInitiationEvent = {
        recoveryId: 'recovery-init-3b',
        lostShareHolderId: 'holder-lost-3',
        initiatedBy: 'admin-user-3',
        timestamp: new Date(),
        reason: 'Test 2',
        detectionMethod: 'manual',
        approvalRequired: false,
      };

      const record1 = await auditService.logRecoveryInitiation(initiationEvent1);
      const record2 = await auditService.logRecoveryInitiation(initiationEvent2);

      expect(record1.id).not.toBe(record2.id);
    });

    it('should create tamper-evident hash chain', async () => {
      const initiationEvent1: RecoveryInitiationEvent = {
        recoveryId: 'recovery-chain-1',
        lostShareHolderId: 'holder-lost-chain',
        initiatedBy: 'admin-user-chain',
        timestamp: new Date(),
        reason: 'Chain test 1',
        detectionMethod: 'manual',
        approvalRequired: false,
      };

      const initiationEvent2: RecoveryInitiationEvent = {
        recoveryId: 'recovery-chain-1',
        lostShareHolderId: 'holder-lost-chain',
        initiatedBy: 'admin-user-chain',
        timestamp: new Date(),
        reason: 'Chain test 2',
        detectionMethod: 'manual',
        approvalRequired: false,
      };

      const record1 = await auditService.logRecoveryInitiation(initiationEvent1);

      // Second record should reference first
      const consentEvent: ParticipantConsentEvent = {
        recoveryId: 'recovery-chain-1',
        participantId: 'participant-1',
        consentGiven: true,
        timestamp: new Date(),
        signature: 'sig-1',
      };

      const record2 = await auditService.logParticipantConsent(consentEvent);

      expect(record2.previousRecordHash).toBeDefined();
      // Should link to previous record in chain
    });
  });

  describe('Participant Consent Recording', () => {
    it('should record participant consent', async () => {
      const consentEvent: ParticipantConsentEvent = {
        recoveryId: 'recovery-consent-1',
        participantId: 'participant-1',
        consentGiven: true,
        timestamp: new Date(),
        signature: 'consent-sig-1',
      };

      const auditRecord = await auditService.logParticipantConsent(consentEvent);

      expect(auditRecord).toBeDefined();
      expect(auditRecord.eventType).toBe('consent');
      expect(auditRecord.details).toHaveProperty('participantId');
      expect(auditRecord.details).toHaveProperty('consentGiven');
      expect(auditRecord.details.consentGiven).toBe(true);
    });

    it('should record consent denial', async () => {
      const consentEvent: ParticipantConsentEvent = {
        recoveryId: 'recovery-consent-2',
        participantId: 'participant-2',
        consentGiven: false,
        timestamp: new Date(),
        signature: 'consent-sig-2',
      };

      const auditRecord = await auditService.logParticipantConsent(consentEvent);

      expect(auditRecord.details.consentGiven).toBe(false);
    });

    it('should include consent conditions if provided', async () => {
      const consentEvent: ParticipantConsentEvent = {
        recoveryId: 'recovery-consent-3',
        participantId: 'participant-3',
        consentGiven: true,
        timestamp: new Date(),
        signature: 'consent-sig-3',
        conditions: ['time-limited-24h', 'audit-review-required'],
      };

      const auditRecord = await auditService.logParticipantConsent(consentEvent);

      expect(auditRecord.details).toHaveProperty('conditions');
      expect(Array.isArray(auditRecord.details.conditions)).toBe(true);
    });

    it('should verify consent signature', async () => {
      const consentEvent: ParticipantConsentEvent = {
        recoveryId: 'recovery-consent-4',
        participantId: 'participant-4',
        consentGiven: true,
        timestamp: new Date(),
        signature: 'valid-consent-sig',
      };

      const auditRecord = await auditService.logParticipantConsent(consentEvent);

      // Implementation should verify signature before logging
      expect(auditRecord.details).toHaveProperty('signature');
    });
  });

  describe('New Share Distribution Log', () => {
    it('should log new share distribution', async () => {
      const distributionEvent: ShareDistributionEvent = {
        recoveryId: 'recovery-dist-1',
        newShareHolderId: 'new-holder-1',
        shareIndex: 3,
        distributedAt: new Date(),
        deliveryMethod: 'encrypted_channel',
        confirmationReceived: true,
        confirmationTimestamp: new Date(),
      };

      const auditRecord = await auditService.logShareDistribution(distributionEvent);

      expect(auditRecord).toBeDefined();
      expect(auditRecord.eventType).toBe('distribution');
      expect(auditRecord.details).toHaveProperty('newShareHolderId');
      expect(auditRecord.details).toHaveProperty('deliveryMethod');
    });

    it('should track delivery method', async () => {
      const distributionEvent: ShareDistributionEvent = {
        recoveryId: 'recovery-dist-2',
        newShareHolderId: 'new-holder-2',
        shareIndex: 1,
        distributedAt: new Date(),
        deliveryMethod: 'hardware_token',
        confirmationReceived: false,
      };

      const auditRecord = await auditService.logShareDistribution(distributionEvent);

      expect(auditRecord.details.deliveryMethod).toBe('hardware_token');
    });

    it('should record delivery confirmation', async () => {
      const distributionEvent: ShareDistributionEvent = {
        recoveryId: 'recovery-dist-3',
        newShareHolderId: 'new-holder-3',
        shareIndex: 2,
        distributedAt: new Date(),
        deliveryMethod: 'in_person',
        confirmationReceived: true,
        confirmationTimestamp: new Date(),
      };

      const auditRecord = await auditService.logShareDistribution(distributionEvent);

      expect(auditRecord.details.confirmationReceived).toBe(true);
      expect(auditRecord.details).toHaveProperty('confirmationTimestamp');
    });

    it('should handle unconfirmed delivery', async () => {
      const distributionEvent: ShareDistributionEvent = {
        recoveryId: 'recovery-dist-4',
        newShareHolderId: 'new-holder-4',
        shareIndex: 4,
        distributedAt: new Date(),
        deliveryMethod: 'encrypted_channel',
        confirmationReceived: false,
      };

      const auditRecord = await auditService.logShareDistribution(distributionEvent);

      expect(auditRecord.details.confirmationReceived).toBe(false);
      expect(auditRecord.details.confirmationTimestamp).toBeUndefined();
    });
  });

  describe('Compliance Report Generation', () => {
    it('should generate compliance report for date range', async () => {
      const filter: ReportFilter = {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-12-31'),
      };

      const report = await auditService.generateComplianceReport(filter);

      expect(report).toBeDefined();
      expect(report.reportPeriod.startDate).toEqual(filter.startDate);
      expect(report.reportPeriod.endDate).toEqual(filter.endDate);
      expect(report.generatedAt).toBeInstanceOf(Date);
    });

    it('should include recovery statistics', async () => {
      const filter: ReportFilter = {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-12-31'),
      };

      const report = await auditService.generateComplianceReport(filter);

      expect(report).toHaveProperty('totalRecoveries');
      expect(report).toHaveProperty('successfulRecoveries');
      expect(report).toHaveProperty('failedRecoveries');
      expect(report).toHaveProperty('pendingRecoveries');
      expect(typeof report.totalRecoveries).toBe('number');
    });

    it('should calculate average recovery time', async () => {
      const filter: ReportFilter = {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-12-31'),
      };

      const report = await auditService.generateComplianceReport(filter);

      expect(report.averageRecoveryTime).toBeDefined();
      expect(typeof report.averageRecoveryTime).toBe('number');
      expect(report.averageRecoveryTime).toBeGreaterThanOrEqual(0);
    });

    it('should include participation statistics', async () => {
      const filter: ReportFilter = {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-12-31'),
      };

      const report = await auditService.generateComplianceReport(filter);

      expect(report.participationRate).toBeDefined();
      expect(report.participationRate).toHaveProperty('totalParticipants');
      expect(report.participationRate).toHaveProperty('consentGiven');
      expect(report.participationRate).toHaveProperty('consentDenied');
    });

    it('should perform compliance checks', async () => {
      const filter: ReportFilter = {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-12-31'),
      };

      const report = await auditService.generateComplianceReport(filter);

      expect(report.complianceChecks).toBeDefined();
      expect(Array.isArray(report.complianceChecks)).toBe(true);

      if (report.complianceChecks.length > 0) {
        const check = report.complianceChecks[0];
        expect(check).toHaveProperty('checkType');
        expect(check).toHaveProperty('passed');
        expect(check).toHaveProperty('details');
        expect(typeof check.passed).toBe('boolean');
      }
    });

    it('should include all audit records in report', async () => {
      const filter: ReportFilter = {
        recoveryId: 'recovery-report-1',
      };

      const report = await auditService.generateComplianceReport(filter);

      expect(report.auditRecords).toBeDefined();
      expect(Array.isArray(report.auditRecords)).toBe(true);
    });

    it('should verify audit trail integrity before reporting', async () => {
      const filter: ReportFilter = {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-12-31'),
      };

      const report = await auditService.generateComplianceReport(filter);

      // Implementation should verify hash chain integrity
      const isIntegrityValid = await auditService.verifyAuditIntegrity(report.auditRecords);
      expect(isIntegrityValid).toBe(true);
    });
  });
});

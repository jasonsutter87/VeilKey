/**
 * Data Residency Manager Tests
 *
 * Tests for geographic data residency controls
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { DataResidencyManager } from '../../../compliance/data-residency.js';
import { ComplianceError, ComplianceErrorCode } from '../../../compliance/types.js';

describe('DataResidencyManager', () => {
  let manager: DataResidencyManager;

  beforeEach(() => {
    manager = new DataResidencyManager();

    // Set up common regions
    manager.defineRegion({
      id: 'us-east-1',
      name: 'US East (N. Virginia)',
      countryCodes: ['US'],
      jurisdiction: 'US',
      enabled: true,
    });

    manager.defineRegion({
      id: 'eu-west-1',
      name: 'EU West (Ireland)',
      countryCodes: ['IE'],
      jurisdiction: 'EU',
      dataProtectionLaw: 'GDPR',
      enabled: true,
    });

    manager.defineRegion({
      id: 'eu-central-1',
      name: 'EU Central (Frankfurt)',
      countryCodes: ['DE'],
      jurisdiction: 'EU',
      dataProtectionLaw: 'GDPR',
      enabled: true,
    });
  });

  describe('region management', () => {
    it('should define a region', () => {
      manager.defineRegion({
        id: 'ap-northeast-1',
        name: 'Asia Pacific (Tokyo)',
        countryCodes: ['JP'],
        jurisdiction: 'Japan',
        enabled: true,
      });

      const region = manager.getRegion('ap-northeast-1');
      expect(region).toBeDefined();
      expect(region?.name).toBe('Asia Pacific (Tokyo)');
    });

    it('should get all regions', () => {
      const regions = manager.getAllRegions();
      expect(regions.length).toBe(3);
    });

    it('should get regions by country code', () => {
      const usRegions = manager.getRegionsByCountry('US');
      expect(usRegions.length).toBe(1);
      expect(usRegions[0].id).toBe('us-east-1');
    });

    it('should handle case-insensitive country lookup', () => {
      const regions = manager.getRegionsByCountry('us');
      expect(regions.length).toBe(1);
    });

    it('should remove region', () => {
      const result = manager.removeRegion('us-east-1');
      expect(result).toBe(true);
      expect(manager.getRegion('us-east-1')).toBeUndefined();
    });
  });

  describe('policy management', () => {
    it('should create policy', () => {
      manager.createPolicy({
        id: 'gdpr-compliance',
        name: 'GDPR Data Residency',
        allowedRegions: ['eu-west-1', 'eu-central-1'],
        dataClassifications: ['confidential', 'restricted'],
        resourceTypes: ['key', 'share'],
        enforceAtRest: true,
        enforceInTransit: true,
        enabled: true,
      });

      const policy = manager.getPolicy('gdpr-compliance');
      expect(policy).toBeDefined();
      expect(policy?.allowedRegions.length).toBe(2);
    });

    it('should reject policy with invalid region', () => {
      expect(() => {
        manager.createPolicy({
          id: 'invalid-policy',
          name: 'Invalid',
          allowedRegions: ['invalid-region'],
          dataClassifications: ['public'],
          resourceTypes: ['*'],
          enforceAtRest: true,
          enforceInTransit: true,
          enabled: true,
        });
      }).toThrow(ComplianceError);
    });

    it('should get all policies', () => {
      manager.createPolicy({
        id: 'policy1',
        name: 'Policy 1',
        allowedRegions: ['us-east-1'],
        dataClassifications: ['public'],
        resourceTypes: ['*'],
        enforceAtRest: true,
        enforceInTransit: false,
        enabled: true,
      });

      manager.createPolicy({
        id: 'policy2',
        name: 'Policy 2',
        allowedRegions: ['eu-west-1'],
        dataClassifications: ['confidential'],
        resourceTypes: ['key'],
        enforceAtRest: true,
        enforceInTransit: true,
        enabled: true,
      });

      const policies = manager.getAllPolicies();
      expect(policies.length).toBe(2);
    });

    it('should remove policy', () => {
      manager.createPolicy({
        id: 'temp-policy',
        name: 'Temporary',
        allowedRegions: ['us-east-1'],
        dataClassifications: ['public'],
        resourceTypes: ['*'],
        enforceAtRest: true,
        enforceInTransit: false,
        enabled: true,
      });

      const result = manager.removePolicy('temp-policy');
      expect(result).toBe(true);
      expect(manager.getPolicy('temp-policy')).toBeUndefined();
    });
  });

  describe('location recording', () => {
    it('should record data location', () => {
      const record = manager.recordLocation('key', 'key-001', 'us-east-1', 'restricted');

      expect(record.id).toBe('key:key-001');
      expect(record.region).toBe('us-east-1');
      expect(record.classification).toBe('restricted');
      expect(record.createdAt).toBeInstanceOf(Date);
    });

    it('should update existing location', () => {
      manager.recordLocation('key', 'key-001', 'us-east-1', 'restricted');
      const updated = manager.recordLocation('key', 'key-001', 'eu-west-1', 'restricted');

      expect(updated.region).toBe('eu-west-1');
      expect(updated.previousRegion).toBe('us-east-1');
      expect(updated.movedAt).toBeDefined();
    });

    it('should get location record', () => {
      manager.recordLocation('share', 'share-001', 'eu-central-1', 'confidential');

      const record = manager.getLocationRecord('share', 'share-001');
      expect(record).toBeDefined();
      expect(record?.region).toBe('eu-central-1');
    });
  });

  describe('location validation', () => {
    beforeEach(() => {
      manager.createPolicy({
        id: 'eu-only',
        name: 'EU Only Policy',
        allowedRegions: ['eu-west-1', 'eu-central-1'],
        dataClassifications: ['restricted'],
        resourceTypes: ['key'],
        enforceAtRest: true,
        enforceInTransit: true,
        enabled: true,
      });
    });

    it('should validate allowed location', () => {
      const result = manager.validateLocation('key', 'key-001', 'eu-west-1', 'restricted');

      expect(result.valid).toBe(true);
      expect(result.violations.length).toBe(0);
    });

    it('should detect policy violation', () => {
      const result = manager.validateLocation('key', 'key-001', 'us-east-1', 'restricted');

      expect(result.valid).toBe(false);
      expect(result.violations.length).toBe(1);
      expect(result.violations[0].severity).toBe('error');
    });

    it('should skip disabled policies', () => {
      manager.createPolicy({
        id: 'disabled-policy',
        name: 'Disabled',
        allowedRegions: ['eu-west-1'],
        dataClassifications: ['public'],
        resourceTypes: ['*'],
        enforceAtRest: true,
        enforceInTransit: true,
        enabled: false,
      });

      const result = manager.validateLocation('key', 'key-001', 'us-east-1', 'public');
      expect(result.valid).toBe(true);
    });

    it('should skip policies for different resource types', () => {
      const result = manager.validateLocation('share', 'share-001', 'us-east-1', 'restricted');
      expect(result.valid).toBe(true);
    });

    it('should skip policies for different classifications', () => {
      const result = manager.validateLocation('key', 'key-001', 'us-east-1', 'public');
      expect(result.valid).toBe(true);
    });
  });

  describe('data transfers', () => {
    beforeEach(() => {
      manager.recordLocation('key', 'key-001', 'us-east-1', 'confidential');

      manager.createPolicy({
        id: 'allow-all',
        name: 'Allow All Regions',
        allowedRegions: ['us-east-1', 'eu-west-1', 'eu-central-1'],
        dataClassifications: ['confidential'],
        resourceTypes: ['key'],
        enforceAtRest: true,
        enforceInTransit: true,
        enabled: true,
      });
    });

    it('should create transfer request', () => {
      const request = manager.requestTransfer(
        'key',
        'key-001',
        'eu-west-1',
        'admin@example.com',
        'GDPR compliance'
      );

      expect(request.id).toBeDefined();
      expect(request.sourceRegion).toBe('us-east-1');
      expect(request.targetRegion).toBe('eu-west-1');
      expect(request.status).toBe('pending');
    });

    it('should reject transfer to disallowed region', () => {
      manager.createPolicy({
        id: 'restrict-to-us',
        name: 'US Only',
        allowedRegions: ['us-east-1'],
        dataClassifications: ['confidential'],
        resourceTypes: ['key'],
        enforceAtRest: true,
        enforceInTransit: true,
        enabled: true,
      });

      // Remove the allow-all policy
      manager.removePolicy('allow-all');

      const request = manager.requestTransfer(
        'key',
        'key-001',
        'eu-west-1',
        'admin@example.com',
        'Test'
      );

      expect(request.status).toBe('rejected');
    });

    it('should throw error for non-existent resource', () => {
      expect(() => {
        manager.requestTransfer('key', 'non-existent', 'eu-west-1', 'admin', 'Test');
      }).toThrow(ComplianceError);
    });

    it('should approve transfer', () => {
      const request = manager.requestTransfer(
        'key',
        'key-001',
        'eu-west-1',
        'admin@example.com',
        'Test'
      );

      manager.approveTransfer(request.id, 'approver@example.com');

      const updated = manager.getTransferRequests({ status: 'approved' });
      expect(updated.length).toBe(1);
      expect(updated[0].approvedBy).toBe('approver@example.com');
    });

    it('should complete transfer', () => {
      const request = manager.requestTransfer(
        'key',
        'key-001',
        'eu-west-1',
        'admin@example.com',
        'Test'
      );

      manager.approveTransfer(request.id, 'approver@example.com');
      manager.completeTransfer(request.id);

      const record = manager.getLocationRecord('key', 'key-001');
      expect(record?.region).toBe('eu-west-1');

      const completed = manager.getTransferRequests({ status: 'completed' });
      expect(completed.length).toBe(1);
    });

    it('should reject transfer request', () => {
      const request = manager.requestTransfer(
        'key',
        'key-001',
        'eu-west-1',
        'admin@example.com',
        'Test'
      );

      manager.rejectTransfer(request.id, 'security@example.com', 'Not justified');

      const rejected = manager.getTransferRequests({ status: 'rejected' });
      expect(rejected.length).toBe(1);
    });

    it('should not complete unapproved transfer', () => {
      const request = manager.requestTransfer(
        'key',
        'key-001',
        'eu-west-1',
        'admin@example.com',
        'Test'
      );

      expect(() => {
        manager.completeTransfer(request.id);
      }).toThrow(ComplianceError);
    });
  });

  describe('data queries', () => {
    beforeEach(() => {
      manager.recordLocation('key', 'key-001', 'us-east-1', 'restricted');
      manager.recordLocation('key', 'key-002', 'us-east-1', 'confidential');
      manager.recordLocation('key', 'key-003', 'eu-west-1', 'restricted');
      manager.recordLocation('share', 'share-001', 'eu-west-1', 'public');
    });

    it('should get data by region', () => {
      const usData = manager.getDataByRegion('us-east-1');
      expect(usData.length).toBe(2);
    });

    it('should get data by classification', () => {
      const restricted = manager.getDataByClassification('restricted');
      expect(restricted.length).toBe(2);
    });
  });

  describe('cross-border requirements', () => {
    it('should identify GDPR transfer requirements', () => {
      const result = manager.checkCrossBorderRequirements('eu-west-1', 'us-east-1');

      expect(result.allowed).toBe(true);
      expect(result.requirements).toContain('Standard Contractual Clauses (SCCs) required');
    });

    it('should identify jurisdiction changes', () => {
      const result = manager.checkCrossBorderRequirements('us-east-1', 'eu-west-1');

      expect(result.requirements.some(r => r.includes('crosses jurisdictions'))).toBe(true);
    });

    it('should handle transfers within same GDPR zone', () => {
      const result = manager.checkCrossBorderRequirements('eu-west-1', 'eu-central-1');

      expect(result.allowed).toBe(true);
      // Both are GDPR, so no SCCs needed
      expect(result.requirements).not.toContain('Standard Contractual Clauses (SCCs) required');
    });

    it('should handle invalid regions', () => {
      const result = manager.checkCrossBorderRequirements('invalid', 'us-east-1');

      expect(result.allowed).toBe(false);
      expect(result.requirements).toContain('Invalid region');
    });
  });

  describe('regional summary', () => {
    it('should generate regional summary', () => {
      manager.recordLocation('key', 'key-001', 'us-east-1', 'restricted');
      manager.recordLocation('key', 'key-002', 'us-east-1', 'confidential');
      manager.recordLocation('key', 'key-003', 'eu-west-1', 'restricted');

      const summary = manager.getRegionalSummary();

      expect(summary.get('us-east-1')?.total).toBe(2);
      expect(summary.get('us-east-1')?.byClassification.restricted).toBe(1);
      expect(summary.get('us-east-1')?.byClassification.confidential).toBe(1);
      expect(summary.get('eu-west-1')?.total).toBe(1);
    });

    it('should handle empty data', () => {
      const summary = manager.getRegionalSummary();
      expect(summary.size).toBe(0);
    });
  });

  describe('audit logging', () => {
    it('should record audit entries', () => {
      manager.recordLocation('key', 'key-001', 'us-east-1', 'restricted');

      const auditLog = manager.getAuditLog();
      expect(auditLog.length).toBeGreaterThan(0);
      expect(auditLog[0].action).toBe('location_recorded');
    });

    it('should maintain hash chain', () => {
      manager.recordLocation('key', 'key-001', 'us-east-1', 'restricted');
      manager.recordLocation('key', 'key-002', 'us-east-1', 'restricted');

      const auditLog = manager.getAuditLog();
      expect(auditLog[1].previousHash).toBe(auditLog[0].hash);
    });

    it('should limit audit log size', () => {
      for (let i = 0; i < 150; i++) {
        manager.recordLocation('key', `key-${i}`, 'us-east-1', 'public');
      }

      const auditLog = manager.getAuditLog(50);
      expect(auditLog.length).toBe(50);
    });
  });
});

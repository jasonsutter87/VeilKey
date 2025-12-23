/**
 * SOC 2 Compliance Manager Tests
 *
 * Tests for SOC 2 Type II compliance framework
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  SOC2ComplianceManager,
  DEFAULT_SOC2_CONTROLS,
} from '../../../compliance/soc2.js';
import { ComplianceError, ComplianceErrorCode } from '../../../compliance/types.js';

describe('SOC2ComplianceManager', () => {
  let manager: SOC2ComplianceManager;

  beforeEach(() => {
    manager = new SOC2ComplianceManager();
  });

  describe('initialization', () => {
    it('should initialize with default controls', () => {
      const controls = manager.getAllControls();
      expect(controls.length).toBe(DEFAULT_SOC2_CONTROLS.length);
    });

    it('should initialize without defaults when specified', () => {
      const emptyManager = new SOC2ComplianceManager(false);
      expect(emptyManager.getAllControls().length).toBe(0);
    });

    it('should set all controls to not_implemented initially', () => {
      const controls = manager.getAllControls();
      expect(controls.every(c => c.status === 'not_implemented')).toBe(true);
    });
  });

  describe('control management', () => {
    it('should get control by ID', () => {
      const control = manager.getControl('CC1.1');
      expect(control).toBeDefined();
      expect(control?.name).toBe('Control Environment');
    });

    it('should return undefined for non-existent control', () => {
      const control = manager.getControl('INVALID');
      expect(control).toBeUndefined();
    });

    it('should add custom control', () => {
      manager.setControl({
        id: 'CUSTOM.1',
        category: 'security',
        name: 'Custom Control',
        description: 'A custom control',
        requirements: ['Requirement 1'],
        status: 'implemented',
      });

      const control = manager.getControl('CUSTOM.1');
      expect(control).toBeDefined();
      expect(control?.name).toBe('Custom Control');
    });

    it('should update control status', () => {
      manager.updateControlStatus('CC1.1', 'implemented', 'Fully implemented');

      const control = manager.getControl('CC1.1');
      expect(control?.status).toBe('implemented');
      expect(control?.implementationNotes).toBe('Fully implemented');
      expect(control?.lastReviewedAt).toBeDefined();
    });

    it('should throw error when updating non-existent control', () => {
      expect(() => {
        manager.updateControlStatus('INVALID', 'implemented');
      }).toThrow(ComplianceError);
    });
  });

  describe('control filtering', () => {
    it('should filter controls by category', () => {
      const securityControls = manager.getControlsByCategory('security');
      expect(securityControls.every(c => c.category === 'security')).toBe(true);
      expect(securityControls.length).toBeGreaterThan(0);
    });

    it('should filter controls by status', () => {
      manager.updateControlStatus('CC1.1', 'implemented');
      manager.updateControlStatus('CC1.2', 'implemented');

      const implementedControls = manager.getControlsByStatus('implemented');
      expect(implementedControls.length).toBe(2);
    });

    it('should return empty array for category with no controls', () => {
      const emptyManager = new SOC2ComplianceManager(false);
      const controls = emptyManager.getControlsByCategory('security');
      expect(controls.length).toBe(0);
    });
  });

  describe('evidence management', () => {
    it('should add evidence to control', () => {
      const evidence = manager.addEvidence('CC1.1', {
        type: 'policy',
        title: 'Code of Conduct Policy',
        description: 'Employee code of conduct',
        location: '/policies/code-of-conduct.pdf',
        collectedAt: new Date(),
        collectedBy: 'admin',
      });

      expect(evidence.id).toBeDefined();
      expect(evidence.hash).toBeDefined();
      expect(evidence.controlId).toBe('CC1.1');
    });

    it('should get evidence for control', () => {
      manager.addEvidence('CC1.1', {
        type: 'policy',
        title: 'Policy 1',
        description: 'Test policy',
        location: '/test',
        collectedAt: new Date(),
        collectedBy: 'admin',
      });

      manager.addEvidence('CC1.1', {
        type: 'screenshot',
        title: 'Screenshot 1',
        description: 'Test screenshot',
        location: '/screenshots/test.png',
        collectedAt: new Date(),
        collectedBy: 'admin',
      });

      const evidence = manager.getEvidence('CC1.1');
      expect(evidence.length).toBe(2);
    });

    it('should throw error when adding evidence to non-existent control', () => {
      expect(() => {
        manager.addEvidence('INVALID', {
          type: 'policy',
          title: 'Test',
          description: 'Test',
          location: '/test',
          collectedAt: new Date(),
          collectedBy: 'admin',
        });
      }).toThrow(ComplianceError);
    });

    it('should remove evidence', () => {
      const evidence = manager.addEvidence('CC1.1', {
        type: 'policy',
        title: 'Test',
        description: 'Test',
        location: '/test',
        collectedAt: new Date(),
        collectedBy: 'admin',
      });

      const result = manager.removeEvidence('CC1.1', evidence.id);
      expect(result).toBe(true);
      expect(manager.getEvidence('CC1.1').length).toBe(0);
    });

    it('should return false when removing non-existent evidence', () => {
      const result = manager.removeEvidence('CC1.1', 'non-existent');
      expect(result).toBe(false);
    });
  });

  describe('findings management', () => {
    it('should add finding', () => {
      const finding = manager.addFinding({
        severity: 'major',
        controlId: 'CC1.1',
        title: 'Missing Policy',
        description: 'Code of conduct policy not documented',
        recommendation: 'Document and implement code of conduct policy',
      });

      expect(finding.id).toBeDefined();
      expect(finding.status).toBe('open');
    });

    it('should update finding status', () => {
      const finding = manager.addFinding({
        severity: 'minor',
        title: 'Test Finding',
        description: 'Test',
        recommendation: 'Fix it',
      });

      manager.updateFindingStatus(finding.id, 'remediated');

      const findings = manager.getFindings();
      const updated = findings.find(f => f.id === finding.id);
      expect(updated?.status).toBe('remediated');
    });

    it('should filter findings by severity', () => {
      manager.addFinding({
        severity: 'critical',
        title: 'Critical Finding',
        description: 'Test',
        recommendation: 'Fix now',
      });

      manager.addFinding({
        severity: 'minor',
        title: 'Minor Finding',
        description: 'Test',
        recommendation: 'Fix later',
      });

      const criticalFindings = manager.getFindings({ severity: 'critical' });
      expect(criticalFindings.length).toBe(1);
      expect(criticalFindings[0].title).toBe('Critical Finding');
    });

    it('should filter findings by status', () => {
      const finding = manager.addFinding({
        severity: 'major',
        title: 'Test',
        description: 'Test',
        recommendation: 'Fix',
      });

      manager.updateFindingStatus(finding.id, 'in_progress');

      const openFindings = manager.getFindings({ status: 'open' });
      const inProgressFindings = manager.getFindings({ status: 'in_progress' });

      expect(openFindings.length).toBe(0);
      expect(inProgressFindings.length).toBe(1);
    });
  });

  describe('compliance summary', () => {
    it('should calculate summary correctly', () => {
      manager.updateControlStatus('CC1.1', 'implemented');
      manager.updateControlStatus('CC1.2', 'partially_implemented');
      manager.updateControlStatus('CC2.1', 'not_applicable');

      manager.addFinding({
        severity: 'critical',
        title: 'Critical',
        description: 'Test',
        recommendation: 'Fix',
      });

      const summary = manager.calculateSummary();

      expect(summary.totalControls).toBe(DEFAULT_SOC2_CONTROLS.length);
      expect(summary.implementedControls).toBe(1);
      expect(summary.partialControls).toBe(1);
      expect(summary.notApplicableControls).toBe(1);
      expect(summary.criticalFindings).toBe(1);
    });
  });

  describe('compliance score', () => {
    it('should calculate 100% when all controls implemented', () => {
      for (const control of manager.getAllControls()) {
        manager.updateControlStatus(control.id, 'implemented');
      }

      expect(manager.getComplianceScore()).toBe(100);
    });

    it('should calculate 50% for partial implementation', () => {
      for (const control of manager.getAllControls()) {
        manager.updateControlStatus(control.id, 'partially_implemented');
      }

      expect(manager.getComplianceScore()).toBe(50);
    });

    it('should exclude not_applicable controls from calculation', () => {
      const controls = manager.getAllControls();

      for (let i = 0; i < controls.length; i++) {
        if (i < controls.length / 2) {
          manager.updateControlStatus(controls[i].id, 'implemented');
        } else {
          manager.updateControlStatus(controls[i].id, 'not_applicable');
        }
      }

      expect(manager.getComplianceScore()).toBe(100);
    });
  });

  describe('compliance report', () => {
    it('should generate report', () => {
      const periodStart = new Date('2024-01-01');
      const periodEnd = new Date('2024-12-31');

      const report = manager.generateReport(periodStart, periodEnd, 'auditor@example.com');

      expect(report.id).toBeDefined();
      expect(report.reportType).toBe('soc2');
      expect(report.generatedBy).toBe('auditor@example.com');
      expect(report.summary).toBeDefined();
    });

    it('should include recommendations for gaps', () => {
      manager.addFinding({
        severity: 'critical',
        title: 'Critical Gap',
        description: 'Test',
        recommendation: 'Fix',
      });

      const report = manager.generateReport(new Date(), new Date(), 'auditor');

      expect(report.recommendations.length).toBeGreaterThan(0);
    });
  });

  describe('control reviews', () => {
    it('should schedule review', () => {
      const reviewDate = new Date();
      reviewDate.setMonth(reviewDate.getMonth() + 1);

      manager.scheduleReview('CC1.1', reviewDate, 'security-team');

      const control = manager.getControl('CC1.1');
      expect(control?.nextReviewAt).toEqual(reviewDate);
      expect(control?.owner).toBe('security-team');
    });

    it('should get controls requiring review', () => {
      const soonDate = new Date();
      soonDate.setDate(soonDate.getDate() + 10);

      const laterDate = new Date();
      laterDate.setDate(laterDate.getDate() + 60);

      manager.scheduleReview('CC1.1', soonDate);
      manager.scheduleReview('CC1.2', laterDate);

      const dueForReview = manager.getControlsRequiringReview(30);
      expect(dueForReview.length).toBe(1);
      expect(dueForReview[0].id).toBe('CC1.1');
    });
  });

  describe('import/export', () => {
    it('should export and import controls', () => {
      manager.updateControlStatus('CC1.1', 'implemented', 'Test notes');
      manager.addEvidence('CC1.1', {
        type: 'policy',
        title: 'Test',
        description: 'Test',
        location: '/test',
        collectedAt: new Date(),
        collectedBy: 'admin',
      });

      const exported = manager.exportControls();

      const newManager = new SOC2ComplianceManager(false);
      newManager.importControls(exported);

      const control = newManager.getControl('CC1.1');
      expect(control?.status).toBe('implemented');
      expect(newManager.getEvidence('CC1.1').length).toBe(1);
    });
  });
});

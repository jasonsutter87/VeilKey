/**
 * VeilKey SOC 2 Compliance Framework
 *
 * Implements SOC 2 Type II control framework for threshold cryptography
 * operations, including control definitions, evidence collection, and
 * compliance reporting.
 *
 * @module compliance/soc2
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import {
  TrustServiceCategory,
  ControlStatus,
  SOC2Control,
  ControlEvidence,
  EvidenceType,
  ComplianceReport,
  ComplianceReportSummary,
  ComplianceFinding,
  ComplianceError,
  ComplianceErrorCode,
} from './types.js';

/**
 * Default SOC 2 Controls for VeilKey
 */
export const DEFAULT_SOC2_CONTROLS: Omit<SOC2Control, 'status'>[] = [
  // Security Controls
  {
    id: 'CC1.1',
    category: 'security',
    name: 'Control Environment',
    description: 'The organization demonstrates commitment to integrity and ethical values',
    requirements: [
      'Code of conduct policy',
      'Ethics training records',
      'Background check procedures',
    ],
  },
  {
    id: 'CC1.2',
    category: 'security',
    name: 'Board Oversight',
    description: 'The board demonstrates independence and exercises oversight',
    requirements: [
      'Board charter',
      'Meeting minutes',
      'Independence declarations',
    ],
  },
  {
    id: 'CC2.1',
    category: 'security',
    name: 'Information Communication',
    description: 'The organization obtains and generates relevant information',
    requirements: [
      'Information security policy',
      'Communication procedures',
      'Reporting mechanisms',
    ],
  },
  {
    id: 'CC3.1',
    category: 'security',
    name: 'Risk Assessment',
    description: 'The organization specifies objectives and identifies risks',
    requirements: [
      'Risk assessment methodology',
      'Risk register',
      'Risk treatment plans',
    ],
  },
  {
    id: 'CC4.1',
    category: 'security',
    name: 'Monitoring Activities',
    description: 'The organization selects and develops monitoring activities',
    requirements: [
      'Monitoring procedures',
      'Security metrics',
      'Dashboards and reports',
    ],
  },
  {
    id: 'CC5.1',
    category: 'security',
    name: 'Logical Access Controls',
    description: 'Logical access security software and infrastructure are implemented',
    requirements: [
      'Access control policy',
      'Authentication mechanisms',
      'Authorization procedures',
    ],
  },
  {
    id: 'CC5.2',
    category: 'security',
    name: 'Access Provisioning',
    description: 'Access to protected information is provisioned appropriately',
    requirements: [
      'User provisioning procedures',
      'Access request workflow',
      'Approval documentation',
    ],
  },
  {
    id: 'CC5.3',
    category: 'security',
    name: 'Access Removal',
    description: 'Access is removed when no longer required',
    requirements: [
      'Termination procedures',
      'Access review schedules',
      'Deprovisioning logs',
    ],
  },
  {
    id: 'CC6.1',
    category: 'security',
    name: 'Physical Access',
    description: 'Physical access to facilities is restricted',
    requirements: [
      'Physical security policy',
      'Badge access logs',
      'Visitor procedures',
    ],
  },
  {
    id: 'CC6.2',
    category: 'security',
    name: 'Asset Management',
    description: 'Assets are classified and managed throughout lifecycle',
    requirements: [
      'Asset inventory',
      'Classification policy',
      'Disposal procedures',
    ],
  },
  {
    id: 'CC6.3',
    category: 'security',
    name: 'Encryption',
    description: 'Data is encrypted at rest and in transit',
    requirements: [
      'Encryption policy',
      'Key management procedures',
      'Certificate management',
    ],
  },
  {
    id: 'CC6.4',
    category: 'security',
    name: 'Change Management',
    description: 'Changes are authorized, tested, and documented',
    requirements: [
      'Change management policy',
      'Change request records',
      'Testing documentation',
    ],
  },
  {
    id: 'CC7.1',
    category: 'security',
    name: 'Incident Response',
    description: 'Security incidents are detected and responded to',
    requirements: [
      'Incident response plan',
      'Incident logs',
      'Post-incident reviews',
    ],
  },
  {
    id: 'CC7.2',
    category: 'security',
    name: 'Vulnerability Management',
    description: 'Vulnerabilities are identified and remediated',
    requirements: [
      'Vulnerability scanning procedures',
      'Remediation tracking',
      'Penetration test reports',
    ],
  },
  // Availability Controls
  {
    id: 'A1.1',
    category: 'availability',
    name: 'Capacity Planning',
    description: 'Current processing capacity is maintained',
    requirements: [
      'Capacity monitoring',
      'Performance metrics',
      'Scaling procedures',
    ],
  },
  {
    id: 'A1.2',
    category: 'availability',
    name: 'Backup and Recovery',
    description: 'Data is backed up and can be recovered',
    requirements: [
      'Backup policy',
      'Recovery procedures',
      'Recovery testing logs',
    ],
  },
  {
    id: 'A1.3',
    category: 'availability',
    name: 'Business Continuity',
    description: 'Business continuity plans are established',
    requirements: [
      'BCP documentation',
      'DR testing records',
      'Recovery time objectives',
    ],
  },
  // Confidentiality Controls
  {
    id: 'C1.1',
    category: 'confidentiality',
    name: 'Data Classification',
    description: 'Confidential information is properly classified',
    requirements: [
      'Classification policy',
      'Data inventory',
      'Handling procedures',
    ],
  },
  {
    id: 'C1.2',
    category: 'confidentiality',
    name: 'Data Disposal',
    description: 'Confidential information is securely disposed',
    requirements: [
      'Disposal policy',
      'Disposal certificates',
      'Media sanitization logs',
    ],
  },
  // Processing Integrity Controls
  {
    id: 'PI1.1',
    category: 'processing_integrity',
    name: 'Input Validation',
    description: 'System inputs are validated for accuracy',
    requirements: [
      'Validation procedures',
      'Error handling documentation',
      'Validation test results',
    ],
  },
  {
    id: 'PI1.2',
    category: 'processing_integrity',
    name: 'Output Verification',
    description: 'System outputs are verified for accuracy',
    requirements: [
      'Output verification procedures',
      'Reconciliation logs',
      'Error tracking',
    ],
  },
  // Privacy Controls
  {
    id: 'P1.1',
    category: 'privacy',
    name: 'Privacy Notice',
    description: 'Privacy notice is provided to data subjects',
    requirements: [
      'Privacy policy',
      'Notice acknowledgments',
      'Consent records',
    ],
  },
  {
    id: 'P1.2',
    category: 'privacy',
    name: 'Data Subject Rights',
    description: 'Data subject rights requests are handled',
    requirements: [
      'Rights request procedures',
      'Request tracking',
      'Response documentation',
    ],
  },
];

/**
 * SOC 2 Compliance Manager
 */
export class SOC2ComplianceManager {
  private controls: Map<string, SOC2Control> = new Map();
  private evidence: Map<string, ControlEvidence[]> = new Map();
  private findings: ComplianceFinding[] = [];

  constructor(initializeDefaults = true) {
    if (initializeDefaults) {
      this.initializeDefaultControls();
    }
  }

  /**
   * Initialize default SOC 2 controls
   */
  private initializeDefaultControls(): void {
    for (const controlDef of DEFAULT_SOC2_CONTROLS) {
      const control: SOC2Control = {
        ...controlDef,
        status: 'not_implemented',
      };
      this.controls.set(control.id, control);
      this.evidence.set(control.id, []);
    }
  }

  /**
   * Add or update a control
   */
  setControl(control: SOC2Control): void {
    this.controls.set(control.id, control);
    if (!this.evidence.has(control.id)) {
      this.evidence.set(control.id, []);
    }
  }

  /**
   * Get a control by ID
   */
  getControl(controlId: string): SOC2Control | undefined {
    return this.controls.get(controlId);
  }

  /**
   * Get all controls
   */
  getAllControls(): SOC2Control[] {
    return Array.from(this.controls.values());
  }

  /**
   * Get controls by category
   */
  getControlsByCategory(category: TrustServiceCategory): SOC2Control[] {
    return this.getAllControls().filter(c => c.category === category);
  }

  /**
   * Get controls by status
   */
  getControlsByStatus(status: ControlStatus): SOC2Control[] {
    return this.getAllControls().filter(c => c.status === status);
  }

  /**
   * Update control status
   */
  updateControlStatus(
    controlId: string,
    status: ControlStatus,
    notes?: string
  ): void {
    const control = this.controls.get(controlId);
    if (!control) {
      throw new ComplianceError(
        `Control ${controlId} not found`,
        ComplianceErrorCode.CONTROL_NOT_FOUND
      );
    }

    control.status = status;
    if (notes) {
      control.implementationNotes = notes;
    }
    control.lastReviewedAt = new Date();

    this.controls.set(controlId, control);
  }

  /**
   * Add evidence to a control
   */
  addEvidence(
    controlId: string,
    evidenceData: Omit<ControlEvidence, 'id' | 'controlId' | 'hash'>
  ): ControlEvidence {
    if (!this.controls.has(controlId)) {
      throw new ComplianceError(
        `Control ${controlId} not found`,
        ComplianceErrorCode.CONTROL_NOT_FOUND
      );
    }

    const evidence: ControlEvidence = {
      id: bytesToHex(new Uint8Array(16).map(() => Math.floor(Math.random() * 256))),
      controlId,
      ...evidenceData,
      hash: '',
    };

    // Calculate hash
    const hashData = JSON.stringify({ ...evidence, hash: undefined });
    evidence.hash = bytesToHex(sha256(new TextEncoder().encode(hashData)));

    const controlEvidence = this.evidence.get(controlId) || [];
    controlEvidence.push(evidence);
    this.evidence.set(controlId, controlEvidence);

    return evidence;
  }

  /**
   * Get evidence for a control
   */
  getEvidence(controlId: string): ControlEvidence[] {
    return this.evidence.get(controlId) || [];
  }

  /**
   * Remove evidence
   */
  removeEvidence(controlId: string, evidenceId: string): boolean {
    const controlEvidence = this.evidence.get(controlId);
    if (!controlEvidence) return false;

    const index = controlEvidence.findIndex(e => e.id === evidenceId);
    if (index === -1) return false;

    controlEvidence.splice(index, 1);
    this.evidence.set(controlId, controlEvidence);
    return true;
  }

  /**
   * Add a compliance finding
   */
  addFinding(
    findingData: Omit<ComplianceFinding, 'id' | 'status'>
  ): ComplianceFinding {
    const finding: ComplianceFinding = {
      id: bytesToHex(new Uint8Array(16).map(() => Math.floor(Math.random() * 256))),
      ...findingData,
      status: 'open',
    };

    this.findings.push(finding);
    return finding;
  }

  /**
   * Update finding status
   */
  updateFindingStatus(
    findingId: string,
    status: ComplianceFinding['status']
  ): void {
    const finding = this.findings.find(f => f.id === findingId);
    if (!finding) {
      throw new ComplianceError(
        `Finding ${findingId} not found`,
        ComplianceErrorCode.EVIDENCE_NOT_FOUND
      );
    }
    finding.status = status;
  }

  /**
   * Get all findings
   */
  getFindings(filters?: {
    severity?: ComplianceFinding['severity'];
    status?: ComplianceFinding['status'];
    controlId?: string;
  }): ComplianceFinding[] {
    let result = [...this.findings];

    if (filters) {
      if (filters.severity) {
        result = result.filter(f => f.severity === filters.severity);
      }
      if (filters.status) {
        result = result.filter(f => f.status === filters.status);
      }
      if (filters.controlId) {
        result = result.filter(f => f.controlId === filters.controlId);
      }
    }

    return result;
  }

  /**
   * Calculate compliance summary
   */
  calculateSummary(): ComplianceReportSummary {
    const controls = this.getAllControls();

    const summary: ComplianceReportSummary = {
      totalControls: controls.length,
      implementedControls: controls.filter(c => c.status === 'implemented').length,
      partialControls: controls.filter(c => c.status === 'partially_implemented').length,
      notImplementedControls: controls.filter(c => c.status === 'not_implemented').length,
      notApplicableControls: controls.filter(c => c.status === 'not_applicable').length,
      criticalFindings: this.findings.filter(f => f.severity === 'critical' && f.status === 'open').length,
      majorFindings: this.findings.filter(f => f.severity === 'major' && f.status === 'open').length,
      minorFindings: this.findings.filter(f => f.severity === 'minor' && f.status === 'open').length,
    };

    return summary;
  }

  /**
   * Generate compliance report
   */
  generateReport(
    periodStart: Date,
    periodEnd: Date,
    generatedBy: string
  ): ComplianceReport {
    const summary = this.calculateSummary();
    const recommendations: string[] = [];

    // Generate recommendations based on gaps
    if (summary.notImplementedControls > 0) {
      recommendations.push(
        `Address ${summary.notImplementedControls} controls that are not yet implemented`
      );
    }

    if (summary.criticalFindings > 0) {
      recommendations.push(
        `Prioritize remediation of ${summary.criticalFindings} critical findings`
      );
    }

    if (summary.partialControls > 0) {
      recommendations.push(
        `Complete implementation of ${summary.partialControls} partially implemented controls`
      );
    }

    // Check for missing evidence
    const controlsWithoutEvidence = this.getAllControls().filter(
      c => c.status === 'implemented' && (this.evidence.get(c.id) || []).length === 0
    );

    if (controlsWithoutEvidence.length > 0) {
      recommendations.push(
        `Collect evidence for ${controlsWithoutEvidence.length} implemented controls`
      );
    }

    const report: ComplianceReport = {
      id: bytesToHex(new Uint8Array(16).map(() => Math.floor(Math.random() * 256))),
      reportType: 'soc2',
      generatedAt: new Date(),
      generatedBy,
      periodStart,
      periodEnd,
      summary,
      findings: this.getFindings({ status: 'open' }),
      recommendations,
    };

    return report;
  }

  /**
   * Get compliance score (percentage)
   */
  getComplianceScore(): number {
    const controls = this.getAllControls().filter(c => c.status !== 'not_applicable');
    if (controls.length === 0) return 100;

    const implemented = controls.filter(c => c.status === 'implemented').length;
    const partial = controls.filter(c => c.status === 'partially_implemented').length;

    return Math.round(((implemented + partial * 0.5) / controls.length) * 100);
  }

  /**
   * Get controls requiring review
   */
  getControlsRequiringReview(withinDays = 30): SOC2Control[] {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() + withinDays);

    return this.getAllControls().filter(c => {
      if (!c.nextReviewAt) return false;
      return c.nextReviewAt <= cutoff;
    });
  }

  /**
   * Schedule control review
   */
  scheduleReview(controlId: string, reviewDate: Date, owner?: string): void {
    const control = this.controls.get(controlId);
    if (!control) {
      throw new ComplianceError(
        `Control ${controlId} not found`,
        ComplianceErrorCode.CONTROL_NOT_FOUND
      );
    }

    control.nextReviewAt = reviewDate;
    if (owner) {
      control.owner = owner;
    }

    this.controls.set(controlId, control);
  }

  /**
   * Export controls as JSON
   */
  exportControls(): string {
    const data = {
      controls: this.getAllControls(),
      evidence: Object.fromEntries(this.evidence),
      findings: this.findings,
      exportedAt: new Date().toISOString(),
    };

    return JSON.stringify(data, null, 2);
  }

  /**
   * Import controls from JSON
   */
  importControls(jsonData: string): void {
    const data = JSON.parse(jsonData);

    if (data.controls) {
      for (const control of data.controls) {
        this.controls.set(control.id, control);
      }
    }

    if (data.evidence) {
      for (const [controlId, evidenceList] of Object.entries(data.evidence)) {
        this.evidence.set(controlId, evidenceList as ControlEvidence[]);
      }
    }

    if (data.findings) {
      this.findings = data.findings;
    }
  }
}

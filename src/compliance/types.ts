/**
 * VeilKey Compliance Module - Type Definitions
 *
 * Types for SOC 2 compliance, audit logging, data residency,
 * and key escrow functionality.
 *
 * @module compliance/types
 */

/**
 * SOC 2 Trust Service Categories
 */
export type TrustServiceCategory =
  | 'security'
  | 'availability'
  | 'processing_integrity'
  | 'confidentiality'
  | 'privacy';

/**
 * Control Status
 */
export type ControlStatus = 'implemented' | 'partially_implemented' | 'not_implemented' | 'not_applicable';

/**
 * Evidence Type
 */
export type EvidenceType =
  | 'policy'
  | 'procedure'
  | 'screenshot'
  | 'log'
  | 'configuration'
  | 'report'
  | 'certificate'
  | 'attestation';

/**
 * SOC 2 Control Definition
 */
export interface SOC2Control {
  id: string;
  category: TrustServiceCategory;
  name: string;
  description: string;
  requirements: string[];
  status: ControlStatus;
  implementationNotes?: string;
  owner?: string;
  lastReviewedAt?: Date;
  nextReviewAt?: Date;
}

/**
 * Control Evidence
 */
export interface ControlEvidence {
  id: string;
  controlId: string;
  type: EvidenceType;
  title: string;
  description: string;
  location: string; // File path or URL
  collectedAt: Date;
  collectedBy: string;
  validUntil?: Date;
  hash: string;
}

/**
 * Audit Event Severity
 */
export type AuditSeverity = 'debug' | 'info' | 'warning' | 'error' | 'critical';

/**
 * Audit Event Category
 */
export type AuditCategory =
  | 'authentication'
  | 'authorization'
  | 'key_operation'
  | 'share_operation'
  | 'configuration'
  | 'access_control'
  | 'data_access'
  | 'admin_action'
  | 'system_event'
  | 'security_event';

/**
 * Enhanced Audit Event
 */
export interface AuditEvent {
  id: string;
  timestamp: Date;
  category: AuditCategory;
  severity: AuditSeverity;
  action: string;
  outcome: 'success' | 'failure' | 'partial';
  userId?: string;
  userAgent?: string;
  ipAddress?: string;
  resourceType?: string;
  resourceId?: string;
  details: Record<string, unknown>;
  dataClassification?: DataClassification;
  region?: string;
  hash: string;
  previousHash: string;
}

/**
 * Data Classification Level
 */
export type DataClassification = 'public' | 'internal' | 'confidential' | 'restricted';

/**
 * Geographic Region for Data Residency
 */
export interface DataRegion {
  id: string;
  name: string;
  countryCodes: string[];
  jurisdiction: string;
  dataProtectionLaw?: string; // e.g., "GDPR", "CCPA", "LGPD"
  enabled: boolean;
}

/**
 * Data Residency Policy
 */
export interface DataResidencyPolicy {
  id: string;
  name: string;
  allowedRegions: string[]; // Region IDs
  dataClassifications: DataClassification[];
  resourceTypes: string[];
  enforceAtRest: boolean;
  enforceInTransit: boolean;
  enabled: boolean;
}

/**
 * Data Location Record
 */
export interface DataLocationRecord {
  id: string;
  resourceType: string;
  resourceId: string;
  region: string;
  classification: DataClassification;
  createdAt: Date;
  movedAt?: Date;
  previousRegion?: string;
}

/**
 * Key Escrow Configuration
 */
export interface KeyEscrowConfig {
  id: string;
  name: string;
  escrowAgents: EscrowAgent[];
  threshold: number; // M-of-N escrow agents needed
  encryptionAlgorithm: 'AES-256-GCM' | 'ChaCha20-Poly1305';
  keyDerivation: 'PBKDF2' | 'Argon2id' | 'scrypt';
  rotationPeriodDays: number;
  requiresApproval: boolean;
  approvers?: string[];
  enabled: boolean;
}

/**
 * Escrow Agent
 */
export interface EscrowAgent {
  id: string;
  name: string;
  type: 'internal' | 'external' | 'hsm';
  publicKey: string;
  contactEmail?: string;
  organization?: string;
  enabled: boolean;
}

/**
 * Escrowed Key
 */
export interface EscrowedKey {
  id: string;
  keyId: string;
  keyType: 'master' | 'share' | 'signing' | 'encryption';
  escrowConfigId: string;
  encryptedShares: EscrowedKeyShare[];
  createdAt: Date;
  expiresAt?: Date;
  recoveredAt?: Date;
  recoveredBy?: string;
  status: 'active' | 'recovered' | 'expired' | 'revoked';
}

/**
 * Escrowed Key Share
 */
export interface EscrowedKeyShare {
  agentId: string;
  encryptedShare: string;
  encryptedAt: Date;
  algorithm: string;
}

/**
 * Escrow Recovery Request
 */
export interface EscrowRecoveryRequest {
  id: string;
  escrowedKeyId: string;
  requestedBy: string;
  requestedAt: Date;
  reason: string;
  approvals: EscrowApproval[];
  status: 'pending' | 'approved' | 'rejected' | 'completed' | 'expired';
  expiresAt: Date;
}

/**
 * Escrow Approval
 */
export interface EscrowApproval {
  approverId: string;
  decision: 'approved' | 'rejected';
  decidedAt: Date;
  comment?: string;
}

/**
 * Compliance Report
 */
export interface ComplianceReport {
  id: string;
  reportType: 'soc2' | 'audit' | 'data_residency' | 'escrow';
  generatedAt: Date;
  generatedBy: string;
  periodStart: Date;
  periodEnd: Date;
  summary: ComplianceReportSummary;
  findings: ComplianceFinding[];
  recommendations: string[];
}

/**
 * Compliance Report Summary
 */
export interface ComplianceReportSummary {
  totalControls: number;
  implementedControls: number;
  partialControls: number;
  notImplementedControls: number;
  notApplicableControls: number;
  criticalFindings: number;
  majorFindings: number;
  minorFindings: number;
}

/**
 * Compliance Finding
 */
export interface ComplianceFinding {
  id: string;
  severity: 'critical' | 'major' | 'minor' | 'observation';
  controlId?: string;
  title: string;
  description: string;
  recommendation: string;
  dueDate?: Date;
  assignee?: string;
  status: 'open' | 'in_progress' | 'remediated' | 'accepted';
}

/**
 * Retention Policy
 */
export interface RetentionPolicy {
  id: string;
  name: string;
  resourceTypes: string[];
  retentionDays: number;
  archiveAfterDays?: number;
  deleteAfterArchive: boolean;
  legalHoldExempt: boolean;
  enabled: boolean;
}

/**
 * Compliance Error
 */
export class ComplianceError extends Error {
  constructor(
    message: string,
    public readonly code: ComplianceErrorCode
  ) {
    super(message);
    this.name = 'ComplianceError';
  }
}

/**
 * Compliance Error Codes
 */
export enum ComplianceErrorCode {
  CONTROL_NOT_FOUND = 'CONTROL_NOT_FOUND',
  EVIDENCE_NOT_FOUND = 'EVIDENCE_NOT_FOUND',
  POLICY_VIOLATION = 'POLICY_VIOLATION',
  DATA_RESIDENCY_VIOLATION = 'DATA_RESIDENCY_VIOLATION',
  ESCROW_NOT_FOUND = 'ESCROW_NOT_FOUND',
  RECOVERY_NOT_APPROVED = 'RECOVERY_NOT_APPROVED',
  THRESHOLD_NOT_MET = 'THRESHOLD_NOT_MET',
  AUDIT_INTEGRITY_FAILURE = 'AUDIT_INTEGRITY_FAILURE',
  RETENTION_VIOLATION = 'RETENTION_VIOLATION',
}

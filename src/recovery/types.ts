/**
 * Types for Share Recovery System
 *
 * Provides types for detecting lost shares, executing recovery protocol,
 * generating replacement shares, and auditing recovery operations.
 */

// =============================================================================
// Recovery Protocol Types
// =============================================================================

export interface RecoveryRequest {
  id: string;
  lostShareHolderId: string;
  requestedBy: string;
  timestamp: Date;
  reason: string;
  status: RecoveryStatus;
  requiredApprovals: number;
  receivedApprovals: string[]; // IDs of approvers
  participatingHolders: string[]; // IDs of holders providing shares
}

export type RecoveryStatus =
  | 'pending_authorization'
  | 'authorized'
  | 'in_progress'
  | 'completed'
  | 'aborted'
  | 'failed';

export interface RecoveryAuthorization {
  recoveryId: string;
  approverId: string;
  timestamp: Date;
  signature: string;
  conditions?: string[];
}

export interface RecoverySession {
  id: string;
  recoveryRequestId: string;
  startTime: Date;
  endTime?: Date;
  currentStep: RecoveryStep;
  completedSteps: RecoveryStep[];
  participants: RecoveryParticipant[];
  reconstructedSecret?: string;
  newShareGenerated?: boolean;
  retryCount?: number;
}

export type RecoveryStep =
  | 'authorization'
  | 'share_collection'
  | 'secret_reconstruction'
  | 'new_share_generation'
  | 'distribution'
  | 'verification'
  | 'old_share_revocation';

export interface RecoveryParticipant {
  shareHolderId: string;
  shareProvided: boolean;
  shareIndex?: number;
  timestamp?: Date;
}

export interface ParticipatingShare {
  holderId: string;
  shareIndex: number;
  shareValue: string;
  signature: string;
}

export interface EscrowConfig {
  enabled: boolean;
  escrowAgentId: string;
  escrowPublicKey: string;
  releaseConditions: string[];
  dualControlRequired: boolean;
  secondaryAuthorityId?: string;
}

// =============================================================================
// Detection Types
// =============================================================================

export interface ShareHolder {
  id: string;
  publicKey: string;
  endpoint?: string;
  lastHeartbeat?: Date;
  status: 'active' | 'unresponsive' | 'lost' | 'recovering';
}

export interface DetectionConfig {
  heartbeatInterval: number; // milliseconds
  timeoutThreshold: number; // milliseconds
  maxMissedHeartbeats: number;
  autoDetectionEnabled: boolean;
  notificationChannels: NotificationChannel[];
}

export interface NotificationChannel {
  type: 'email' | 'sms' | 'webhook' | 'push';
  destination: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
}

export interface DetectionEvent {
  id: string;
  timestamp: Date;
  shareHolderId: string;
  detectionType: 'timeout' | 'heartbeat' | 'manual' | 'network';
  severity: 'warning' | 'critical';
  metadata?: Record<string, unknown>;
  acknowledged?: boolean;
}

export interface DetectionEventFilter {
  shareHolderId?: string;
  detectionType?: DetectionEvent['detectionType'];
  severity?: DetectionEvent['severity'];
  startDate?: Date;
  endDate?: Date;
  acknowledged?: boolean;
}

// =============================================================================
// Share Generation Types
// =============================================================================

export interface GeneratedShare {
  id: string;
  shareIndex: number;
  shareValue: string;
  holderId: string;
  generatedAt: Date;
  publicCommitment: string;
  proof?: string; // Zero-knowledge proof of validity
  metadata: ShareMetadata;
}

export interface ShareMetadata {
  version: number;
  threshold: number;
  totalShares: number;
  algorithm: 'shamir' | 'feldman-vss';
  createdAt: Date;
  replacesShareId?: string;
  generationContext: 'initial' | 'recovery' | 'rotation';
  invalidated?: boolean;
  invalidatedAt?: Date;
}

export interface PublicParameters {
  prime: string;
  generator: string;
  commitments: string[];
  threshold: number;
}

export interface ShareIndexAssignment {
  oldIndex: number;
  newIndex: number;
  holderId: string;
  assignedAt: Date;
  reason: string;
}

// =============================================================================
// Audit Types
// =============================================================================

export interface RecoveryInitiationEvent {
  recoveryId: string;
  lostShareHolderId: string;
  initiatedBy: string;
  timestamp: Date;
  reason: string;
  detectionMethod: 'automatic' | 'manual';
  approvalRequired: boolean;
}

export interface ParticipantConsentEvent {
  recoveryId: string;
  participantId: string;
  consentGiven: boolean;
  timestamp: Date;
  signature: string;
  conditions?: string[];
}

export interface ShareDistributionEvent {
  recoveryId: string;
  newShareHolderId: string;
  shareIndex: number;
  distributedAt: Date;
  deliveryMethod: 'encrypted_channel' | 'in_person' | 'hardware_token';
  confirmationReceived: boolean;
  confirmationTimestamp?: Date;
}

export interface AuditRecord {
  id: string;
  eventType: 'initiation' | 'consent' | 'distribution' | 'completion' | 'failure';
  recoveryId: string;
  timestamp: Date;
  actor: string;
  action: string;
  details: Record<string, unknown>;
  previousRecordHash?: string;
  recordHash: string;
}

export interface ReportFilter {
  startDate?: Date;
  endDate?: Date;
  recoveryId?: string;
  eventType?: AuditRecord['eventType'];
  actor?: string;
  status?: 'success' | 'failed' | 'pending';
}

export interface ComplianceReport {
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

// =============================================================================
// Storage Types
// =============================================================================

export interface RecoveryStorage {
  saveRecoveryRequest(request: RecoveryRequest): Promise<void>;
  getRecoveryRequest(id: string): Promise<RecoveryRequest | null>;
  listRecoveryRequests(): Promise<RecoveryRequest[]>;

  saveRecoverySession(session: RecoverySession): Promise<void>;
  getRecoverySession(id: string): Promise<RecoverySession | null>;

  saveAuthorization(auth: RecoveryAuthorization): Promise<void>;
  getAuthorizations(recoveryId: string): Promise<RecoveryAuthorization[]>;

  saveShareHolder(holder: ShareHolder): Promise<void>;
  getShareHolder(id: string): Promise<ShareHolder | null>;
  listShareHolders(): Promise<ShareHolder[]>;
  updateShareHolder(id: string, updates: Partial<ShareHolder>): Promise<void>;

  saveDetectionEvent(event: DetectionEvent): Promise<void>;
  getDetectionEvents(filter?: DetectionEventFilter): Promise<DetectionEvent[]>;
  acknowledgeEvent(eventId: string): Promise<void>;

  saveGeneratedShare(share: GeneratedShare): Promise<void>;
  getGeneratedShare(id: string): Promise<GeneratedShare | null>;
  getShareMetadata(shareId: string): Promise<ShareMetadata | null>;
  updateShareMetadata(shareId: string, updates: Partial<ShareMetadata>): Promise<void>;

  saveAuditRecord(record: AuditRecord): Promise<void>;
  getAuditRecords(filter?: ReportFilter): Promise<AuditRecord[]>;
  getLastAuditRecord(): Promise<AuditRecord | null>;

  saveEscrowConfig(config: EscrowConfig): Promise<void>;
  getEscrowConfig(): Promise<EscrowConfig | null>;
}

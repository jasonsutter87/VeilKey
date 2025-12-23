/**
 * Types for Key Ceremony System
 *
 * Defines types for conducting threshold key generation ceremonies
 * where multiple participants coordinate to create distributed keys.
 */

import type { FeldmanCommitments, CurvePoint } from '../feldman/types.js';

/**
 * Phases of a key ceremony
 */
export enum CeremonyPhase {
  /** Ceremony created, awaiting participants */
  CREATED = 'CREATED',
  /** Accepting participant registrations */
  REGISTRATION = 'REGISTRATION',
  /** Collecting commitments from participants */
  COMMITMENT = 'COMMITMENT',
  /** Distributing shares to participants */
  SHARE_DISTRIBUTION = 'SHARE_DISTRIBUTION',
  /** Ceremony complete, shares distributed */
  FINALIZED = 'FINALIZED',
}

/**
 * Configuration for creating a ceremony
 */
export interface CeremonyConfig {
  /** Unique ceremony identifier */
  id: string;

  /** Minimum shares needed for operations (t) */
  threshold: number;

  /** Total number of participants (n) */
  totalParticipants: number;

  /** Optional timeout for each phase (milliseconds) */
  phaseTimeout?: number;

  /** Optional ceremony description */
  description?: string;
}

/**
 * Status of a participant in the ceremony
 */
export enum ParticipantStatus {
  /** Registered but not yet committed */
  REGISTERED = 'REGISTERED',
  /** Commitment submitted */
  COMMITTED = 'COMMITTED',
  /** Share received */
  SHARE_RECEIVED = 'SHARE_RECEIVED',
}

/**
 * A participant in the key ceremony
 */
export interface Participant {
  /** Unique participant identifier */
  id: string;

  /** Public key for identity verification (hex-encoded) */
  publicKey: string;

  /** Current status */
  status: ParticipantStatus;

  /** Registration timestamp */
  registeredAt: Date;

  /** Share index assigned to this participant (1-based) */
  shareIndex?: number;
}

/**
 * A commitment from a participant
 * Contains hash of their polynomial coefficients
 */
export interface Commitment {
  /** Participant ID */
  participantId: string;

  /** Hash of polynomial coefficients (hex-encoded SHA-256) */
  commitmentHash: string;

  /** Feldman VSS commitments (curve points) */
  feldmanCommitments: FeldmanCommitments;

  /** Timestamp when commitment was made */
  timestamp: Date;
}

/**
 * A share to be distributed to a participant
 */
export interface CeremonyShare {
  /** Participant ID */
  participantId: string;

  /** Share index (1-based) */
  index: number;

  /** Share value (hex-encoded) */
  value: string;

  /** Verification key (hex-encoded) */
  verificationKey: string;
}

/**
 * Result of a completed ceremony
 */
export interface CeremonyResult {
  /** Ceremony ID */
  ceremonyId: string;

  /** Public key (hex-encoded, format: "n:e" for RSA or curve point for ECC) */
  publicKey: string;

  /** Public commitment (g^secret) */
  publicCommitment: CurvePoint;

  /** All Feldman commitments for verification */
  commitments: FeldmanCommitments;

  /** Threshold */
  threshold: number;

  /** Total participants */
  totalParticipants: number;

  /** Shares distributed to participants */
  shares: CeremonyShare[];

  /** Completion timestamp */
  completedAt: Date;
}

/**
 * Type of audit event
 */
export enum AuditEventType {
  CEREMONY_CREATED = 'CEREMONY_CREATED',
  PHASE_TRANSITION = 'PHASE_TRANSITION',
  PARTICIPANT_REGISTERED = 'PARTICIPANT_REGISTERED',
  COMMITMENT_SUBMITTED = 'COMMITMENT_SUBMITTED',
  SHARES_DISTRIBUTED = 'SHARES_DISTRIBUTED',
  CEREMONY_FINALIZED = 'CEREMONY_FINALIZED',
  ERROR = 'ERROR',
}

/**
 * An entry in the audit log
 * Hash-linked for tamper evidence
 */
export interface AuditEntry {
  /** Sequential entry number */
  sequence: number;

  /** Type of event */
  eventType: AuditEventType;

  /** Timestamp */
  timestamp: Date;

  /** Event data (JSON-serializable) */
  data: Record<string, unknown>;

  /** Hash of previous entry (for chain integrity) */
  previousHash: string;

  /** Hash of this entry */
  hash: string;
}

/**
 * Current state of a ceremony
 */
export interface CeremonyState {
  /** Ceremony configuration */
  config: CeremonyConfig;

  /** Current phase */
  phase: CeremonyPhase;

  /** Registered participants */
  participants: Map<string, Participant>;

  /** Collected commitments */
  commitments: Map<string, Commitment>;

  /** Result (only set when finalized) */
  result?: CeremonyResult;

  /** Audit trail */
  auditLog: AuditEntry[];

  /** Creation timestamp */
  createdAt: Date;

  /** Last update timestamp */
  updatedAt: Date;
}

/**
 * Options for state transitions
 */
export interface TransitionOptions {
  /** Force transition even if guards fail (use with caution) */
  force?: boolean;

  /** Additional data to log */
  metadata?: Record<string, unknown>;
}

/**
 * Error thrown when a state transition is invalid
 */
export class CeremonyError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'CeremonyError';
  }
}

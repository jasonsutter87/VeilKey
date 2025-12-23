/**
 * Types for Share Management System
 *
 * Provides secure storage, access control, and audit logging for threshold key shares.
 */

import type { Share, KeyGroup } from '../veilkey.js';

// =============================================================================
// Encrypted Share Storage
// =============================================================================

/**
 * An encrypted share ready for secure storage
 */
export interface EncryptedShare {
  /** Unique identifier for this share */
  id: string;

  /** Index of the share (1-based) */
  index: number;

  /** ID of the key group this share belongs to */
  keyGroupId: string;

  /** Encrypted share data (AES-256-GCM) */
  ciphertext: string;

  /** Salt used for key derivation (hex-encoded) */
  salt: string;

  /** IV/nonce for AES-GCM (hex-encoded) */
  iv: string;

  /** Authentication tag for AES-GCM (hex-encoded) */
  authTag: string;

  /** Metadata (not encrypted) */
  metadata: ShareMetadata;

  /** Creation timestamp */
  createdAt: Date;

  /** Last access timestamp */
  lastAccessedAt?: Date;
}

/**
 * Metadata associated with a share (not encrypted)
 */
export interface ShareMetadata {
  /** Human-readable label */
  label?: string;

  /** Custom tags for organization */
  tags?: string[];

  /** Algorithm used */
  algorithm: string;

  /** Threshold value */
  threshold: number;

  /** Total parties */
  parties: number;
}

// =============================================================================
// Share Holders
// =============================================================================

/**
 * A party who holds one or more shares
 */
export interface ShareHolder {
  /** Unique identifier */
  id: string;

  /** Human-readable name */
  name: string;

  /** Email or contact information */
  contact?: string;

  /** Role (for RBAC) */
  role: Role;

  /** When this holder was created */
  createdAt: Date;

  /** Whether this holder is active */
  active: boolean;
}

/**
 * Assignment of a share to a holder
 */
export interface ShareAssignment {
  /** Unique identifier for this assignment */
  id: string;

  /** Share ID */
  shareId: string;

  /** Holder ID */
  holderId: string;

  /** When this assignment was created */
  assignedAt: Date;

  /** Optional expiration date */
  expiresAt?: Date;

  /** Whether this assignment is active */
  active: boolean;
}

// =============================================================================
// Access Control (RBAC)
// =============================================================================

/**
 * Roles in the system
 */
export type Role = 'admin' | 'trustee' | 'auditor';

/**
 * Permissions in the system
 */
export type Permission =
  | 'share:create'
  | 'share:read'
  | 'share:use'
  | 'share:delete'
  | 'share:assign'
  | 'holder:create'
  | 'holder:read'
  | 'holder:update'
  | 'holder:delete'
  | 'audit:read'
  | 'audit:export';

/**
 * Access policy defining role-based permissions
 */
export interface AccessPolicy {
  /** Role this policy applies to */
  role: Role;

  /** Permissions granted to this role */
  permissions: Permission[];

  /** Optional conditions */
  conditions?: PolicyCondition[];
}

/**
 * Conditions for policy evaluation
 */
export interface PolicyCondition {
  /** Type of condition */
  type: 'time' | 'ip' | 'custom';

  /** Condition-specific data */
  data: unknown;
}

// =============================================================================
// Audit Logging
// =============================================================================

/**
 * Types of auditable events
 */
export type AuditEventType =
  | 'share.created'
  | 'share.accessed'
  | 'share.used'
  | 'share.deleted'
  | 'share.assigned'
  | 'holder.created'
  | 'holder.updated'
  | 'holder.deleted'
  | 'audit.exported';

/**
 * A single audit log entry
 */
export interface AuditEntry {
  /** Unique identifier */
  id: string;

  /** Event type */
  event: AuditEventType;

  /** When the event occurred */
  timestamp: Date;

  /** Who performed the action */
  actor: string;

  /** Resource affected (e.g., share ID, holder ID) */
  resource: string;

  /** Additional details */
  details?: Record<string, unknown>;

  /** Hash chain linking to previous entry */
  previousHash?: string;

  /** Hash of this entry */
  hash: string;

  /** IP address of the actor (if available) */
  ipAddress?: string;
}

/**
 * Audit log export format
 */
export interface AuditLog {
  /** All entries in the log */
  entries: AuditEntry[];

  /** When the log was exported */
  exportedAt: Date;

  /** Hash of the entire log */
  logHash: string;

  /** Integrity status */
  verified: boolean;
}

// =============================================================================
// Configuration
// =============================================================================

/**
 * Configuration for the ShareManager
 */
export interface ShareManagerConfig {
  /** Storage backend type */
  storage?: 'memory' | 'file';

  /** File path for file-based storage */
  storagePath?: string;

  /** Default access policies */
  policies?: AccessPolicy[];

  /** Enable audit logging */
  enableAudit?: boolean;

  /** Key derivation function */
  kdf?: 'pbkdf2' | 'argon2';

  /** KDF iterations (for PBKDF2) */
  kdfIterations?: number;
}

/**
 * Options for storing shares
 */
export interface StoreSharesOptions {
  /** Labels for each share */
  labels?: string[];

  /** Tags for organization */
  tags?: string[];

  /** Password for encryption */
  password: string;

  /** Custom KDF iterations */
  kdfIterations?: number;
}

/**
 * Options for retrieving a share
 */
export interface GetShareOptions {
  /** Password for decryption */
  password: string;

  /** Whether to log this access */
  skipAudit?: boolean;
}

/**
 * Result of a share retrieval
 */
export interface ShareRetrievalResult {
  /** The decrypted share */
  share: Share;

  /** Metadata about the share */
  metadata: ShareMetadata;

  /** When this share was created */
  createdAt: Date;
}

// =============================================================================
// Storage Backend Interface
// =============================================================================

/**
 * Interface for storage backends
 */
export interface StorageBackend {
  /** Store an encrypted share */
  saveShare(share: EncryptedShare): Promise<void>;

  /** Retrieve an encrypted share */
  getShare(shareId: string): Promise<EncryptedShare | null>;

  /** List all encrypted shares */
  listShares(): Promise<EncryptedShare[]>;

  /** Delete an encrypted share */
  deleteShare(shareId: string): Promise<boolean>;

  /** Store a share holder */
  saveHolder(holder: ShareHolder): Promise<void>;

  /** Retrieve a share holder */
  getHolder(holderId: string): Promise<ShareHolder | null>;

  /** List all holders */
  listHolders(): Promise<ShareHolder[]>;

  /** Store a share assignment */
  saveAssignment(assignment: ShareAssignment): Promise<void>;

  /** Get assignments for a holder */
  getAssignmentsByHolder(holderId: string): Promise<ShareAssignment[]>;

  /** Get assignment for a share */
  getAssignmentByShare(shareId: string): Promise<ShareAssignment | null>;

  /** Store an audit entry */
  saveAuditEntry(entry: AuditEntry): Promise<void>;

  /** Get all audit entries */
  getAuditEntries(): Promise<AuditEntry[]>;

  /** Get the last audit entry */
  getLastAuditEntry(): Promise<AuditEntry | null>;
}

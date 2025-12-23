/**
 * ShareManager - Secure storage and access control for threshold key shares
 *
 * Provides:
 * - Encrypted storage of shares
 * - Role-based access control (RBAC)
 * - Audit logging with hash chain
 * - Share assignment to holders
 *
 * @example
 * ```typescript
 * // 1. Generate a key group
 * const keyGroup = await VeilKey.generate({
 *   threshold: 3,
 *   parties: 5,
 *   algorithm: 'RSA-2048'
 * });
 *
 * // 2. Create share manager
 * const manager = new ShareManager();
 * await manager.init();
 *
 * // 3. Store encrypted shares
 * await manager.storeShares(keyGroup, {
 *   password: 'secure-password',
 *   labels: ['Trustee 1', 'Trustee 2', ...],
 * });
 *
 * // 4. Create holders and assign shares
 * const alice = await manager.createHolder({
 *   name: 'Alice',
 *   role: 'trustee',
 *   contact: 'alice@example.com',
 * });
 *
 * await manager.assignShare(shareIds[0], alice.id);
 *
 * // 5. Retrieve a share (with password)
 * const { share } = await manager.getShare(
 *   shareIds[0],
 *   alice.id,
 *   { password: 'secure-password' }
 * );
 *
 * // 6. Use the share for threshold operations
 * const partial = await VeilKey.partialDecrypt(ciphertext, share, keyGroup);
 * ```
 */

import type { Share, KeyGroup } from '../veilkey.js';
import type {
  ShareManagerConfig,
  StoreSharesOptions,
  GetShareOptions,
  ShareRetrievalResult,
  EncryptedShare,
  ShareHolder,
  ShareAssignment,
  Role,
  AuditLog,
  StorageBackend,
  ShareMetadata,
} from './types.js';
import { encryptShare, decryptShare } from './crypto.js';
import { createStorage, MemoryStorage, FileStorage } from './storage.js';
import { AccessControl, DEFAULT_POLICIES, assertPermission, assertShareAccess } from './access-control.js';
import { AuditLogger, logShareCreated, logShareAccessed, logShareAssigned, logHolderCreated } from './audit.js';

// =============================================================================
// ShareManager Class
// =============================================================================

/**
 * Main class for managing threshold key shares
 */
export class ShareManager {
  private storage: StorageBackend;
  private accessControl: AccessControl;
  private auditLogger: AuditLogger;
  private config: ShareManagerConfig;
  private initialized: boolean = false;

  constructor(config: ShareManagerConfig = {}) {
    this.config = {
      storage: 'memory',
      enableAudit: true,
      kdf: 'pbkdf2',
      kdfIterations: 100000,
      policies: DEFAULT_POLICIES,
      ...config,
    };

    // Storage will be initialized in init()
    this.storage = new MemoryStorage();
    this.accessControl = new AccessControl(this.config.policies);
    this.auditLogger = new AuditLogger(this.storage, this.config.enableAudit);
  }

  /**
   * Initialize the share manager
   *
   * Must be called before using the manager.
   */
  async init(): Promise<void> {
    if (this.initialized) {
      return;
    }

    // Initialize storage
    this.storage = await createStorage(
      this.config.storage || 'memory',
      this.config.storagePath
    );

    // Re-create audit logger with initialized storage
    this.auditLogger = new AuditLogger(this.storage, this.config.enableAudit);

    this.initialized = true;
  }

  /**
   * Ensure manager is initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('ShareManager not initialized. Call init() first.');
    }
  }

  // ===========================================================================
  // Share Storage
  // ===========================================================================

  /**
   * Store encrypted shares from a key group
   *
   * @param keyGroup - Key group containing shares to store
   * @param options - Storage options (password, labels, etc.)
   * @returns Array of encrypted share IDs
   *
   * @example
   * ```typescript
   * const shareIds = await manager.storeShares(keyGroup, {
   *   password: 'secure-password',
   *   labels: ['Trustee 1', 'Trustee 2', 'Trustee 3'],
   *   tags: ['election-2024'],
   * });
   * ```
   */
  async storeShares(
    keyGroup: KeyGroup,
    options: StoreSharesOptions
  ): Promise<string[]> {
    this.ensureInitialized();

    const shareIds: string[] = [];

    for (let i = 0; i < keyGroup.shares.length; i++) {
      const share = keyGroup.shares[i]!;
      const label = options.labels?.[i] || `Share ${share.index}`;

      // Serialize share for encryption
      const shareData = JSON.stringify(share);

      // Encrypt share
      const encrypted = await encryptShare(
        shareData,
        options.password,
        options.kdfIterations || this.config.kdfIterations
      );

      // Create metadata
      const metadata: ShareMetadata = {
        label,
        ...(options.tags && { tags: options.tags }),
        algorithm: keyGroup.algorithm,
        threshold: keyGroup.threshold,
        parties: keyGroup.parties,
      };

      // Create encrypted share record
      const encryptedShare: EncryptedShare = {
        id: crypto.randomUUID(),
        index: share.index,
        keyGroupId: keyGroup.id,
        ciphertext: encrypted.ciphertext,
        salt: encrypted.salt,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        metadata,
        createdAt: new Date(),
      };

      // Store encrypted share
      await this.storage.saveShare(encryptedShare);
      shareIds.push(encryptedShare.id);

      // Log creation
      await logShareCreated(
        this.auditLogger,
        'system',
        encryptedShare.id,
        keyGroup.id
      );
    }

    return shareIds;
  }

  /**
   * Retrieve and decrypt a share
   *
   * Requires:
   * - Valid holder ID
   * - Correct password
   * - Holder has permission and assignment
   *
   * @param shareId - ID of the share to retrieve
   * @param holderId - ID of the holder requesting the share
   * @param options - Retrieval options (password)
   * @returns Decrypted share with metadata
   *
   * @example
   * ```typescript
   * const { share, metadata } = await manager.getShare(
   *   'share-123',
   *   'holder-456',
   *   { password: 'secure-password' }
   * );
   * ```
   */
  async getShare(
    shareId: string,
    holderId: string,
    options: GetShareOptions
  ): Promise<ShareRetrievalResult> {
    this.ensureInitialized();

    // Get holder
    const holder = await this.storage.getHolder(holderId);
    if (!holder) {
      throw new Error(`Holder not found: ${holderId}`);
    }

    // Get holder's assigned shares
    const assignments = await this.storage.getAssignmentsByHolder(holderId);
    const assignedShareIds = assignments
      .filter(a => a.active)
      .filter(a => !a.expiresAt || a.expiresAt > new Date())
      .map(a => a.shareId);

    // Check access permission
    assertShareAccess(this.accessControl, holder, shareId, assignedShareIds);

    // Get encrypted share
    const encryptedShare = await this.storage.getShare(shareId);
    if (!encryptedShare) {
      throw new Error(`Share not found: ${shareId}`);
    }

    // Decrypt share
    const decrypted = await decryptShare(
      {
        ciphertext: encryptedShare.ciphertext,
        salt: encryptedShare.salt,
        iv: encryptedShare.iv,
        authTag: encryptedShare.authTag,
      },
      options.password,
      this.config.kdfIterations
    );

    const share: Share = JSON.parse(decrypted);

    // Update last accessed timestamp
    encryptedShare.lastAccessedAt = new Date();
    await this.storage.saveShare(encryptedShare);

    // Log access
    if (!options.skipAudit) {
      await logShareAccessed(this.auditLogger, holder.name, shareId);
    }

    return {
      share,
      metadata: encryptedShare.metadata,
      createdAt: encryptedShare.createdAt,
    };
  }

  /**
   * List all encrypted shares
   *
   * @returns Array of encrypted shares (without decrypted data)
   */
  async listShares(): Promise<EncryptedShare[]> {
    this.ensureInitialized();
    return this.storage.listShares();
  }

  /**
   * Delete a share
   *
   * @param shareId - ID of the share to delete
   * @param holderId - ID of the holder requesting deletion
   * @returns true if deleted
   */
  async deleteShare(shareId: string, holderId: string): Promise<boolean> {
    this.ensureInitialized();

    // Get holder
    const holder = await this.storage.getHolder(holderId);
    if (!holder) {
      throw new Error(`Holder not found: ${holderId}`);
    }

    // Check permission
    assertPermission(this.accessControl, holder, 'share:delete', shareId);

    // Delete share
    const deleted = await this.storage.deleteShare(shareId);

    if (deleted) {
      await this.auditLogger.log('share.deleted', holder.name, shareId);
    }

    return deleted;
  }

  // ===========================================================================
  // Share Holders
  // ===========================================================================

  /**
   * Create a new share holder
   *
   * @param params - Holder parameters
   * @returns Created holder
   *
   * @example
   * ```typescript
   * const alice = await manager.createHolder({
   *   name: 'Alice',
   *   role: 'trustee',
   *   contact: 'alice@example.com',
   * });
   * ```
   */
  async createHolder(params: {
    name: string;
    role: Role;
    contact?: string;
  }): Promise<ShareHolder> {
    this.ensureInitialized();

    const holder: ShareHolder = {
      id: crypto.randomUUID(),
      name: params.name,
      role: params.role,
      ...(params.contact && { contact: params.contact }),
      createdAt: new Date(),
      active: true,
    };

    await this.storage.saveHolder(holder);

    await logHolderCreated(
      this.auditLogger,
      'system',
      holder.id,
      holder.name,
      holder.role
    );

    return holder;
  }

  /**
   * Get a holder by ID
   *
   * @param holderId - Holder ID
   * @returns Holder or null
   */
  async getHolder(holderId: string): Promise<ShareHolder | null> {
    this.ensureInitialized();
    return this.storage.getHolder(holderId);
  }

  /**
   * List all holders
   *
   * @returns Array of holders
   */
  async listHolders(): Promise<ShareHolder[]> {
    this.ensureInitialized();
    return this.storage.listHolders();
  }

  /**
   * Update a holder
   *
   * @param holderId - Holder ID
   * @param updates - Fields to update
   * @returns Updated holder
   */
  async updateHolder(
    holderId: string,
    updates: Partial<Omit<ShareHolder, 'id' | 'createdAt'>>
  ): Promise<ShareHolder> {
    this.ensureInitialized();

    const holder = await this.storage.getHolder(holderId);
    if (!holder) {
      throw new Error(`Holder not found: ${holderId}`);
    }

    const updated = { ...holder, ...updates };
    await this.storage.saveHolder(updated);

    await this.auditLogger.log('holder.updated', 'system', holderId, updates);

    return updated;
  }

  // ===========================================================================
  // Share Assignment
  // ===========================================================================

  /**
   * Assign a share to a holder
   *
   * @param shareId - Share ID
   * @param holderId - Holder ID
   * @param expiresAt - Optional expiration date
   * @returns Created assignment
   *
   * @example
   * ```typescript
   * await manager.assignShare('share-123', 'holder-456');
   * ```
   */
  async assignShare(
    shareId: string,
    holderId: string,
    expiresAt?: Date
  ): Promise<ShareAssignment> {
    this.ensureInitialized();

    // Verify share exists
    const share = await this.storage.getShare(shareId);
    if (!share) {
      throw new Error(`Share not found: ${shareId}`);
    }

    // Verify holder exists
    const holder = await this.storage.getHolder(holderId);
    if (!holder) {
      throw new Error(`Holder not found: ${holderId}`);
    }

    // Check if already assigned
    const existing = await this.storage.getAssignmentByShare(shareId);
    if (existing && existing.active) {
      throw new Error(`Share ${shareId} is already assigned to ${existing.holderId}`);
    }

    const assignment: ShareAssignment = {
      id: crypto.randomUUID(),
      shareId,
      holderId,
      assignedAt: new Date(),
      ...(expiresAt && { expiresAt }),
      active: true,
    };

    await this.storage.saveAssignment(assignment);

    await logShareAssigned(this.auditLogger, 'system', shareId, holderId);

    return assignment;
  }

  /**
   * Get assignments for a holder
   *
   * @param holderId - Holder ID
   * @returns Array of assignments
   */
  async getAssignmentsByHolder(holderId: string): Promise<ShareAssignment[]> {
    this.ensureInitialized();
    return this.storage.getAssignmentsByHolder(holderId);
  }

  /**
   * Unassign a share
   *
   * @param shareId - Share ID
   * @returns true if unassigned
   */
  async unassignShare(shareId: string): Promise<boolean> {
    this.ensureInitialized();

    const assignment = await this.storage.getAssignmentByShare(shareId);
    if (!assignment) {
      return false;
    }

    assignment.active = false;
    await this.storage.saveAssignment(assignment);

    return true;
  }

  // ===========================================================================
  // Audit Log
  // ===========================================================================

  /**
   * Get audit log
   *
   * @returns Audit log with all entries
   */
  async getAuditLog(): Promise<AuditLog> {
    this.ensureInitialized();
    return this.auditLogger.export();
  }

  /**
   * Verify audit log integrity
   *
   * @returns Verification result
   */
  async verifyAuditLog(): Promise<{
    valid: boolean;
    totalEntries: number;
    invalidEntries: number[];
    errors: string[];
  }> {
    this.ensureInitialized();
    return this.auditLogger.verify();
  }

  // ===========================================================================
  // Utility Methods
  // ===========================================================================

  /**
   * Close the share manager and flush any pending writes
   */
  async close(): Promise<void> {
    if (this.storage instanceof FileStorage) {
      await this.storage.close();
    }
  }

  /**
   * Get configuration
   */
  getConfig(): ShareManagerConfig {
    return { ...this.config };
  }
}

// =============================================================================
// Exports
// =============================================================================

export * from './types.js';
export { encryptShare, decryptShare } from './crypto.js';
export { MemoryStorage, FileStorage, createStorage } from './storage.js';
export { AccessControl, DEFAULT_POLICIES } from './access-control.js';
export { AuditLogger } from './audit.js';

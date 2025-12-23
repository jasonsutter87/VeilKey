/**
 * VeilKey Key Escrow System
 *
 * Implements secure key escrow functionality with M-of-N threshold
 * recovery, encrypted share distribution, and comprehensive audit trails.
 *
 * @module compliance/key-escrow
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/hashes/utils';
import {
  KeyEscrowConfig,
  EscrowAgent,
  EscrowedKey,
  EscrowedKeyShare,
  EscrowRecoveryRequest,
  EscrowApproval,
  ComplianceError,
  ComplianceErrorCode,
} from './types.js';

/**
 * Key Escrow Audit Entry
 */
interface EscrowAuditEntry {
  id: string;
  action: string;
  escrowedKeyId?: string;
  configId?: string;
  agentId?: string;
  userId?: string;
  details: Record<string, unknown>;
  timestamp: Date;
  hash: string;
  previousHash: string;
}

/**
 * Escrow Statistics
 */
export interface EscrowStatistics {
  totalConfigs: number;
  totalAgents: number;
  activeEscrowedKeys: number;
  recoveredKeys: number;
  expiredKeys: number;
  revokedKeys: number;
  pendingRecoveryRequests: number;
}

/**
 * Key Derivation Options
 */
interface KeyDerivationOptions {
  algorithm: 'PBKDF2' | 'Argon2id' | 'scrypt';
  salt: Uint8Array;
  iterations?: number;
  memory?: number;
  parallelism?: number;
}

/**
 * Key Escrow Manager
 *
 * Manages the complete lifecycle of escrowed keys including:
 * - Configuration of escrow policies
 * - Agent management
 * - Key escrow with threshold distribution
 * - Recovery request workflow
 * - Comprehensive audit logging
 */
export class KeyEscrowManager {
  private configs: Map<string, KeyEscrowConfig> = new Map();
  private agents: Map<string, EscrowAgent> = new Map();
  private escrowedKeys: Map<string, EscrowedKey> = new Map();
  private recoveryRequests: Map<string, EscrowRecoveryRequest> = new Map();
  private auditLog: EscrowAuditEntry[] = [];
  private lastAuditHash = '0'.repeat(64);

  /**
   * Create an escrow configuration
   */
  createConfig(config: KeyEscrowConfig): void {
    // Validate threshold
    if (config.threshold < 1) {
      throw new ComplianceError(
        'Threshold must be at least 1',
        ComplianceErrorCode.POLICY_VIOLATION
      );
    }

    if (config.threshold > config.escrowAgents.length) {
      throw new ComplianceError(
        'Threshold cannot exceed number of escrow agents',
        ComplianceErrorCode.THRESHOLD_NOT_MET
      );
    }

    // Store agents
    for (const agent of config.escrowAgents) {
      this.agents.set(agent.id, agent);
    }

    this.configs.set(config.id, config);
    this.recordAudit('config_created', undefined, config.id, undefined, undefined, { config });
  }

  /**
   * Get escrow configuration
   */
  getConfig(configId: string): KeyEscrowConfig | undefined {
    return this.configs.get(configId);
  }

  /**
   * Get all configurations
   */
  getAllConfigs(): KeyEscrowConfig[] {
    return Array.from(this.configs.values());
  }

  /**
   * Update escrow configuration
   */
  updateConfig(configId: string, updates: Partial<KeyEscrowConfig>): void {
    const config = this.configs.get(configId);
    if (!config) {
      throw new ComplianceError(
        `Escrow config ${configId} not found`,
        ComplianceErrorCode.ESCROW_NOT_FOUND
      );
    }

    const updatedConfig = { ...config, ...updates };

    // Re-validate threshold if agents or threshold changed
    if (updates.threshold || updates.escrowAgents) {
      if (updatedConfig.threshold > updatedConfig.escrowAgents.length) {
        throw new ComplianceError(
          'Threshold cannot exceed number of escrow agents',
          ComplianceErrorCode.THRESHOLD_NOT_MET
        );
      }
    }

    this.configs.set(configId, updatedConfig);
    this.recordAudit('config_updated', undefined, configId, undefined, undefined, { updates });
  }

  /**
   * Add an escrow agent
   */
  addAgent(agent: EscrowAgent): void {
    this.agents.set(agent.id, agent);
    this.recordAudit('agent_added', undefined, undefined, agent.id, undefined, { agent });
  }

  /**
   * Get escrow agent
   */
  getAgent(agentId: string): EscrowAgent | undefined {
    return this.agents.get(agentId);
  }

  /**
   * Get all agents
   */
  getAllAgents(): EscrowAgent[] {
    return Array.from(this.agents.values());
  }

  /**
   * Disable an escrow agent
   */
  disableAgent(agentId: string): void {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new ComplianceError(
        `Agent ${agentId} not found`,
        ComplianceErrorCode.ESCROW_NOT_FOUND
      );
    }

    agent.enabled = false;
    this.agents.set(agentId, agent);
    this.recordAudit('agent_disabled', undefined, undefined, agentId, undefined, {});
  }

  /**
   * Escrow a key using the specified configuration
   */
  escrowKey(
    keyId: string,
    keyType: EscrowedKey['keyType'],
    keyMaterial: Uint8Array,
    configId: string,
    expiresAt?: Date
  ): EscrowedKey {
    const config = this.configs.get(configId);
    if (!config) {
      throw new ComplianceError(
        `Escrow config ${configId} not found`,
        ComplianceErrorCode.ESCROW_NOT_FOUND
      );
    }

    if (!config.enabled) {
      throw new ComplianceError(
        'Escrow configuration is disabled',
        ComplianceErrorCode.POLICY_VIOLATION
      );
    }

    // Generate shares using Shamir-like distribution
    const shares = this.splitKeyForEscrow(
      keyMaterial,
      config.escrowAgents.length,
      config.threshold
    );

    // Encrypt each share for its respective agent
    const encryptedShares: EscrowedKeyShare[] = [];
    for (let i = 0; i < config.escrowAgents.length; i++) {
      const agent = config.escrowAgents[i];
      const encryptedShare = this.encryptShareForAgent(
        shares[i],
        agent,
        config.encryptionAlgorithm
      );

      encryptedShares.push({
        agentId: agent.id,
        encryptedShare,
        encryptedAt: new Date(),
        algorithm: config.encryptionAlgorithm,
      });
    }

    const escrowedKey: EscrowedKey = {
      id: bytesToHex(randomBytes(16)),
      keyId,
      keyType,
      escrowConfigId: configId,
      encryptedShares,
      createdAt: new Date(),
      expiresAt,
      status: 'active',
    };

    this.escrowedKeys.set(escrowedKey.id, escrowedKey);
    this.recordAudit('key_escrowed', escrowedKey.id, configId, undefined, undefined, {
      keyId,
      keyType,
      agentCount: config.escrowAgents.length,
      threshold: config.threshold,
    });

    return escrowedKey;
  }

  /**
   * Get escrowed key by ID
   */
  getEscrowedKey(escrowedKeyId: string): EscrowedKey | undefined {
    return this.escrowedKeys.get(escrowedKeyId);
  }

  /**
   * Get escrowed keys by original key ID
   */
  getEscrowedKeysByKeyId(keyId: string): EscrowedKey[] {
    return Array.from(this.escrowedKeys.values()).filter(k => k.keyId === keyId);
  }

  /**
   * Get all escrowed keys
   */
  getAllEscrowedKeys(filters?: {
    status?: EscrowedKey['status'];
    keyType?: EscrowedKey['keyType'];
    configId?: string;
  }): EscrowedKey[] {
    let keys = Array.from(this.escrowedKeys.values());

    if (filters) {
      if (filters.status) {
        keys = keys.filter(k => k.status === filters.status);
      }
      if (filters.keyType) {
        keys = keys.filter(k => k.keyType === filters.keyType);
      }
      if (filters.configId) {
        keys = keys.filter(k => k.escrowConfigId === filters.configId);
      }
    }

    return keys;
  }

  /**
   * Request key recovery
   */
  requestRecovery(
    escrowedKeyId: string,
    requestedBy: string,
    reason: string,
    expiresInHours = 24
  ): EscrowRecoveryRequest {
    const escrowedKey = this.escrowedKeys.get(escrowedKeyId);
    if (!escrowedKey) {
      throw new ComplianceError(
        `Escrowed key ${escrowedKeyId} not found`,
        ComplianceErrorCode.ESCROW_NOT_FOUND
      );
    }

    if (escrowedKey.status !== 'active') {
      throw new ComplianceError(
        `Escrowed key is not active (status: ${escrowedKey.status})`,
        ComplianceErrorCode.POLICY_VIOLATION
      );
    }

    const config = this.configs.get(escrowedKey.escrowConfigId);
    if (!config) {
      throw new ComplianceError(
        'Escrow configuration not found',
        ComplianceErrorCode.ESCROW_NOT_FOUND
      );
    }

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + expiresInHours);

    const request: EscrowRecoveryRequest = {
      id: bytesToHex(randomBytes(16)),
      escrowedKeyId,
      requestedBy,
      requestedAt: new Date(),
      reason,
      approvals: [],
      status: config.requiresApproval ? 'pending' : 'approved',
      expiresAt,
    };

    this.recoveryRequests.set(request.id, request);
    this.recordAudit('recovery_requested', escrowedKeyId, undefined, undefined, requestedBy, {
      reason,
      requiresApproval: config.requiresApproval,
    });

    return request;
  }

  /**
   * Approve a recovery request
   */
  approveRecovery(
    requestId: string,
    approverId: string,
    comment?: string
  ): EscrowRecoveryRequest {
    const request = this.recoveryRequests.get(requestId);
    if (!request) {
      throw new ComplianceError(
        `Recovery request ${requestId} not found`,
        ComplianceErrorCode.ESCROW_NOT_FOUND
      );
    }

    if (request.status !== 'pending') {
      throw new ComplianceError(
        'Recovery request is not pending',
        ComplianceErrorCode.POLICY_VIOLATION
      );
    }

    if (new Date() > request.expiresAt) {
      request.status = 'expired';
      this.recoveryRequests.set(requestId, request);
      throw new ComplianceError(
        'Recovery request has expired',
        ComplianceErrorCode.POLICY_VIOLATION
      );
    }

    // Check if approver is authorized
    const escrowedKey = this.escrowedKeys.get(request.escrowedKeyId);
    if (!escrowedKey) {
      throw new ComplianceError(
        'Escrowed key not found',
        ComplianceErrorCode.ESCROW_NOT_FOUND
      );
    }

    const config = this.configs.get(escrowedKey.escrowConfigId);
    if (!config) {
      throw new ComplianceError(
        'Escrow configuration not found',
        ComplianceErrorCode.ESCROW_NOT_FOUND
      );
    }

    if (config.approvers && !config.approvers.includes(approverId)) {
      throw new ComplianceError(
        'User is not authorized to approve recovery requests',
        ComplianceErrorCode.RECOVERY_NOT_APPROVED
      );
    }

    // Add approval
    const approval: EscrowApproval = {
      approverId,
      decision: 'approved',
      decidedAt: new Date(),
      comment,
    };

    request.approvals.push(approval);

    // Check if we have enough approvals (simple majority of approvers)
    const requiredApprovals = config.approvers
      ? Math.ceil(config.approvers.length / 2)
      : 1;

    const currentApprovals = request.approvals.filter(a => a.decision === 'approved').length;

    if (currentApprovals >= requiredApprovals) {
      request.status = 'approved';
    }

    this.recoveryRequests.set(requestId, request);
    this.recordAudit('recovery_approved', request.escrowedKeyId, undefined, undefined, approverId, {
      requestId,
      currentApprovals,
      requiredApprovals,
      status: request.status,
    });

    return request;
  }

  /**
   * Reject a recovery request
   */
  rejectRecovery(
    requestId: string,
    rejecterId: string,
    comment?: string
  ): EscrowRecoveryRequest {
    const request = this.recoveryRequests.get(requestId);
    if (!request) {
      throw new ComplianceError(
        `Recovery request ${requestId} not found`,
        ComplianceErrorCode.ESCROW_NOT_FOUND
      );
    }

    if (request.status !== 'pending') {
      throw new ComplianceError(
        'Recovery request is not pending',
        ComplianceErrorCode.POLICY_VIOLATION
      );
    }

    const approval: EscrowApproval = {
      approverId: rejecterId,
      decision: 'rejected',
      decidedAt: new Date(),
      comment,
    };

    request.approvals.push(approval);
    request.status = 'rejected';

    this.recoveryRequests.set(requestId, request);
    this.recordAudit('recovery_rejected', request.escrowedKeyId, undefined, undefined, rejecterId, {
      requestId,
      comment,
    });

    return request;
  }

  /**
   * Complete key recovery
   */
  completeRecovery(
    requestId: string,
    agentDecryptedShares: Map<string, Uint8Array>,
    recoveredBy: string
  ): Uint8Array {
    const request = this.recoveryRequests.get(requestId);
    if (!request) {
      throw new ComplianceError(
        `Recovery request ${requestId} not found`,
        ComplianceErrorCode.ESCROW_NOT_FOUND
      );
    }

    if (request.status !== 'approved') {
      throw new ComplianceError(
        'Recovery request is not approved',
        ComplianceErrorCode.RECOVERY_NOT_APPROVED
      );
    }

    const escrowedKey = this.escrowedKeys.get(request.escrowedKeyId);
    if (!escrowedKey) {
      throw new ComplianceError(
        'Escrowed key not found',
        ComplianceErrorCode.ESCROW_NOT_FOUND
      );
    }

    const config = this.configs.get(escrowedKey.escrowConfigId);
    if (!config) {
      throw new ComplianceError(
        'Escrow configuration not found',
        ComplianceErrorCode.ESCROW_NOT_FOUND
      );
    }

    // Verify we have enough shares
    if (agentDecryptedShares.size < config.threshold) {
      throw new ComplianceError(
        `Not enough shares provided (need ${config.threshold}, got ${agentDecryptedShares.size})`,
        ComplianceErrorCode.THRESHOLD_NOT_MET
      );
    }

    // Combine shares to recover the key
    const shares: Uint8Array[] = [];
    const shareIndexes: number[] = [];

    for (const [agentId, share] of agentDecryptedShares) {
      const agentIndex = escrowedKey.encryptedShares.findIndex(s => s.agentId === agentId);
      if (agentIndex !== -1) {
        shares.push(share);
        shareIndexes.push(agentIndex);
      }
    }

    const recoveredKey = this.combineSharesForRecovery(shares, shareIndexes, config.threshold);

    // Update escrowed key status
    escrowedKey.status = 'recovered';
    escrowedKey.recoveredAt = new Date();
    escrowedKey.recoveredBy = recoveredBy;
    this.escrowedKeys.set(escrowedKey.id, escrowedKey);

    // Update request status
    request.status = 'completed';
    this.recoveryRequests.set(requestId, request);

    this.recordAudit('recovery_completed', escrowedKey.id, undefined, undefined, recoveredBy, {
      requestId,
      sharesUsed: shares.length,
    });

    return recoveredKey;
  }

  /**
   * Revoke an escrowed key
   */
  revokeEscrowedKey(escrowedKeyId: string, revokedBy: string, reason: string): void {
    const escrowedKey = this.escrowedKeys.get(escrowedKeyId);
    if (!escrowedKey) {
      throw new ComplianceError(
        `Escrowed key ${escrowedKeyId} not found`,
        ComplianceErrorCode.ESCROW_NOT_FOUND
      );
    }

    escrowedKey.status = 'revoked';
    this.escrowedKeys.set(escrowedKeyId, escrowedKey);

    this.recordAudit('key_revoked', escrowedKeyId, undefined, undefined, revokedBy, { reason });
  }

  /**
   * Check and expire old keys
   */
  processExpirations(): number {
    let expiredCount = 0;
    const now = new Date();

    for (const [id, key] of this.escrowedKeys) {
      if (key.status === 'active' && key.expiresAt && key.expiresAt < now) {
        key.status = 'expired';
        this.escrowedKeys.set(id, key);
        expiredCount++;
        this.recordAudit('key_expired', id, undefined, undefined, undefined, {});
      }
    }

    // Also expire pending recovery requests
    for (const [id, request] of this.recoveryRequests) {
      if (request.status === 'pending' && request.expiresAt < now) {
        request.status = 'expired';
        this.recoveryRequests.set(id, request);
      }
    }

    return expiredCount;
  }

  /**
   * Get recovery requests
   */
  getRecoveryRequests(filters?: {
    status?: EscrowRecoveryRequest['status'];
    escrowedKeyId?: string;
  }): EscrowRecoveryRequest[] {
    let requests = Array.from(this.recoveryRequests.values());

    if (filters) {
      if (filters.status) {
        requests = requests.filter(r => r.status === filters.status);
      }
      if (filters.escrowedKeyId) {
        requests = requests.filter(r => r.escrowedKeyId === filters.escrowedKeyId);
      }
    }

    return requests;
  }

  /**
   * Get escrow statistics
   */
  getStatistics(): EscrowStatistics {
    const keys = Array.from(this.escrowedKeys.values());
    const requests = Array.from(this.recoveryRequests.values());

    return {
      totalConfigs: this.configs.size,
      totalAgents: this.agents.size,
      activeEscrowedKeys: keys.filter(k => k.status === 'active').length,
      recoveredKeys: keys.filter(k => k.status === 'recovered').length,
      expiredKeys: keys.filter(k => k.status === 'expired').length,
      revokedKeys: keys.filter(k => k.status === 'revoked').length,
      pendingRecoveryRequests: requests.filter(r => r.status === 'pending').length,
    };
  }

  /**
   * Get audit log
   */
  getAuditLog(limit = 100): EscrowAuditEntry[] {
    return this.auditLog.slice(-limit);
  }

  /**
   * Verify audit log integrity
   */
  verifyAuditIntegrity(): { valid: boolean; invalidEntryIds: string[] } {
    const invalidEntryIds: string[] = [];
    let previousHash = '0'.repeat(64);

    for (const entry of this.auditLog) {
      if (entry.previousHash !== previousHash) {
        invalidEntryIds.push(entry.id);
      }

      const hashData = JSON.stringify({ ...entry, hash: undefined });
      const expectedHash = bytesToHex(sha256(new TextEncoder().encode(hashData)));

      if (entry.hash !== expectedHash) {
        invalidEntryIds.push(entry.id);
      }

      previousHash = entry.hash;
    }

    return {
      valid: invalidEntryIds.length === 0,
      invalidEntryIds,
    };
  }

  /**
   * Split key material into shares for escrow
   * Uses a simplified threshold scheme for demonstration
   */
  private splitKeyForEscrow(
    keyMaterial: Uint8Array,
    totalShares: number,
    threshold: number
  ): Uint8Array[] {
    const shares: Uint8Array[] = [];

    // Generate random coefficients for polynomial
    const coefficients: Uint8Array[] = [keyMaterial];
    for (let i = 1; i < threshold; i++) {
      coefficients.push(randomBytes(keyMaterial.length));
    }

    // Generate shares by evaluating polynomial at different points
    for (let x = 1; x <= totalShares; x++) {
      const share = new Uint8Array(keyMaterial.length + 1);
      share[0] = x; // Store the x-coordinate

      // Evaluate polynomial at x
      for (let byteIdx = 0; byteIdx < keyMaterial.length; byteIdx++) {
        let value = 0;
        let xPower = 1;

        for (let coeffIdx = 0; coeffIdx < coefficients.length; coeffIdx++) {
          value = (value + (coefficients[coeffIdx][byteIdx] * xPower) % 256) % 256;
          xPower = (xPower * x) % 256;
        }

        share[byteIdx + 1] = value;
      }

      shares.push(share);
    }

    return shares;
  }

  /**
   * Combine shares to recover key material
   */
  private combineSharesForRecovery(
    shares: Uint8Array[],
    _shareIndexes: number[],
    threshold: number
  ): Uint8Array {
    if (shares.length < threshold) {
      throw new ComplianceError(
        `Need at least ${threshold} shares`,
        ComplianceErrorCode.THRESHOLD_NOT_MET
      );
    }

    const shareLength = shares[0].length - 1;
    const result = new Uint8Array(shareLength);

    // Lagrange interpolation to recover secret
    const usedShares = shares.slice(0, threshold);
    const xValues = usedShares.map(s => s[0]);

    for (let byteIdx = 0; byteIdx < shareLength; byteIdx++) {
      let value = 0;

      for (let i = 0; i < threshold; i++) {
        const xi = xValues[i];
        const yi = usedShares[i][byteIdx + 1];

        // Calculate Lagrange basis polynomial
        let numerator = 1;
        let denominator = 1;

        for (let j = 0; j < threshold; j++) {
          if (i !== j) {
            const xj = xValues[j];
            numerator = (numerator * (256 - xj)) % 256;
            denominator = (denominator * ((xi - xj + 256) % 256)) % 256;
          }
        }

        // Modular inverse approximation for GF(256)
        const inverseDenom = this.modInverse(denominator, 256);
        const lagrangeCoeff = (numerator * inverseDenom) % 256;
        value = (value + (yi * lagrangeCoeff) % 256) % 256;
      }

      result[byteIdx] = value;
    }

    return result;
  }

  /**
   * Calculate modular multiplicative inverse
   */
  private modInverse(a: number, m: number): number {
    let [old_r, r] = [a, m];
    let [old_s, s] = [1, 0];

    while (r !== 0) {
      const quotient = Math.floor(old_r / r);
      [old_r, r] = [r, old_r - quotient * r];
      [old_s, s] = [s, old_s - quotient * s];
    }

    return ((old_s % m) + m) % m;
  }

  /**
   * Encrypt a share for a specific agent using their public key
   */
  private encryptShareForAgent(
    share: Uint8Array,
    agent: EscrowAgent,
    _algorithm: 'AES-256-GCM' | 'ChaCha20-Poly1305'
  ): string {
    // In production, this would use the agent's actual public key
    // For now, we derive an encryption key from the agent's public key
    const keyMaterial = sha256(new TextEncoder().encode(agent.publicKey));
    const nonce = randomBytes(12);

    const cipher = gcm(keyMaterial, nonce);
    const encrypted = cipher.encrypt(share);

    // Combine nonce and ciphertext
    const combined = new Uint8Array(nonce.length + encrypted.length);
    combined.set(nonce);
    combined.set(encrypted, nonce.length);

    return bytesToHex(combined);
  }

  /**
   * Record an audit entry
   */
  private recordAudit(
    action: string,
    escrowedKeyId?: string,
    configId?: string,
    agentId?: string,
    userId?: string,
    details: Record<string, unknown> = {}
  ): void {
    const entry: EscrowAuditEntry = {
      id: bytesToHex(randomBytes(16)),
      action,
      escrowedKeyId,
      configId,
      agentId,
      userId,
      details,
      timestamp: new Date(),
      hash: '',
      previousHash: this.lastAuditHash,
    };

    const hashData = JSON.stringify({ ...entry, hash: undefined });
    entry.hash = bytesToHex(sha256(new TextEncoder().encode(hashData)));

    this.auditLog.push(entry);
    this.lastAuditHash = entry.hash;
  }
}

/**
 * Create a default escrow agent
 */
export function createEscrowAgent(
  id: string,
  name: string,
  type: EscrowAgent['type'],
  publicKey: string,
  options?: Partial<EscrowAgent>
): EscrowAgent {
  return {
    id,
    name,
    type,
    publicKey,
    enabled: true,
    ...options,
  };
}

/**
 * Create a default escrow configuration
 */
export function createEscrowConfig(
  id: string,
  name: string,
  agents: EscrowAgent[],
  threshold: number,
  options?: Partial<KeyEscrowConfig>
): KeyEscrowConfig {
  return {
    id,
    name,
    escrowAgents: agents,
    threshold,
    encryptionAlgorithm: 'AES-256-GCM',
    keyDerivation: 'PBKDF2',
    rotationPeriodDays: 365,
    requiresApproval: true,
    enabled: true,
    ...options,
  };
}

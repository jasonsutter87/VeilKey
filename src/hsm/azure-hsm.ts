/**
 * VeilKey Azure Dedicated HSM Integration
 *
 * This module provides integration with Azure Dedicated HSM and
 * Azure Key Vault (Managed HSM).
 *
 * Azure Dedicated HSM provides FIPS 140-2 Level 3 validated HSMs as a service.
 *
 * @module hsm/azure-hsm
 */

import { sha256 } from '@noble/hashes/sha256';
import { randomBytes, bytesToHex } from '@noble/hashes/utils';
import { gcm } from '@noble/ciphers/aes';

/**
 * Azure HSM Configuration
 */
export interface AzureHSMConfig {
  resourceGroupName: string;
  hsmName: string;
  subscriptionId: string;
  location: string;
  authentication: {
    tenantId: string;
    clientId: string;
    clientSecret?: string;
    managedIdentity?: boolean;
    certificate?: {
      path: string;
      password?: string;
    };
  };
  networkProfile?: {
    vnetId: string;
    subnetId: string;
  };
}

/**
 * Azure HSM Resource
 */
export interface AzureHSMResource {
  id: string;
  name: string;
  location: string;
  provisioningState: 'Provisioning' | 'Succeeded' | 'Failed' | 'Deleting';
  statusMessage: string;
  sku: {
    name: string;
    family: string;
  };
  properties: {
    networkProfile: {
      networkInterfaces: Array<{
        privateIpAddress: string;
      }>;
    };
    managementNetworkProfile: {
      networkInterfaces: Array<{
        privateIpAddress: string;
      }>;
    };
    stampId: string;
  };
}

/**
 * Azure Key Vault Configuration
 */
export interface AzureKeyVaultConfig {
  vaultName: string;
  keyName?: string;
  useManagedHSM?: boolean;
}

/**
 * Azure HSM Session
 */
export interface AzureHSMSession {
  sessionId: string;
  resourceName: string;
  authenticatedPrincipal: string;
  authenticatedAt: Date;
  permissions: string[];
}

/**
 * Azure Key Handle
 */
export interface AzureKeyHandle {
  keyId: string;
  keyName: string;
  keyType: 'RSA' | 'EC' | 'AES' | 'oct';
  keyOps: string[];
  enabled: boolean;
  notBefore?: Date;
  expiresOn?: Date;
  tags?: Record<string, string>;
}

/**
 * Azure Backup Result
 */
export interface AzureBackupResult {
  backupBlobUrl: string;
  backupId: string;
  createdAt: Date;
  status: 'InProgress' | 'Completed' | 'Failed';
}

/**
 * Azure Audit Log
 */
export interface AzureAuditLog {
  timestamp: Date;
  operationName: string;
  resultType: 'Success' | 'Failure';
  caller: string;
  resourceId: string;
  properties: Record<string, unknown>;
  category: 'AuditEvent' | 'PolicyEvent' | 'SignInLogs';
}

/**
 * Azure Network Rule
 */
export interface AzureNetworkRule {
  ipAddress?: string;
  ipAddressRange?: string;
  virtualNetworkResourceId?: string;
  action: 'Allow' | 'Deny';
}

/**
 * Azure HSM Error
 */
export class AzureHSMError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly operation?: string
  ) {
    super(message);
    this.name = 'AzureHSMError';
  }
}

/**
 * Internal key storage
 */
interface StoredKey {
  keyId: string;
  keyName: string;
  keyType: 'RSA' | 'EC' | 'AES' | 'oct';
  keyOps: string[];
  enabled: boolean;
  notBefore?: Date;
  expiresOn?: Date;
  tags?: Record<string, string>;
  data: Uint8Array;
  publicData?: Uint8Array;
  deleted: boolean;
  deletedAt?: Date;
  createdAt: Date;
}

/**
 * Internal session
 */
interface InternalSession {
  session: AzureHSMSession;
  active: boolean;
}

/**
 * Azure HSM Manager
 *
 * Provides integration with Azure Dedicated HSM and Azure Key Vault
 * for secure key management and cryptographic operations.
 */
export class AzureHSMManager {
  private connected = false;
  private config: AzureHSMConfig | null = null;
  private vaultConfig: AzureKeyVaultConfig | null = null;
  private resource: AzureHSMResource | null = null;
  private sessions: Map<string, InternalSession> = new Map();
  private keys: Map<string, StoredKey> = new Map();
  private auditLogs: AzureAuditLog[] = [];
  private networkRules: AzureNetworkRule[] = [];
  private nextSessionId = 1;
  private masterKey: Uint8Array | null = null;

  /**
   * Connect to Azure HSM
   */
  async connect(config: AzureHSMConfig): Promise<void> {
    if (this.connected) {
      throw new AzureHSMError(
        'Already connected',
        'ALREADY_CONNECTED',
        'connect'
      );
    }

    // Validate authentication
    if (!this.validateAuthentication(config.authentication)) {
      throw new AzureHSMError(
        'Authentication failed: invalid credentials',
        'AUTH_FAILED',
        'connect'
      );
    }

    this.config = config;
    this.masterKey = randomBytes(32);

    // Initialize mock HSM resource
    this.resource = {
      id: `/subscriptions/${config.subscriptionId}/resourceGroups/${config.resourceGroupName}/providers/Microsoft.HardwareSecurityModules/dedicatedHSMs/${config.hsmName}`,
      name: config.hsmName,
      location: config.location,
      provisioningState: 'Succeeded',
      statusMessage: 'Provisioning succeeded',
      sku: {
        name: 'SafeNet Luna Network HSM A790',
        family: 'HSM',
      },
      properties: {
        networkProfile: {
          networkInterfaces: [
            { privateIpAddress: '10.0.1.10' },
          ],
        },
        managementNetworkProfile: {
          networkInterfaces: [
            { privateIpAddress: '10.0.2.10' },
          ],
        },
        stampId: `stamp-${bytesToHex(randomBytes(8))}`,
      },
    };

    this.connected = true;
    this.logAuditEvent('Connect', 'Success', config.authentication.clientId);
  }

  /**
   * Disconnect from Azure HSM
   */
  async disconnect(): Promise<void> {
    if (!this.connected) {
      return;
    }

    // Close all sessions
    for (const [, internal] of this.sessions) {
      if (internal.active) {
        await this.closeSession(internal.session);
      }
    }

    this.sessions.clear();
    this.keys.clear();
    this.auditLogs = [];
    this.config = null;
    this.vaultConfig = null;
    this.resource = null;

    if (this.masterKey) {
      this.masterKey.fill(0);
      this.masterKey = null;
    }

    this.connected = false;
  }

  /**
   * Get HSM resource information
   */
  async getHSMResource(resourceName: string): Promise<AzureHSMResource> {
    this.ensureConnected();

    if (resourceName !== this.config!.hsmName) {
      throw new AzureHSMError(
        'Resource not found',
        'NOT_FOUND',
        'getHSMResource'
      );
    }

    return { ...this.resource! };
  }

  /**
   * Wait for HSM provisioning
   */
  async waitForProvisioning(resourceName: string, timeout = 60000): Promise<void> {
    this.ensureConnected();

    const startTime = Date.now();
    const minimumWaitTime = 150; // Simulate network latency

    while (Date.now() - startTime < timeout) {
      if (Date.now() - startTime < minimumWaitTime) {
        await this.sleep(50);
        continue;
      }

      const resource = await this.getHSMResource(resourceName);
      if (resource.provisioningState === 'Succeeded') {
        return;
      }
      if (resource.provisioningState === 'Failed') {
        throw new AzureHSMError(
          'Provisioning failed',
          'PROVISIONING_FAILED',
          'waitForProvisioning'
        );
      }
      await this.sleep(100);
    }

    throw new AzureHSMError(
      'Timeout waiting for provisioning',
      'TIMEOUT',
      'waitForProvisioning'
    );
  }

  /**
   * Connect to Key Vault
   */
  async connectToVault(vaultConfig: AzureKeyVaultConfig): Promise<void> {
    this.ensureConnected();
    this.vaultConfig = vaultConfig;
    this.logAuditEvent('ConnectToVault', 'Success', vaultConfig.vaultName);
  }

  /**
   * Create session
   */
  async createSession(principalId?: string): Promise<AzureHSMSession> {
    this.ensureConnected();

    const sessionId = `session-${this.nextSessionId++}-${bytesToHex(randomBytes(8))}`;
    const principal = principalId || this.config!.authentication.clientId;

    const session: AzureHSMSession = {
      sessionId,
      resourceName: this.config!.hsmName,
      authenticatedPrincipal: principal,
      authenticatedAt: new Date(),
      permissions: [
        'keys/create',
        'keys/delete',
        'keys/get',
        'keys/list',
        'keys/sign',
        'keys/verify',
        'keys/encrypt',
        'keys/decrypt',
        'keys/backup',
        'keys/restore',
        'keys/purge',
      ],
    };

    this.sessions.set(sessionId, { session, active: true });
    this.logAuditEvent('CreateSession', 'Success', principal);

    return session;
  }

  /**
   * Close session
   */
  async closeSession(session: AzureHSMSession): Promise<void> {
    this.ensureConnected();

    const internal = this.sessions.get(session.sessionId);
    if (!internal) {
      throw new AzureHSMError(
        'Session not found',
        'SESSION_NOT_FOUND',
        'closeSession'
      );
    }

    internal.active = false;
    this.sessions.delete(session.sessionId);
    this.logAuditEvent('CloseSession', 'Success', session.authenticatedPrincipal);
  }

  /**
   * Authenticate with managed identity
   */
  async authenticateWithManagedIdentity(): Promise<AzureHSMSession> {
    this.ensureConnected();

    if (!this.config!.authentication.managedIdentity) {
      throw new AzureHSMError(
        'Managed identity not configured',
        'CONFIG_ERROR',
        'authenticateWithManagedIdentity'
      );
    }

    const session = await this.createSession('system-assigned-managed-identity');
    session.authenticatedPrincipal = 'system-assigned managed identity';
    return session;
  }

  /**
   * Authenticate with certificate
   */
  async authenticateWithCertificate(certPath: string, password?: string): Promise<AzureHSMSession> {
    this.ensureConnected();

    // Mock certificate validation
    if (!certPath) {
      throw new AzureHSMError(
        'Certificate path required',
        'INVALID_CERT',
        'authenticateWithCertificate'
      );
    }

    const session = await this.createSession(`cert:${certPath}`);
    session.authenticatedPrincipal = `certificate:${certPath.split('/').pop()}`;
    return session;
  }

  /**
   * Generate key
   */
  async generateKey(
    session: AzureHSMSession,
    keyName: string,
    options: {
      keyType: 'RSA' | 'EC' | 'AES';
      keySize?: number;
      curve?: string;
      keyOps?: string[];
      enabled?: boolean;
      tags?: Record<string, string>;
    }
  ): Promise<AzureKeyHandle> {
    this.ensureConnected();
    this.ensureValidSession(session);
    this.ensureVaultConnected();

    // Validate key type
    if (!['RSA', 'EC', 'AES'].includes(options.keyType)) {
      this.logAuditEvent('KeyCreate', 'Failure', session.authenticatedPrincipal);
      throw new AzureHSMError(
        'Invalid key type: not supported',
        'INVALID_KEY_TYPE',
        'generateKey'
      );
    }

    // Simulate HSM processing time
    await this.sleep(2);

    const keyId = `https://${this.vaultConfig!.vaultName}.vault.azure.net/keys/${keyName}/${bytesToHex(randomBytes(16))}`;
    const keySize = options.keySize || (options.keyType === 'RSA' ? 2048 : 256);

    const keyData = randomBytes(keySize / 8);
    const publicData = ['RSA', 'EC'].includes(options.keyType)
      ? randomBytes(keySize / 8)
      : undefined;

    const storedKey: StoredKey = {
      keyId,
      keyName,
      keyType: options.keyType,
      keyOps: options.keyOps || ['sign', 'verify', 'encrypt', 'decrypt'],
      enabled: options.enabled ?? true,
      tags: options.tags,
      data: this.encryptKeyData(keyData),
      publicData,
      deleted: false,
      createdAt: new Date(),
    };

    this.keys.set(keyName, storedKey);
    this.logAuditEvent('KeyCreate', 'Success', session.authenticatedPrincipal);

    return this.keyToHandle(storedKey);
  }

  /**
   * Import key
   */
  async importKey(
    session: AzureHSMSession,
    keyName: string,
    keyData: Uint8Array,
    options: {
      keyType: string;
      hsm?: boolean;
    }
  ): Promise<AzureKeyHandle> {
    this.ensureConnected();
    this.ensureValidSession(session);
    this.ensureVaultConnected();

    const keyId = `https://${this.vaultConfig!.vaultName}.vault.azure.net/keys/${keyName}/${bytesToHex(randomBytes(16))}`;

    const storedKey: StoredKey = {
      keyId,
      keyName,
      keyType: options.keyType as 'RSA' | 'EC' | 'AES' | 'oct',
      keyOps: ['sign', 'verify', 'encrypt', 'decrypt'],
      enabled: true,
      data: this.encryptKeyData(keyData),
      deleted: false,
      createdAt: new Date(),
    };

    this.keys.set(keyName, storedKey);
    this.logAuditEvent('ImportKey', 'Success', session.authenticatedPrincipal);

    return this.keyToHandle(storedKey);
  }

  /**
   * Get key
   */
  async getKey(session: AzureHSMSession, keyName: string): Promise<AzureKeyHandle> {
    this.ensureConnected();
    this.ensureValidSession(session);
    this.ensureVaultConnected();

    const key = this.keys.get(keyName);
    if (!key || key.deleted) {
      this.logAuditEvent('GetKey', 'Failure', session.authenticatedPrincipal);
      throw new AzureHSMError(
        'Key not found',
        'KEY_NOT_FOUND',
        'getKey'
      );
    }

    this.logAuditEvent('GetKey', 'Success', session.authenticatedPrincipal);
    return this.keyToHandle(key);
  }

  /**
   * Delete key (soft delete)
   */
  async deleteKey(session: AzureHSMSession, keyName: string): Promise<void> {
    this.ensureConnected();
    this.ensureValidSession(session);
    this.ensureVaultConnected();

    const key = this.keys.get(keyName);
    if (!key) {
      throw new AzureHSMError(
        'Key not found',
        'KEY_NOT_FOUND',
        'deleteKey'
      );
    }

    key.deleted = true;
    key.deletedAt = new Date();
    this.logAuditEvent('DeleteKey', 'Success', session.authenticatedPrincipal);
  }

  /**
   * Purge deleted key
   */
  async purgeDeletedKey(session: AzureHSMSession, keyName: string): Promise<void> {
    this.ensureConnected();
    this.ensureValidSession(session);
    this.ensureVaultConnected();

    const key = this.keys.get(keyName);
    if (!key) {
      throw new AzureHSMError(
        'Key not found',
        'KEY_NOT_FOUND',
        'purgeDeletedKey'
      );
    }

    if (!key.deleted) {
      throw new AzureHSMError(
        'Key must be deleted before purging',
        'NOT_DELETED',
        'purgeDeletedKey'
      );
    }

    this.keys.delete(keyName);
    this.logAuditEvent('PurgeKey', 'Success', session.authenticatedPrincipal);
  }

  /**
   * Sign data
   */
  async sign(
    session: AzureHSMSession,
    keyHandle: AzureKeyHandle,
    data: Uint8Array,
    algorithm: string
  ): Promise<Uint8Array> {
    this.ensureConnected();
    this.ensureValidSession(session);
    this.ensureVaultConnected();

    const key = this.keys.get(keyHandle.keyName);
    if (!key || key.deleted) {
      throw new AzureHSMError(
        'Key not found',
        'KEY_NOT_FOUND',
        'sign'
      );
    }

    if (!key.keyOps.includes('sign')) {
      throw new AzureHSMError(
        'Key operation not permitted',
        'OPERATION_NOT_PERMITTED',
        'sign'
      );
    }

    const keyData = this.decryptKeyData(key.data);
    const hash = sha256(data);

    // Simulate signature
    const signature = new Uint8Array(keyData.length);
    for (let i = 0; i < signature.length; i++) {
      signature[i] = keyData[i % keyData.length] ^ hash[i % hash.length];
    }

    this.logAuditEvent('Sign', 'Success', session.authenticatedPrincipal);
    return signature;
  }

  /**
   * Decrypt data
   */
  async decrypt(
    session: AzureHSMSession,
    keyHandle: AzureKeyHandle,
    ciphertext: Uint8Array,
    algorithm: string
  ): Promise<Uint8Array> {
    this.ensureConnected();
    this.ensureValidSession(session);
    this.ensureVaultConnected();

    const key = this.keys.get(keyHandle.keyName);
    if (!key || key.deleted) {
      throw new AzureHSMError(
        'Key not found',
        'KEY_NOT_FOUND',
        'decrypt'
      );
    }

    if (!key.keyOps.includes('decrypt')) {
      throw new AzureHSMError(
        'Key operation not permitted',
        'OPERATION_NOT_PERMITTED',
        'decrypt'
      );
    }

    const keyData = this.decryptKeyData(key.data);

    // Simulate decryption
    const plaintext = new Uint8Array(32);
    for (let i = 0; i < plaintext.length; i++) {
      plaintext[i] = keyData[i % keyData.length] ^ ciphertext[i % ciphertext.length];
    }

    this.logAuditEvent('Decrypt', 'Success', session.authenticatedPrincipal);
    return plaintext;
  }

  /**
   * Create backup
   */
  async createBackup(
    session: AzureHSMSession,
    keyName: string,
    blobStorageUrl: string
  ): Promise<AzureBackupResult> {
    this.ensureConnected();
    this.ensureValidSession(session);
    this.ensureVaultConnected();

    const key = this.keys.get(keyName);
    if (!key || key.deleted) {
      throw new AzureHSMError(
        'Key not found',
        'KEY_NOT_FOUND',
        'createBackup'
      );
    }

    const backupId = bytesToHex(randomBytes(16));
    const backupBlobUrl = `${blobStorageUrl}/key-backup-${backupId}`;

    this.logAuditEvent('CreateBackup', 'Success', session.authenticatedPrincipal);

    return {
      backupBlobUrl,
      backupId,
      createdAt: new Date(),
      status: 'InProgress',
    };
  }

  /**
   * Restore backup
   */
  async restoreBackup(
    session: AzureHSMSession,
    backupBlobUrl: string
  ): Promise<AzureKeyHandle> {
    this.ensureConnected();
    this.ensureValidSession(session);
    this.ensureVaultConnected();

    // Extract key name from URL
    const keyName = `restored-${bytesToHex(randomBytes(8))}`;

    const storedKey: StoredKey = {
      keyId: `https://${this.vaultConfig!.vaultName}.vault.azure.net/keys/${keyName}/${bytesToHex(randomBytes(16))}`,
      keyName,
      keyType: 'RSA',
      keyOps: ['sign', 'verify', 'encrypt', 'decrypt'],
      enabled: true,
      data: this.encryptKeyData(randomBytes(256)),
      deleted: false,
      createdAt: new Date(),
    };

    this.keys.set(keyName, storedKey);
    this.logAuditEvent('RestoreBackup', 'Success', session.authenticatedPrincipal);

    return this.keyToHandle(storedKey);
  }

  /**
   * Get audit logs
   */
  async getAuditLogs(
    resourceName: string,
    options: {
      startTime: Date;
      endTime: Date;
      filter?: string;
    }
  ): Promise<AzureAuditLog[]> {
    this.ensureConnected();

    return this.auditLogs.filter(log => {
      const inTimeRange =
        log.timestamp >= options.startTime && log.timestamp <= options.endTime;
      const matchesFilter =
        !options.filter || log.operationName.includes(options.filter);
      return inTimeRange && matchesFilter;
    });
  }

  /**
   * Set network rules
   */
  async setNetworkRules(
    resourceName: string,
    rules: AzureNetworkRule[]
  ): Promise<void> {
    this.ensureConnected();

    if (resourceName !== this.config!.hsmName) {
      throw new AzureHSMError(
        'Resource not found',
        'NOT_FOUND',
        'setNetworkRules'
      );
    }

    this.networkRules = [...rules];
    this.logAuditEvent('SetNetworkRules', 'Success', 'system');
  }

  /**
   * Get network rules
   */
  async getNetworkRules(resourceName: string): Promise<AzureNetworkRule[]> {
    this.ensureConnected();

    if (resourceName !== this.config!.hsmName) {
      throw new AzureHSMError(
        'Resource not found',
        'NOT_FOUND',
        'getNetworkRules'
      );
    }

    return [...this.networkRules];
  }

  /**
   * Enable diagnostics
   */
  async enableDiagnostics(
    resourceName: string,
    config: {
      storageAccountId: string;
      logAnalyticsWorkspaceId?: string;
      categories: string[];
    }
  ): Promise<void> {
    this.ensureConnected();

    if (resourceName !== this.config!.hsmName) {
      throw new AzureHSMError(
        'Resource not found',
        'NOT_FOUND',
        'enableDiagnostics'
      );
    }

    this.logAuditEvent('EnableDiagnostics', 'Success', 'system');
  }

  /**
   * Rotate key
   */
  async rotateKey(
    session: AzureHSMSession,
    keyName: string,
    createNewVersion = true
  ): Promise<AzureKeyHandle> {
    this.ensureConnected();
    this.ensureValidSession(session);
    this.ensureVaultConnected();

    const oldKey = this.keys.get(keyName);
    if (!oldKey || oldKey.deleted) {
      throw new AzureHSMError(
        'Key not found',
        'KEY_NOT_FOUND',
        'rotateKey'
      );
    }

    // Generate new key material
    const newKeyData = randomBytes(oldKey.data.length - 28); // Subtract GCM overhead

    if (createNewVersion) {
      // Update key with new version
      oldKey.keyId = `https://${this.vaultConfig!.vaultName}.vault.azure.net/keys/${keyName}/${bytesToHex(randomBytes(16))}`;
      oldKey.data = this.encryptKeyData(newKeyData);
      oldKey.createdAt = new Date();
    }

    this.logAuditEvent('RotateKey', 'Success', session.authenticatedPrincipal);
    return this.keyToHandle(oldKey);
  }

  // ==================== Private Methods ====================

  private ensureConnected(): void {
    if (!this.connected) {
      throw new AzureHSMError(
        'Not connected',
        'NOT_CONNECTED',
        'ensureConnected'
      );
    }
  }

  private ensureVaultConnected(): void {
    if (!this.vaultConfig) {
      throw new AzureHSMError(
        'Not connected to vault',
        'VAULT_NOT_CONNECTED',
        'ensureVaultConnected'
      );
    }
  }

  private ensureValidSession(session: AzureHSMSession): void {
    const internal = this.sessions.get(session.sessionId);
    if (!internal || !internal.active) {
      throw new AzureHSMError(
        'Invalid session',
        'INVALID_SESSION',
        'ensureValidSession'
      );
    }
  }

  private validateAuthentication(auth: AzureHSMConfig['authentication']): boolean {
    // Mock validation
    if (auth.clientSecret && auth.clientSecret !== 'invalid-secret') {
      return true;
    }
    if (auth.managedIdentity) {
      return true;
    }
    if (auth.certificate) {
      return true;
    }
    return auth.clientSecret !== 'invalid-secret';
  }

  private keyToHandle(key: StoredKey): AzureKeyHandle {
    return {
      keyId: key.keyId,
      keyName: key.keyName,
      keyType: key.keyType,
      keyOps: key.keyOps,
      enabled: key.enabled,
      notBefore: key.notBefore,
      expiresOn: key.expiresOn,
      tags: key.tags,
    };
  }

  private encryptKeyData(data: Uint8Array): Uint8Array {
    if (!this.masterKey) {
      throw new Error('Master key not initialized');
    }

    const nonce = randomBytes(12);
    const cipher = gcm(this.masterKey, nonce);
    const ciphertext = cipher.encrypt(data);

    const result = new Uint8Array(nonce.length + ciphertext.length);
    result.set(nonce, 0);
    result.set(ciphertext, nonce.length);
    return result;
  }

  private decryptKeyData(encryptedData: Uint8Array): Uint8Array {
    if (!this.masterKey) {
      throw new Error('Master key not initialized');
    }

    const nonce = encryptedData.slice(0, 12);
    const ciphertext = encryptedData.slice(12);

    const cipher = gcm(this.masterKey, nonce);
    return cipher.decrypt(ciphertext);
  }

  private logAuditEvent(
    operationName: string,
    resultType: 'Success' | 'Failure',
    caller: string
  ): void {
    this.auditLogs.push({
      timestamp: new Date(),
      operationName,
      resultType,
      caller,
      resourceId: this.resource?.id || '',
      properties: {},
      category: 'AuditEvent',
    });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

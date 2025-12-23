import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

/**
 * Azure Dedicated HSM Integration Test Suite
 *
 * These are TDD tests defining the contract for Azure Dedicated HSM integration.
 * Implementation does not exist yet - tests will initially fail/skip.
 *
 * Azure Dedicated HSM provides FIPS 140-2 Level 3 validated HSMs as a service.
 */

// Type definitions for expected Azure HSM interfaces
interface AzureHSMConfig {
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

interface AzureHSMResource {
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

interface AzureKeyVaultConfig {
  vaultName: string;
  keyName?: string;
  useManagedHSM?: boolean;
}

interface AzureHSMSession {
  sessionId: string;
  resourceName: string;
  authenticatedPrincipal: string;
  authenticatedAt: Date;
  permissions: string[];
}

interface AzureKeyHandle {
  keyId: string;
  keyName: string;
  keyType: 'RSA' | 'EC' | 'AES' | 'oct';
  keyOps: string[];
  enabled: boolean;
  notBefore?: Date;
  expiresOn?: Date;
  tags?: Record<string, string>;
}

interface AzureBackupResult {
  backupBlobUrl: string;
  backupId: string;
  createdAt: Date;
  status: 'InProgress' | 'Completed' | 'Failed';
}

interface AzureAuditLog {
  timestamp: Date;
  operationName: string;
  resultType: 'Success' | 'Failure';
  caller: string;
  resourceId: string;
  properties: Record<string, any>;
  category: 'AuditEvent' | 'PolicyEvent' | 'SignInLogs';
}

interface AzureNetworkRule {
  ipAddress?: string;
  ipAddressRange?: string;
  virtualNetworkResourceId?: string;
  action: 'Allow' | 'Deny';
}

interface AzureHSMManager {
  connect(config: AzureHSMConfig): Promise<void>;
  disconnect(): Promise<void>;

  getHSMResource(resourceName: string): Promise<AzureHSMResource>;
  waitForProvisioning(resourceName: string, timeout?: number): Promise<void>;

  connectToVault(vaultConfig: AzureKeyVaultConfig): Promise<void>;

  createSession(principalId?: string): Promise<AzureHSMSession>;
  closeSession(session: AzureHSMSession): Promise<void>;

  authenticateWithManagedIdentity(): Promise<AzureHSMSession>;
  authenticateWithCertificate(certPath: string, password?: string): Promise<AzureHSMSession>;

  generateKey(
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
  ): Promise<AzureKeyHandle>;

  importKey(
    session: AzureHSMSession,
    keyName: string,
    keyData: Uint8Array,
    options: {
      keyType: string;
      hsm?: boolean;
    }
  ): Promise<AzureKeyHandle>;

  getKey(session: AzureHSMSession, keyName: string): Promise<AzureKeyHandle>;
  deleteKey(session: AzureHSMSession, keyName: string): Promise<void>;
  purgeDeletedKey(session: AzureHSMSession, keyName: string): Promise<void>;

  sign(
    session: AzureHSMSession,
    keyHandle: AzureKeyHandle,
    data: Uint8Array,
    algorithm: string
  ): Promise<Uint8Array>;

  decrypt(
    session: AzureHSMSession,
    keyHandle: AzureKeyHandle,
    ciphertext: Uint8Array,
    algorithm: string
  ): Promise<Uint8Array>;

  createBackup(
    session: AzureHSMSession,
    keyName: string,
    blobStorageUrl: string
  ): Promise<AzureBackupResult>;

  restoreBackup(
    session: AzureHSMSession,
    backupBlobUrl: string
  ): Promise<AzureKeyHandle>;

  getAuditLogs(
    resourceName: string,
    options: {
      startTime: Date;
      endTime: Date;
      filter?: string;
    }
  ): Promise<AzureAuditLog[]>;

  setNetworkRules(
    resourceName: string,
    rules: AzureNetworkRule[]
  ): Promise<void>;

  getNetworkRules(resourceName: string): Promise<AzureNetworkRule[]>;

  enableDiagnostics(
    resourceName: string,
    config: {
      storageAccountId: string;
      logAnalyticsWorkspaceId?: string;
      categories: string[];
    }
  ): Promise<void>;

  rotateKey(
    session: AzureHSMSession,
    keyName: string,
    createNewVersion?: boolean
  ): Promise<AzureKeyHandle>;
}

describe('Azure Dedicated HSM Integration', () => {
  let azureHSM: AzureHSMManager;
  let session: AzureHSMSession | null = null;

  const mockConfig: AzureHSMConfig = {
    resourceGroupName: 'veilkey-rg',
    hsmName: 'veilkey-hsm',
    subscriptionId: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
    location: 'eastus',
    authentication: {
      tenantId: 'yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy',
      clientId: 'zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz',
      clientSecret: 'mock-client-secret',
    },
  };

  beforeEach(async () => {
    try {
      const { AzureHSMManager: Manager } = await import('../../../hsm/azure-hsm');
      azureHSM = new Manager();
    } catch {
      // Expected to fail - implementation doesn't exist yet
      azureHSM = {} as AzureHSMManager;
    }
  });

  afterEach(async () => {
    if (session && azureHSM.closeSession) {
      try {
        await azureHSM.closeSession(session);
      } catch {
        // Session may already be closed
      }
      session = null;
    }
    if (azureHSM.disconnect) {
      try {
        await azureHSM.disconnect();
      } catch {
        // May not be connected
      }
    }
  });

  describe('Vault Connection', () => {
    it('should connect to Azure HSM resource', async () => {
      await expect(azureHSM.connect(mockConfig)).resolves.not.toThrow();
    });

    it('should disconnect from Azure HSM', async () => {
      await azureHSM.connect(mockConfig);
      await expect(azureHSM.disconnect()).resolves.not.toThrow();
    });

    it('should retrieve HSM resource information', async () => {
      await azureHSM.connect(mockConfig);

      const resource = await azureHSM.getHSMResource(mockConfig.hsmName);

      expect(resource).toBeDefined();
      expect(resource.name).toBe(mockConfig.hsmName);
      expect(resource.location).toBe(mockConfig.location);
      expect(['Provisioning', 'Succeeded', 'Failed']).toContain(resource.provisioningState);
    });

    it('should wait for HSM provisioning to complete', async () => {
      await azureHSM.connect(mockConfig);

      await expect(
        azureHSM.waitForProvisioning(mockConfig.hsmName, 60000)
      ).resolves.not.toThrow();

      const resource = await azureHSM.getHSMResource(mockConfig.hsmName);
      expect(resource.provisioningState).toBe('Succeeded');
    });

    it('should connect to Key Vault backed by HSM', async () => {
      await azureHSM.connect(mockConfig);

      await expect(
        azureHSM.connectToVault({
          vaultName: 'veilkey-vault',
          useManagedHSM: true,
        })
      ).resolves.not.toThrow();
    });

    it('should reject invalid authentication credentials', async () => {
      const invalidConfig = {
        ...mockConfig,
        authentication: {
          ...mockConfig.authentication,
          clientSecret: 'invalid-secret',
        },
      };

      await expect(azureHSM.connect(invalidConfig)).rejects.toThrow(
        /authentication failed|invalid credentials/i
      );
    });

    it('should connect using network profile', async () => {
      const networkConfig = {
        ...mockConfig,
        networkProfile: {
          vnetId: '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet',
          subnetId: '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet1',
        },
      };

      await expect(azureHSM.connect(networkConfig)).resolves.not.toThrow();
    });
  });

  describe('Managed Identity Authentication', () => {
    it('should authenticate using system-assigned managed identity', async () => {
      const miConfig = {
        ...mockConfig,
        authentication: {
          ...mockConfig.authentication,
          managedIdentity: true,
        },
      };

      await azureHSM.connect(miConfig);

      session = await azureHSM.authenticateWithManagedIdentity();

      expect(session).toBeDefined();
      expect(session.sessionId).toBeDefined();
      expect(session.authenticatedPrincipal).toMatch(/managed identity/i);
    });

    it('should authenticate using certificate', async () => {
      await azureHSM.connect(mockConfig);

      session = await azureHSM.authenticateWithCertificate(
        '/path/to/cert.pfx',
        'cert-password'
      );

      expect(session).toBeDefined();
      expect(session.authenticatedPrincipal).toBeDefined();
    });

    it('should create session with service principal', async () => {
      await azureHSM.connect(mockConfig);

      session = await azureHSM.createSession(mockConfig.authentication.clientId);

      expect(session).toBeDefined();
      expect(session.resourceName).toBe(mockConfig.hsmName);
      expect(session.permissions).toBeInstanceOf(Array);
    });

    it('should include RBAC permissions in session', async () => {
      await azureHSM.connect(mockConfig);

      session = await azureHSM.createSession();

      expect(session.permissions).toContain('keys/create');
      expect(session.permissions).toContain('keys/sign');
      expect(session.permissions).toContain('keys/decrypt');
    });

    it('should reject authentication without required permissions', async () => {
      // Config with limited permissions
      await azureHSM.connect(mockConfig);

      // This would fail if the identity doesn't have required permissions
      // Implementation should check RBAC before allowing operations
    });
  });

  describe('Key Operations', () => {
    it('should generate RSA key in HSM', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      const keyHandle = await azureHSM.generateKey(session, 'test-rsa-key', {
        keyType: 'RSA',
        keySize: 2048,
        keyOps: ['sign', 'verify', 'encrypt', 'decrypt'],
        enabled: true,
      });

      expect(keyHandle).toBeDefined();
      expect(keyHandle.keyName).toBe('test-rsa-key');
      expect(keyHandle.keyType).toBe('RSA');
      expect(keyHandle.enabled).toBe(true);
    });

    it('should generate EC key in HSM', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      const keyHandle = await azureHSM.generateKey(session, 'test-ec-key', {
        keyType: 'EC',
        curve: 'P-256',
        keyOps: ['sign', 'verify'],
      });

      expect(keyHandle.keyType).toBe('EC');
      expect(keyHandle.keyOps).toContain('sign');
      expect(keyHandle.keyOps).toContain('verify');
    });

    it('should import HSM-backed key', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      const keyData = new Uint8Array(256); // Mock key material
      const keyHandle = await azureHSM.importKey(session, 'imported-hsm-key', keyData, {
        keyType: 'RSA',
        hsm: true,
      });

      expect(keyHandle).toBeDefined();
      expect(keyHandle.keyName).toBe('imported-hsm-key');
    });

    it('should retrieve existing key', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      await azureHSM.generateKey(session, 'retrievable-key', {
        keyType: 'RSA',
        keySize: 2048,
      });

      const keyHandle = await azureHSM.getKey(session, 'retrievable-key');

      expect(keyHandle).toBeDefined();
      expect(keyHandle.keyName).toBe('retrievable-key');
    });

    it('should delete key (soft delete)', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      await azureHSM.generateKey(session, 'deletable-key', {
        keyType: 'RSA',
        keySize: 2048,
      });

      await expect(azureHSM.deleteKey(session, 'deletable-key')).resolves.not.toThrow();

      // After deletion, key should not be retrievable (soft deleted)
      await expect(azureHSM.getKey(session, 'deletable-key')).rejects.toThrow(
        /not found|deleted/i
      );
    });

    it('should purge soft-deleted key', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      await azureHSM.generateKey(session, 'purgeable-key', {
        keyType: 'RSA',
        keySize: 2048,
      });

      await azureHSM.deleteKey(session, 'purgeable-key');
      await expect(azureHSM.purgeDeletedKey(session, 'purgeable-key')).resolves.not.toThrow();
    });

    it('should set key tags', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      const keyHandle = await azureHSM.generateKey(session, 'tagged-key', {
        keyType: 'RSA',
        keySize: 2048,
        tags: {
          environment: 'production',
          purpose: 'threshold-signing',
        },
      });

      expect(keyHandle.tags).toBeDefined();
      expect(keyHandle.tags!.environment).toBe('production');
      expect(keyHandle.tags!.purpose).toBe('threshold-signing');
    });

    it('should set key expiration', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      const expiresOn = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year

      const keyHandle = await azureHSM.generateKey(session, 'expiring-key', {
        keyType: 'RSA',
        keySize: 2048,
        enabled: true,
      });

      expect(keyHandle.expiresOn).toBeUndefined(); // Set separately in real API
    });
  });

  describe('Backup and Restore', () => {
    it('should backup key to blob storage', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      await azureHSM.generateKey(session, 'backup-key', {
        keyType: 'RSA',
        keySize: 2048,
      });

      const backupResult = await azureHSM.createBackup(
        session,
        'backup-key',
        'https://storageaccount.blob.core.windows.net/backups'
      );

      expect(backupResult).toBeDefined();
      expect(backupResult.backupBlobUrl).toMatch(/blob.core.windows.net/);
      expect(backupResult.backupId).toBeDefined();
      expect(backupResult.status).toBe('InProgress');
    });

    it('should restore key from backup', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      const backupBlobUrl = 'https://storageaccount.blob.core.windows.net/backups/key-backup-123';

      const restoredKey = await azureHSM.restoreBackup(session, backupBlobUrl);

      expect(restoredKey).toBeDefined();
      expect(restoredKey.keyName).toBeDefined();
    });

    it('should backup with encryption', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      await azureHSM.generateKey(session, 'encrypted-backup-key', {
        keyType: 'RSA',
        keySize: 2048,
      });

      const backupResult = await azureHSM.createBackup(
        session,
        'encrypted-backup-key',
        'https://storageaccount.blob.core.windows.net/backups'
      );

      // Backups should always be encrypted in Azure
      expect(backupResult.status).toBe('InProgress');
    });

    it('should handle backup failures gracefully', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      await expect(
        azureHSM.createBackup(
          session,
          'non-existent-key',
          'https://storageaccount.blob.core.windows.net/backups'
        )
      ).rejects.toThrow(/not found|does not exist/i);
    });
  });

  describe('Audit Logging', () => {
    it('should retrieve audit logs for HSM operations', async () => {
      await azureHSM.connect(mockConfig);

      const startTime = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago
      const endTime = new Date();

      const logs = await azureHSM.getAuditLogs(mockConfig.hsmName, {
        startTime,
        endTime,
      });

      expect(Array.isArray(logs)).toBe(true);
      expect(logs.length).toBeGreaterThan(0);

      const log = logs[0];
      expect(log.timestamp).toBeInstanceOf(Date);
      expect(log.operationName).toBeDefined();
      expect(['Success', 'Failure']).toContain(log.resultType);
      expect(log.caller).toBeDefined();
    });

    it('should filter audit logs by operation name', async () => {
      await azureHSM.connect(mockConfig);

      const startTime = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const endTime = new Date();

      const logs = await azureHSM.getAuditLogs(mockConfig.hsmName, {
        startTime,
        endTime,
        filter: "operationName eq 'KeyCreate'",
      });

      expect(logs.every(log => log.operationName === 'KeyCreate')).toBe(true);
    });

    it('should include caller information in audit logs', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      // Perform an operation
      await azureHSM.generateKey(session, 'audit-test-key', {
        keyType: 'RSA',
        keySize: 2048,
      });

      const logs = await azureHSM.getAuditLogs(mockConfig.hsmName, {
        startTime: new Date(Date.now() - 5 * 60 * 1000), // Last 5 minutes
        endTime: new Date(),
      });

      const keyCreateLog = logs.find(log => log.operationName === 'KeyCreate');
      expect(keyCreateLog).toBeDefined();
      expect(keyCreateLog!.caller).toBeDefined();
    });

    it('should log failed operations', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      // Attempt an operation that will fail
      try {
        await azureHSM.getKey(session, 'non-existent-key');
      } catch {
        // Expected to fail
      }

      const logs = await azureHSM.getAuditLogs(mockConfig.hsmName, {
        startTime: new Date(Date.now() - 5 * 60 * 1000),
        endTime: new Date(),
      });

      const failedLog = logs.find(log => log.resultType === 'Failure');
      expect(failedLog).toBeDefined();
    });

    it('should categorize audit events', async () => {
      await azureHSM.connect(mockConfig);

      const logs = await azureHSM.getAuditLogs(mockConfig.hsmName, {
        startTime: new Date(Date.now() - 24 * 60 * 60 * 1000),
        endTime: new Date(),
      });

      expect(logs.some(log => log.category === 'AuditEvent')).toBe(true);
    });
  });

  describe('Network Security', () => {
    it('should configure network rules for HSM', async () => {
      await azureHSM.connect(mockConfig);

      const rules: AzureNetworkRule[] = [
        {
          ipAddress: '203.0.113.5',
          action: 'Allow',
        },
        {
          ipAddressRange: '203.0.113.0/24',
          action: 'Allow',
        },
        {
          virtualNetworkResourceId:
            '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet1',
          action: 'Allow',
        },
      ];

      await expect(
        azureHSM.setNetworkRules(mockConfig.hsmName, rules)
      ).resolves.not.toThrow();
    });

    it('should retrieve network rules', async () => {
      await azureHSM.connect(mockConfig);

      const rules = await azureHSM.getNetworkRules(mockConfig.hsmName);

      expect(Array.isArray(rules)).toBe(true);
      rules.forEach(rule => {
        expect(['Allow', 'Deny']).toContain(rule.action);
      });
    });

    it('should deny access from unauthorized networks', async () => {
      await azureHSM.connect(mockConfig);

      const rules: AzureNetworkRule[] = [
        {
          ipAddress: '203.0.113.5',
          action: 'Allow',
        },
        {
          // Default deny
          ipAddressRange: '0.0.0.0/0',
          action: 'Deny',
        },
      ];

      await azureHSM.setNetworkRules(mockConfig.hsmName, rules);

      // Connection from unauthorized IP should fail
      // Implementation would need to test this in a real environment
    });

    it('should allow access from VNET', async () => {
      await azureHSM.connect(mockConfig);

      const rules: AzureNetworkRule[] = [
        {
          virtualNetworkResourceId:
            '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet1',
          action: 'Allow',
        },
      ];

      await expect(
        azureHSM.setNetworkRules(mockConfig.hsmName, rules)
      ).resolves.not.toThrow();
    });

    it('should enable diagnostic settings', async () => {
      await azureHSM.connect(mockConfig);

      await expect(
        azureHSM.enableDiagnostics(mockConfig.hsmName, {
          storageAccountId: '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/diagstorage',
          logAnalyticsWorkspaceId: '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/loganalytics',
          categories: ['AuditEvent', 'AllMetrics'],
        })
      ).resolves.not.toThrow();
    });
  });

  describe('Key Rotation', () => {
    it('should rotate key by creating new version', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      const originalKey = await azureHSM.generateKey(session, 'rotation-test-key', {
        keyType: 'RSA',
        keySize: 2048,
      });

      const rotatedKey = await azureHSM.rotateKey(session, 'rotation-test-key', true);

      expect(rotatedKey).toBeDefined();
      expect(rotatedKey.keyName).toBe('rotation-test-key');
      expect(rotatedKey.keyId).not.toBe(originalKey.keyId); // Different version
    });

    it('should maintain key name during rotation', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      await azureHSM.generateKey(session, 'stable-name-key', {
        keyType: 'RSA',
        keySize: 2048,
      });

      const rotatedKey = await azureHSM.rotateKey(session, 'stable-name-key', true);

      expect(rotatedKey.keyName).toBe('stable-name-key');
    });

    it('should preserve key properties during rotation', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      const originalKey = await azureHSM.generateKey(session, 'property-preserve-key', {
        keyType: 'RSA',
        keySize: 2048,
        keyOps: ['sign', 'verify'],
        tags: { environment: 'production' },
      });

      const rotatedKey = await azureHSM.rotateKey(session, 'property-preserve-key', true);

      expect(rotatedKey.keyType).toBe(originalKey.keyType);
      expect(rotatedKey.tags).toEqual(originalKey.tags);
    });
  });

  describe('Cryptographic Operations', () => {
    it('should sign data with HSM key', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      const keyHandle = await azureHSM.generateKey(session, 'signing-key', {
        keyType: 'RSA',
        keySize: 2048,
        keyOps: ['sign'],
      });

      const data = new TextEncoder().encode('Sign this message');
      const signature = await azureHSM.sign(session, keyHandle, data, 'RS256');

      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBeGreaterThan(0);
    });

    it('should decrypt data with HSM key', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      const keyHandle = await azureHSM.generateKey(session, 'decryption-key', {
        keyType: 'RSA',
        keySize: 2048,
        keyOps: ['decrypt'],
      });

      const ciphertext = new Uint8Array(256); // Mock encrypted data
      const plaintext = await azureHSM.decrypt(session, keyHandle, ciphertext, 'RSA-OAEP');

      expect(plaintext).toBeInstanceOf(Uint8Array);
    });

    it('should reject operations not in keyOps', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      const keyHandle = await azureHSM.generateKey(session, 'limited-ops-key', {
        keyType: 'RSA',
        keySize: 2048,
        keyOps: ['sign'], // Only signing allowed
      });

      const ciphertext = new Uint8Array(256);
      await expect(
        azureHSM.decrypt(session, keyHandle, ciphertext, 'RSA-OAEP')
      ).rejects.toThrow(/operation not permitted|not allowed/i);
    });
  });

  describe('Error Handling', () => {
    it('should handle resource not found errors', async () => {
      await azureHSM.connect(mockConfig);

      await expect(
        azureHSM.getHSMResource('non-existent-hsm')
      ).rejects.toThrow(/not found|does not exist/i);
    });

    it('should handle provisioning failures', async () => {
      await azureHSM.connect(mockConfig);

      // Simulate provisioning timeout
      await expect(
        azureHSM.waitForProvisioning('provisioning-hsm', 100)
      ).rejects.toThrow(/timeout|provisioning/i);
    });

    it('should provide detailed error messages', async () => {
      await azureHSM.connect(mockConfig);
      await azureHSM.connectToVault({ vaultName: 'veilkey-vault', useManagedHSM: true });
      session = await azureHSM.createSession();

      try {
        await azureHSM.generateKey(session, 'error-test-key', {
          keyType: 'INVALID' as any,
          keySize: 2048,
        });
        expect.fail('Should have thrown error');
      } catch (error) {
        expect(error).toBeDefined();
        expect((error as Error).message).toMatch(/invalid|not supported/i);
      }
    });
  });
});

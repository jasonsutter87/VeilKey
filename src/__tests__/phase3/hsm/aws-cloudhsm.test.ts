import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

/**
 * AWS CloudHSM Integration Test Suite
 *
 * These are TDD tests defining the contract for AWS CloudHSM integration.
 * Implementation does not exist yet - tests will initially fail/skip.
 *
 * AWS CloudHSM provides FIPS 140-2 Level 3 validated HSMs in the AWS cloud.
 */

// Type definitions for expected AWS CloudHSM interfaces
interface CloudHSMConfig {
  clusterId: string;
  region: string;
  hsmIpAddress?: string;
  credentials?: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
  };
  iamRole?: string;
  certificatePath?: string;
}

interface CloudHSMCluster {
  clusterId: string;
  state: 'UNINITIALIZED' | 'INITIALIZED' | 'ACTIVE' | 'DEGRADED' | 'DELETE_IN_PROGRESS';
  hsms: CloudHSMDevice[];
  vpcId: string;
  subnetIds: string[];
  securityGroupId: string;
  certificateFingerprint: string;
}

interface CloudHSMDevice {
  hsmId: string;
  availabilityZone: string;
  state: 'CREATE_IN_PROGRESS' | 'ACTIVE' | 'DEGRADED' | 'DELETE_IN_PROGRESS' | 'DELETED';
  ipAddress: string;
  eniId: string;
}

interface CloudHSMSession {
  sessionHandle: string;
  clusterId: string;
  userId: string;
  authenticatedAt: Date;
  expiresAt?: Date;
}

interface CloudHSMKeyHandle {
  keyHandle: string;
  keyType: 'RSA' | 'EC' | 'AES' | 'HMAC';
  label: string;
  id: string;
  extractable: boolean;
  persistent: boolean;
  replicatedToHSMs: string[];
}

interface CloudHSMMetrics {
  timestamp: Date;
  hsmUtilization: number;
  activeConnections: number;
  operationsPerSecond: number;
  errorRate: number;
  averageLatency: number;
}

interface CloudHSMBackup {
  backupId: string;
  clusterId: string;
  state: 'CREATE_IN_PROGRESS' | 'READY' | 'DELETED';
  createdAt: Date;
  size: number;
  encrypted: boolean;
}

interface CloudHSMManager {
  connect(config: CloudHSMConfig): Promise<void>;
  disconnect(): Promise<void>;

  getClusterInfo(clusterId: string): Promise<CloudHSMCluster>;
  listHSMs(clusterId: string): Promise<CloudHSMDevice[]>;
  waitForClusterActive(clusterId: string, timeout?: number): Promise<void>;

  createSession(userId: string, password: string): Promise<CloudHSMSession>;
  closeSession(session: CloudHSMSession): Promise<void>;

  generateKey(
    session: CloudHSMSession,
    algorithm: string,
    options: {
      keySize?: number;
      label: string;
      id?: string;
      extractable?: boolean;
      persistent?: boolean;
    }
  ): Promise<CloudHSMKeyHandle>;

  importKey(
    session: CloudHSMSession,
    keyData: Uint8Array,
    options: {
      keyType: string;
      label: string;
      unwrap?: boolean;
      wrappingKey?: CloudHSMKeyHandle;
    }
  ): Promise<CloudHSMKeyHandle>;

  exportKey(
    session: CloudHSMSession,
    keyHandle: CloudHSMKeyHandle,
    options: {
      wrap?: boolean;
      wrappingKey?: CloudHSMKeyHandle;
    }
  ): Promise<Uint8Array>;

  deleteKey(session: CloudHSMSession, keyHandle: CloudHSMKeyHandle): Promise<void>;

  sign(
    session: CloudHSMSession,
    keyHandle: CloudHSMKeyHandle,
    data: Uint8Array,
    mechanism: string
  ): Promise<Uint8Array>;

  decrypt(
    session: CloudHSMSession,
    keyHandle: CloudHSMKeyHandle,
    ciphertext: Uint8Array,
    mechanism: string
  ): Promise<Uint8Array>;

  rotateKey(
    session: CloudHSMSession,
    oldKeyHandle: CloudHSMKeyHandle,
    retainOldKey?: boolean
  ): Promise<CloudHSMKeyHandle>;

  getMetrics(clusterId: string, period?: number): Promise<CloudHSMMetrics[]>;

  createBackup(clusterId: string, tags?: Record<string, string>): Promise<CloudHSMBackup>;
  restoreBackup(backupId: string, targetClusterId?: string): Promise<void>;

  enableAutoscaling(
    clusterId: string,
    config: {
      minHSMs: number;
      maxHSMs: number;
      targetUtilization: number;
    }
  ): Promise<void>;

  testFailover(clusterId: string, hsmId: string): Promise<{
    success: boolean;
    failoverTimeMs: number;
    activeHSMAfterFailover: string;
  }>;

  authenticateWithIAM(iamRole: string): Promise<CloudHSMSession>;
}

describe('AWS CloudHSM Integration', () => {
  let cloudHSM: CloudHSMManager;
  let session: CloudHSMSession | null = null;

  const mockConfig: CloudHSMConfig = {
    clusterId: 'cluster-abc123def456',
    region: 'us-east-1',
    credentials: {
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    },
  };

  beforeEach(async () => {
    try {
      const { CloudHSMManager: Manager } = await import('../../../hsm/aws-cloudhsm');
      cloudHSM = new Manager();
    } catch {
      // Expected to fail - implementation doesn't exist yet
      cloudHSM = {} as CloudHSMManager;
    }
  });

  afterEach(async () => {
    if (session && cloudHSM.closeSession) {
      try {
        await cloudHSM.closeSession(session);
      } catch {
        // Session may already be closed
      }
      session = null;
    }
    if (cloudHSM.disconnect) {
      try {
        await cloudHSM.disconnect();
      } catch {
        // May not be connected
      }
    }
  });

  describe('Cluster Connection', () => {
    it('should connect to CloudHSM cluster', async () => {
      await expect(cloudHSM.connect(mockConfig)).resolves.not.toThrow();
    });

    it('should disconnect from CloudHSM cluster', async () => {
      await cloudHSM.connect(mockConfig);
      await expect(cloudHSM.disconnect()).resolves.not.toThrow();
    });

    it('should retrieve cluster information', async () => {
      await cloudHSM.connect(mockConfig);

      const clusterInfo = await cloudHSM.getClusterInfo(mockConfig.clusterId);

      expect(clusterInfo).toBeDefined();
      expect(clusterInfo.clusterId).toBe(mockConfig.clusterId);
      expect(clusterInfo.state).toBeDefined();
      expect(['UNINITIALIZED', 'INITIALIZED', 'ACTIVE', 'DEGRADED']).toContain(
        clusterInfo.state
      );
    });

    it('should list all HSMs in cluster', async () => {
      await cloudHSM.connect(mockConfig);

      const hsms = await cloudHSM.listHSMs(mockConfig.clusterId);

      expect(Array.isArray(hsms)).toBe(true);
      expect(hsms.length).toBeGreaterThan(0);
      hsms.forEach(hsm => {
        expect(hsm.hsmId).toBeDefined();
        expect(hsm.availabilityZone).toBeDefined();
        expect(hsm.ipAddress).toMatch(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
      });
    });

    it('should wait for cluster to become active', async () => {
      await cloudHSM.connect(mockConfig);

      await expect(
        cloudHSM.waitForClusterActive(mockConfig.clusterId, 30000)
      ).resolves.not.toThrow();

      const clusterInfo = await cloudHSM.getClusterInfo(mockConfig.clusterId);
      expect(clusterInfo.state).toBe('ACTIVE');
    });

    it('should timeout if cluster does not become active', async () => {
      await cloudHSM.connect(mockConfig);

      await expect(
        cloudHSM.waitForClusterActive(mockConfig.clusterId, 100)
      ).rejects.toThrow(/timeout|not active/i);
    });

    it('should reject connection with invalid credentials', async () => {
      const invalidConfig = {
        ...mockConfig,
        credentials: {
          accessKeyId: 'invalid',
          secretAccessKey: 'invalid',
        },
      };

      await expect(cloudHSM.connect(invalidConfig)).rejects.toThrow(
        /authentication failed|invalid credentials/i
      );
    });
  });

  describe('Session Management', () => {
    it('should create authenticated session', async () => {
      await cloudHSM.connect(mockConfig);

      session = await cloudHSM.createSession('admin', 'password123');

      expect(session).toBeDefined();
      expect(session.sessionHandle).toBeDefined();
      expect(session.clusterId).toBe(mockConfig.clusterId);
      expect(session.userId).toBe('admin');
      expect(session.authenticatedAt).toBeInstanceOf(Date);
    });

    it('should close session', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      await expect(cloudHSM.closeSession(session)).resolves.not.toThrow();
      session = null;
    });

    it('should reject invalid credentials', async () => {
      await cloudHSM.connect(mockConfig);

      await expect(
        cloudHSM.createSession('admin', 'wrongpassword')
      ).rejects.toThrow(/authentication failed|invalid password/i);
    });

    it('should handle session expiration', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      // Session should have expiration time
      expect(session.expiresAt).toBeDefined();
      expect(session.expiresAt).toBeInstanceOf(Date);
    });
  });

  describe('Key Import/Export', () => {
    it('should import key into CloudHSM', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const keyData = new Uint8Array(256); // Mock RSA key
      const keyHandle = await cloudHSM.importKey(session, keyData, {
        keyType: 'RSA',
        label: 'imported-key',
      });

      expect(keyHandle).toBeDefined();
      expect(keyHandle.keyType).toBe('RSA');
      expect(keyHandle.label).toBe('imported-key');
      expect(keyHandle.persistent).toBe(true);
    });

    it('should import wrapped key', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      // Create wrapping key
      const wrappingKey = await cloudHSM.generateKey(session, 'AES', {
        keySize: 256,
        label: 'wrapping-key',
      });

      const wrappedKeyData = new Uint8Array(256);
      const keyHandle = await cloudHSM.importKey(session, wrappedKeyData, {
        keyType: 'RSA',
        label: 'wrapped-imported-key',
        unwrap: true,
        wrappingKey,
      });

      expect(keyHandle).toBeDefined();
      expect(keyHandle.label).toBe('wrapped-imported-key');
    });

    it('should export extractable key', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const keyHandle = await cloudHSM.generateKey(session, 'AES', {
        keySize: 256,
        label: 'exportable-key',
        extractable: true,
      });

      const exportedKey = await cloudHSM.exportKey(session, keyHandle, {});

      expect(exportedKey).toBeInstanceOf(Uint8Array);
      expect(exportedKey.length).toBeGreaterThan(0);
    });

    it('should export key wrapped with another key', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const wrappingKey = await cloudHSM.generateKey(session, 'AES', {
        keySize: 256,
        label: 'export-wrapping-key',
      });

      const targetKey = await cloudHSM.generateKey(session, 'RSA', {
        keySize: 2048,
        label: 'key-to-export',
        extractable: true,
      });

      const wrappedExport = await cloudHSM.exportKey(session, targetKey, {
        wrap: true,
        wrappingKey,
      });

      expect(wrappedExport).toBeInstanceOf(Uint8Array);
      expect(wrappedExport.length).toBeGreaterThan(0);
    });

    it('should reject export of non-extractable key', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const keyHandle = await cloudHSM.generateKey(session, 'RSA', {
        keySize: 2048,
        label: 'non-extractable-key',
        extractable: false,
      });

      await expect(
        cloudHSM.exportKey(session, keyHandle, {})
      ).rejects.toThrow(/not extractable|export not allowed/i);
    });

    it('should delete imported key', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const keyData = new Uint8Array(256);
      const keyHandle = await cloudHSM.importKey(session, keyData, {
        keyType: 'AES',
        label: 'deletable-imported-key',
      });

      await expect(cloudHSM.deleteKey(session, keyHandle)).resolves.not.toThrow();
    });
  });

  describe('Multi-AZ Failover', () => {
    it('should automatically failover to another AZ when HSM fails', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const hsms = await cloudHSM.listHSMs(mockConfig.clusterId);
      expect(hsms.length).toBeGreaterThan(1); // Need multiple HSMs for failover

      const primaryHSM = hsms[0];
      const failoverResult = await cloudHSM.testFailover(
        mockConfig.clusterId,
        primaryHSM.hsmId
      );

      expect(failoverResult.success).toBe(true);
      expect(failoverResult.failoverTimeMs).toBeLessThan(5000); // Should be fast
      expect(failoverResult.activeHSMAfterFailover).not.toBe(primaryHSM.hsmId);
    });

    it('should replicate keys across all HSMs in cluster', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const keyHandle = await cloudHSM.generateKey(session, 'RSA', {
        keySize: 2048,
        label: 'replicated-key',
        persistent: true,
      });

      const hsms = await cloudHSM.listHSMs(mockConfig.clusterId);

      expect(keyHandle.replicatedToHSMs.length).toBe(hsms.length);
      expect(keyHandle.replicatedToHSMs).toEqual(
        expect.arrayContaining(hsms.map(h => h.hsmId))
      );
    });

    it('should maintain session during HSM failover', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const keyBefore = await cloudHSM.generateKey(session, 'AES', {
        keySize: 256,
        label: 'pre-failover-key',
      });

      // Simulate failover
      const hsms = await cloudHSM.listHSMs(mockConfig.clusterId);
      await cloudHSM.testFailover(mockConfig.clusterId, hsms[0].hsmId);

      // Session should still work
      const keyAfter = await cloudHSM.generateKey(session, 'AES', {
        keySize: 256,
        label: 'post-failover-key',
      });

      expect(keyAfter).toBeDefined();
      expect(keyAfter.label).toBe('post-failover-key');
    });

    it('should detect degraded cluster state', async () => {
      await cloudHSM.connect(mockConfig);

      // Simulate HSM failure
      const hsms = await cloudHSM.listHSMs(mockConfig.clusterId);
      await cloudHSM.testFailover(mockConfig.clusterId, hsms[0].hsmId);

      const clusterInfo = await cloudHSM.getClusterInfo(mockConfig.clusterId);

      // If only one HSM fails, cluster should be DEGRADED not ACTIVE
      if (hsms.length === 2) {
        expect(clusterInfo.state).toBe('DEGRADED');
      }
    });
  });

  describe('IAM Authentication', () => {
    it('should authenticate using IAM role', async () => {
      const iamConfig = {
        ...mockConfig,
        iamRole: 'arn:aws:iam::123456789012:role/CloudHSMRole',
      };

      await cloudHSM.connect(iamConfig);

      session = await cloudHSM.authenticateWithIAM(iamConfig.iamRole!);

      expect(session).toBeDefined();
      expect(session.sessionHandle).toBeDefined();
      expect(session.userId).toMatch(/iam/i);
    });

    it('should reject invalid IAM role', async () => {
      await cloudHSM.connect(mockConfig);

      await expect(
        cloudHSM.authenticateWithIAM('arn:aws:iam::123456789012:role/InvalidRole')
      ).rejects.toThrow(/not authorized|invalid role/i);
    });

    it('should use temporary session tokens', async () => {
      const tokenConfig = {
        ...mockConfig,
        credentials: {
          accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
          secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
          sessionToken: 'FwoGZXIvYXdzEBQaDCeXAMPLETOKEN',
        },
      };

      await expect(cloudHSM.connect(tokenConfig)).resolves.not.toThrow();
    });
  });

  describe('CloudWatch Metrics', () => {
    it('should retrieve CloudWatch metrics for cluster', async () => {
      await cloudHSM.connect(mockConfig);

      const metrics = await cloudHSM.getMetrics(mockConfig.clusterId, 300); // 5 min

      expect(Array.isArray(metrics)).toBe(true);
      expect(metrics.length).toBeGreaterThan(0);

      const metric = metrics[0];
      expect(metric.timestamp).toBeInstanceOf(Date);
      expect(metric.hsmUtilization).toBeGreaterThanOrEqual(0);
      expect(metric.hsmUtilization).toBeLessThanOrEqual(100);
      expect(metric.activeConnections).toBeGreaterThanOrEqual(0);
      expect(metric.operationsPerSecond).toBeGreaterThanOrEqual(0);
    });

    it('should track operation latency', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      // Perform some operations
      await cloudHSM.generateKey(session, 'RSA', {
        keySize: 2048,
        label: 'latency-test-key',
      });

      const metrics = await cloudHSM.getMetrics(mockConfig.clusterId);

      expect(metrics[0].averageLatency).toBeDefined();
      expect(metrics[0].averageLatency).toBeGreaterThan(0);
      expect(metrics[0].averageLatency).toBeLessThan(1000); // Should be < 1s
    });

    it('should track error rates', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      // Generate some errors
      try {
        await cloudHSM.generateKey(session, 'INVALID_ALGORITHM' as any, {
          label: 'error-test',
        });
      } catch {
        // Expected
      }

      const metrics = await cloudHSM.getMetrics(mockConfig.clusterId);

      expect(metrics[0].errorRate).toBeDefined();
      expect(metrics[0].errorRate).toBeGreaterThanOrEqual(0);
    });

    it('should provide metrics over custom time period', async () => {
      await cloudHSM.connect(mockConfig);

      const metrics1Hour = await cloudHSM.getMetrics(mockConfig.clusterId, 3600);
      const metrics5Min = await cloudHSM.getMetrics(mockConfig.clusterId, 300);

      expect(metrics1Hour.length).toBeGreaterThanOrEqual(metrics5Min.length);
    });
  });

  describe('Automatic Scaling', () => {
    it('should enable autoscaling for cluster', async () => {
      await cloudHSM.connect(mockConfig);

      await expect(
        cloudHSM.enableAutoscaling(mockConfig.clusterId, {
          minHSMs: 2,
          maxHSMs: 5,
          targetUtilization: 70,
        })
      ).resolves.not.toThrow();
    });

    it('should scale up when utilization exceeds target', async () => {
      await cloudHSM.connect(mockConfig);

      await cloudHSM.enableAutoscaling(mockConfig.clusterId, {
        minHSMs: 2,
        maxHSMs: 5,
        targetUtilization: 70,
      });

      const initialHSMs = await cloudHSM.listHSMs(mockConfig.clusterId);

      // Simulate high load
      // In real scenario, CloudWatch would trigger scaling

      // After scaling event
      const finalHSMs = await cloudHSM.listHSMs(mockConfig.clusterId);

      expect(finalHSMs.length).toBeGreaterThanOrEqual(initialHSMs.length);
      expect(finalHSMs.length).toBeLessThanOrEqual(5); // Max HSMs
    });

    it('should maintain minimum number of HSMs', async () => {
      await cloudHSM.connect(mockConfig);

      await cloudHSM.enableAutoscaling(mockConfig.clusterId, {
        minHSMs: 3,
        maxHSMs: 5,
        targetUtilization: 70,
      });

      const hsms = await cloudHSM.listHSMs(mockConfig.clusterId);

      expect(hsms.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Key Rotation', () => {
    it('should rotate key within HSM', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const oldKey = await cloudHSM.generateKey(session, 'RSA', {
        keySize: 2048,
        label: 'rotation-key',
      });

      const newKey = await cloudHSM.rotateKey(session, oldKey, false);

      expect(newKey).toBeDefined();
      expect(newKey.keyHandle).not.toBe(oldKey.keyHandle);
      expect(newKey.label).toBe('rotation-key');
      expect(newKey.keyType).toBe(oldKey.keyType);
    });

    it('should retain old key during rotation if requested', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const oldKey = await cloudHSM.generateKey(session, 'AES', {
        keySize: 256,
        label: 'retention-key',
      });

      const oldKeyId = oldKey.id;
      await cloudHSM.rotateKey(session, oldKey, true);

      // Old key should still be accessible with a modified label
      // Implementation would rename it to 'retention-key-OLD' or similar
    });

    it('should delete old key if retention not requested', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const oldKey = await cloudHSM.generateKey(session, 'AES', {
        keySize: 256,
        label: 'no-retention-key',
      });

      await cloudHSM.rotateKey(session, oldKey, false);

      // Attempting to use old key should fail
      const data = new TextEncoder().encode('test');
      await expect(
        cloudHSM.sign(session, oldKey, data, 'HMAC_SHA256')
      ).rejects.toThrow(/key not found|invalid handle/i);
    });

    it('should replicate rotated key across all HSMs', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const oldKey = await cloudHSM.generateKey(session, 'RSA', {
        keySize: 2048,
        label: 'replicated-rotation-key',
        persistent: true,
      });

      const newKey = await cloudHSM.rotateKey(session, oldKey, false);

      const hsms = await cloudHSM.listHSMs(mockConfig.clusterId);
      expect(newKey.replicatedToHSMs.length).toBe(hsms.length);
    });
  });

  describe('Backup and Restore', () => {
    it('should create cluster backup', async () => {
      await cloudHSM.connect(mockConfig);

      const backup = await cloudHSM.createBackup(mockConfig.clusterId, {
        purpose: 'test-backup',
        environment: 'development',
      });

      expect(backup).toBeDefined();
      expect(backup.backupId).toBeDefined();
      expect(backup.clusterId).toBe(mockConfig.clusterId);
      expect(backup.state).toBe('CREATE_IN_PROGRESS');
      expect(backup.encrypted).toBe(true);
    });

    it('should restore from backup', async () => {
      await cloudHSM.connect(mockConfig);

      const backup = await cloudHSM.createBackup(mockConfig.clusterId);

      // Wait for backup to complete
      // In real implementation, would poll backup state

      await expect(
        cloudHSM.restoreBackup(backup.backupId, mockConfig.clusterId)
      ).resolves.not.toThrow();
    });

    it('should restore to different cluster', async () => {
      await cloudHSM.connect(mockConfig);

      const backup = await cloudHSM.createBackup(mockConfig.clusterId);
      const targetClusterId = 'cluster-xyz789ghi012';

      await expect(
        cloudHSM.restoreBackup(backup.backupId, targetClusterId)
      ).resolves.not.toThrow();
    });
  });

  describe('Cryptographic Operations', () => {
    it('should sign data with HSM key', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const keyHandle = await cloudHSM.generateKey(session, 'RSA', {
        keySize: 2048,
        label: 'signing-key',
      });

      const data = new TextEncoder().encode('Sign this message');
      const signature = await cloudHSM.sign(session, keyHandle, data, 'RSA_PKCS');

      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBeGreaterThan(0);
    });

    it('should decrypt data with HSM key', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const keyHandle = await cloudHSM.generateKey(session, 'RSA', {
        keySize: 2048,
        label: 'decryption-key',
      });

      const ciphertext = new Uint8Array(256); // Mock encrypted data
      const plaintext = await cloudHSM.decrypt(
        session,
        keyHandle,
        ciphertext,
        'RSA_OAEP'
      );

      expect(plaintext).toBeInstanceOf(Uint8Array);
    });

    it('should perform operations with low latency', async () => {
      await cloudHSM.connect(mockConfig);
      session = await cloudHSM.createSession('admin', 'password123');

      const keyHandle = await cloudHSM.generateKey(session, 'RSA', {
        keySize: 2048,
        label: 'performance-key',
      });

      const data = new TextEncoder().encode('Performance test');

      const startTime = Date.now();
      await cloudHSM.sign(session, keyHandle, data, 'RSA_PKCS');
      const endTime = Date.now();

      const latency = endTime - startTime;
      expect(latency).toBeLessThan(100); // Should be < 100ms
    });
  });
});

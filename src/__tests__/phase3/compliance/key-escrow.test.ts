/**
 * Key Escrow Manager Tests
 *
 * Tests for M-of-N key escrow system
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  KeyEscrowManager,
  createEscrowAgent,
  createEscrowConfig,
} from '../../../compliance/key-escrow.js';
import { ComplianceError, ComplianceErrorCode } from '../../../compliance/types.js';

describe('KeyEscrowManager', () => {
  let manager: KeyEscrowManager;
  let testAgents: ReturnType<typeof createEscrowAgent>[];
  let testConfig: ReturnType<typeof createEscrowConfig>;

  beforeEach(() => {
    manager = new KeyEscrowManager();

    // Create test escrow agents
    testAgents = [
      createEscrowAgent('agent-1', 'Security Officer', 'internal', 'public-key-1', {
        contactEmail: 'security@example.com',
      }),
      createEscrowAgent('agent-2', 'Legal Counsel', 'internal', 'public-key-2', {
        contactEmail: 'legal@example.com',
      }),
      createEscrowAgent('agent-3', 'External Auditor', 'external', 'public-key-3', {
        organization: 'Audit Corp',
      }),
    ];

    // Create test configuration with 2-of-3 threshold
    testConfig = createEscrowConfig('config-1', 'Standard Escrow', testAgents, 2, {
      approvers: ['approver-1', 'approver-2'],
    });
  });

  describe('configuration management', () => {
    it('should create escrow configuration', () => {
      manager.createConfig(testConfig);

      const config = manager.getConfig('config-1');
      expect(config).toBeDefined();
      expect(config?.threshold).toBe(2);
      expect(config?.escrowAgents.length).toBe(3);
    });

    it('should reject config with threshold > agents', () => {
      const invalidConfig = createEscrowConfig(
        'invalid',
        'Invalid',
        testAgents.slice(0, 2),
        3 // threshold > 2 agents
      );

      expect(() => {
        manager.createConfig(invalidConfig);
      }).toThrow(ComplianceError);
    });

    it('should reject config with threshold < 1', () => {
      const invalidConfig = createEscrowConfig('invalid', 'Invalid', testAgents, 0);

      expect(() => {
        manager.createConfig(invalidConfig);
      }).toThrow(ComplianceError);
    });

    it('should get all configurations', () => {
      manager.createConfig(testConfig);
      manager.createConfig(createEscrowConfig('config-2', 'Config 2', testAgents, 2));

      const configs = manager.getAllConfigs();
      expect(configs.length).toBe(2);
    });

    it('should update configuration', () => {
      manager.createConfig(testConfig);
      manager.updateConfig('config-1', { rotationPeriodDays: 180 });

      const config = manager.getConfig('config-1');
      expect(config?.rotationPeriodDays).toBe(180);
    });

    it('should throw error updating non-existent config', () => {
      expect(() => {
        manager.updateConfig('non-existent', { enabled: false });
      }).toThrow(ComplianceError);
    });
  });

  describe('agent management', () => {
    it('should add agent', () => {
      const agent = createEscrowAgent('new-agent', 'New Agent', 'hsm', 'hsm-public-key');
      manager.addAgent(agent);

      const retrieved = manager.getAgent('new-agent');
      expect(retrieved).toBeDefined();
      expect(retrieved?.type).toBe('hsm');
    });

    it('should get all agents', () => {
      manager.createConfig(testConfig);

      const agents = manager.getAllAgents();
      expect(agents.length).toBe(3);
    });

    it('should disable agent', () => {
      manager.createConfig(testConfig);
      manager.disableAgent('agent-1');

      const agent = manager.getAgent('agent-1');
      expect(agent?.enabled).toBe(false);
    });

    it('should throw error disabling non-existent agent', () => {
      expect(() => {
        manager.disableAgent('non-existent');
      }).toThrow(ComplianceError);
    });
  });

  describe('key escrow', () => {
    beforeEach(() => {
      manager.createConfig(testConfig);
    });

    it('should escrow a key', () => {
      const keyMaterial = new Uint8Array(32).fill(0xab);

      const escrowed = manager.escrowKey('key-001', 'master', keyMaterial, 'config-1');

      expect(escrowed.id).toBeDefined();
      expect(escrowed.keyId).toBe('key-001');
      expect(escrowed.keyType).toBe('master');
      expect(escrowed.status).toBe('active');
      expect(escrowed.encryptedShares.length).toBe(3);
    });

    it('should escrow key with expiration', () => {
      const keyMaterial = new Uint8Array(32).fill(0xcd);
      const expiresAt = new Date();
      expiresAt.setFullYear(expiresAt.getFullYear() + 1);

      const escrowed = manager.escrowKey('key-002', 'signing', keyMaterial, 'config-1', expiresAt);

      expect(escrowed.expiresAt).toEqual(expiresAt);
    });

    it('should reject escrow with disabled config', () => {
      manager.updateConfig('config-1', { enabled: false });

      expect(() => {
        manager.escrowKey('key-001', 'master', new Uint8Array(32), 'config-1');
      }).toThrow(ComplianceError);
    });

    it('should reject escrow with non-existent config', () => {
      expect(() => {
        manager.escrowKey('key-001', 'master', new Uint8Array(32), 'non-existent');
      }).toThrow(ComplianceError);
    });

    it('should get escrowed key by ID', () => {
      const keyMaterial = new Uint8Array(32).fill(0xef);
      const escrowed = manager.escrowKey('key-001', 'master', keyMaterial, 'config-1');

      const retrieved = manager.getEscrowedKey(escrowed.id);
      expect(retrieved).toEqual(escrowed);
    });

    it('should get escrowed keys by original key ID', () => {
      const keyMaterial = new Uint8Array(32).fill(0x11);
      manager.escrowKey('key-001', 'master', keyMaterial, 'config-1');
      manager.escrowKey('key-001', 'share', keyMaterial, 'config-1');
      manager.escrowKey('key-002', 'master', keyMaterial, 'config-1');

      const keys = manager.getEscrowedKeysByKeyId('key-001');
      expect(keys.length).toBe(2);
    });

    it('should filter escrowed keys', () => {
      const keyMaterial = new Uint8Array(32).fill(0x22);
      manager.escrowKey('key-001', 'master', keyMaterial, 'config-1');
      manager.escrowKey('key-002', 'signing', keyMaterial, 'config-1');

      const masterKeys = manager.getAllEscrowedKeys({ keyType: 'master' });
      expect(masterKeys.length).toBe(1);
    });
  });

  describe('recovery workflow', () => {
    let escrowedKeyId: string;

    beforeEach(() => {
      manager.createConfig(testConfig);
      const keyMaterial = new Uint8Array(32).fill(0x33);
      const escrowed = manager.escrowKey('key-001', 'master', keyMaterial, 'config-1');
      escrowedKeyId = escrowed.id;
    });

    it('should request recovery', () => {
      const request = manager.requestRecovery(
        escrowedKeyId,
        'requester@example.com',
        'Key needed for audit'
      );

      expect(request.id).toBeDefined();
      expect(request.status).toBe('pending');
      expect(request.reason).toBe('Key needed for audit');
    });

    it('should auto-approve if approval not required', () => {
      manager.updateConfig('config-1', { requiresApproval: false });

      const request = manager.requestRecovery(
        escrowedKeyId,
        'requester@example.com',
        'Urgent'
      );

      expect(request.status).toBe('approved');
    });

    it('should throw error for non-existent escrowed key', () => {
      expect(() => {
        manager.requestRecovery('non-existent', 'user', 'reason');
      }).toThrow(ComplianceError);
    });

    it('should throw error for inactive escrowed key', () => {
      manager.revokeEscrowedKey(escrowedKeyId, 'admin', 'Compromised');

      expect(() => {
        manager.requestRecovery(escrowedKeyId, 'user', 'reason');
      }).toThrow(ComplianceError);
    });

    it('should approve recovery request', () => {
      const request = manager.requestRecovery(
        escrowedKeyId,
        'requester@example.com',
        'Audit'
      );

      const updated = manager.approveRecovery(request.id, 'approver-1', 'Approved');

      expect(updated.approvals.length).toBe(1);
      expect(updated.approvals[0].decision).toBe('approved');
      expect(updated.status).toBe('approved'); // 1 approval needed (majority of 2)
    });

    it('should reject unauthorized approver', () => {
      const request = manager.requestRecovery(
        escrowedKeyId,
        'requester@example.com',
        'Audit'
      );

      expect(() => {
        manager.approveRecovery(request.id, 'unauthorized-user');
      }).toThrow(ComplianceError);
    });

    it('should reject recovery request', () => {
      const request = manager.requestRecovery(
        escrowedKeyId,
        'requester@example.com',
        'Invalid reason'
      );

      const rejected = manager.rejectRecovery(request.id, 'approver-1', 'Not justified');

      expect(rejected.status).toBe('rejected');
    });

    it('should not approve already decided request', () => {
      const request = manager.requestRecovery(
        escrowedKeyId,
        'requester@example.com',
        'Test'
      );

      manager.rejectRecovery(request.id, 'approver-1');

      expect(() => {
        manager.approveRecovery(request.id, 'approver-2');
      }).toThrow(ComplianceError);
    });
  });

  describe('key recovery', () => {
    let escrowedKey: ReturnType<typeof manager.escrowKey>;
    let keyMaterial: Uint8Array;

    beforeEach(() => {
      manager.createConfig(testConfig);
      keyMaterial = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        keyMaterial[i] = i;
      }
      escrowedKey = manager.escrowKey('key-001', 'master', keyMaterial, 'config-1');
    });

    it('should complete recovery with sufficient shares', () => {
      // Request and approve recovery
      const request = manager.requestRecovery(escrowedKey.id, 'user', 'Audit');
      manager.approveRecovery(request.id, 'approver-1');

      // In a real scenario, agents would decrypt their shares
      // For testing, we simulate providing decrypted shares
      const simulatedShares = new Map<string, Uint8Array>();

      // We need to extract the shares that were created
      // In production, each agent would decrypt their share using their private key
      // For this test, we'll provide mock decrypted shares
      const share1 = new Uint8Array(keyMaterial.length + 1);
      share1[0] = 1;
      share1.set(keyMaterial, 1);

      const share2 = new Uint8Array(keyMaterial.length + 1);
      share2[0] = 2;
      share2.set(keyMaterial, 1);

      simulatedShares.set('agent-1', share1);
      simulatedShares.set('agent-2', share2);

      // This tests the recovery workflow
      // The actual cryptographic recovery is implementation-dependent
      expect(() => {
        manager.completeRecovery(request.id, simulatedShares, 'recoverer');
      }).not.toThrow();

      // Verify status update
      const updated = manager.getEscrowedKey(escrowedKey.id);
      expect(updated?.status).toBe('recovered');
      expect(updated?.recoveredBy).toBe('recoverer');
    });

    it('should reject recovery without approval', () => {
      const request = manager.requestRecovery(escrowedKey.id, 'user', 'Test');

      expect(() => {
        manager.completeRecovery(request.id, new Map(), 'user');
      }).toThrow(ComplianceError);
    });

    it('should reject recovery with insufficient shares', () => {
      const request = manager.requestRecovery(escrowedKey.id, 'user', 'Test');
      manager.approveRecovery(request.id, 'approver-1');

      const singleShare = new Map<string, Uint8Array>();
      singleShare.set('agent-1', new Uint8Array(33));

      expect(() => {
        manager.completeRecovery(request.id, singleShare, 'user');
      }).toThrow(ComplianceError);
    });
  });

  describe('key lifecycle', () => {
    beforeEach(() => {
      manager.createConfig(testConfig);
    });

    it('should revoke escrowed key', () => {
      const keyMaterial = new Uint8Array(32).fill(0x44);
      const escrowed = manager.escrowKey('key-001', 'master', keyMaterial, 'config-1');

      manager.revokeEscrowedKey(escrowed.id, 'admin', 'Key compromised');

      const updated = manager.getEscrowedKey(escrowed.id);
      expect(updated?.status).toBe('revoked');
    });

    it('should process expirations', () => {
      const keyMaterial = new Uint8Array(32).fill(0x55);
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 1);

      manager.escrowKey('key-001', 'master', keyMaterial, 'config-1', pastDate);

      const expiredCount = manager.processExpirations();
      expect(expiredCount).toBe(1);

      const keys = manager.getAllEscrowedKeys({ status: 'expired' });
      expect(keys.length).toBe(1);
    });

    it('should not expire active keys', () => {
      const keyMaterial = new Uint8Array(32).fill(0x66);
      const futureDate = new Date();
      futureDate.setFullYear(futureDate.getFullYear() + 1);

      manager.escrowKey('key-001', 'master', keyMaterial, 'config-1', futureDate);

      const expiredCount = manager.processExpirations();
      expect(expiredCount).toBe(0);
    });
  });

  describe('recovery request management', () => {
    beforeEach(() => {
      manager.createConfig(testConfig);
    });

    it('should get recovery requests with filters', () => {
      const keyMaterial = new Uint8Array(32).fill(0x77);
      const escrowed1 = manager.escrowKey('key-001', 'master', keyMaterial, 'config-1');
      const escrowed2 = manager.escrowKey('key-002', 'master', keyMaterial, 'config-1');

      manager.requestRecovery(escrowed1.id, 'user1', 'Reason 1');
      const request2 = manager.requestRecovery(escrowed2.id, 'user2', 'Reason 2');
      manager.approveRecovery(request2.id, 'approver-1');

      const pending = manager.getRecoveryRequests({ status: 'pending' });
      expect(pending.length).toBe(1);

      const approved = manager.getRecoveryRequests({ status: 'approved' });
      expect(approved.length).toBe(1);
    });
  });

  describe('statistics', () => {
    beforeEach(() => {
      manager.createConfig(testConfig);
      manager.createConfig(createEscrowConfig('config-2', 'Config 2', testAgents, 2));
    });

    it('should calculate statistics', () => {
      const keyMaterial = new Uint8Array(32).fill(0x88);

      // Create some escrowed keys
      manager.escrowKey('key-001', 'master', keyMaterial, 'config-1');
      manager.escrowKey('key-002', 'signing', keyMaterial, 'config-1');
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 1);
      manager.escrowKey('key-003', 'encryption', keyMaterial, 'config-1', pastDate);

      // Process expirations
      manager.processExpirations();

      const stats = manager.getStatistics();

      expect(stats.totalConfigs).toBe(2);
      expect(stats.totalAgents).toBe(3);
      expect(stats.activeEscrowedKeys).toBe(2);
      expect(stats.expiredKeys).toBe(1);
    });
  });

  describe('audit logging', () => {
    beforeEach(() => {
      manager.createConfig(testConfig);
    });

    it('should record audit entries', () => {
      const keyMaterial = new Uint8Array(32).fill(0x99);
      manager.escrowKey('key-001', 'master', keyMaterial, 'config-1');

      const auditLog = manager.getAuditLog();
      expect(auditLog.length).toBeGreaterThan(0);
    });

    it('should verify audit integrity', () => {
      const keyMaterial = new Uint8Array(32).fill(0xaa);
      manager.escrowKey('key-001', 'master', keyMaterial, 'config-1');
      manager.escrowKey('key-002', 'signing', keyMaterial, 'config-1');

      const result = manager.verifyAuditIntegrity();
      expect(result.valid).toBe(true);
      expect(result.invalidEntryIds.length).toBe(0);
    });

    it('should maintain hash chain', () => {
      const keyMaterial = new Uint8Array(32).fill(0xbb);
      manager.escrowKey('key-001', 'master', keyMaterial, 'config-1');
      manager.escrowKey('key-002', 'signing', keyMaterial, 'config-1');

      const auditLog = manager.getAuditLog();
      expect(auditLog[1].previousHash).toBe(auditLog[0].hash);
    });
  });

  describe('helper functions', () => {
    it('should create escrow agent with defaults', () => {
      const agent = createEscrowAgent('test', 'Test Agent', 'internal', 'pk123');

      expect(agent.id).toBe('test');
      expect(agent.enabled).toBe(true);
    });

    it('should create escrow config with defaults', () => {
      const config = createEscrowConfig('test', 'Test Config', testAgents, 2);

      expect(config.encryptionAlgorithm).toBe('AES-256-GCM');
      expect(config.keyDerivation).toBe('PBKDF2');
      expect(config.rotationPeriodDays).toBe(365);
      expect(config.requiresApproval).toBe(true);
      expect(config.enabled).toBe(true);
    });

    it('should allow overriding defaults', () => {
      const config = createEscrowConfig('test', 'Test Config', testAgents, 2, {
        encryptionAlgorithm: 'ChaCha20-Poly1305',
        requiresApproval: false,
      });

      expect(config.encryptionAlgorithm).toBe('ChaCha20-Poly1305');
      expect(config.requiresApproval).toBe(false);
    });
  });
});

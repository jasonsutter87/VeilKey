/**
 * Tests for ShareManager
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ShareManager } from './index.js';
import { VeilKey } from '../veilkey.js';
import type { KeyGroup, ShareHolder } from './types.js';

describe('ShareManager', () => {
  let manager: ShareManager;
  let keyGroup: KeyGroup;

  beforeEach(async () => {
    // Create a new manager for each test
    manager = new ShareManager({
      storage: 'memory',
      enableAudit: true,
    });
    await manager.init();

    // Generate a test key group
    keyGroup = await VeilKey.generate({
      threshold: 2,
      parties: 3,
      algorithm: 'RSA-2048',
    });
  });

  // ===========================================================================
  // Initialization
  // ===========================================================================

  describe('Initialization', () => {
    it('should initialize successfully', async () => {
      const newManager = new ShareManager();
      await newManager.init();
      expect(newManager).toBeDefined();
    });

    it('should throw if not initialized', async () => {
      const newManager = new ShareManager();
      await expect(
        newManager.listShares()
      ).rejects.toThrow('ShareManager not initialized');
    });

    it('should allow multiple init calls', async () => {
      await manager.init();
      await manager.init(); // Should not throw
    });
  });

  // ===========================================================================
  // Share Storage
  // ===========================================================================

  describe('Share Storage', () => {
    it('should store encrypted shares', async () => {
      const shareIds = await manager.storeShares(keyGroup, {
        password: 'test-password',
        labels: ['Trustee 1', 'Trustee 2', 'Trustee 3'],
      });

      expect(shareIds).toHaveLength(3);
      expect(shareIds[0]).toMatch(/^[0-9a-f-]+$/);
    });

    it('should list stored shares', async () => {
      await manager.storeShares(keyGroup, {
        password: 'test-password',
      });

      const shares = await manager.listShares();
      expect(shares).toHaveLength(3);
      expect(shares[0].metadata.algorithm).toBe('RSA-2048');
      expect(shares[0].metadata.threshold).toBe(2);
      expect(shares[0].metadata.parties).toBe(3);
    });

    it('should include custom labels and tags', async () => {
      const shareIds = await manager.storeShares(keyGroup, {
        password: 'test-password',
        labels: ['Alice', 'Bob', 'Charlie'],
        tags: ['election-2024', 'important'],
      });

      const shares = await manager.listShares();
      expect(shares[0].metadata.label).toBe('Alice');
      expect(shares[0].metadata.tags).toEqual(['election-2024', 'important']);
    });

    it('should generate unique IDs for shares', async () => {
      const shareIds1 = await manager.storeShares(keyGroup, {
        password: 'password1',
      });

      const shareIds2 = await manager.storeShares(keyGroup, {
        password: 'password2',
      });

      expect(shareIds1[0]).not.toBe(shareIds2[0]);
    });
  });

  // ===========================================================================
  // Share Retrieval
  // ===========================================================================

  describe('Share Retrieval', () => {
    let shareIds: string[];
    let alice: ShareHolder;

    beforeEach(async () => {
      // Store shares
      shareIds = await manager.storeShares(keyGroup, {
        password: 'test-password',
      });

      // Create holder
      alice = await manager.createHolder({
        name: 'Alice',
        role: 'trustee',
        contact: 'alice@example.com',
      });

      // Assign share to holder
      await manager.assignShare(shareIds[0], alice.id);
    });

    it('should retrieve and decrypt a share', async () => {
      const result = await manager.getShare(shareIds[0], alice.id, {
        password: 'test-password',
      });

      expect(result.share).toBeDefined();
      expect(result.share.index).toBe(keyGroup.shares[0].index);
      expect(result.share.value).toBe(keyGroup.shares[0].value);
      expect(result.metadata.algorithm).toBe('RSA-2048');
    });

    it('should fail with wrong password', async () => {
      await expect(
        manager.getShare(shareIds[0], alice.id, {
          password: 'wrong-password',
        })
      ).rejects.toThrow('Decryption failed');
    });

    it('should fail if holder not found', async () => {
      await expect(
        manager.getShare(shareIds[0], 'nonexistent-holder', {
          password: 'test-password',
        })
      ).rejects.toThrow('Holder not found');
    });

    it('should fail if share not found', async () => {
      // Alice is a trustee, so unauthorized for nonexistent shares (correct security behavior)
      await expect(
        manager.getShare('nonexistent-share', alice.id, {
          password: 'test-password',
        })
      ).rejects.toThrow('Unauthorized');
    });

    it('should fail if holder not assigned to share', async () => {
      const bob = await manager.createHolder({
        name: 'Bob',
        role: 'trustee',
      });

      await expect(
        manager.getShare(shareIds[0], bob.id, {
          password: 'test-password',
        })
      ).rejects.toThrow('Unauthorized');
    });

    it('should allow admin to access any share', async () => {
      const admin = await manager.createHolder({
        name: 'Admin',
        role: 'admin',
      });

      // Admin can access without assignment
      const result = await manager.getShare(shareIds[0], admin.id, {
        password: 'test-password',
      });

      expect(result.share).toBeDefined();
    });

    it('should update last accessed timestamp', async () => {
      const sharesBefore = await manager.listShares();
      expect(sharesBefore[0].lastAccessedAt).toBeUndefined();

      await manager.getShare(shareIds[0], alice.id, {
        password: 'test-password',
      });

      const sharesAfter = await manager.listShares();
      expect(sharesAfter[0].lastAccessedAt).toBeDefined();
    });
  });

  // ===========================================================================
  // Share Deletion
  // ===========================================================================

  describe('Share Deletion', () => {
    it('should delete a share', async () => {
      const shareIds = await manager.storeShares(keyGroup, {
        password: 'test-password',
      });

      const admin = await manager.createHolder({
        name: 'Admin',
        role: 'admin',
      });

      const deleted = await manager.deleteShare(shareIds[0], admin.id);
      expect(deleted).toBe(true);

      const shares = await manager.listShares();
      expect(shares).toHaveLength(2);
    });

    it('should fail if not admin', async () => {
      const shareIds = await manager.storeShares(keyGroup, {
        password: 'test-password',
      });

      const trustee = await manager.createHolder({
        name: 'Trustee',
        role: 'trustee',
      });

      await expect(
        manager.deleteShare(shareIds[0], trustee.id)
      ).rejects.toThrow('Unauthorized');
    });
  });

  // ===========================================================================
  // Holders
  // ===========================================================================

  describe('Holders', () => {
    it('should create a holder', async () => {
      const holder = await manager.createHolder({
        name: 'Alice',
        role: 'trustee',
        contact: 'alice@example.com',
      });

      expect(holder.id).toMatch(/^[0-9a-f-]+$/);
      expect(holder.name).toBe('Alice');
      expect(holder.role).toBe('trustee');
      expect(holder.contact).toBe('alice@example.com');
      expect(holder.active).toBe(true);
    });

    it('should get a holder by ID', async () => {
      const created = await manager.createHolder({
        name: 'Bob',
        role: 'admin',
      });

      const retrieved = await manager.getHolder(created.id);
      expect(retrieved).toEqual(created);
    });

    it('should list all holders', async () => {
      await manager.createHolder({ name: 'Alice', role: 'trustee' });
      await manager.createHolder({ name: 'Bob', role: 'admin' });
      await manager.createHolder({ name: 'Charlie', role: 'auditor' });

      const holders = await manager.listHolders();
      expect(holders).toHaveLength(3);
    });

    it('should update a holder', async () => {
      const holder = await manager.createHolder({
        name: 'Alice',
        role: 'trustee',
      });

      const updated = await manager.updateHolder(holder.id, {
        name: 'Alice Smith',
        contact: 'alice.smith@example.com',
      });

      expect(updated.name).toBe('Alice Smith');
      expect(updated.contact).toBe('alice.smith@example.com');
      expect(updated.role).toBe('trustee');
    });

    it('should deactivate a holder', async () => {
      const holder = await manager.createHolder({
        name: 'Alice',
        role: 'trustee',
      });

      const updated = await manager.updateHolder(holder.id, {
        active: false,
      });

      expect(updated.active).toBe(false);
    });
  });

  // ===========================================================================
  // Share Assignment
  // ===========================================================================

  describe('Share Assignment', () => {
    let shareIds: string[];
    let alice: ShareHolder;

    beforeEach(async () => {
      shareIds = await manager.storeShares(keyGroup, {
        password: 'test-password',
      });

      alice = await manager.createHolder({
        name: 'Alice',
        role: 'trustee',
      });
    });

    it('should assign a share to a holder', async () => {
      const assignment = await manager.assignShare(shareIds[0], alice.id);

      expect(assignment.shareId).toBe(shareIds[0]);
      expect(assignment.holderId).toBe(alice.id);
      expect(assignment.active).toBe(true);
    });

    it('should get assignments for a holder', async () => {
      await manager.assignShare(shareIds[0], alice.id);
      await manager.assignShare(shareIds[1], alice.id);

      const assignments = await manager.getAssignmentsByHolder(alice.id);
      expect(assignments).toHaveLength(2);
    });

    it('should fail if share already assigned', async () => {
      await manager.assignShare(shareIds[0], alice.id);

      const bob = await manager.createHolder({
        name: 'Bob',
        role: 'trustee',
      });

      await expect(
        manager.assignShare(shareIds[0], bob.id)
      ).rejects.toThrow('already assigned');
    });

    it('should unassign a share', async () => {
      await manager.assignShare(shareIds[0], alice.id);

      const unassigned = await manager.unassignShare(shareIds[0]);
      expect(unassigned).toBe(true);

      const assignments = await manager.getAssignmentsByHolder(alice.id);
      expect(assignments[0].active).toBe(false);
    });

    it('should support expiration dates', async () => {
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1);

      const assignment = await manager.assignShare(
        shareIds[0],
        alice.id,
        tomorrow
      );

      expect(assignment.expiresAt).toEqual(tomorrow);
    });
  });

  // ===========================================================================
  // Access Control
  // ===========================================================================

  describe('Access Control', () => {
    let shareIds: string[];

    beforeEach(async () => {
      shareIds = await manager.storeShares(keyGroup, {
        password: 'test-password',
      });
    });

    it('should allow trustee to read assigned shares', async () => {
      const trustee = await manager.createHolder({
        name: 'Trustee',
        role: 'trustee',
      });

      await manager.assignShare(shareIds[0], trustee.id);

      const result = await manager.getShare(shareIds[0], trustee.id, {
        password: 'test-password',
      });

      expect(result.share).toBeDefined();
    });

    it('should deny trustee access to unassigned shares', async () => {
      const trustee = await manager.createHolder({
        name: 'Trustee',
        role: 'trustee',
      });

      await expect(
        manager.getShare(shareIds[0], trustee.id, {
          password: 'test-password',
        })
      ).rejects.toThrow('Unauthorized');
    });

    it('should deny auditor access to shares', async () => {
      const auditor = await manager.createHolder({
        name: 'Auditor',
        role: 'auditor',
      });

      await expect(
        manager.getShare(shareIds[0], auditor.id, {
          password: 'test-password',
        })
      ).rejects.toThrow('Unauthorized');
    });

    it('should deny inactive holder access', async () => {
      const trustee = await manager.createHolder({
        name: 'Trustee',
        role: 'trustee',
      });

      await manager.assignShare(shareIds[0], trustee.id);
      await manager.updateHolder(trustee.id, { active: false });

      await expect(
        manager.getShare(shareIds[0], trustee.id, {
          password: 'test-password',
        })
      ).rejects.toThrow('Unauthorized');
    });
  });

  // ===========================================================================
  // Audit Logging
  // ===========================================================================

  describe('Audit Logging', () => {
    it('should log share creation', async () => {
      await manager.storeShares(keyGroup, {
        password: 'test-password',
      });

      const auditLog = await manager.getAuditLog();
      expect(auditLog.entries).toHaveLength(3); // One per share
      expect(auditLog.entries[0].event).toBe('share.created');
    });

    it('should log share access', async () => {
      const shareIds = await manager.storeShares(keyGroup, {
        password: 'test-password',
      });

      const alice = await manager.createHolder({
        name: 'Alice',
        role: 'admin',
      });

      await manager.getShare(shareIds[0], alice.id, {
        password: 'test-password',
      });

      const auditLog = await manager.getAuditLog();
      const accessEvents = auditLog.entries.filter(
        e => e.event === 'share.accessed'
      );
      expect(accessEvents).toHaveLength(1);
      expect(accessEvents[0].actor).toBe('Alice');
    });

    it('should log holder creation', async () => {
      await manager.createHolder({
        name: 'Alice',
        role: 'trustee',
      });

      const auditLog = await manager.getAuditLog();
      const holderEvents = auditLog.entries.filter(
        e => e.event === 'holder.created'
      );
      expect(holderEvents).toHaveLength(1);
    });

    it('should log share assignment', async () => {
      const shareIds = await manager.storeShares(keyGroup, {
        password: 'test-password',
      });

      const alice = await manager.createHolder({
        name: 'Alice',
        role: 'trustee',
      });

      await manager.assignShare(shareIds[0], alice.id);

      const auditLog = await manager.getAuditLog();
      const assignEvents = auditLog.entries.filter(
        e => e.event === 'share.assigned'
      );
      expect(assignEvents).toHaveLength(1);
    });

    it('should create hash chain', async () => {
      await manager.createHolder({ name: 'Alice', role: 'trustee' });
      await manager.createHolder({ name: 'Bob', role: 'trustee' });
      await manager.createHolder({ name: 'Charlie', role: 'trustee' });

      const auditLog = await manager.getAuditLog();

      // First entry should have no previous hash
      expect(auditLog.entries[0].previousHash).toBeUndefined();

      // Subsequent entries should link to previous
      expect(auditLog.entries[1].previousHash).toBe(auditLog.entries[0].hash);
      expect(auditLog.entries[2].previousHash).toBe(auditLog.entries[1].hash);
    });

    it('should verify audit log integrity', async () => {
      await manager.createHolder({ name: 'Alice', role: 'trustee' });
      await manager.createHolder({ name: 'Bob', role: 'trustee' });

      const verification = await manager.verifyAuditLog();

      expect(verification.valid).toBe(true);
      expect(verification.totalEntries).toBe(2);
      expect(verification.invalidEntries).toHaveLength(0);
    });

    it('should detect tampering', async () => {
      await manager.createHolder({ name: 'Alice', role: 'trustee' });
      await manager.createHolder({ name: 'Bob', role: 'trustee' });

      // Get the audit log
      const auditLog = await manager.getAuditLog();

      // Tamper with an entry
      // @ts-ignore - accessing private storage for testing
      const entries = await manager.storage.getAuditEntries();
      entries[0].actor = 'Mallory'; // Change actor

      // Verification should fail
      const verification = await manager.verifyAuditLog();
      expect(verification.valid).toBe(false);
      expect(verification.invalidEntries).toContain(0);
    });

    it('should export audit log', async () => {
      await manager.createHolder({ name: 'Alice', role: 'trustee' });

      const auditLog = await manager.getAuditLog();

      expect(auditLog.entries).toHaveLength(1);
      expect(auditLog.exportedAt).toBeInstanceOf(Date);
      expect(auditLog.logHash).toBeDefined();
      expect(auditLog.verified).toBe(true);
    });

    it('should skip audit if requested', async () => {
      const shareIds = await manager.storeShares(keyGroup, {
        password: 'test-password',
      });

      const alice = await manager.createHolder({
        name: 'Alice',
        role: 'admin',
      });

      await manager.getShare(shareIds[0], alice.id, {
        password: 'test-password',
        skipAudit: true,
      });

      const auditLog = await manager.getAuditLog();
      const accessEvents = auditLog.entries.filter(
        e => e.event === 'share.accessed'
      );
      expect(accessEvents).toHaveLength(0);
    });
  });

  // ===========================================================================
  // Integration Tests
  // ===========================================================================

  describe('Integration', () => {
    it('should support full workflow', async () => {
      // 1. Generate keys
      const keys = await VeilKey.generate({
        threshold: 2,
        parties: 3,
        algorithm: 'RSA-2048',
      });

      // 2. Store shares
      const shareIds = await manager.storeShares(keys, {
        password: 'secure-password',
        labels: ['Alice', 'Bob', 'Charlie'],
        tags: ['production'],
      });

      // 3. Create holders
      const alice = await manager.createHolder({
        name: 'Alice',
        role: 'trustee',
        contact: 'alice@example.com',
      });

      const bob = await manager.createHolder({
        name: 'Bob',
        role: 'trustee',
        contact: 'bob@example.com',
      });

      const charlie = await manager.createHolder({
        name: 'Charlie',
        role: 'trustee',
        contact: 'charlie@example.com',
      });

      // 4. Assign shares
      await manager.assignShare(shareIds[0], alice.id);
      await manager.assignShare(shareIds[1], bob.id);
      await manager.assignShare(shareIds[2], charlie.id);

      // 5. Retrieve shares for threshold operation
      const share1 = await manager.getShare(shareIds[0], alice.id, {
        password: 'secure-password',
      });

      const share2 = await manager.getShare(shareIds[1], bob.id, {
        password: 'secure-password',
      });

      // 6. Use shares for threshold decryption
      const plaintext = 0x123456789ABCDEFn;
      const ciphertext = await VeilKey.encrypt(plaintext, keys);

      const partial1 = await VeilKey.partialDecrypt(
        ciphertext,
        share1.share,
        keys
      );

      const partial2 = await VeilKey.partialDecrypt(
        ciphertext,
        share2.share,
        keys
      );

      const recovered = await VeilKey.combineDecryptions(
        ciphertext,
        [partial1, partial2],
        keys
      );

      expect(BigInt('0x' + recovered)).toBe(plaintext);

      // 7. Verify audit log
      const verification = await manager.verifyAuditLog();
      expect(verification.valid).toBe(true);
    });
  });

  // ===========================================================================
  // Error Handling
  // ===========================================================================

  describe('Error Handling', () => {
    it('should handle missing share gracefully', async () => {
      const admin = await manager.createHolder({
        name: 'Admin',
        role: 'admin',
      });

      await expect(
        manager.getShare('nonexistent', admin.id, {
          password: 'test',
        })
      ).rejects.toThrow(); // Share not found or similar error
    });

    it('should handle missing holder gracefully', async () => {
      const shareIds = await manager.storeShares(keyGroup, {
        password: 'test',
      });

      await expect(
        manager.getShare(shareIds[0], 'nonexistent', {
          password: 'test',
        })
      ).rejects.toThrow('Holder not found');
    });

    it('should validate share assignment', async () => {
      await expect(
        manager.assignShare('nonexistent-share', 'nonexistent-holder')
      ).rejects.toThrow('Share not found');
    });
  });
});

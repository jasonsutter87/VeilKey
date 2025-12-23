/**
 * Tests for Key Ceremony System
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { CeremonyCoordinator } from './coordinator.js';
import {
  CeremonyPhase,
  ParticipantStatus,
  CeremonyError,
  type CeremonyConfig,
} from './types.js';
import {
  generateCommitmentHash,
  verifyCommitmentHash,
} from './commitment.js';
import { verifyAuditLog } from './state-machine.js';
import { split as feldmanSplit } from '../feldman/index.js';

describe('CeremonyCoordinator', () => {
  let config: CeremonyConfig;

  beforeEach(() => {
    config = {
      id: 'test-ceremony-' + Date.now(),
      threshold: 3,
      totalParticipants: 5,
      description: 'Test ceremony',
    };
  });

  describe('constructor', () => {
    it('should create a new ceremony', () => {
      const coordinator = new CeremonyCoordinator(config);
      const status = coordinator.getStatus();

      expect(status.ceremonyId).toBe(config.id);
      expect(status.phase).toBe(CeremonyPhase.CREATED);
      expect(status.registration.total).toBe(5);
      expect(status.registration.registered).toBe(0);
    });

    it('should throw error for invalid threshold', () => {
      const badConfig = { ...config, threshold: 0 };
      expect(() => new CeremonyCoordinator(badConfig)).toThrow('positive integer');
    });

    it('should throw error for threshold > participants', () => {
      const badConfig = { ...config, threshold: 6, totalParticipants: 5 };
      expect(() => new CeremonyCoordinator(badConfig)).toThrow(
        'cannot exceed total participants'
      );
    });

    it('should throw error for empty ID', () => {
      const badConfig = { ...config, id: '' };
      expect(() => new CeremonyCoordinator(badConfig)).toThrow('cannot be empty');
    });
  });

  describe('registration phase', () => {
    it('should start registration phase', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      expect(coordinator.getCurrentPhase()).toBe(CeremonyPhase.REGISTRATION);
    });

    it('should register participants', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      const participant = coordinator.addParticipant('alice', 'deadbeef');

      expect(participant.id).toBe('alice');
      expect(participant.publicKey).toBe('deadbeef');
      expect(participant.status).toBe(ParticipantStatus.REGISTERED);
      expect(participant.shareIndex).toBe(1);
    });

    it('should register multiple participants', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      coordinator.addParticipant('alice', 'aaaa');
      coordinator.addParticipant('bob', 'bbbb');
      coordinator.addParticipant('charlie', 'cccc');

      const participants = coordinator.getParticipants();
      expect(participants).toHaveLength(3);
      expect(participants.map((p) => p.id)).toEqual(['alice', 'bob', 'charlie']);
    });

    it('should assign sequential share indices', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      const p1 = coordinator.addParticipant('alice', 'aaaa');
      const p2 = coordinator.addParticipant('bob', 'bbbb');
      const p3 = coordinator.addParticipant('charlie', 'cccc');

      expect(p1.shareIndex).toBe(1);
      expect(p2.shareIndex).toBe(2);
      expect(p3.shareIndex).toBe(3);
    });

    it('should throw error for duplicate participant ID', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      coordinator.addParticipant('alice', 'aaaa');

      expect(() => coordinator.addParticipant('alice', 'bbbb')).toThrow(
        'already registered'
      );
    });

    it('should throw error for duplicate public key', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      coordinator.addParticipant('alice', 'aaaa');

      expect(() => coordinator.addParticipant('bob', 'aaaa')).toThrow(
        'already in use'
      );
    });

    it('should throw error when ceremony is full', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      coordinator.addParticipant('p1', 'aa');
      coordinator.addParticipant('p2', 'bb');
      coordinator.addParticipant('p3', 'cc');
      coordinator.addParticipant('p4', 'dd');
      coordinator.addParticipant('p5', 'ee');

      expect(() => coordinator.addParticipant('p6', 'ff')).toThrow(
        'Ceremony is full'
      );
    });

    it('should throw error when not in registration phase', () => {
      const coordinator = new CeremonyCoordinator(config);

      expect(() => coordinator.addParticipant('alice', 'aaaa')).toThrow(
        'ceremony is in CREATED phase'
      );
    });

    it('should track registration progress', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      let status = coordinator.getStatus();
      expect(status.registration.remaining).toBe(5);

      coordinator.addParticipant('alice', 'aa');
      coordinator.addParticipant('bob', 'bb');

      status = coordinator.getStatus();
      expect(status.registration.registered).toBe(2);
      expect(status.registration.remaining).toBe(3);
    });
  });

  describe('commitment phase', () => {
    let coordinator: CeremonyCoordinator;

    beforeEach(() => {
      coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      // Register all participants
      coordinator.addParticipant('alice', 'aa');
      coordinator.addParticipant('bob', 'bb');
      coordinator.addParticipant('charlie', 'cc');
      coordinator.addParticipant('dave', 'dd');
      coordinator.addParticipant('eve', 'ee');
    });

    it('should transition to commitment phase when all registered', () => {
      coordinator.startCommitmentPhase();
      expect(coordinator.getCurrentPhase()).toBe(CeremonyPhase.COMMITMENT);
    });

    it('should throw error if not all participants registered', () => {
      const partial = new CeremonyCoordinator({
        id: 'partial',
        threshold: 2,
        totalParticipants: 3,
      });
      partial.startRegistration();
      partial.addParticipant('alice', 'aa');

      expect(() => partial.startCommitmentPhase()).toThrow('guard conditions not met');
    });

    it('should submit commitments', () => {
      coordinator.startCommitmentPhase();

      // Generate a real commitment
      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, config.threshold, config.totalParticipants);
      const commitmentHash = generateCommitmentHash(['12345']);

      const commitment = coordinator.submitCommitment(
        'alice',
        commitmentHash,
        feldmanResult.commitments
      );

      expect(commitment.participantId).toBe('alice');
      expect(commitment.commitmentHash).toBe(commitmentHash);
      expect(commitment.feldmanCommitments).toHaveLength(config.threshold);
    });

    it('should update participant status on commitment', () => {
      coordinator.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, config.threshold, config.totalParticipants);
      const commitmentHash = generateCommitmentHash(['12345']);

      coordinator.submitCommitment('alice', commitmentHash, feldmanResult.commitments);

      const participant = coordinator.getParticipant('alice');
      expect(participant?.status).toBe(ParticipantStatus.COMMITTED);
    });

    it('should throw error for duplicate commitment', () => {
      coordinator.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, config.threshold, config.totalParticipants);
      const commitmentHash = generateCommitmentHash(['12345']);

      coordinator.submitCommitment('alice', commitmentHash, feldmanResult.commitments);

      expect(() =>
        coordinator.submitCommitment('alice', commitmentHash, feldmanResult.commitments)
      ).toThrow('already submitted');
    });

    it('should throw error for invalid commitment hash', () => {
      coordinator.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, config.threshold, config.totalParticipants);

      expect(() =>
        coordinator.submitCommitment('alice', 'invalid', feldmanResult.commitments)
      ).toThrow('Invalid commitment hash format');
    });

    it('should track commitment progress', () => {
      coordinator.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, config.threshold, config.totalParticipants);
      const commitmentHash = generateCommitmentHash(['12345']);

      let status = coordinator.getStatus();
      expect(status.commitments.received).toBe(0);
      expect(status.commitments.pending).toBe(5);

      coordinator.submitCommitment('alice', commitmentHash, feldmanResult.commitments);
      coordinator.submitCommitment('bob', commitmentHash, feldmanResult.commitments);

      status = coordinator.getStatus();
      expect(status.commitments.received).toBe(2);
      expect(status.commitments.pending).toBe(3);
    });
  });

  describe('finalization', () => {
    let coordinator: CeremonyCoordinator;

    beforeEach(() => {
      coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      // Register all participants
      coordinator.addParticipant('alice', 'aa');
      coordinator.addParticipant('bob', 'bb');
      coordinator.addParticipant('charlie', 'cc');
      coordinator.addParticipant('dave', 'dd');
      coordinator.addParticipant('eve', 'ee');

      coordinator.startCommitmentPhase();

      // Submit all commitments
      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, config.threshold, config.totalParticipants);
      const commitmentHash = generateCommitmentHash(['12345']);

      coordinator.submitCommitment('alice', commitmentHash, feldmanResult.commitments);
      coordinator.submitCommitment('bob', commitmentHash, feldmanResult.commitments);
      coordinator.submitCommitment('charlie', commitmentHash, feldmanResult.commitments);
      coordinator.submitCommitment('dave', commitmentHash, feldmanResult.commitments);
      coordinator.submitCommitment('eve', commitmentHash, feldmanResult.commitments);
    });

    it('should finalize ceremony and generate shares', () => {
      const result = coordinator.finalize();

      expect(result.ceremonyId).toBe(config.id);
      expect(result.threshold).toBe(3);
      expect(result.totalParticipants).toBe(5);
      expect(result.shares).toHaveLength(5);
      expect(result.publicKey).toBeDefined();
      expect(result.publicCommitment).toBeDefined();
      expect(result.commitments).toHaveLength(3); // threshold commitments
    });

    it('should assign shares to correct participants', () => {
      const result = coordinator.finalize();

      const aliceShare = result.shares.find((s) => s.participantId === 'alice');
      const bobShare = result.shares.find((s) => s.participantId === 'bob');

      expect(aliceShare).toBeDefined();
      expect(bobShare).toBeDefined();
      expect(aliceShare?.index).toBe(1);
      expect(bobShare?.index).toBe(2);
    });

    it('should update all participant statuses', () => {
      coordinator.finalize();

      const participants = coordinator.getParticipants();
      for (const participant of participants) {
        expect(participant.status).toBe(ParticipantStatus.SHARE_RECEIVED);
      }
    });

    it('should transition to finalized phase', () => {
      coordinator.finalize();
      expect(coordinator.getCurrentPhase()).toBe(CeremonyPhase.FINALIZED);
      expect(coordinator.isComplete()).toBe(true);
    });

    it('should store result in coordinator', () => {
      const result = coordinator.finalize();
      const storedResult = coordinator.getResult();

      expect(storedResult).toEqual(result);
    });

    it('should allow retrieving shares by participant', () => {
      coordinator.finalize();

      const aliceShare = coordinator.getShareForParticipant('alice');
      expect(aliceShare).toBeDefined();
      expect(aliceShare?.participantId).toBe('alice');
    });
  });

  describe('full ceremony flow (3-of-5)', () => {
    it('should complete a full ceremony', () => {
      const coordinator = new CeremonyCoordinator({
        id: 'election-2024',
        threshold: 3,
        totalParticipants: 5,
        description: 'Test election key ceremony',
      });

      // Phase 1: Registration
      coordinator.startRegistration();
      coordinator.addParticipant('trustee-1', 'a1b2c3d4e5f6');
      coordinator.addParticipant('trustee-2', 'b2c3d4e5f6a1');
      coordinator.addParticipant('trustee-3', 'c3d4e5f6a1b2');
      coordinator.addParticipant('trustee-4', 'd4e5f6a1b2c3');
      coordinator.addParticipant('trustee-5', 'e5f6a1b2c3d4');

      expect(coordinator.getStatus().canProgress).toBe(true);

      // Phase 2: Commitment
      coordinator.startCommitmentPhase();

      const secret = 99999n;
      const feldmanResult = feldmanSplit(secret, 3, 5);
      const hash = generateCommitmentHash(['99999']);

      coordinator.submitCommitment('trustee-1', hash, feldmanResult.commitments);
      coordinator.submitCommitment('trustee-2', hash, feldmanResult.commitments);
      coordinator.submitCommitment('trustee-3', hash, feldmanResult.commitments);
      coordinator.submitCommitment('trustee-4', hash, feldmanResult.commitments);
      coordinator.submitCommitment('trustee-5', hash, feldmanResult.commitments);

      expect(coordinator.getStatus().canProgress).toBe(true);

      // Phase 3: Finalization
      const result = coordinator.finalize();

      expect(result.shares).toHaveLength(5);
      expect(result.threshold).toBe(3);
      expect(coordinator.isComplete()).toBe(true);

      // Verify audit log
      const auditLog = coordinator.getAuditLog();
      expect(auditLog.length).toBeGreaterThan(0);
      expect(coordinator.verifyAuditLog()).toBe(true);
    });
  });

  describe('audit log', () => {
    it('should create audit entries for each action', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'aa');

      const auditLog = coordinator.getAuditLog();

      expect(auditLog.length).toBeGreaterThan(0);
      expect(auditLog[0].eventType).toBe('CEREMONY_CREATED');
    });

    it('should maintain hash chain integrity', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'aa');
      coordinator.addParticipant('bob', 'bb');

      const auditLog = coordinator.getAuditLog();

      // First entry should have zero hash as previous
      expect(auditLog[0].previousHash).toBe('0'.repeat(64));

      // Each subsequent entry should reference previous
      for (let i = 1; i < auditLog.length; i++) {
        expect(auditLog[i].previousHash).toBe(auditLog[i - 1].hash);
      }
    });

    it('should verify audit log integrity', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'aa');

      expect(coordinator.verifyAuditLog()).toBe(true);
    });

    it('should detect tampered audit log', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'aa');

      const auditLog = coordinator.getAuditLog();

      // Tamper with an entry
      auditLog[0].data.tampered = true;

      // Verification should fail
      expect(verifyAuditLog(auditLog)).toBe(false);
    });
  });

  describe('commitment hash utilities', () => {
    it('should generate consistent hashes', () => {
      const coefficients = ['12345', 'abcdef', '999999'];
      const hash1 = generateCommitmentHash(coefficients);
      const hash2 = generateCommitmentHash(coefficients);

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should generate different hashes for different inputs', () => {
      const hash1 = generateCommitmentHash(['12345']);
      const hash2 = generateCommitmentHash(['54321']);

      expect(hash1).not.toBe(hash2);
    });

    it('should verify correct commitment hash', () => {
      const coefficients = ['12345', 'abcdef'];
      const hash = generateCommitmentHash(coefficients);

      expect(verifyCommitmentHash(hash, coefficients)).toBe(true);
    });

    it('should reject incorrect commitment hash', () => {
      const coefficients = ['12345', 'abcdef'];
      const hash = generateCommitmentHash(['different']);

      expect(verifyCommitmentHash(hash, coefficients)).toBe(false);
    });
  });

  describe('error handling', () => {
    it('should throw CeremonyError with code and details', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      try {
        coordinator.addParticipant('alice', 'aa');
        coordinator.addParticipant('alice', 'bb');
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(CeremonyError);
        expect((error as CeremonyError).code).toBe('DUPLICATE_PARTICIPANT');
        expect((error as CeremonyError).details).toBeDefined();
      }
    });
  });

  describe('export/import', () => {
    it('should export ceremony state as JSON', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'aa');

      const json = coordinator.exportState();
      expect(json).toBeTruthy();
      expect(typeof json).toBe('string');

      const parsed = JSON.parse(json);
      expect(parsed.config.id).toBe(config.id);
      expect(parsed.phase).toBe(CeremonyPhase.REGISTRATION);
    });

    it('should import ceremony state from JSON', () => {
      const coordinator1 = new CeremonyCoordinator(config);
      coordinator1.startRegistration();
      coordinator1.addParticipant('alice', 'aa');

      const json = coordinator1.exportState();
      const coordinator2 = CeremonyCoordinator.importState(json);

      const status1 = coordinator1.getStatus();
      const status2 = coordinator2.getStatus();

      expect(status2.ceremonyId).toBe(status1.ceremonyId);
      expect(status2.phase).toBe(status1.phase);
      expect(coordinator2.getParticipants()).toHaveLength(1);
    });
  });
});

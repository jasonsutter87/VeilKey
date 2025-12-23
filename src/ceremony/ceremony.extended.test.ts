/**
 * Extended Tests for Key Ceremony System
 *
 * Comprehensive test coverage for:
 * - All phase transitions
 * - Phase timeout handling
 * - Participant dropout scenarios
 * - Malicious commitment detection
 * - State export/import roundtrip
 * - Concurrent ceremony coordination
 * - Large participant counts
 * - Audit log integrity
 * - Recovery scenarios
 * - Edge cases
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { CeremonyCoordinator } from './coordinator.js';
import {
  CeremonyPhase,
  ParticipantStatus,
  CeremonyError,
  AuditEventType,
  type CeremonyConfig,
} from './types.js';
import {
  generateCommitmentHash,
  verifyCommitmentHash,
} from './commitment.js';
import {
  isValidTransition,
  hasPhaseTimedOut,
  getPhaseDescription,
  getNextPhase,
} from './state-machine.js';
import { split as feldmanSplit } from '../feldman/index.js';

describe('CeremonyCoordinator - Extended Tests', () => {
  let config: CeremonyConfig;

  beforeEach(() => {
    config = {
      id: 'extended-test-' + Date.now(),
      threshold: 3,
      totalParticipants: 5,
      description: 'Extended test ceremony',
    };
  });

  // ===========================================================================
  // Phase Transitions - Comprehensive Coverage
  // ===========================================================================

  describe('Phase Transitions', () => {
    it('should transition through all phases in correct order', () => {
      const coordinator = new CeremonyCoordinator(config);

      expect(coordinator.getCurrentPhase()).toBe(CeremonyPhase.CREATED);

      coordinator.startRegistration();
      expect(coordinator.getCurrentPhase()).toBe(CeremonyPhase.REGISTRATION);

      // Register all participants
      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }

      coordinator.startCommitmentPhase();
      expect(coordinator.getCurrentPhase()).toBe(CeremonyPhase.COMMITMENT);

      // Submit all commitments
      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 3, 5);
      const hash = generateCommitmentHash(['12345']);

      for (let i = 1; i <= 5; i++) {
        coordinator.submitCommitment(`p${i}`, hash, feldmanResult.commitments);
      }

      coordinator.finalize();
      expect(coordinator.getCurrentPhase()).toBe(CeremonyPhase.FINALIZED);
    });

    it('should prevent skipping phases', () => {
      const coordinator = new CeremonyCoordinator(config);

      // Cannot jump directly to commitment
      expect(() => coordinator.startCommitmentPhase()).toThrow('Invalid phase transition');

      coordinator.startRegistration();

      // Cannot jump directly to finalized
      expect(() => coordinator.finalize()).toThrow('Invalid phase transition');
    });

    it('should prevent backward phase transitions', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      // Register all participants
      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }

      coordinator.startCommitmentPhase();

      // Cannot go back to registration
      expect(() => coordinator.startRegistration()).toThrow('Invalid phase transition');
    });

    it('should track all phase transitions in audit log', () => {
      const coordinator = new CeremonyCoordinator(config);

      coordinator.startRegistration();
      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }
      coordinator.startCommitmentPhase();

      const auditLog = coordinator.getAuditLog();
      const phaseTransitions = auditLog.filter(
        e => e.eventType === AuditEventType.PHASE_TRANSITION
      );

      expect(phaseTransitions.length).toBeGreaterThanOrEqual(2);
      expect(phaseTransitions[0].data.to).toBe(CeremonyPhase.REGISTRATION);
      expect(phaseTransitions[1].data.to).toBe(CeremonyPhase.COMMITMENT);
    });

    it('should maintain canProgress status correctly across phases', () => {
      const coordinator = new CeremonyCoordinator(config);

      // CREATED phase can always progress
      expect(coordinator.getStatus().canProgress).toBe(true);

      coordinator.startRegistration();
      // REGISTRATION cannot progress until all registered
      expect(coordinator.getStatus().canProgress).toBe(false);

      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }
      expect(coordinator.getStatus().canProgress).toBe(true);

      coordinator.startCommitmentPhase();
      expect(coordinator.getStatus().canProgress).toBe(false);

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 3, 5);
      const hash = generateCommitmentHash(['12345']);

      for (let i = 1; i <= 5; i++) {
        coordinator.submitCommitment(`p${i}`, hash, feldmanResult.commitments);
      }
      expect(coordinator.getStatus().canProgress).toBe(true);
    });

    it('should report correct next phase at each stage', () => {
      const coordinator = new CeremonyCoordinator(config);

      expect(coordinator.getStatus().nextPhase).toBe(CeremonyPhase.REGISTRATION);

      coordinator.startRegistration();
      expect(coordinator.getStatus().nextPhase).toBe(CeremonyPhase.COMMITMENT);

      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }
      coordinator.startCommitmentPhase();
      expect(coordinator.getStatus().nextPhase).toBe(CeremonyPhase.SHARE_DISTRIBUTION);
    });
  });

  // ===========================================================================
  // Phase Timeout Handling
  // ===========================================================================

  describe('Phase Timeouts', () => {
    it('should detect phase timeout when configured', () => {
      const timeoutConfig: CeremonyConfig = {
        ...config,
        phaseTimeout: 1000, // 1 second
      };

      const coordinator = new CeremonyCoordinator(timeoutConfig);
      coordinator.startRegistration();

      // Initially not timed out
      const initialState = (coordinator as any).state;
      expect(hasPhaseTimedOut(initialState)).toBe(false);

      // Fast-forward by manipulating updatedAt
      initialState.updatedAt = new Date(Date.now() - 2000);
      expect(hasPhaseTimedOut(initialState)).toBe(true);
    });

    it('should not timeout when phaseTimeout is not set', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      const state = (coordinator as any).state;
      state.updatedAt = new Date(Date.now() - 1000000);
      expect(hasPhaseTimedOut(state)).toBe(false);
    });

    it('should throw error for negative timeout in config', () => {
      const badConfig: CeremonyConfig = {
        ...config,
        phaseTimeout: -100,
      };

      expect(() => new CeremonyCoordinator(badConfig)).toThrow('cannot be negative');
    });
  });

  // ===========================================================================
  // Participant Dropout Scenarios
  // ===========================================================================

  describe('Participant Dropout Scenarios', () => {
    it('should prevent progression if participant drops during registration', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      // Only register 4 out of 5 participants
      for (let i = 1; i <= 4; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }

      // Should not be able to progress
      expect(coordinator.getStatus().canProgress).toBe(false);
      expect(() => coordinator.startCommitmentPhase()).toThrow('guard conditions not met');
    });

    it('should prevent finalization if commitment is missing', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }

      coordinator.startCommitmentPhase();

      // Only 4 out of 5 submit commitments
      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 3, 5);
      const hash = generateCommitmentHash(['12345']);

      for (let i = 1; i <= 4; i++) {
        coordinator.submitCommitment(`p${i}`, hash, feldmanResult.commitments);
      }

      expect(coordinator.getStatus().canProgress).toBe(false);
    });

    it('should track exactly which participants have committed', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }

      coordinator.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 3, 5);
      const hash = generateCommitmentHash(['12345']);

      coordinator.submitCommitment('p1', hash, feldmanResult.commitments);
      coordinator.submitCommitment('p3', hash, feldmanResult.commitments);
      coordinator.submitCommitment('p5', hash, feldmanResult.commitments);

      expect(coordinator.getParticipant('p1')?.status).toBe(ParticipantStatus.COMMITTED);
      expect(coordinator.getParticipant('p2')?.status).toBe(ParticipantStatus.REGISTERED);
      expect(coordinator.getParticipant('p3')?.status).toBe(ParticipantStatus.COMMITTED);
      expect(coordinator.getParticipant('p4')?.status).toBe(ParticipantStatus.REGISTERED);
      expect(coordinator.getParticipant('p5')?.status).toBe(ParticipantStatus.COMMITTED);
    });
  });

  // ===========================================================================
  // Malicious Commitment Detection
  // ===========================================================================

  describe('Malicious Commitment Detection', () => {
    it('should reject commitment with invalid hash format', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }

      coordinator.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 3, 5);

      expect(() =>
        coordinator.submitCommitment('p1', 'not-a-valid-hash', feldmanResult.commitments)
      ).toThrow('Invalid commitment hash format');
    });

    it('should reject commitment hash with wrong length', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }

      coordinator.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 3, 5);

      expect(() =>
        coordinator.submitCommitment('p1', 'a'.repeat(60), feldmanResult.commitments)
      ).toThrow('Invalid commitment hash format');
    });

    it('should verify commitment hash correctly', () => {
      const coefficients = ['12345', 'abcdef', '999999'];
      const hash = generateCommitmentHash(coefficients);

      expect(verifyCommitmentHash(hash, coefficients)).toBe(true);
      expect(verifyCommitmentHash(hash, ['different'])).toBe(false);
    });

    it('should detect commitment hash mismatch during verification', () => {
      const coefficients1 = ['12345'];
      const coefficients2 = ['54321'];

      const hash1 = generateCommitmentHash(coefficients1);
      const hash2 = generateCommitmentHash(coefficients2);

      expect(hash1).not.toBe(hash2);
      expect(verifyCommitmentHash(hash1, coefficients2)).toBe(false);
    });
  });

  // ===========================================================================
  // State Export/Import Roundtrip
  // ===========================================================================

  describe('State Export/Import Roundtrip', () => {
    it('should preserve all state through export/import cycle', () => {
      const coordinator1 = new CeremonyCoordinator(config);
      coordinator1.startRegistration();

      coordinator1.addParticipant('alice', 'aaaa');
      coordinator1.addParticipant('bob', 'bbbb');
      coordinator1.addParticipant('charlie', 'cccc');

      const exported = coordinator1.exportState();
      const coordinator2 = CeremonyCoordinator.importState(exported);

      expect(coordinator2.getCurrentPhase()).toBe(coordinator1.getCurrentPhase());
      expect(coordinator2.getParticipants().length).toBe(3);
      expect(coordinator2.getConfig().id).toBe(config.id);
    });

    it('should preserve audit log through export/import', () => {
      const coordinator1 = new CeremonyCoordinator(config);
      coordinator1.startRegistration();
      coordinator1.addParticipant('alice', 'aaaa');
      coordinator1.addParticipant('bob', 'bbbb');

      const exported = coordinator1.exportState();
      const coordinator2 = CeremonyCoordinator.importState(exported);

      const auditLog1 = coordinator1.getAuditLog();
      const auditLog2 = coordinator2.getAuditLog();

      expect(auditLog2.length).toBe(auditLog1.length);
      expect(auditLog2[0].eventType).toBe(auditLog1[0].eventType);
    });

    it('should handle export/import with commitments', () => {
      const coordinator1 = new CeremonyCoordinator(config);
      coordinator1.startRegistration();

      for (let i = 1; i <= 5; i++) {
        coordinator1.addParticipant(`p${i}`, `key${i}`);
      }

      coordinator1.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 3, 5);
      const hash = generateCommitmentHash(['12345']);

      coordinator1.submitCommitment('p1', hash, feldmanResult.commitments);
      coordinator1.submitCommitment('p2', hash, feldmanResult.commitments);

      const exported = coordinator1.exportState();
      const coordinator2 = CeremonyCoordinator.importState(exported);

      expect(coordinator2.getCommitments().length).toBe(2);
      expect(coordinator2.getCommitment('p1')).toBeDefined();
      expect(coordinator2.getCommitment('p2')).toBeDefined();
    });

    it('should handle export/import of finalized ceremony', () => {
      const coordinator1 = new CeremonyCoordinator(config);
      coordinator1.startRegistration();

      for (let i = 1; i <= 5; i++) {
        coordinator1.addParticipant(`p${i}`, `key${i}`);
      }

      coordinator1.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 3, 5);
      const hash = generateCommitmentHash(['12345']);

      for (let i = 1; i <= 5; i++) {
        coordinator1.submitCommitment(`p${i}`, hash, feldmanResult.commitments);
      }

      const result1 = coordinator1.finalize();

      const exported = coordinator1.exportState();
      const coordinator2 = CeremonyCoordinator.importState(exported);

      expect(coordinator2.isComplete()).toBe(true);
      expect(coordinator2.getResult()).toBeDefined();
      expect(coordinator2.getResult()?.shares.length).toBe(5);
    });
  });

  // ===========================================================================
  // Large Participant Counts
  // ===========================================================================

  describe('Large Participant Counts', () => {
    it('should handle 10-of-15 ceremony', () => {
      const largeConfig: CeremonyConfig = {
        id: 'large-ceremony-10-15',
        threshold: 10,
        totalParticipants: 15,
      };

      const coordinator = new CeremonyCoordinator(largeConfig);
      coordinator.startRegistration();

      for (let i = 1; i <= 15; i++) {
        coordinator.addParticipant(`participant-${i}`, `key-${i}`);
      }

      expect(coordinator.getParticipants().length).toBe(15);
      expect(coordinator.getStatus().canProgress).toBe(true);
    });

    it('should handle 20-of-30 ceremony', () => {
      const largeConfig: CeremonyConfig = {
        id: 'large-ceremony-20-30',
        threshold: 20,
        totalParticipants: 30,
      };

      const coordinator = new CeremonyCoordinator(largeConfig);
      coordinator.startRegistration();

      for (let i = 1; i <= 30; i++) {
        coordinator.addParticipant(`trustee-${i}`, `pubkey-${i}`);
      }

      coordinator.startCommitmentPhase();

      const secret = 99999n;
      const feldmanResult = feldmanSplit(secret, 20, 30);
      const hash = generateCommitmentHash(['99999']);

      for (let i = 1; i <= 30; i++) {
        coordinator.submitCommitment(`trustee-${i}`, hash, feldmanResult.commitments);
      }

      const result = coordinator.finalize();

      expect(result.shares.length).toBe(30);
      expect(result.threshold).toBe(20);
    });

    it('should assign sequential indices for 50 participants', () => {
      const massiveConfig: CeremonyConfig = {
        id: 'massive-ceremony',
        threshold: 25,
        totalParticipants: 50,
      };

      const coordinator = new CeremonyCoordinator(massiveConfig);
      coordinator.startRegistration();

      for (let i = 1; i <= 50; i++) {
        const participant = coordinator.addParticipant(`p${i}`, `key${i}`);
        expect(participant.shareIndex).toBe(i);
      }

      const participants = coordinator.getParticipants();
      expect(participants.length).toBe(50);
      expect(participants[0].shareIndex).toBe(1);
      expect(participants[49].shareIndex).toBe(50);
    });
  });

  // ===========================================================================
  // Audit Log Integrity Verification
  // ===========================================================================

  describe('Audit Log Integrity', () => {
    it('should create hash chain with correct genesis hash', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'aaaa');

      const auditLog = coordinator.getAuditLog();

      expect(auditLog[0].previousHash).toBe('0'.repeat(64));
      expect(auditLog[0].hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should link all audit entries in chain', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }

      const auditLog = coordinator.getAuditLog();

      for (let i = 1; i < auditLog.length; i++) {
        expect(auditLog[i].previousHash).toBe(auditLog[i - 1].hash);
      }
    });

    it('should include all event types in audit log', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }

      coordinator.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 3, 5);
      const hash = generateCommitmentHash(['12345']);

      for (let i = 1; i <= 5; i++) {
        coordinator.submitCommitment(`p${i}`, hash, feldmanResult.commitments);
      }

      coordinator.finalize();

      const auditLog = coordinator.getAuditLog();
      const eventTypes = new Set(auditLog.map(e => e.eventType));

      expect(eventTypes.has(AuditEventType.CEREMONY_CREATED)).toBe(true);
      expect(eventTypes.has(AuditEventType.PHASE_TRANSITION)).toBe(true);
      expect(eventTypes.has(AuditEventType.PARTICIPANT_REGISTERED)).toBe(true);
      expect(eventTypes.has(AuditEventType.COMMITMENT_SUBMITTED)).toBe(true);
      expect(eventTypes.has(AuditEventType.CEREMONY_FINALIZED)).toBe(true);
    });

    it('should assign sequential numbers to audit entries', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'aaaa');
      coordinator.addParticipant('bob', 'bbbb');
      coordinator.addParticipant('charlie', 'cccc');

      const auditLog = coordinator.getAuditLog();

      for (let i = 0; i < auditLog.length; i++) {
        expect(auditLog[i].sequence).toBe(i);
      }
    });

    it('should verify clean audit log as valid', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'aaaa');

      expect(coordinator.verifyAuditLog()).toBe(true);
    });
  });

  // ===========================================================================
  // Recovery from Interrupted Ceremonies
  // ===========================================================================

  describe('Recovery from Interrupted Ceremonies', () => {
    it('should recover ceremony from registration phase', () => {
      const coordinator1 = new CeremonyCoordinator(config);
      coordinator1.startRegistration();
      coordinator1.addParticipant('alice', 'aaaa');
      coordinator1.addParticipant('bob', 'bbbb');

      const exported = coordinator1.exportState();
      const coordinator2 = CeremonyCoordinator.importState(exported);

      // Continue from where we left off
      coordinator2.addParticipant('charlie', 'cccc');
      coordinator2.addParticipant('dave', 'dddd');
      coordinator2.addParticipant('eve', 'eeee');

      expect(coordinator2.getParticipants().length).toBe(5);
      expect(coordinator2.getStatus().canProgress).toBe(true);
    });

    it('should recover ceremony from commitment phase', () => {
      const coordinator1 = new CeremonyCoordinator(config);
      coordinator1.startRegistration();

      for (let i = 1; i <= 5; i++) {
        coordinator1.addParticipant(`p${i}`, `key${i}`);
      }

      coordinator1.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 3, 5);
      const hash = generateCommitmentHash(['12345']);

      coordinator1.submitCommitment('p1', hash, feldmanResult.commitments);
      coordinator1.submitCommitment('p2', hash, feldmanResult.commitments);

      const exported = coordinator1.exportState();
      const coordinator2 = CeremonyCoordinator.importState(exported);

      // Continue commitments
      coordinator2.submitCommitment('p3', hash, feldmanResult.commitments);
      coordinator2.submitCommitment('p4', hash, feldmanResult.commitments);
      coordinator2.submitCommitment('p5', hash, feldmanResult.commitments);

      expect(coordinator2.getStatus().canProgress).toBe(true);
    });
  });

  // ===========================================================================
  // Edge Case Threshold Configurations
  // ===========================================================================

  describe('Edge Case Threshold Configurations', () => {
    it('should handle 1-of-1 ceremony', () => {
      const minConfig: CeremonyConfig = {
        id: 'min-ceremony',
        threshold: 1,
        totalParticipants: 1,
      };

      const coordinator = new CeremonyCoordinator(minConfig);
      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'aaaa');

      coordinator.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 1, 1);
      const hash = generateCommitmentHash(['12345']);

      coordinator.submitCommitment('alice', hash, feldmanResult.commitments);

      const result = coordinator.finalize();

      expect(result.shares.length).toBe(1);
      expect(result.threshold).toBe(1);
    });

    it('should handle threshold equal to participants', () => {
      const allRequiredConfig: CeremonyConfig = {
        id: 'all-required',
        threshold: 5,
        totalParticipants: 5,
      };

      const coordinator = new CeremonyCoordinator(allRequiredConfig);
      coordinator.startRegistration();

      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }

      coordinator.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 5, 5);
      const hash = generateCommitmentHash(['12345']);

      for (let i = 1; i <= 5; i++) {
        coordinator.submitCommitment(`p${i}`, hash, feldmanResult.commitments);
      }

      const result = coordinator.finalize();

      expect(result.threshold).toBe(5);
      expect(result.totalParticipants).toBe(5);
    });

    it('should handle 2-of-3 ceremony', () => {
      const simpleConfig: CeremonyConfig = {
        id: 'simple-2-of-3',
        threshold: 2,
        totalParticipants: 3,
      };

      const coordinator = new CeremonyCoordinator(simpleConfig);
      coordinator.startRegistration();

      coordinator.addParticipant('alice', 'aaaa');
      coordinator.addParticipant('bob', 'bbbb');
      coordinator.addParticipant('charlie', 'cccc');

      coordinator.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 2, 3);
      const hash = generateCommitmentHash(['12345']);

      coordinator.submitCommitment('alice', hash, feldmanResult.commitments);
      coordinator.submitCommitment('bob', hash, feldmanResult.commitments);
      coordinator.submitCommitment('charlie', hash, feldmanResult.commitments);

      const result = coordinator.finalize();

      expect(result.threshold).toBe(2);
      expect(result.shares.length).toBe(3);
    });
  });

  // ===========================================================================
  // Additional Status and Monitoring Tests
  // ===========================================================================

  describe('Status and Monitoring', () => {
    it('should provide accurate registration summary', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      let status = coordinator.getStatus();
      expect(status.registration.total).toBe(5);
      expect(status.registration.registered).toBe(0);
      expect(status.registration.remaining).toBe(5);

      coordinator.addParticipant('alice', 'aaaa');
      coordinator.addParticipant('bob', 'bbbb');

      status = coordinator.getStatus();
      expect(status.registration.registered).toBe(2);
      expect(status.registration.remaining).toBe(3);
    });

    it('should provide accurate commitment summary', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }

      coordinator.startCommitmentPhase();

      const secret = 12345n;
      const feldmanResult = feldmanSplit(secret, 3, 5);
      const hash = generateCommitmentHash(['12345']);

      let status = coordinator.getStatus();
      expect(status.commitments.received).toBe(0);
      expect(status.commitments.pending).toBe(5);

      coordinator.submitCommitment('p1', hash, feldmanResult.commitments);
      coordinator.submitCommitment('p2', hash, feldmanResult.commitments);

      status = coordinator.getStatus();
      expect(status.commitments.received).toBe(2);
      expect(status.commitments.pending).toBe(3);
    });

    it('should report phase descriptions correctly', () => {
      expect(getPhaseDescription(CeremonyPhase.CREATED)).toContain('created');
      expect(getPhaseDescription(CeremonyPhase.REGISTRATION)).toContain('registration');
      expect(getPhaseDescription(CeremonyPhase.COMMITMENT)).toContain('commitment');
      expect(getPhaseDescription(CeremonyPhase.SHARE_DISTRIBUTION)).toContain('share');
      expect(getPhaseDescription(CeremonyPhase.FINALIZED)).toContain('complete');
    });

    it('should track creation and update timestamps', () => {
      const coordinator = new CeremonyCoordinator(config);
      const status1 = coordinator.getStatus();

      expect(status1.createdAt).toBeInstanceOf(Date);
      expect(status1.updatedAt).toBeInstanceOf(Date);

      coordinator.startRegistration();
      const status2 = coordinator.getStatus();

      expect(status2.updatedAt.getTime()).toBeGreaterThanOrEqual(status1.updatedAt.getTime());
    });
  });

  // ===========================================================================
  // State Machine Utilities
  // ===========================================================================

  describe('State Machine Utilities', () => {
    it('should validate all legal transitions', () => {
      expect(isValidTransition(CeremonyPhase.CREATED, CeremonyPhase.REGISTRATION)).toBe(true);
      expect(isValidTransition(CeremonyPhase.REGISTRATION, CeremonyPhase.COMMITMENT)).toBe(true);
      expect(isValidTransition(CeremonyPhase.COMMITMENT, CeremonyPhase.SHARE_DISTRIBUTION)).toBe(true);
      expect(isValidTransition(CeremonyPhase.SHARE_DISTRIBUTION, CeremonyPhase.FINALIZED)).toBe(true);
    });

    it('should reject all illegal transitions', () => {
      expect(isValidTransition(CeremonyPhase.CREATED, CeremonyPhase.COMMITMENT)).toBe(false);
      expect(isValidTransition(CeremonyPhase.CREATED, CeremonyPhase.FINALIZED)).toBe(false);
      expect(isValidTransition(CeremonyPhase.REGISTRATION, CeremonyPhase.CREATED)).toBe(false);
      expect(isValidTransition(CeremonyPhase.FINALIZED, CeremonyPhase.CREATED)).toBe(false);
    });

    it('should return correct next phase for each state', () => {
      expect(getNextPhase(CeremonyPhase.CREATED)).toBe(CeremonyPhase.REGISTRATION);
      expect(getNextPhase(CeremonyPhase.REGISTRATION)).toBe(CeremonyPhase.COMMITMENT);
      expect(getNextPhase(CeremonyPhase.COMMITMENT)).toBe(CeremonyPhase.SHARE_DISTRIBUTION);
      expect(getNextPhase(CeremonyPhase.SHARE_DISTRIBUTION)).toBe(CeremonyPhase.FINALIZED);
      expect(getNextPhase(CeremonyPhase.FINALIZED)).toBe(null);
    });
  });

  // ===========================================================================
  // Additional Error Handling
  // ===========================================================================

  describe('Additional Error Handling', () => {
    it('should throw CeremonyError with correct error codes', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      try {
        coordinator.addParticipant('alice', 'aaaa');
        coordinator.addParticipant('alice', 'bbbb');
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(CeremonyError);
        expect((error as CeremonyError).code).toBe('DUPLICATE_PARTICIPANT');
      }
    });

    it('should include relevant details in error objects', () => {
      try {
        new CeremonyCoordinator({
          id: 'test',
          threshold: 10,
          totalParticipants: 5,
        });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(CeremonyError);
        const ceremonyError = error as CeremonyError;
        expect(ceremonyError.details?.threshold).toBe(10);
        expect(ceremonyError.details?.totalParticipants).toBe(5);
      }
    });

    it('should return undefined for non-existent participant', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'aaaa');

      expect(coordinator.getParticipant('bob')).toBeUndefined();
    });

    it('should return undefined for non-existent commitment', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();

      for (let i = 1; i <= 5; i++) {
        coordinator.addParticipant(`p${i}`, `key${i}`);
      }

      coordinator.startCommitmentPhase();

      expect(coordinator.getCommitment('p1')).toBeUndefined();
    });

    it('should return undefined for share before finalization', () => {
      const coordinator = new CeremonyCoordinator(config);
      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'aaaa');

      expect(coordinator.getShareForParticipant('alice')).toBeUndefined();
    });
  });
});

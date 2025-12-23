/**
 * Ceremony Coordinator
 *
 * Main orchestrator for key generation ceremonies.
 * Coordinates participants, collects commitments, and distributes shares.
 */

import {
  CeremonyPhase,
  CeremonyError,
  AuditEventType,
  ParticipantStatus,
  type CeremonyConfig,
  type CeremonyState,
  type CeremonyResult,
  type Participant,
  type Commitment,
  type CeremonyShare,
  type AuditEntry,
} from './types.js';
import type { FeldmanCommitments } from '../feldman/types.js';
import {
  transitionPhase,
  addAuditEntry,
  verifyAuditLog,
  getPhaseDescription,
  getNextPhase,
} from './state-machine.js';
import {
  registerParticipant,
  updateParticipantStatus,
  getAllParticipants,
  getRegistrationSummary,
} from './participant.js';
import {
  submitCommitment,
  getAllCommitments,
  getCommitmentSummary,
} from './commitment.js';
import { split as feldmanSplit, getPublicCommitment } from '../feldman/index.js';
import { randomBigInt } from '../utils/mod-arithmetic.js';
import { SECP256K1_ORDER } from '../shamir/index.js';

/**
 * Ceremony Coordinator
 *
 * Manages the full lifecycle of a threshold key generation ceremony.
 *
 * @example
 * ```typescript
 * // Create a 3-of-5 ceremony
 * const coordinator = new CeremonyCoordinator({
 *   id: 'election-2024',
 *   threshold: 3,
 *   totalParticipants: 5,
 * });
 *
 * // Start registration
 * coordinator.startRegistration();
 *
 * // Add participants
 * coordinator.addParticipant('alice', 'deadbeef...');
 * coordinator.addParticipant('bob', 'cafebabe...');
 * // ... 3 more participants
 *
 * // Start commitment phase
 * coordinator.startCommitmentPhase();
 *
 * // Collect commitments (in real ceremony, participants would generate these)
 * coordinator.submitCommitment('alice', commitmentHash, feldmanCommitments);
 * // ... other participants
 *
 * // Finalize and distribute shares
 * const result = coordinator.finalize();
 * ```
 */
export class CeremonyCoordinator {
  private state: CeremonyState;

  /**
   * Create a new ceremony coordinator
   *
   * @param config - Ceremony configuration
   */
  constructor(config: CeremonyConfig) {
    this.validateConfig(config);

    this.state = {
      config,
      phase: CeremonyPhase.CREATED,
      participants: new Map(),
      commitments: new Map(),
      auditLog: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // Log creation
    addAuditEntry(this.state, AuditEventType.CEREMONY_CREATED, {
      id: config.id,
      threshold: config.threshold,
      totalParticipants: config.totalParticipants,
      description: config.description,
    });
  }

  // ===========================================================================
  // Phase Management
  // ===========================================================================

  /**
   * Start the registration phase
   */
  startRegistration(): void {
    transitionPhase(this.state, CeremonyPhase.REGISTRATION);
  }

  /**
   * Start the commitment phase
   * All participants must be registered first
   */
  startCommitmentPhase(): void {
    transitionPhase(this.state, CeremonyPhase.COMMITMENT);
  }

  /**
   * Start share distribution phase
   * All participants must have submitted commitments first
   */
  startShareDistribution(): void {
    transitionPhase(this.state, CeremonyPhase.SHARE_DISTRIBUTION);
  }

  // ===========================================================================
  // Participant Management
  // ===========================================================================

  /**
   * Add a participant to the ceremony
   *
   * @param participantId - Unique participant ID
   * @param publicKey - Participant's public key (hex-encoded)
   * @returns Registered participant
   */
  addParticipant(participantId: string, publicKey: string): Participant {
    return registerParticipant(this.state, participantId, publicKey);
  }

  /**
   * Get participant by ID
   */
  getParticipant(participantId: string): Participant | undefined {
    return this.state.participants.get(participantId);
  }

  /**
   * Get all participants
   */
  getParticipants(): Participant[] {
    return getAllParticipants(this.state);
  }

  // ===========================================================================
  // Commitment Collection
  // ===========================================================================

  /**
   * Submit a commitment from a participant
   *
   * @param participantId - Participant ID
   * @param commitmentHash - Hash of polynomial coefficients
   * @param feldmanCommitments - Feldman VSS commitments
   * @returns Submitted commitment
   */
  submitCommitment(
    participantId: string,
    commitmentHash: string,
    feldmanCommitments: FeldmanCommitments
  ): Commitment {
    return submitCommitment(
      this.state,
      participantId,
      commitmentHash,
      feldmanCommitments
    );
  }

  /**
   * Get commitment for a participant
   */
  getCommitment(participantId: string): Commitment | undefined {
    return this.state.commitments.get(participantId);
  }

  /**
   * Get all commitments
   */
  getCommitments(): Commitment[] {
    return getAllCommitments(this.state);
  }

  // ===========================================================================
  // Share Generation & Distribution
  // ===========================================================================

  /**
   * Generate and distribute shares to all participants
   * This finalizes the ceremony
   *
   * @returns Ceremony result with shares
   */
  finalize(): CeremonyResult {
    // Transition to share distribution phase
    transitionPhase(this.state, CeremonyPhase.SHARE_DISTRIBUTION);

    // Generate secret and shares using Feldman VSS
    const secret = randomBigInt(1n, SECP256K1_ORDER);
    const feldmanResult = feldmanSplit(
      secret,
      this.state.config.threshold,
      this.state.config.totalParticipants,
      SECP256K1_ORDER
    );

    // Combine Feldman commitments from all participants
    // In this simple implementation, we use the coordinator's commitments
    const commitments = feldmanResult.commitments;
    const publicCommitment = getPublicCommitment(commitments);

    // Create shares for distribution
    const shares: CeremonyShare[] = [];
    const participants = getAllParticipants(this.state);

    for (let i = 0; i < participants.length; i++) {
      const participant = participants[i]!;
      const feldmanShare = feldmanResult.shares[i]!;

      shares.push({
        participantId: participant.id,
        index: feldmanShare.index,
        value: feldmanShare.y.toString(16),
        verificationKey: feldmanShare.x.toString(16),
      });

      // Update participant status
      updateParticipantStatus(
        this.state,
        participant.id,
        ParticipantStatus.SHARE_RECEIVED
      );
    }

    // Create result
    const result: CeremonyResult = {
      ceremonyId: this.state.config.id,
      publicKey: publicCommitment.x.toString(16) + ':' + publicCommitment.y.toString(16),
      publicCommitment,
      commitments,
      threshold: this.state.config.threshold,
      totalParticipants: this.state.config.totalParticipants,
      shares,
      completedAt: new Date(),
    };

    // Store result
    this.state.result = result;

    // Log share distribution
    addAuditEntry(this.state, AuditEventType.SHARES_DISTRIBUTED, {
      shareCount: shares.length,
      publicCommitment: {
        x: publicCommitment.x.toString(16),
        y: publicCommitment.y.toString(16),
      },
    });

    // Transition to finalized
    transitionPhase(this.state, CeremonyPhase.FINALIZED);

    // Log finalization
    addAuditEntry(this.state, AuditEventType.CEREMONY_FINALIZED, {
      ceremonyId: this.state.config.id,
      completedAt: result.completedAt.toISOString(),
    });

    return result;
  }

  /**
   * Get the ceremony result (only available after finalization)
   */
  getResult(): CeremonyResult | undefined {
    return this.state.result;
  }

  /**
   * Get share for a specific participant
   */
  getShareForParticipant(participantId: string): CeremonyShare | undefined {
    if (!this.state.result) {
      return undefined;
    }

    return this.state.result.shares.find(
      (s) => s.participantId === participantId
    );
  }

  // ===========================================================================
  // Status & Monitoring
  // ===========================================================================

  /**
   * Get current ceremony status
   */
  getStatus(): {
    ceremonyId: string;
    phase: CeremonyPhase;
    phaseDescription: string;
    nextPhase: CeremonyPhase | null;
    registration: ReturnType<typeof getRegistrationSummary>;
    commitments: ReturnType<typeof getCommitmentSummary>;
    canProgress: boolean;
    createdAt: Date;
    updatedAt: Date;
  } {
    const nextPhase = getNextPhase(this.state.phase);

    return {
      ceremonyId: this.state.config.id,
      phase: this.state.phase,
      phaseDescription: getPhaseDescription(this.state.phase),
      nextPhase,
      registration: getRegistrationSummary(this.state),
      commitments: getCommitmentSummary(this.state),
      canProgress: this.canProgressToNextPhase(),
      createdAt: this.state.createdAt,
      updatedAt: this.state.updatedAt,
    };
  }

  /**
   * Get full audit log
   */
  getAuditLog(): AuditEntry[] {
    return [...this.state.auditLog];
  }

  /**
   * Verify integrity of audit log
   */
  verifyAuditLog(): boolean {
    return verifyAuditLog(this.state.auditLog);
  }

  /**
   * Get ceremony configuration
   */
  getConfig(): CeremonyConfig {
    return { ...this.state.config };
  }

  /**
   * Get current phase
   */
  getCurrentPhase(): CeremonyPhase {
    return this.state.phase;
  }

  /**
   * Check if ceremony is complete
   */
  isComplete(): boolean {
    return this.state.phase === CeremonyPhase.FINALIZED;
  }

  /**
   * Check if ceremony can progress to next phase
   */
  canProgressToNextPhase(): boolean {
    switch (this.state.phase) {
      case CeremonyPhase.CREATED:
        return true; // Can always start registration

      case CeremonyPhase.REGISTRATION:
        return (
          this.state.participants.size === this.state.config.totalParticipants
        );

      case CeremonyPhase.COMMITMENT:
        return (
          this.state.commitments.size === this.state.config.totalParticipants
        );

      case CeremonyPhase.SHARE_DISTRIBUTION:
        return this.state.result !== undefined;

      case CeremonyPhase.FINALIZED:
        return false; // Terminal state

      default:
        return false;
    }
  }

  // ===========================================================================
  // Export/Import
  // ===========================================================================

  /**
   * Export ceremony state as JSON
   */
  exportState(): string {
    const exportData = {
      config: this.state.config,
      phase: this.state.phase,
      participants: Array.from(this.state.participants.entries()),
      commitments: Array.from(this.state.commitments.entries()),
      result: this.state.result,
      auditLog: this.state.auditLog,
      createdAt: this.state.createdAt.toISOString(),
      updatedAt: this.state.updatedAt.toISOString(),
    };

    return JSON.stringify(exportData, (_key, value) =>
      typeof value === 'bigint' ? value.toString() : value
    );
  }

  /**
   * Import ceremony state from JSON
   * (Static factory method)
   */
  static importState(json: string): CeremonyCoordinator {
    const data = JSON.parse(json);

    const coordinator = new CeremonyCoordinator(data.config);

    // Restore state (this is a simplified version)
    coordinator.state.phase = data.phase;
    coordinator.state.participants = new Map(data.participants);
    coordinator.state.commitments = new Map(data.commitments);
    coordinator.state.result = data.result;
    coordinator.state.auditLog = data.auditLog;
    coordinator.state.createdAt = new Date(data.createdAt);
    coordinator.state.updatedAt = new Date(data.updatedAt);

    return coordinator;
  }

  // ===========================================================================
  // Private Helpers
  // ===========================================================================

  private validateConfig(config: CeremonyConfig): void {
    if (!config.id || config.id.trim().length === 0) {
      throw new CeremonyError(
        'Ceremony ID cannot be empty',
        'INVALID_CONFIG'
      );
    }

    if (!Number.isInteger(config.threshold) || config.threshold < 1) {
      throw new CeremonyError(
        'Threshold must be a positive integer',
        'INVALID_CONFIG',
        { threshold: config.threshold }
      );
    }

    if (
      !Number.isInteger(config.totalParticipants) ||
      config.totalParticipants < 1
    ) {
      throw new CeremonyError(
        'Total participants must be a positive integer',
        'INVALID_CONFIG',
        { totalParticipants: config.totalParticipants }
      );
    }

    if (config.threshold > config.totalParticipants) {
      throw new CeremonyError(
        'Threshold cannot exceed total participants',
        'INVALID_CONFIG',
        {
          threshold: config.threshold,
          totalParticipants: config.totalParticipants,
        }
      );
    }

    if (config.phaseTimeout !== undefined && config.phaseTimeout < 0) {
      throw new CeremonyError(
        'Phase timeout cannot be negative',
        'INVALID_CONFIG',
        { phaseTimeout: config.phaseTimeout }
      );
    }
  }
}

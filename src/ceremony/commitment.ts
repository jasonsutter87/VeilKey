/**
 * Commitment Collection
 *
 * Manages collection and verification of participant commitments
 * during the ceremony commitment phase.
 */

import {
  ParticipantStatus,
  CeremonyPhase,
  CeremonyError,
  AuditEventType,
  type Commitment,
  type CeremonyState,
} from './types.js';
import type { FeldmanCommitments } from '../feldman/types.js';
import { updateParticipantStatus } from './participant.js';
import { addAuditEntry } from './state-machine.js';
import { sha256 } from '@noble/hashes/sha256';

/**
 * Generate commitment hash from polynomial coefficients
 *
 * @param coefficients - Array of polynomial coefficients (hex-encoded)
 * @returns SHA-256 hash (hex-encoded)
 */
export function generateCommitmentHash(coefficients: string[]): string {
  // Concatenate all coefficients
  const combined = coefficients.join(':');
  const hashBytes = sha256(new TextEncoder().encode(combined));

  return Array.from(hashBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verify that a commitment hash matches coefficients
 *
 * @param commitmentHash - Claimed hash
 * @param coefficients - Polynomial coefficients to verify
 * @returns True if hash matches
 */
export function verifyCommitmentHash(
  commitmentHash: string,
  coefficients: string[]
): boolean {
  const computedHash = generateCommitmentHash(coefficients);
  return computedHash === commitmentHash;
}

/**
 * Submit a commitment from a participant
 *
 * @param state - Ceremony state
 * @param participantId - Participant submitting commitment
 * @param commitmentHash - Hash of polynomial coefficients
 * @param feldmanCommitments - Feldman VSS commitments
 * @throws {CeremonyError} If submission is invalid
 */
export function submitCommitment(
  state: CeremonyState,
  participantId: string,
  commitmentHash: string,
  feldmanCommitments: FeldmanCommitments
): Commitment {
  // Validate ceremony phase
  if (state.phase !== CeremonyPhase.COMMITMENT) {
    throw new CeremonyError(
      `Cannot submit commitment: ceremony is in ${state.phase} phase`,
      'INVALID_PHASE',
      { currentPhase: state.phase, expectedPhase: CeremonyPhase.COMMITMENT }
    );
  }

  // Validate participant exists
  const participant = state.participants.get(participantId);
  if (!participant) {
    throw new CeremonyError(
      `Participant ${participantId} not found`,
      'PARTICIPANT_NOT_FOUND',
      { participantId }
    );
  }

  // Check if participant already submitted
  if (state.commitments.has(participantId)) {
    throw new CeremonyError(
      `Participant ${participantId} already submitted commitment`,
      'DUPLICATE_COMMITMENT',
      { participantId }
    );
  }

  // Validate commitment hash format
  if (!isValidHash(commitmentHash)) {
    throw new CeremonyError(
      'Invalid commitment hash format: must be 64-character hex string',
      'INVALID_COMMITMENT_HASH',
      { commitmentHash }
    );
  }

  // Validate Feldman commitments
  if (!feldmanCommitments || feldmanCommitments.length === 0) {
    throw new CeremonyError(
      'Feldman commitments cannot be empty',
      'INVALID_FELDMAN_COMMITMENTS'
    );
  }

  // Verify commitments length matches threshold
  if (feldmanCommitments.length !== state.config.threshold) {
    throw new CeremonyError(
      `Expected ${state.config.threshold} Feldman commitments, got ${feldmanCommitments.length}`,
      'INVALID_COMMITMENT_COUNT',
      {
        expected: state.config.threshold,
        actual: feldmanCommitments.length,
      }
    );
  }

  // Validate each curve point
  for (let i = 0; i < feldmanCommitments.length; i++) {
    const point = feldmanCommitments[i]!;
    if (!isValidCurvePoint(point)) {
      throw new CeremonyError(
        `Invalid curve point at index ${i}`,
        'INVALID_CURVE_POINT',
        { index: i, point }
      );
    }
  }

  // Create commitment
  const commitment: Commitment = {
    participantId,
    commitmentHash,
    feldmanCommitments,
    timestamp: new Date(),
  };

  // Add to state
  state.commitments.set(participantId, commitment);
  state.updatedAt = new Date();

  // Update participant status
  updateParticipantStatus(state, participantId, ParticipantStatus.COMMITTED);

  // Log commitment
  addAuditEntry(state, AuditEventType.COMMITMENT_SUBMITTED, {
    participantId,
    commitmentHash,
    feldmanCommitmentsCount: feldmanCommitments.length,
  });

  return commitment;
}

/**
 * Get commitment for a participant
 *
 * @param state - Ceremony state
 * @param participantId - Participant ID
 * @returns Commitment or undefined
 */
export function getCommitment(
  state: CeremonyState,
  participantId: string
): Commitment | undefined {
  return state.commitments.get(participantId);
}

/**
 * Get all commitments
 *
 * @param state - Ceremony state
 * @returns Array of all commitments
 */
export function getAllCommitments(state: CeremonyState): Commitment[] {
  return Array.from(state.commitments.values());
}

/**
 * Check if all participants have submitted commitments
 *
 * @param state - Ceremony state
 * @returns True if all registered participants have submitted
 */
export function allCommitmentsReceived(state: CeremonyState): boolean {
  const expectedCount = state.config.totalParticipants;
  const actualCount = state.commitments.size;
  return actualCount === expectedCount;
}

/**
 * Combine all Feldman commitments from participants
 * This aggregates commitments for the final ceremony result
 *
 * @param state - Ceremony state
 * @returns Combined commitments
 */
export function combineAllFeldmanCommitments(
  state: CeremonyState
): FeldmanCommitments {
  const commitments = getAllCommitments(state);

  if (commitments.length === 0) {
    throw new CeremonyError(
      'No commitments to combine',
      'NO_COMMITMENTS'
    );
  }

  // For simplicity, we'll use the first participant's commitments
  // In a real distributed key generation, you would combine these
  // using secure multi-party computation techniques
  //
  // For now, this assumes we're using a single dealer approach
  // where one participant generates the shares and the others verify
  return commitments[0]!.feldmanCommitments;
}

/**
 * Get commitment collection summary
 */
export function getCommitmentSummary(state: CeremonyState): {
  expected: number;
  received: number;
  pending: number;
  complete: boolean;
} {
  const expected = state.config.totalParticipants;
  const received = state.commitments.size;

  return {
    expected,
    received,
    pending: expected - received,
    complete: received === expected,
  };
}

/**
 * Validate SHA-256 hash format
 */
function isValidHash(hash: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(hash);
}

/**
 * Validate curve point structure
 */
function isValidCurvePoint(point: { x: bigint; y: bigint }): boolean {
  if (!point || typeof point !== 'object') {
    return false;
  }

  if (typeof point.x !== 'bigint' || typeof point.y !== 'bigint') {
    return false;
  }

  // Basic range check (secp256k1 field)
  const p = 2n ** 256n - 2n ** 32n - 977n; // secp256k1 field modulus
  return point.x >= 0n && point.x < p && point.y >= 0n && point.y < p;
}

/**
 * Verify all Feldman commitments are consistent
 * (Placeholder for multi-party verification)
 *
 * @param state - Ceremony state
 * @returns True if all commitments are valid and consistent
 */
export function verifyAllCommitments(state: CeremonyState): boolean {
  const commitments = getAllCommitments(state);

  if (commitments.length === 0) {
    return false;
  }

  // All commitments should have the same length (threshold)
  const expectedLength = state.config.threshold;
  for (const commitment of commitments) {
    if (commitment.feldmanCommitments.length !== expectedLength) {
      return false;
    }
  }

  // In a real implementation, you would verify that all commitments
  // are consistent with each other using zero-knowledge proofs or
  // other cryptographic techniques

  return true;
}

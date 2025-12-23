/**
 * Participant Management
 *
 * Handles participant registration, status tracking, and identity verification
 */

import {
  ParticipantStatus,
  CeremonyPhase,
  CeremonyError,
  AuditEventType,
  type Participant,
  type CeremonyState,
} from './types.js';
import { addAuditEntry } from './state-machine.js';

/**
 * Register a new participant in the ceremony
 *
 * @param state - Ceremony state
 * @param participantId - Unique participant identifier
 * @param publicKey - Participant's public key (hex-encoded)
 * @throws {CeremonyError} If registration is invalid
 */
export function registerParticipant(
  state: CeremonyState,
  participantId: string,
  publicKey: string
): Participant {
  // Validate ceremony phase
  if (state.phase !== CeremonyPhase.REGISTRATION) {
    throw new CeremonyError(
      `Cannot register participant: ceremony is in ${state.phase} phase`,
      'INVALID_PHASE',
      { currentPhase: state.phase, expectedPhase: CeremonyPhase.REGISTRATION }
    );
  }

  // Validate participant ID
  if (!participantId || participantId.trim().length === 0) {
    throw new CeremonyError(
      'Participant ID cannot be empty',
      'INVALID_PARTICIPANT_ID'
    );
  }

  // Check for duplicate participant
  if (state.participants.has(participantId)) {
    throw new CeremonyError(
      `Participant ${participantId} is already registered`,
      'DUPLICATE_PARTICIPANT',
      { participantId }
    );
  }

  // Check if we've reached capacity
  if (state.participants.size >= state.config.totalParticipants) {
    throw new CeremonyError(
      `Ceremony is full: ${state.config.totalParticipants} participants already registered`,
      'CEREMONY_FULL',
      {
        totalParticipants: state.config.totalParticipants,
        registered: state.participants.size,
      }
    );
  }

  // Validate public key format (basic hex check)
  if (!isValidHex(publicKey)) {
    throw new CeremonyError(
      'Invalid public key format: must be hex-encoded',
      'INVALID_PUBLIC_KEY',
      { publicKey }
    );
  }

  // Check for duplicate public key (prevent impersonation)
  for (const existing of state.participants.values()) {
    if (existing.publicKey === publicKey) {
      throw new CeremonyError(
        'Public key already in use by another participant',
        'DUPLICATE_PUBLIC_KEY',
        { publicKey }
      );
    }
  }

  // Assign share index (1-based, sequential)
  const shareIndex = state.participants.size + 1;

  // Create participant
  const participant: Participant = {
    id: participantId,
    publicKey,
    status: ParticipantStatus.REGISTERED,
    registeredAt: new Date(),
    shareIndex,
  };

  // Add to state
  state.participants.set(participantId, participant);
  state.updatedAt = new Date();

  // Log registration
  addAuditEntry(state, AuditEventType.PARTICIPANT_REGISTERED, {
    participantId,
    publicKey,
    shareIndex,
  });

  return participant;
}

/**
 * Update participant status
 *
 * @param state - Ceremony state
 * @param participantId - Participant ID
 * @param newStatus - New status
 * @throws {CeremonyError} If participant not found
 */
export function updateParticipantStatus(
  state: CeremonyState,
  participantId: string,
  newStatus: ParticipantStatus
): void {
  const participant = state.participants.get(participantId);
  if (!participant) {
    throw new CeremonyError(
      `Participant ${participantId} not found`,
      'PARTICIPANT_NOT_FOUND',
      { participantId }
    );
  }

  participant.status = newStatus;
  state.updatedAt = new Date();
}

/**
 * Get participant by ID
 *
 * @param state - Ceremony state
 * @param participantId - Participant ID
 * @returns Participant or undefined
 */
export function getParticipant(
  state: CeremonyState,
  participantId: string
): Participant | undefined {
  return state.participants.get(participantId);
}

/**
 * Get all participants
 *
 * @param state - Ceremony state
 * @returns Array of all participants
 */
export function getAllParticipants(state: CeremonyState): Participant[] {
  return Array.from(state.participants.values());
}

/**
 * Get participants by status
 *
 * @param state - Ceremony state
 * @param status - Status filter
 * @returns Array of matching participants
 */
export function getParticipantsByStatus(
  state: CeremonyState,
  status: ParticipantStatus
): Participant[] {
  return Array.from(state.participants.values()).filter(
    (p) => p.status === status
  );
}

/**
 * Check if all participants have a given status
 *
 * @param state - Ceremony state
 * @param status - Status to check
 * @returns True if all participants have the status
 */
export function allParticipantsHaveStatus(
  state: CeremonyState,
  status: ParticipantStatus
): boolean {
  if (state.participants.size === 0) {
    return false;
  }

  return Array.from(state.participants.values()).every(
    (p) => p.status === status
  );
}

/**
 * Verify participant identity using public key
 * (Placeholder for signature verification)
 *
 * @param participant - Participant to verify
 * @param signature - Signature to verify (hex-encoded)
 * @param message - Message that was signed
 * @returns True if signature is valid
 */
export function verifyParticipantIdentity(
  participant: Participant,
  signature: string,
  message: string
): boolean {
  // TODO: Implement actual signature verification
  // This would use the participant's public key to verify a signature
  // For now, basic validation that signature exists and is hex
  return (
    signature.length > 0 &&
    isValidHex(signature) &&
    message.length > 0 &&
    participant.publicKey.length > 0
  );
}

/**
 * Get participant registration summary
 */
export function getRegistrationSummary(state: CeremonyState): {
  total: number;
  registered: number;
  committed: number;
  sharesReceived: number;
  remaining: number;
} {
  const participants = Array.from(state.participants.values());

  return {
    total: state.config.totalParticipants,
    registered: participants.filter(
      (p) => p.status === ParticipantStatus.REGISTERED
    ).length,
    committed: participants.filter(
      (p) => p.status === ParticipantStatus.COMMITTED
    ).length,
    sharesReceived: participants.filter(
      (p) => p.status === ParticipantStatus.SHARE_RECEIVED
    ).length,
    remaining: state.config.totalParticipants - state.participants.size,
  };
}

/**
 * Validate hex string format
 */
function isValidHex(str: string): boolean {
  return /^[0-9a-fA-F]+$/.test(str) && str.length % 2 === 0;
}

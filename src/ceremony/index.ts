/**
 * Key Ceremony Module
 *
 * Tools for conducting threshold key generation ceremonies with
 * multiple participants in a secure, auditable way.
 *
 * @example
 * ```typescript
 * import { CeremonyCoordinator } from '@veilkey/core';
 *
 * // Create a 3-of-5 ceremony
 * const ceremony = new CeremonyCoordinator({
 *   id: 'election-2024',
 *   threshold: 3,
 *   totalParticipants: 5,
 * });
 *
 * // Run the ceremony
 * ceremony.startRegistration();
 * ceremony.addParticipant('alice', 'pubkey1');
 * ceremony.addParticipant('bob', 'pubkey2');
 * // ... more participants
 *
 * ceremony.startCommitmentPhase();
 * ceremony.submitCommitment('alice', hash, commitments);
 * // ... more commitments
 *
 * const result = ceremony.finalize();
 * ```
 */

// Main coordinator
export { CeremonyCoordinator } from './coordinator.js';

// Types
export type {
  CeremonyConfig,
  CeremonyState,
  CeremonyResult,
  Participant,
  Commitment,
  CeremonyShare,
  AuditEntry,
  TransitionOptions,
} from './types.js';

export {
  CeremonyPhase,
  ParticipantStatus,
  AuditEventType,
  CeremonyError,
} from './types.js';

// State machine utilities (for advanced users)
export {
  transitionPhase,
  isValidTransition,
  canStartRegistration,
  canStartCommitment,
  canStartShareDistribution,
  canFinalize,
  hasPhaseTimedOut,
  verifyAuditLog,
  getPhaseDescription,
  getNextPhase,
} from './state-machine.js';

// Participant management utilities
export {
  registerParticipant,
  updateParticipantStatus,
  getParticipant,
  getAllParticipants,
  getParticipantsByStatus,
  allParticipantsHaveStatus,
  verifyParticipantIdentity,
  getRegistrationSummary,
} from './participant.js';

// Commitment utilities
export {
  generateCommitmentHash,
  verifyCommitmentHash,
  submitCommitment,
  getCommitment,
  getAllCommitments,
  allCommitmentsReceived,
  combineAllFeldmanCommitments,
  getCommitmentSummary,
  verifyAllCommitments,
} from './commitment.js';

/**
 * Ceremony State Machine
 *
 * Manages phase transitions and enforces ceremony workflow:
 * CREATED → REGISTRATION → COMMITMENT → SHARE_DISTRIBUTION → FINALIZED
 */

import {
  CeremonyPhase,
  CeremonyError,
  AuditEventType,
  type CeremonyState,
  type TransitionOptions,
  type AuditEntry,
} from './types.js';
import { sha256 } from '@noble/hashes/sha256';

/**
 * Valid phase transitions
 */
const VALID_TRANSITIONS: Record<CeremonyPhase, CeremonyPhase[]> = {
  [CeremonyPhase.CREATED]: [CeremonyPhase.REGISTRATION],
  [CeremonyPhase.REGISTRATION]: [CeremonyPhase.COMMITMENT],
  [CeremonyPhase.COMMITMENT]: [CeremonyPhase.SHARE_DISTRIBUTION],
  [CeremonyPhase.SHARE_DISTRIBUTION]: [CeremonyPhase.FINALIZED],
  [CeremonyPhase.FINALIZED]: [], // Terminal state
};

/**
 * Check if a phase transition is valid
 */
export function isValidTransition(
  from: CeremonyPhase,
  to: CeremonyPhase
): boolean {
  return VALID_TRANSITIONS[from]?.includes(to) ?? false;
}

/**
 * Guard: Check if ceremony can transition to REGISTRATION
 */
export function canStartRegistration(state: CeremonyState): boolean {
  return state.phase === CeremonyPhase.CREATED;
}

/**
 * Guard: Check if ceremony can transition to COMMITMENT
 */
export function canStartCommitment(state: CeremonyState): boolean {
  if (state.phase !== CeremonyPhase.REGISTRATION) {
    return false;
  }

  // All participants must be registered
  const expectedParticipants = state.config.totalParticipants;
  const actualParticipants = state.participants.size;

  return actualParticipants === expectedParticipants;
}

/**
 * Guard: Check if ceremony can transition to SHARE_DISTRIBUTION
 */
export function canStartShareDistribution(state: CeremonyState): boolean {
  if (state.phase !== CeremonyPhase.COMMITMENT) {
    return false;
  }

  // All participants must have submitted commitments
  const expectedCommitments = state.config.totalParticipants;
  const actualCommitments = state.commitments.size;

  return actualCommitments === expectedCommitments;
}

/**
 * Guard: Check if ceremony can be finalized
 */
export function canFinalize(state: CeremonyState): boolean {
  if (state.phase !== CeremonyPhase.SHARE_DISTRIBUTION) {
    return false;
  }

  // Result must be set
  return state.result !== undefined;
}

/**
 * Get the guard function for a transition
 */
function getTransitionGuard(
  to: CeremonyPhase
): ((state: CeremonyState) => boolean) | null {
  switch (to) {
    case CeremonyPhase.REGISTRATION:
      return canStartRegistration;
    case CeremonyPhase.COMMITMENT:
      return canStartCommitment;
    case CeremonyPhase.SHARE_DISTRIBUTION:
      return canStartShareDistribution;
    case CeremonyPhase.FINALIZED:
      return canFinalize;
    default:
      return null;
  }
}

/**
 * Transition ceremony to a new phase
 *
 * @param state - Current ceremony state
 * @param newPhase - Target phase
 * @param options - Transition options
 * @throws {CeremonyError} If transition is invalid
 */
export function transitionPhase(
  state: CeremonyState,
  newPhase: CeremonyPhase,
  options: TransitionOptions = {}
): void {
  const currentPhase = state.phase;

  // Check if transition is structurally valid
  if (!isValidTransition(currentPhase, newPhase)) {
    throw new CeremonyError(
      `Invalid phase transition: ${currentPhase} → ${newPhase}`,
      'INVALID_TRANSITION',
      { from: currentPhase, to: newPhase }
    );
  }

  // Check guard conditions unless forced
  if (!options.force) {
    const guard = getTransitionGuard(newPhase);
    if (guard && !guard(state)) {
      throw new CeremonyError(
        `Cannot transition to ${newPhase}: guard conditions not met`,
        'GUARD_FAILED',
        {
          from: currentPhase,
          to: newPhase,
          participantCount: state.participants.size,
          commitmentCount: state.commitments.size,
          hasResult: state.result !== undefined,
        }
      );
    }
  }

  // Perform transition
  state.phase = newPhase;
  state.updatedAt = new Date();

  // Log transition
  addAuditEntry(state, AuditEventType.PHASE_TRANSITION, {
    from: currentPhase,
    to: newPhase,
    forced: options.force ?? false,
    ...options.metadata,
  });
}

/**
 * Check if ceremony has timed out in current phase
 */
export function hasPhaseTimedOut(state: CeremonyState): boolean {
  if (!state.config.phaseTimeout) {
    return false;
  }

  const elapsed = Date.now() - state.updatedAt.getTime();
  return elapsed > state.config.phaseTimeout;
}

/**
 * Add an entry to the audit log with hash chaining
 */
export function addAuditEntry(
  state: CeremonyState,
  eventType: AuditEventType,
  data: Record<string, unknown>
): AuditEntry {
  const sequence = state.auditLog.length;
  const previousHash =
    sequence > 0 ? state.auditLog[sequence - 1]!.hash : '0'.repeat(64);

  // Create entry (without hash first)
  const entry: Omit<AuditEntry, 'hash'> = {
    sequence,
    eventType,
    timestamp: new Date(),
    data,
    previousHash,
  };

  // Compute hash of entry
  const entryJson = JSON.stringify({
    sequence: entry.sequence,
    eventType: entry.eventType,
    timestamp: entry.timestamp.toISOString(),
    data: entry.data,
    previousHash: entry.previousHash,
  });
  const hashBytes = sha256(new TextEncoder().encode(entryJson));
  const hash = Array.from(hashBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const fullEntry: AuditEntry = { ...entry, hash };
  state.auditLog.push(fullEntry);

  return fullEntry;
}

/**
 * Verify integrity of audit log hash chain
 */
export function verifyAuditLog(auditLog: AuditEntry[]): boolean {
  if (auditLog.length === 0) {
    return true;
  }

  // Check first entry
  if (auditLog[0]!.previousHash !== '0'.repeat(64)) {
    return false;
  }

  // Verify each entry's hash and chain
  for (let i = 0; i < auditLog.length; i++) {
    const entry = auditLog[i]!;

    // Verify sequence
    if (entry.sequence !== i) {
      return false;
    }

    // Verify hash chain
    if (i > 0 && entry.previousHash !== auditLog[i - 1]!.hash) {
      return false;
    }

    // Recompute hash
    const entryJson = JSON.stringify({
      sequence: entry.sequence,
      eventType: entry.eventType,
      timestamp: entry.timestamp.toISOString(),
      data: entry.data,
      previousHash: entry.previousHash,
    });
    const hashBytes = sha256(new TextEncoder().encode(entryJson));
    const computedHash = Array.from(hashBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    if (computedHash !== entry.hash) {
      return false;
    }
  }

  return true;
}

/**
 * Get human-readable description of current phase
 */
export function getPhaseDescription(phase: CeremonyPhase): string {
  switch (phase) {
    case CeremonyPhase.CREATED:
      return 'Ceremony created, ready to begin registration';
    case CeremonyPhase.REGISTRATION:
      return 'Accepting participant registrations';
    case CeremonyPhase.COMMITMENT:
      return 'Collecting commitments from participants';
    case CeremonyPhase.SHARE_DISTRIBUTION:
      return 'Distributing shares to participants';
    case CeremonyPhase.FINALIZED:
      return 'Ceremony complete';
    default:
      return 'Unknown phase';
  }
}

/**
 * Get next expected phase
 */
export function getNextPhase(
  currentPhase: CeremonyPhase
): CeremonyPhase | null {
  const validTransitions = VALID_TRANSITIONS[currentPhase];
  return validTransitions.length > 0 ? validTransitions[0] ?? null : null;
}

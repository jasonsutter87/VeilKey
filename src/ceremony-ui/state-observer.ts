/**
 * VeilKey Ceremony State Observer
 *
 * Provides real-time observation of ceremony state changes with
 * event-based notifications for UI updates.
 *
 * @module ceremony-ui/state-observer
 */

import type { CeremonyCoordinator } from '../ceremony/coordinator.js';
import {
  CeremonyPhase,
  ParticipantStatus,
  type Participant,
  type AuditEntry,
} from '../ceremony/types.js';
import type {
  CeremonyUIState,
  CeremonyUIConfig,
  UIParticipant,
  CeremonyUIEvent,
  CeremonyUIEventType,
  CeremonyStateObserver,
  CeremonyEventListener,
  PhaseDisplayInfo,
  CeremonyStatistics,
  ConnectionStatus,
} from './types.js';

/**
 * Phase display information
 */
const PHASE_INFO: Record<CeremonyPhase, Omit<PhaseDisplayInfo, 'phase'>> = {
  [CeremonyPhase.CREATED]: {
    name: 'Created',
    description: 'Ceremony has been created and is ready to start',
    icon: 'plus-circle',
    color: 'gray',
    stepNumber: 1,
    isTerminal: false,
  },
  [CeremonyPhase.REGISTRATION]: {
    name: 'Registration',
    description: 'Accepting participant registrations',
    icon: 'users',
    color: 'blue',
    stepNumber: 2,
    isTerminal: false,
  },
  [CeremonyPhase.COMMITMENT]: {
    name: 'Commitment',
    description: 'Collecting cryptographic commitments from participants',
    icon: 'lock',
    color: 'yellow',
    stepNumber: 3,
    isTerminal: false,
  },
  [CeremonyPhase.SHARE_DISTRIBUTION]: {
    name: 'Share Distribution',
    description: 'Distributing key shares to participants',
    icon: 'share-2',
    color: 'green',
    stepNumber: 4,
    isTerminal: false,
  },
  [CeremonyPhase.FINALIZED]: {
    name: 'Complete',
    description: 'Ceremony has been successfully completed',
    icon: 'check-circle',
    color: 'green',
    stepNumber: 5,
    isTerminal: true,
  },
};

/**
 * Status colors for participants
 */
const STATUS_COLORS: Record<ParticipantStatus, UIParticipant['statusColor']> = {
  [ParticipantStatus.REGISTERED]: 'pending',
  [ParticipantStatus.COMMITTED]: 'active',
  [ParticipantStatus.SHARE_RECEIVED]: 'success',
};

/**
 * Status display text
 */
const STATUS_DISPLAY: Record<ParticipantStatus, string> = {
  [ParticipantStatus.REGISTERED]: 'Registered',
  [ParticipantStatus.COMMITTED]: 'Commitment Submitted',
  [ParticipantStatus.SHARE_RECEIVED]: 'Share Received',
};

/**
 * Generate a deterministic color from a string
 */
function stringToColor(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  const hue = hash % 360;
  return `hsl(${hue}, 70%, 50%)`;
}

/**
 * Truncate public key for display
 */
function truncatePublicKey(key: string): string {
  if (key.length <= 16) return key;
  return `${key.slice(0, 8)}...${key.slice(-8)}`;
}

/**
 * Ceremony State Observer
 *
 * Observes a CeremonyCoordinator and provides real-time UI state updates.
 */
export class CeremonyStateObserverImpl {
  private coordinator: CeremonyCoordinator;
  private config: Required<CeremonyUIConfig>;
  private stateObservers: Set<CeremonyStateObserver> = new Set();
  private eventListeners: Set<CeremonyEventListener> = new Set();
  private currentState: CeremonyUIState;
  private previousPhase: CeremonyPhase;
  private startTime: Date;
  private pollInterval: ReturnType<typeof setInterval> | null = null;
  private connectionStatus: ConnectionStatus = 'connected';
  private onlineParticipants: Set<string> = new Set();

  constructor(coordinator: CeremonyCoordinator, config: Partial<CeremonyUIConfig> = {}) {
    this.coordinator = coordinator;
    this.config = {
      wsUrl: config.wsUrl || 'ws://localhost:8080',
      autoReconnect: config.autoReconnect ?? true,
      reconnectInterval: config.reconnectInterval ?? 3000,
      maxReconnectAttempts: config.maxReconnectAttempts ?? 5,
      theme: config.theme ?? 'system',
      soundEnabled: config.soundEnabled ?? false,
      qrErrorCorrection: config.qrErrorCorrection ?? 'M',
      qrSize: config.qrSize ?? 256,
    };

    this.previousPhase = coordinator.getCurrentPhase();
    this.startTime = new Date();
    this.currentState = this.buildState();
  }

  /**
   * Start observing the ceremony
   */
  start(pollIntervalMs = 1000): void {
    if (this.pollInterval) {
      this.stop();
    }

    this.pollInterval = setInterval(() => {
      this.checkForUpdates();
    }, pollIntervalMs);

    // Initial state notification
    this.notifyStateObservers();
  }

  /**
   * Stop observing
   */
  stop(): void {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  /**
   * Subscribe to state changes
   */
  subscribe(observer: CeremonyStateObserver): () => void {
    this.stateObservers.add(observer);
    // Immediately notify with current state
    observer(this.currentState);

    return () => {
      this.stateObservers.delete(observer);
    };
  }

  /**
   * Add event listener
   */
  addEventListener(listener: CeremonyEventListener): () => void {
    this.eventListeners.add(listener);
    return () => {
      this.eventListeners.delete(listener);
    };
  }

  /**
   * Get current UI state
   */
  getState(): CeremonyUIState {
    return this.currentState;
  }

  /**
   * Get phase display info
   */
  getPhaseInfo(phase?: CeremonyPhase): PhaseDisplayInfo {
    const p = phase ?? this.coordinator.getCurrentPhase();
    return {
      phase: p,
      ...PHASE_INFO[p],
    };
  }

  /**
   * Get all phases info (for progress display)
   */
  getAllPhasesInfo(): PhaseDisplayInfo[] {
    return Object.entries(PHASE_INFO).map(([phase, info]) => ({
      phase: phase as CeremonyPhase,
      ...info,
    }));
  }

  /**
   * Get ceremony statistics
   */
  getStatistics(): CeremonyStatistics {
    const status = this.coordinator.getStatus();
    const now = new Date();
    const totalTime = now.getTime() - this.startTime.getTime();

    return {
      phaseTime: totalTime, // In real implementation, track per-phase
      totalTime,
      participantsRegistered: status.registration.registered,
      commitmentsReceived: status.commitments.submitted,
      sharesDistributed: this.coordinator.isComplete()
        ? this.coordinator.getResult()?.shares.length ?? 0
        : 0,
      auditEntries: this.coordinator.getAuditLog().length,
      estimatedTimeRemaining: this.estimateTimeRemaining(),
    };
  }

  /**
   * Mark participant as online
   */
  markParticipantOnline(participantId: string): void {
    const wasOnline = this.onlineParticipants.has(participantId);
    this.onlineParticipants.add(participantId);

    if (!wasOnline) {
      this.checkForUpdates();
    }
  }

  /**
   * Mark participant as offline
   */
  markParticipantOffline(participantId: string): void {
    const wasOnline = this.onlineParticipants.has(participantId);
    this.onlineParticipants.delete(participantId);

    if (wasOnline) {
      this.checkForUpdates();
      this.emitEvent('PARTICIPANT_LEFT' as CeremonyUIEventType, { participantId });
    }
  }

  /**
   * Set connection status
   */
  setConnectionStatus(status: ConnectionStatus): void {
    if (this.connectionStatus !== status) {
      this.connectionStatus = status;
      this.emitEvent('CONNECTION_STATUS_CHANGED' as CeremonyUIEventType, { status });
      this.checkForUpdates();
    }
  }

  /**
   * Force a state refresh
   */
  refresh(): void {
    this.checkForUpdates();
  }

  /**
   * Check for updates and notify observers if changed
   */
  private checkForUpdates(): void {
    const newState = this.buildState();
    const hasChanges = this.detectChanges(newState);

    if (hasChanges) {
      this.currentState = newState;
      this.notifyStateObservers();
    }
  }

  /**
   * Build current UI state from coordinator
   */
  private buildState(): CeremonyUIState {
    const config = this.coordinator.getConfig();
    const phase = this.coordinator.getCurrentPhase();
    const participants = this.coordinator.getParticipants();
    const status = this.coordinator.getStatus();

    const uiParticipants = participants.map(p => this.buildUIParticipant(p));
    const phaseProgress = this.calculatePhaseProgress(phase, status);

    return {
      ceremonyId: config.id,
      phase,
      phaseProgress,
      config,
      participants: uiParticipants,
      connectionStatus: this.connectionStatus,
      lastUpdate: new Date(),
      isComplete: this.coordinator.isComplete(),
      error: undefined,
    };
  }

  /**
   * Build UI-enhanced participant
   */
  private buildUIParticipant(participant: Participant): UIParticipant {
    const commitment = this.coordinator.getCommitment(participant.id);
    const hasShare = participant.status === ParticipantStatus.SHARE_RECEIVED;

    return {
      id: participant.id,
      displayName: participant.id, // Could be enhanced with metadata
      publicKeyDisplay: truncatePublicKey(participant.publicKey),
      publicKey: participant.publicKey,
      status: participant.status,
      statusDisplay: STATUS_DISPLAY[participant.status],
      statusColor: STATUS_COLORS[participant.status],
      shareIndex: participant.shareIndex,
      hasCommitment: !!commitment,
      hasShare,
      registeredAt: participant.registeredAt,
      lastActivity: commitment?.timestamp,
      avatarColor: stringToColor(participant.id),
      isOnline: this.onlineParticipants.has(participant.id),
    };
  }

  /**
   * Calculate progress percentage for current phase
   */
  private calculatePhaseProgress(
    phase: CeremonyPhase,
    status: ReturnType<CeremonyCoordinator['getStatus']>
  ): number {
    switch (phase) {
      case CeremonyPhase.CREATED:
        return 0;

      case CeremonyPhase.REGISTRATION:
        return Math.round(
          (status.registration.registered / status.registration.total) * 100
        );

      case CeremonyPhase.COMMITMENT:
        return Math.round(
          (status.commitments.submitted / status.commitments.total) * 100
        );

      case CeremonyPhase.SHARE_DISTRIBUTION:
        return 50; // In progress

      case CeremonyPhase.FINALIZED:
        return 100;

      default:
        return 0;
    }
  }

  /**
   * Detect if state has changed
   */
  private detectChanges(newState: CeremonyUIState): boolean {
    // Phase change
    if (newState.phase !== this.previousPhase) {
      this.emitEvent('PHASE_CHANGED' as CeremonyUIEventType, {
        from: this.previousPhase,
        to: newState.phase,
      });
      this.previousPhase = newState.phase;
      return true;
    }

    // Participant count change
    if (newState.participants.length !== this.currentState.participants.length) {
      return true;
    }

    // Progress change
    if (newState.phaseProgress !== this.currentState.phaseProgress) {
      return true;
    }

    // Participant status changes
    for (const newP of newState.participants) {
      const oldP = this.currentState.participants.find(p => p.id === newP.id);
      if (!oldP || oldP.status !== newP.status || oldP.isOnline !== newP.isOnline) {
        return true;
      }
    }

    // Connection status change
    if (newState.connectionStatus !== this.currentState.connectionStatus) {
      return true;
    }

    return false;
  }

  /**
   * Notify all state observers
   */
  private notifyStateObservers(): void {
    for (const observer of this.stateObservers) {
      try {
        observer(this.currentState);
      } catch {
        // Ignore observer errors
      }
    }
  }

  /**
   * Emit an event to all listeners
   */
  private emitEvent(type: CeremonyUIEventType, data: Record<string, unknown>): void {
    const event: CeremonyUIEvent = {
      type,
      timestamp: new Date(),
      data,
    };

    for (const listener of this.eventListeners) {
      try {
        listener(event);
      } catch {
        // Ignore listener errors
      }
    }
  }

  /**
   * Estimate time remaining (simple heuristic)
   */
  private estimateTimeRemaining(): number | undefined {
    const phase = this.coordinator.getCurrentPhase();

    if (phase === CeremonyPhase.FINALIZED) {
      return 0;
    }

    // Simple estimate based on typical ceremony duration
    const phaseEstimates: Record<CeremonyPhase, number> = {
      [CeremonyPhase.CREATED]: 60000,
      [CeremonyPhase.REGISTRATION]: 120000,
      [CeremonyPhase.COMMITMENT]: 180000,
      [CeremonyPhase.SHARE_DISTRIBUTION]: 60000,
      [CeremonyPhase.FINALIZED]: 0,
    };

    const currentEstimate = phaseEstimates[phase] ?? 60000;
    const progress = this.currentState.phaseProgress / 100;

    return Math.round(currentEstimate * (1 - progress));
  }
}

/**
 * Create a ceremony state observer
 */
export function createCeremonyObserver(
  coordinator: CeremonyCoordinator,
  config?: Partial<CeremonyUIConfig>
): CeremonyStateObserverImpl {
  return new CeremonyStateObserverImpl(coordinator, config);
}

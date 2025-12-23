/**
 * VeilKey Key Ceremony Web UI - Type Definitions
 *
 * Types for the real-time ceremony interface including state observation,
 * QR code distribution, and ceremony recording/playback.
 *
 * @module ceremony-ui/types
 */

import type {
  CeremonyPhase,
  CeremonyConfig,
  Participant,
  ParticipantStatus,
  Commitment,
  CeremonyShare,
  AuditEntry,
  CeremonyResult,
} from '../ceremony/types.js';

/**
 * Connection status for real-time updates
 */
export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

/**
 * UI Theme
 */
export type UITheme = 'light' | 'dark' | 'system';

/**
 * Ceremony UI Configuration
 */
export interface CeremonyUIConfig {
  /** Base URL for WebSocket connections */
  wsUrl?: string;

  /** Auto-reconnect on disconnect */
  autoReconnect?: boolean;

  /** Reconnect interval (ms) */
  reconnectInterval?: number;

  /** Max reconnect attempts */
  maxReconnectAttempts?: number;

  /** Theme */
  theme?: UITheme;

  /** Enable sound notifications */
  soundEnabled?: boolean;

  /** QR code error correction level */
  qrErrorCorrection?: 'L' | 'M' | 'Q' | 'H';

  /** QR code size (pixels) */
  qrSize?: number;
}

/**
 * Real-time ceremony state for UI
 */
export interface CeremonyUIState {
  /** Ceremony ID */
  ceremonyId: string;

  /** Current phase */
  phase: CeremonyPhase;

  /** Phase progress (0-100) */
  phaseProgress: number;

  /** Configuration */
  config: CeremonyConfig;

  /** Participants with UI-specific status */
  participants: UIParticipant[];

  /** Current action being performed */
  currentAction?: string;

  /** Connection status */
  connectionStatus: ConnectionStatus;

  /** Last update timestamp */
  lastUpdate: Date;

  /** Is ceremony complete */
  isComplete: boolean;

  /** Error state */
  error?: CeremonyUIError;
}

/**
 * UI-enhanced participant representation
 */
export interface UIParticipant {
  /** Participant ID */
  id: string;

  /** Display name */
  displayName: string;

  /** Public key (truncated for display) */
  publicKeyDisplay: string;

  /** Full public key */
  publicKey: string;

  /** Current status */
  status: ParticipantStatus;

  /** Status display text */
  statusDisplay: string;

  /** Status color for UI */
  statusColor: 'pending' | 'active' | 'success' | 'error';

  /** Share index */
  shareIndex?: number;

  /** Has submitted commitment */
  hasCommitment: boolean;

  /** Has received share */
  hasShare: boolean;

  /** Registration time */
  registeredAt: Date;

  /** Last activity time */
  lastActivity?: Date;

  /** Avatar color (derived from ID) */
  avatarColor: string;

  /** Is online (for real-time tracking) */
  isOnline: boolean;
}

/**
 * Ceremony event types for UI updates
 */
export enum CeremonyUIEventType {
  PHASE_CHANGED = 'PHASE_CHANGED',
  PARTICIPANT_JOINED = 'PARTICIPANT_JOINED',
  PARTICIPANT_LEFT = 'PARTICIPANT_LEFT',
  PARTICIPANT_STATUS_CHANGED = 'PARTICIPANT_STATUS_CHANGED',
  COMMITMENT_RECEIVED = 'COMMITMENT_RECEIVED',
  SHARE_DISTRIBUTED = 'SHARE_DISTRIBUTED',
  CEREMONY_COMPLETED = 'CEREMONY_COMPLETED',
  ERROR = 'ERROR',
  CONNECTION_STATUS_CHANGED = 'CONNECTION_STATUS_CHANGED',
}

/**
 * Ceremony UI event
 */
export interface CeremonyUIEvent {
  type: CeremonyUIEventType;
  timestamp: Date;
  data: Record<string, unknown>;
}

/**
 * QR code data for share distribution
 */
export interface ShareQRCode {
  /** Participant ID */
  participantId: string;

  /** QR code data URL (base64 encoded) */
  dataUrl: string;

  /** Raw share data (encrypted) */
  encryptedShare: string;

  /** Share index */
  shareIndex: number;

  /** Expiration time */
  expiresAt: Date;

  /** Has been scanned */
  scanned: boolean;

  /** Verification code (last 4 characters) */
  verificationCode: string;
}

/**
 * Ceremony recording for playback
 */
export interface CeremonyRecording {
  /** Recording ID */
  id: string;

  /** Ceremony ID */
  ceremonyId: string;

  /** Recording start time */
  startedAt: Date;

  /** Recording end time */
  endedAt?: Date;

  /** Events in order */
  events: RecordedEvent[];

  /** Total duration (ms) */
  duration?: number;

  /** Recording metadata */
  metadata: RecordingMetadata;
}

/**
 * A recorded event with timing
 */
export interface RecordedEvent {
  /** Event index */
  index: number;

  /** Relative timestamp from start (ms) */
  relativeTime: number;

  /** Absolute timestamp */
  timestamp: Date;

  /** Event type */
  type: string;

  /** Event data (sanitized for recording) */
  data: Record<string, unknown>;

  /** Associated audit entry hash (if any) */
  auditHash?: string;
}

/**
 * Recording metadata
 */
export interface RecordingMetadata {
  /** Recording version */
  version: string;

  /** Ceremony configuration snapshot */
  ceremonyConfig: CeremonyConfig;

  /** Total participants */
  participantCount: number;

  /** Final result summary (if complete) */
  resultSummary?: RecordingResultSummary;
}

/**
 * Summary of ceremony result for recording
 */
export interface RecordingResultSummary {
  /** Was successful */
  success: boolean;

  /** Final phase reached */
  finalPhase: CeremonyPhase;

  /** Number of shares distributed */
  sharesDistributed: number;

  /** Public key (first 16 chars) */
  publicKeyPreview: string;
}

/**
 * Playback state
 */
export interface PlaybackState {
  /** Is playing */
  isPlaying: boolean;

  /** Is paused */
  isPaused: boolean;

  /** Current position (ms) */
  position: number;

  /** Total duration (ms) */
  duration: number;

  /** Playback speed (1 = normal) */
  speed: number;

  /** Current event index */
  currentEventIndex: number;

  /** Total events */
  totalEvents: number;
}

/**
 * Playback controls
 */
export interface PlaybackControls {
  play(): void;
  pause(): void;
  stop(): void;
  seek(positionMs: number): void;
  setSpeed(speed: number): void;
  nextEvent(): void;
  previousEvent(): void;
}

/**
 * Ceremony phase display info
 */
export interface PhaseDisplayInfo {
  /** Phase enum value */
  phase: CeremonyPhase;

  /** Display name */
  name: string;

  /** Description */
  description: string;

  /** Icon name (for UI frameworks) */
  icon: string;

  /** Color scheme */
  color: 'gray' | 'blue' | 'yellow' | 'green' | 'red';

  /** Step number (1-based) */
  stepNumber: number;

  /** Is terminal phase */
  isTerminal: boolean;
}

/**
 * Notification for UI
 */
export interface CeremonyNotification {
  /** Notification ID */
  id: string;

  /** Type */
  type: 'info' | 'success' | 'warning' | 'error';

  /** Title */
  title: string;

  /** Message */
  message: string;

  /** Timestamp */
  timestamp: Date;

  /** Auto-dismiss after (ms) */
  autoDismiss?: number;

  /** Action button */
  action?: {
    label: string;
    onClick: () => void;
  };
}

/**
 * Ceremony UI Error
 */
export interface CeremonyUIError {
  /** Error code */
  code: string;

  /** Error message */
  message: string;

  /** Recoverable */
  recoverable: boolean;

  /** Suggested action */
  suggestedAction?: string;

  /** Timestamp */
  timestamp: Date;
}

/**
 * Observer callback for ceremony state changes
 */
export type CeremonyStateObserver = (state: CeremonyUIState) => void;

/**
 * Event listener callback
 */
export type CeremonyEventListener = (event: CeremonyUIEvent) => void;

/**
 * QR scan result
 */
export interface QRScanResult {
  /** Was successful */
  success: boolean;

  /** Participant ID (if decoded) */
  participantId?: string;

  /** Share index (if decoded) */
  shareIndex?: number;

  /** Error message (if failed) */
  error?: string;
}

/**
 * Ceremony statistics for dashboard
 */
export interface CeremonyStatistics {
  /** Time in current phase (ms) */
  phaseTime: number;

  /** Total ceremony time (ms) */
  totalTime: number;

  /** Participants registered */
  participantsRegistered: number;

  /** Commitments received */
  commitmentsReceived: number;

  /** Shares distributed */
  sharesDistributed: number;

  /** Audit entries count */
  auditEntries: number;

  /** Estimated time remaining (ms) */
  estimatedTimeRemaining?: number;
}

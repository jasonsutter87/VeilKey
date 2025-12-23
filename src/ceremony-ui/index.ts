/**
 * VeilKey Key Ceremony Web UI Module
 *
 * Provides tools for building real-time ceremony interfaces:
 * - State observation for live updates
 * - QR code generation for secure share distribution
 * - Recording and playback for audit and review
 *
 * @module ceremony-ui
 */

// Types
export type {
  // Core UI types
  CeremonyUIState,
  CeremonyUIConfig,
  UIParticipant,
  CeremonyUIEvent,
  CeremonyUIError,
  CeremonyStateObserver,
  CeremonyEventListener,
  ConnectionStatus,
  UITheme,

  // QR code types
  ShareQRCode,
  QRScanResult,

  // Recording types
  CeremonyRecording,
  RecordedEvent,
  RecordingMetadata,
  RecordingResultSummary,
  PlaybackState,
  PlaybackControls,

  // Display types
  PhaseDisplayInfo,
  CeremonyNotification,
  CeremonyStatistics,
} from './types.js';

export { CeremonyUIEventType } from './types.js';

// State Observer
export {
  CeremonyStateObserverImpl,
  createCeremonyObserver,
} from './state-observer.js';

// QR Code Share Distribution
export {
  QRShareManager,
  createQRShareManager,
  generateShareQRCode,
  type QRGenerationOptions,
} from './qr-share.js';

// Recording and Playback
export {
  CeremonyRecorder,
  CeremonyPlayer,
  createCeremonyRecorder,
  createCeremonyPlayer,
  loadRecordingAndPlay,
  type RecordingOptions,
} from './recording.js';

/**
 * VeilKey Ceremony Recording and Playback
 *
 * Records ceremony events for audit purposes and enables
 * playback for review and verification.
 *
 * @module ceremony-ui/recording
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import type { CeremonyCoordinator } from '../ceremony/coordinator.js';
import {
  CeremonyPhase,
  AuditEventType,
  type AuditEntry,
  type CeremonyConfig,
} from '../ceremony/types.js';
import type {
  CeremonyRecording,
  RecordedEvent,
  RecordingMetadata,
  RecordingResultSummary,
  PlaybackState,
  PlaybackControls,
} from './types.js';

/**
 * Recording options
 */
export interface RecordingOptions {
  /** Recording version */
  version: string;

  /** Include sensitive data (defaults to false) */
  includeSensitiveData: boolean;

  /** Compress recording data */
  compress: boolean;

  /** Maximum events to record */
  maxEvents: number;
}

const DEFAULT_RECORDING_OPTIONS: RecordingOptions = {
  version: '1.0.0',
  includeSensitiveData: false,
  compress: false,
  maxEvents: 10000,
};

/**
 * Ceremony Recorder
 *
 * Records ceremony events for later playback and audit.
 */
export class CeremonyRecorder {
  private options: RecordingOptions;
  private recording: CeremonyRecording | null = null;
  private isRecording = false;
  private startTime: Date | null = null;
  private coordinator: CeremonyCoordinator | null = null;
  private lastAuditIndex = 0;
  private pollInterval: ReturnType<typeof setInterval> | null = null;

  constructor(options: Partial<RecordingOptions> = {}) {
    this.options = { ...DEFAULT_RECORDING_OPTIONS, ...options };
  }

  /**
   * Start recording a ceremony
   */
  startRecording(coordinator: CeremonyCoordinator): CeremonyRecording {
    if (this.isRecording) {
      this.stopRecording();
    }

    this.coordinator = coordinator;
    this.startTime = new Date();
    this.lastAuditIndex = 0;
    this.isRecording = true;

    const config = coordinator.getConfig();

    this.recording = {
      id: bytesToHex(new Uint8Array(16).map(() => Math.floor(Math.random() * 256))),
      ceremonyId: config.id,
      startedAt: this.startTime,
      events: [],
      metadata: {
        version: this.options.version,
        ceremonyConfig: config,
        participantCount: config.totalParticipants,
      },
    };

    // Record initial state
    this.recordEvent('RECORDING_STARTED', {
      ceremonyId: config.id,
      phase: coordinator.getCurrentPhase(),
    });

    // Start polling for new events
    this.startPolling();

    return this.recording;
  }

  /**
   * Stop recording
   */
  stopRecording(): CeremonyRecording | null {
    if (!this.isRecording || !this.recording) {
      return null;
    }

    this.stopPolling();

    // Capture any remaining events
    this.captureAuditEvents();

    this.recording.endedAt = new Date();
    this.recording.duration = this.recording.endedAt.getTime() - this.recording.startedAt.getTime();

    // Add result summary if ceremony completed
    if (this.coordinator?.isComplete()) {
      const result = this.coordinator.getResult();
      if (result) {
        this.recording.metadata.resultSummary = {
          success: true,
          finalPhase: CeremonyPhase.FINALIZED,
          sharesDistributed: result.shares.length,
          publicKeyPreview: result.publicKey.slice(0, 16),
        };
      }
    }

    this.recordEvent('RECORDING_STOPPED', {
      totalEvents: this.recording.events.length,
      duration: this.recording.duration,
    });

    this.isRecording = false;
    const finalRecording = this.recording;
    this.recording = null;
    this.coordinator = null;

    return finalRecording;
  }

  /**
   * Get current recording
   */
  getRecording(): CeremonyRecording | null {
    return this.recording;
  }

  /**
   * Check if recording
   */
  isCurrentlyRecording(): boolean {
    return this.isRecording;
  }

  /**
   * Add a custom event to the recording
   */
  addCustomEvent(type: string, data: Record<string, unknown>): void {
    if (!this.isRecording) return;
    this.recordEvent(type, data);
  }

  /**
   * Export recording as JSON
   */
  exportRecording(): string | null {
    if (!this.recording) return null;

    return JSON.stringify(this.recording, (key, value) => {
      // Sanitize sensitive data if needed
      if (!this.options.includeSensitiveData) {
        if (key === 'shareValue' || key === 'privateKey') {
          return '[REDACTED]';
        }
      }
      return value;
    }, 2);
  }

  /**
   * Import a recording from JSON
   */
  static importRecording(json: string): CeremonyRecording {
    const data = JSON.parse(json);

    // Reconstruct dates
    data.startedAt = new Date(data.startedAt);
    if (data.endedAt) {
      data.endedAt = new Date(data.endedAt);
    }

    for (const event of data.events) {
      event.timestamp = new Date(event.timestamp);
    }

    return data as CeremonyRecording;
  }

  /**
   * Record an event
   */
  private recordEvent(type: string, data: Record<string, unknown>): void {
    if (!this.recording || !this.startTime) return;

    if (this.recording.events.length >= this.options.maxEvents) {
      return; // Max events reached
    }

    const now = new Date();
    const event: RecordedEvent = {
      index: this.recording.events.length,
      relativeTime: now.getTime() - this.startTime.getTime(),
      timestamp: now,
      type,
      data: this.sanitizeData(data),
    };

    this.recording.events.push(event);
  }

  /**
   * Capture audit events from coordinator
   */
  private captureAuditEvents(): void {
    if (!this.coordinator) return;

    const auditLog = this.coordinator.getAuditLog();

    for (let i = this.lastAuditIndex; i < auditLog.length; i++) {
      const entry = auditLog[i];
      this.recordEvent(`AUDIT_${entry.eventType}`, {
        ...entry.data,
        auditSequence: entry.sequence,
      });
    }

    this.lastAuditIndex = auditLog.length;
  }

  /**
   * Start polling for events
   */
  private startPolling(): void {
    this.pollInterval = setInterval(() => {
      this.captureAuditEvents();
    }, 500);
  }

  /**
   * Stop polling
   */
  private stopPolling(): void {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  /**
   * Sanitize data for recording
   */
  private sanitizeData(data: Record<string, unknown>): Record<string, unknown> {
    if (this.options.includeSensitiveData) {
      return { ...data };
    }

    const sanitized: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(data)) {
      // Redact sensitive fields
      if (
        key.toLowerCase().includes('secret') ||
        key.toLowerCase().includes('private') ||
        key.toLowerCase().includes('password') ||
        key.toLowerCase().includes('key')
      ) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.sanitizeData(value as Record<string, unknown>);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }
}

/**
 * Ceremony Player
 *
 * Plays back recorded ceremonies for review.
 */
export class CeremonyPlayer implements PlaybackControls {
  private recording: CeremonyRecording;
  private state: PlaybackState;
  private eventListeners: ((event: RecordedEvent, state: PlaybackState) => void)[] = [];
  private playbackInterval: ReturnType<typeof setInterval> | null = null;
  private lastPlaybackTime: number = 0;

  constructor(recording: CeremonyRecording) {
    this.recording = recording;
    this.state = {
      isPlaying: false,
      isPaused: false,
      position: 0,
      duration: recording.duration ?? 0,
      speed: 1,
      currentEventIndex: 0,
      totalEvents: recording.events.length,
    };
  }

  /**
   * Start playback
   */
  play(): void {
    if (this.state.isPlaying && !this.state.isPaused) return;

    this.state.isPlaying = true;
    this.state.isPaused = false;
    this.lastPlaybackTime = Date.now();

    this.playbackInterval = setInterval(() => {
      this.tick();
    }, 50); // Update at 20fps
  }

  /**
   * Pause playback
   */
  pause(): void {
    this.state.isPaused = true;
    this.stopPlayback();
  }

  /**
   * Stop playback and reset
   */
  stop(): void {
    this.state.isPlaying = false;
    this.state.isPaused = false;
    this.state.position = 0;
    this.state.currentEventIndex = 0;
    this.stopPlayback();
  }

  /**
   * Seek to position
   */
  seek(positionMs: number): void {
    this.state.position = Math.max(0, Math.min(positionMs, this.state.duration));

    // Find the event index for this position
    let eventIndex = 0;
    for (let i = 0; i < this.recording.events.length; i++) {
      if (this.recording.events[i].relativeTime <= this.state.position) {
        eventIndex = i;
      } else {
        break;
      }
    }

    this.state.currentEventIndex = eventIndex;
    this.lastPlaybackTime = Date.now();
  }

  /**
   * Set playback speed
   */
  setSpeed(speed: number): void {
    this.state.speed = Math.max(0.25, Math.min(4, speed));
  }

  /**
   * Jump to next event
   */
  nextEvent(): void {
    if (this.state.currentEventIndex < this.recording.events.length - 1) {
      this.state.currentEventIndex++;
      const event = this.recording.events[this.state.currentEventIndex];
      this.state.position = event.relativeTime;
      this.emitEvent(event);
    }
  }

  /**
   * Jump to previous event
   */
  previousEvent(): void {
    if (this.state.currentEventIndex > 0) {
      this.state.currentEventIndex--;
      const event = this.recording.events[this.state.currentEventIndex];
      this.state.position = event.relativeTime;
      this.emitEvent(event);
    }
  }

  /**
   * Get current playback state
   */
  getState(): PlaybackState {
    return { ...this.state };
  }

  /**
   * Get current event
   */
  getCurrentEvent(): RecordedEvent | null {
    return this.recording.events[this.state.currentEventIndex] ?? null;
  }

  /**
   * Get all events
   */
  getAllEvents(): RecordedEvent[] {
    return [...this.recording.events];
  }

  /**
   * Get events up to current position
   */
  getEventsUpToCurrent(): RecordedEvent[] {
    return this.recording.events.slice(0, this.state.currentEventIndex + 1);
  }

  /**
   * Subscribe to event emissions during playback
   */
  onEvent(listener: (event: RecordedEvent, state: PlaybackState) => void): () => void {
    this.eventListeners.push(listener);
    return () => {
      const index = this.eventListeners.indexOf(listener);
      if (index > -1) {
        this.eventListeners.splice(index, 1);
      }
    };
  }

  /**
   * Get recording metadata
   */
  getMetadata(): RecordingMetadata {
    return this.recording.metadata;
  }

  /**
   * Get recording info
   */
  getRecordingInfo(): {
    id: string;
    ceremonyId: string;
    startedAt: Date;
    endedAt?: Date;
    duration?: number;
    eventCount: number;
  } {
    return {
      id: this.recording.id,
      ceremonyId: this.recording.ceremonyId,
      startedAt: this.recording.startedAt,
      endedAt: this.recording.endedAt,
      duration: this.recording.duration,
      eventCount: this.recording.events.length,
    };
  }

  /**
   * Search events by type
   */
  findEventsByType(type: string): RecordedEvent[] {
    return this.recording.events.filter(e => e.type === type);
  }

  /**
   * Get timeline data for visualization
   */
  getTimeline(): { time: number; type: string; label: string }[] {
    return this.recording.events.map(e => ({
      time: e.relativeTime,
      type: e.type,
      label: this.getEventLabel(e),
    }));
  }

  /**
   * Playback tick
   */
  private tick(): void {
    if (!this.state.isPlaying || this.state.isPaused) return;

    const now = Date.now();
    const elapsed = (now - this.lastPlaybackTime) * this.state.speed;
    this.lastPlaybackTime = now;

    this.state.position += elapsed;

    if (this.state.position >= this.state.duration) {
      this.state.position = this.state.duration;
      this.stop();
      return;
    }

    // Emit events that should have occurred
    while (
      this.state.currentEventIndex < this.recording.events.length - 1 &&
      this.recording.events[this.state.currentEventIndex + 1].relativeTime <= this.state.position
    ) {
      this.state.currentEventIndex++;
      this.emitEvent(this.recording.events[this.state.currentEventIndex]);
    }
  }

  /**
   * Emit an event to listeners
   */
  private emitEvent(event: RecordedEvent): void {
    for (const listener of this.eventListeners) {
      try {
        listener(event, this.state);
      } catch {
        // Ignore listener errors
      }
    }
  }

  /**
   * Stop playback interval
   */
  private stopPlayback(): void {
    if (this.playbackInterval) {
      clearInterval(this.playbackInterval);
      this.playbackInterval = null;
    }
  }

  /**
   * Get human-readable label for event
   */
  private getEventLabel(event: RecordedEvent): string {
    const labels: Record<string, string> = {
      RECORDING_STARTED: 'Recording Started',
      RECORDING_STOPPED: 'Recording Stopped',
      AUDIT_CEREMONY_CREATED: 'Ceremony Created',
      AUDIT_PHASE_TRANSITION: 'Phase Changed',
      AUDIT_PARTICIPANT_REGISTERED: 'Participant Registered',
      AUDIT_COMMITMENT_SUBMITTED: 'Commitment Submitted',
      AUDIT_SHARES_DISTRIBUTED: 'Shares Distributed',
      AUDIT_CEREMONY_FINALIZED: 'Ceremony Completed',
      AUDIT_ERROR: 'Error',
    };

    return labels[event.type] ?? event.type;
  }
}

/**
 * Create a ceremony recorder
 */
export function createCeremonyRecorder(
  options?: Partial<RecordingOptions>
): CeremonyRecorder {
  return new CeremonyRecorder(options);
}

/**
 * Create a ceremony player from a recording
 */
export function createCeremonyPlayer(recording: CeremonyRecording): CeremonyPlayer {
  return new CeremonyPlayer(recording);
}

/**
 * Load and create player from JSON
 */
export function loadRecordingAndPlay(json: string): CeremonyPlayer {
  const recording = CeremonyRecorder.importRecording(json);
  return createCeremonyPlayer(recording);
}

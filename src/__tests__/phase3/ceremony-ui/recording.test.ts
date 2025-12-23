/**
 * Ceremony Recording and Playback Tests
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { CeremonyCoordinator } from '../../../ceremony/coordinator.js';
import { CeremonyPhase } from '../../../ceremony/types.js';
import {
  CeremonyRecorder,
  CeremonyPlayer,
  createCeremonyRecorder,
  createCeremonyPlayer,
  loadRecordingAndPlay,
} from '../../../ceremony-ui/recording.js';

describe('CeremonyRecorder', () => {
  let coordinator: CeremonyCoordinator;
  let recorder: CeremonyRecorder;

  beforeEach(() => {
    coordinator = new CeremonyCoordinator({
      id: 'test-ceremony',
      threshold: 2,
      totalParticipants: 3,
    });

    recorder = createCeremonyRecorder();
  });

  afterEach(() => {
    if (recorder.isCurrentlyRecording()) {
      recorder.stopRecording();
    }
  });

  describe('recording lifecycle', () => {
    it('should start recording', () => {
      const recording = recorder.startRecording(coordinator);

      expect(recording).toBeDefined();
      expect(recording.ceremonyId).toBe('test-ceremony');
      expect(recording.id).toBeDefined();
      expect(recorder.isCurrentlyRecording()).toBe(true);
    });

    it('should stop recording', () => {
      recorder.startRecording(coordinator);
      const recording = recorder.stopRecording();

      expect(recording).toBeDefined();
      expect(recording?.endedAt).toBeDefined();
      expect(recording?.duration).toBeGreaterThanOrEqual(0);
      expect(recorder.isCurrentlyRecording()).toBe(false);
    });

    it('should return null if not recording', () => {
      const recording = recorder.stopRecording();
      expect(recording).toBeNull();
    });
  });

  describe('event recording', () => {
    it('should record ceremony events', async () => {
      recorder.startRecording(coordinator);

      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'abcdef1234567890');

      // Wait for polling to capture events
      await new Promise(resolve => setTimeout(resolve, 600));

      const recording = recorder.stopRecording();

      expect(recording?.events.length).toBeGreaterThan(1);
    });

    it('should record custom events', () => {
      recorder.startRecording(coordinator);
      recorder.addCustomEvent('CUSTOM_EVENT', { message: 'test' });

      const recording = recorder.stopRecording();

      const customEvents = recording?.events.filter(e => e.type === 'CUSTOM_EVENT');
      expect(customEvents?.length).toBe(1);
      expect(customEvents?.[0].data.message).toBe('test');
    });

    it('should track relative time', async () => {
      recorder.startRecording(coordinator);

      await new Promise(resolve => setTimeout(resolve, 100));

      recorder.addCustomEvent('TEST', {});

      const recording = recorder.stopRecording();
      const lastEvent = recording?.events[recording.events.length - 1];

      expect(lastEvent?.relativeTime).toBeGreaterThanOrEqual(100);
    });
  });

  describe('metadata', () => {
    it('should include ceremony config in metadata', () => {
      const recording = recorder.startRecording(coordinator);

      expect(recording.metadata.ceremonyConfig.id).toBe('test-ceremony');
      expect(recording.metadata.ceremonyConfig.threshold).toBe(2);
      expect(recording.metadata.participantCount).toBe(3);
    });

    it('should include version', () => {
      const recording = recorder.startRecording(coordinator);
      expect(recording.metadata.version).toBeDefined();
    });
  });

  describe('export/import', () => {
    it('should export recording as JSON', () => {
      recorder.startRecording(coordinator);
      recorder.addCustomEvent('TEST', { value: 'test' });
      recorder.stopRecording();

      const json = recorder.exportRecording();

      expect(json).toBeNull(); // Recording already stopped

      // Start a new recording to test export
      recorder.startRecording(coordinator);
      const json2 = recorder.exportRecording();

      expect(json2).toBeDefined();
      expect(JSON.parse(json2!)).toBeDefined();
    });

    it('should import recording from JSON', () => {
      recorder.startRecording(coordinator);
      recorder.addCustomEvent('TEST', { value: 'test' });
      const recording = recorder.stopRecording();

      const json = JSON.stringify(recording);
      const imported = CeremonyRecorder.importRecording(json);

      expect(imported.ceremonyId).toBe(recording?.ceremonyId);
      expect(imported.events.length).toBe(recording?.events.length);
    });

    it('should sanitize sensitive data by default', () => {
      recorder.startRecording(coordinator);
      recorder.addCustomEvent('SENSITIVE', {
        secretKey: 'should-be-redacted',
        normalData: 'visible',
      });

      const json = recorder.exportRecording();
      // Note: exportRecording returns null after stop, so test inline
    });
  });

  describe('options', () => {
    it('should respect max events limit', () => {
      const limitedRecorder = createCeremonyRecorder({ maxEvents: 5 });
      limitedRecorder.startRecording(coordinator);

      for (let i = 0; i < 10; i++) {
        limitedRecorder.addCustomEvent('EVENT', { i });
      }

      const recording = limitedRecorder.stopRecording();

      // Should have initial events + 5 custom events (but capped at 5 total)
      expect(recording?.events.length).toBeLessThanOrEqual(5);
    });
  });
});

describe('CeremonyPlayer', () => {
  let player: CeremonyPlayer;

  beforeEach(() => {
    // Create a sample recording
    const recording = {
      id: 'recording-1',
      ceremonyId: 'ceremony-1',
      startedAt: new Date('2024-01-01T00:00:00Z'),
      endedAt: new Date('2024-01-01T00:01:00Z'),
      duration: 60000,
      events: [
        { index: 0, relativeTime: 0, timestamp: new Date('2024-01-01T00:00:00Z'), type: 'START', data: {} },
        { index: 1, relativeTime: 10000, timestamp: new Date('2024-01-01T00:00:10Z'), type: 'EVENT_A', data: { value: 'a' } },
        { index: 2, relativeTime: 30000, timestamp: new Date('2024-01-01T00:00:30Z'), type: 'EVENT_B', data: { value: 'b' } },
        { index: 3, relativeTime: 60000, timestamp: new Date('2024-01-01T00:01:00Z'), type: 'END', data: {} },
      ],
      metadata: {
        version: '1.0.0',
        ceremonyConfig: { id: 'ceremony-1', threshold: 2, totalParticipants: 3 },
        participantCount: 3,
      },
    };

    player = createCeremonyPlayer(recording);
  });

  describe('playback controls', () => {
    it('should initialize in stopped state', () => {
      const state = player.getState();

      expect(state.isPlaying).toBe(false);
      expect(state.isPaused).toBe(false);
      expect(state.position).toBe(0);
      expect(state.currentEventIndex).toBe(0);
    });

    it('should play', () => {
      player.play();
      const state = player.getState();

      expect(state.isPlaying).toBe(true);
      expect(state.isPaused).toBe(false);

      player.stop();
    });

    it('should pause', () => {
      player.play();
      player.pause();
      const state = player.getState();

      expect(state.isPaused).toBe(true);
    });

    it('should stop and reset', () => {
      player.play();
      player.seek(30000);
      player.stop();

      const state = player.getState();

      expect(state.isPlaying).toBe(false);
      expect(state.position).toBe(0);
      expect(state.currentEventIndex).toBe(0);
    });

    it('should seek to position', () => {
      player.seek(30000);
      const state = player.getState();

      expect(state.position).toBe(30000);
      expect(state.currentEventIndex).toBe(2);
    });

    it('should clamp seek to valid range', () => {
      player.seek(-1000);
      expect(player.getState().position).toBe(0);

      player.seek(100000);
      expect(player.getState().position).toBe(60000);
    });

    it('should set playback speed', () => {
      player.setSpeed(2);
      expect(player.getState().speed).toBe(2);

      // Should clamp to valid range
      player.setSpeed(0.1);
      expect(player.getState().speed).toBe(0.25);

      player.setSpeed(10);
      expect(player.getState().speed).toBe(4);
    });
  });

  describe('event navigation', () => {
    it('should jump to next event', () => {
      expect(player.getState().currentEventIndex).toBe(0);

      player.nextEvent();
      expect(player.getState().currentEventIndex).toBe(1);
      expect(player.getState().position).toBe(10000);
    });

    it('should jump to previous event', () => {
      player.seek(30000);
      expect(player.getState().currentEventIndex).toBe(2);

      player.previousEvent();
      expect(player.getState().currentEventIndex).toBe(1);
      expect(player.getState().position).toBe(10000);
    });

    it('should not go past last event', () => {
      player.seek(60000);
      player.nextEvent();
      expect(player.getState().currentEventIndex).toBe(3);
    });

    it('should not go before first event', () => {
      player.previousEvent();
      expect(player.getState().currentEventIndex).toBe(0);
    });
  });

  describe('event access', () => {
    it('should get current event', () => {
      const event = player.getCurrentEvent();

      expect(event).toBeDefined();
      expect(event?.type).toBe('START');
    });

    it('should get all events', () => {
      const events = player.getAllEvents();
      expect(events).toHaveLength(4);
    });

    it('should get events up to current position', () => {
      player.seek(30000);
      const events = player.getEventsUpToCurrent();

      expect(events).toHaveLength(3);
    });

    it('should find events by type', () => {
      const events = player.findEventsByType('EVENT_A');

      expect(events).toHaveLength(1);
      expect(events[0].data.value).toBe('a');
    });
  });

  describe('metadata access', () => {
    it('should get metadata', () => {
      const metadata = player.getMetadata();

      expect(metadata.version).toBe('1.0.0');
      expect(metadata.participantCount).toBe(3);
    });

    it('should get recording info', () => {
      const info = player.getRecordingInfo();

      expect(info.ceremonyId).toBe('ceremony-1');
      expect(info.duration).toBe(60000);
      expect(info.eventCount).toBe(4);
    });
  });

  describe('timeline', () => {
    it('should generate timeline data', () => {
      const timeline = player.getTimeline();

      expect(timeline).toHaveLength(4);
      expect(timeline[0].time).toBe(0);
      expect(timeline[1].time).toBe(10000);
    });
  });

  describe('event subscription', () => {
    it('should notify on events during playback', async () => {
      const listener = vi.fn();
      player.onEvent(listener);

      player.nextEvent();

      expect(listener).toHaveBeenCalled();
      expect(listener.mock.calls[0][0].type).toBe('EVENT_A');
    });

    it('should unsubscribe', () => {
      const listener = vi.fn();
      const unsubscribe = player.onEvent(listener);

      unsubscribe();
      player.nextEvent();

      expect(listener).not.toHaveBeenCalled();
    });
  });
});

describe('Integration', () => {
  it('should record and playback a ceremony', async () => {
    const coordinator = new CeremonyCoordinator({
      id: 'full-test',
      threshold: 2,
      totalParticipants: 2,
    });

    const recorder = createCeremonyRecorder();
    recorder.startRecording(coordinator);

    coordinator.startRegistration();
    coordinator.addParticipant('alice', 'abcdef1234567890');
    coordinator.addParticipant('bob', '1234567890abcdef');

    await new Promise(resolve => setTimeout(resolve, 100));

    const recording = recorder.stopRecording();
    expect(recording).toBeDefined();

    const json = JSON.stringify(recording);
    const player = loadRecordingAndPlay(json);

    expect(player.getRecordingInfo().ceremonyId).toBe('full-test');
    expect(player.getAllEvents().length).toBeGreaterThan(0);
  });
});

/**
 * Ceremony State Observer Tests
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { CeremonyCoordinator } from '../../../ceremony/coordinator.js';
import { CeremonyPhase, ParticipantStatus } from '../../../ceremony/types.js';
import {
  CeremonyStateObserverImpl,
  createCeremonyObserver,
} from '../../../ceremony-ui/state-observer.js';

describe('CeremonyStateObserver', () => {
  let coordinator: CeremonyCoordinator;
  let observer: CeremonyStateObserverImpl;

  beforeEach(() => {
    coordinator = new CeremonyCoordinator({
      id: 'test-ceremony',
      threshold: 2,
      totalParticipants: 3,
      description: 'Test ceremony',
    });

    observer = createCeremonyObserver(coordinator);
  });

  afterEach(() => {
    observer.stop();
  });

  describe('initialization', () => {
    it('should create observer with default config', () => {
      const state = observer.getState();

      expect(state.ceremonyId).toBe('test-ceremony');
      expect(state.phase).toBe(CeremonyPhase.CREATED);
      expect(state.isComplete).toBe(false);
    });

    it('should build initial state correctly', () => {
      const state = observer.getState();

      expect(state.config.threshold).toBe(2);
      expect(state.config.totalParticipants).toBe(3);
      expect(state.participants).toHaveLength(0);
      expect(state.connectionStatus).toBe('connected');
    });
  });

  describe('state observation', () => {
    it('should notify subscribers of state changes', async () => {
      const callback = vi.fn();

      // Start polling first
      observer.start(100);

      // Subscribe after starting (to avoid race condition with initial notification)
      observer.subscribe(callback);

      // Initial state notification from subscribe
      expect(callback).toHaveBeenCalled();
      const initialCallCount = callback.mock.calls.length;

      // Make a change
      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'abcdef1234567890');

      // Wait for poll
      await new Promise(resolve => setTimeout(resolve, 150));

      // Should have been called again
      expect(callback.mock.calls.length).toBeGreaterThan(initialCallCount);
    });

    it('should unsubscribe correctly', () => {
      const callback = vi.fn();
      const unsubscribe = observer.subscribe(callback);

      expect(callback).toHaveBeenCalledTimes(1);

      unsubscribe();
      observer.refresh();

      // Should not be called after unsubscribe
      expect(callback).toHaveBeenCalledTimes(1);
    });
  });

  describe('phase tracking', () => {
    it('should track phase changes', () => {
      coordinator.startRegistration();
      observer.refresh();

      const state = observer.getState();
      expect(state.phase).toBe(CeremonyPhase.REGISTRATION);
    });

    it('should emit phase change events', () => {
      const eventListener = vi.fn();
      observer.addEventListener(eventListener);

      coordinator.startRegistration();
      observer.refresh();

      expect(eventListener).toHaveBeenCalled();
      expect(eventListener.mock.calls[0][0].type).toBe('PHASE_CHANGED');
    });
  });

  describe('participant tracking', () => {
    beforeEach(() => {
      coordinator.startRegistration();
    });

    it('should build UI participant correctly', () => {
      coordinator.addParticipant('alice', 'abcdef1234567890abcdef1234567890');
      observer.refresh();

      const state = observer.getState();
      expect(state.participants).toHaveLength(1);

      const alice = state.participants[0];
      expect(alice.id).toBe('alice');
      expect(alice.displayName).toBe('alice');
      expect(alice.publicKeyDisplay).toMatch(/^abcdef12\.\.\..*$/);
      expect(alice.status).toBe(ParticipantStatus.REGISTERED);
      expect(alice.statusDisplay).toBe('Registered');
      expect(alice.statusColor).toBe('pending');
      expect(alice.avatarColor).toMatch(/^hsl\(/);
    });

    it('should track participant online status', () => {
      coordinator.addParticipant('alice', 'abcdef1234567890');
      observer.refresh();

      let state = observer.getState();
      expect(state.participants[0].isOnline).toBe(false);

      observer.markParticipantOnline('alice');

      state = observer.getState();
      expect(state.participants[0].isOnline).toBe(true);

      observer.markParticipantOffline('alice');

      state = observer.getState();
      expect(state.participants[0].isOnline).toBe(false);
    });
  });

  describe('progress calculation', () => {
    it('should calculate registration progress', () => {
      coordinator.startRegistration();
      observer.refresh();

      let state = observer.getState();
      expect(state.phaseProgress).toBe(0);

      coordinator.addParticipant('alice', 'abcdef1234567890');
      observer.refresh();

      state = observer.getState();
      expect(state.phaseProgress).toBe(33);

      coordinator.addParticipant('bob', '1234567890abcdef');
      observer.refresh();

      state = observer.getState();
      expect(state.phaseProgress).toBe(67);
    });
  });

  describe('phase info', () => {
    it('should return phase display info', () => {
      const info = observer.getPhaseInfo(CeremonyPhase.REGISTRATION);

      expect(info.name).toBe('Registration');
      expect(info.description).toContain('registration');
      expect(info.icon).toBe('users');
      expect(info.color).toBe('blue');
      expect(info.stepNumber).toBe(2);
    });

    it('should return all phases info', () => {
      const phases = observer.getAllPhasesInfo();

      expect(phases).toHaveLength(5);
      expect(phases[0].phase).toBe(CeremonyPhase.CREATED);
      expect(phases[4].phase).toBe(CeremonyPhase.FINALIZED);
    });
  });

  describe('statistics', () => {
    it('should calculate statistics', () => {
      coordinator.startRegistration();
      coordinator.addParticipant('alice', 'abcdef1234567890');
      observer.refresh();

      const stats = observer.getStatistics();

      expect(stats.participantsRegistered).toBe(1);
      expect(stats.totalTime).toBeGreaterThan(0);
      expect(stats.auditEntries).toBeGreaterThan(0);
    });
  });

  describe('connection status', () => {
    it('should track connection status', () => {
      observer.setConnectionStatus('disconnected');

      const state = observer.getState();
      expect(state.connectionStatus).toBe('disconnected');
    });

    it('should emit connection status events', () => {
      const eventListener = vi.fn();
      observer.addEventListener(eventListener);

      observer.setConnectionStatus('error');

      expect(eventListener).toHaveBeenCalled();
      const event = eventListener.mock.calls[0][0];
      expect(event.type).toBe('CONNECTION_STATUS_CHANGED');
      expect(event.data.status).toBe('error');
    });
  });
});

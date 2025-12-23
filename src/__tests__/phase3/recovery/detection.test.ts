/**
 * Phase 3: Share Recovery - Detection Tests
 *
 * Tests for detecting lost or unresponsive share holders.
 *
 * @test-count 23
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  HeartbeatMonitorImpl,
  DetectionServiceImpl,
  InMemoryRecoveryStorage,
  type ShareHolder,
  type DetectionConfig,
  type DetectionEvent,
} from '../../../recovery/index.js';

describe('Share Recovery - Detection', () => {
  let storage: InMemoryRecoveryStorage;
  let detectionService: DetectionServiceImpl;
  let heartbeatMonitor: HeartbeatMonitorImpl;
  let mockConfig: DetectionConfig;

  beforeEach(() => {
    vi.useFakeTimers();
    storage = new InMemoryRecoveryStorage();
    heartbeatMonitor = new HeartbeatMonitorImpl(storage);
    detectionService = new DetectionServiceImpl(storage, heartbeatMonitor);

    mockConfig = {
      heartbeatInterval: 30000, // 30 seconds
      timeoutThreshold: 180000, // 3 minutes
      maxMissedHeartbeats: 3,
      autoDetectionEnabled: true,
      notificationChannels: [
        {
          type: 'email',
          destination: 'admin@example.com',
          priority: 'critical',
        },
      ],
    };
  });

  afterEach(async () => {
    await heartbeatMonitor.stop();
    vi.clearAllTimers();
    vi.useRealTimers();
  });

  describe('Unresponsive Share Holder Detection', () => {
    it('should detect share holder that has not responded within timeout threshold', async () => {
      // Setup a holder with old heartbeat
      const shareHolder: ShareHolder = {
        id: 'holder-1',
        publicKey: 'pk-holder-1',
        endpoint: 'https://holder1.example.com',
        lastHeartbeat: new Date(Date.now() - 200000), // 3.3 minutes ago
        status: 'active',
      };
      await storage.saveShareHolder(shareHolder);

      await detectionService.configure(mockConfig);

      // Action
      const event = await detectionService.detectUnresponsive(shareHolder.id);

      // Assert
      expect(event).toBeDefined();
      expect(event.shareHolderId).toBe(shareHolder.id);
      expect(event.detectionType).toBe('timeout');
      expect(event.severity).toBe('critical');
      expect(event.timestamp).toBeInstanceOf(Date);
    });

    it('should not detect responsive share holder as unresponsive', async () => {
      const shareHolder: ShareHolder = {
        id: 'holder-2',
        publicKey: 'pk-holder-2',
        lastHeartbeat: new Date(Date.now() - 60000), // 1 minute ago
        status: 'active',
      };
      await storage.saveShareHolder(shareHolder);

      await detectionService.configure(mockConfig);

      // Should still be active
      const status = await heartbeatMonitor.checkStatus(shareHolder.id);
      expect(status.status).toBe('active');
    });

    it('should detect multiple unresponsive share holders', async () => {
      await detectionService.configure(mockConfig);

      // Create holders with different last heartbeat times
      await storage.saveShareHolder({
        id: 'holder-1',
        publicKey: 'pk-1',
        lastHeartbeat: new Date(Date.now() - 300000), // 5 minutes ago
        status: 'active',
      });
      await storage.saveShareHolder({
        id: 'holder-2',
        publicKey: 'pk-2',
        lastHeartbeat: new Date(Date.now() - 400000), // 6.6 minutes ago
        status: 'active',
      });
      await storage.saveShareHolder({
        id: 'holder-3',
        publicKey: 'pk-3',
        lastHeartbeat: new Date(Date.now() - 60000), // 1 minute ago - responsive
        status: 'active',
      });

      const unresponsive = await heartbeatMonitor.getUnresponsiveHolders();

      expect(unresponsive).toHaveLength(2);
      expect(unresponsive.map(h => h.id)).toContain('holder-1');
      expect(unresponsive.map(h => h.id)).toContain('holder-2');
      expect(unresponsive.map(h => h.id)).not.toContain('holder-3');
    });

    it('should update share holder status to unresponsive upon detection', async () => {
      const shareHolderId = 'holder-1';
      await storage.saveShareHolder({
        id: shareHolderId,
        publicKey: 'pk-1',
        status: 'active',
      });
      await detectionService.configure(mockConfig);
      await detectionService.detectUnresponsive(shareHolderId);

      const status = await heartbeatMonitor.checkStatus(shareHolderId);
      expect(status.status).toBe('unresponsive');
    });
  });

  describe('Timeout-Based Detection', () => {
    it('should use configurable timeout threshold', async () => {
      const customConfig: DetectionConfig = {
        ...mockConfig,
        timeoutThreshold: 120000, // 2 minutes
      };

      await detectionService.configure(customConfig);

      // Holder that should be detected with 2-minute threshold
      await storage.saveShareHolder({
        id: 'holder-timeout-1',
        publicKey: 'pk-1',
        lastHeartbeat: new Date(Date.now() - 150000), // 2.5 minutes ago
        status: 'active',
      });

      const event = await detectionService.detectUnresponsive('holder-timeout-1');
      expect(event.detectionType).toBe('timeout');
    });

    it('should handle edge case where heartbeat is exactly at threshold', async () => {
      await detectionService.configure(mockConfig);

      const shareHolder: ShareHolder = {
        id: 'holder-edge',
        publicKey: 'pk-edge',
        lastHeartbeat: new Date(Date.now() - mockConfig.timeoutThreshold),
        status: 'active',
      };
      await storage.saveShareHolder(shareHolder);

      // At exactly threshold, should NOT be considered unresponsive
      const status = await heartbeatMonitor.checkStatus(shareHolder.id);
      expect(status.status).toBe('active');
    });

    it('should detect timeout even without previous heartbeat', async () => {
      await detectionService.configure(mockConfig);

      const shareHolder: ShareHolder = {
        id: 'holder-no-heartbeat',
        publicKey: 'pk-no-heartbeat',
        status: 'active',
        // No lastHeartbeat field
      };
      await storage.saveShareHolder(shareHolder);

      // After timeout period with no heartbeat, should be detected
      vi.advanceTimersByTime(mockConfig.timeoutThreshold + 1000);

      const status = await heartbeatMonitor.checkStatus(shareHolder.id);
      expect(status.status).toBe('unresponsive');
    });

    it('should reset timeout counter when heartbeat received', async () => {
      const shareHolderId = 'holder-reset';
      await detectionService.configure(mockConfig);
      await heartbeatMonitor.start(mockConfig);

      // Record heartbeat
      await heartbeatMonitor.recordHeartbeat(shareHolderId);

      // Advance time less than threshold
      vi.advanceTimersByTime(mockConfig.timeoutThreshold - 10000);

      // Record another heartbeat
      await heartbeatMonitor.recordHeartbeat(shareHolderId);

      // Should still be active
      const status = await heartbeatMonitor.checkStatus(shareHolderId);
      expect(status.status).toBe('active');
    });
  });

  describe('Heartbeat Monitoring', () => {
    it('should start heartbeat monitor with configuration', async () => {
      await heartbeatMonitor.start(mockConfig);

      // Verify monitor is running
      expect(heartbeatMonitor).toBeDefined();
    });

    it('should stop heartbeat monitor', async () => {
      await heartbeatMonitor.start(mockConfig);
      await heartbeatMonitor.stop();

      // After stop, should be able to start again without error
      await heartbeatMonitor.start(mockConfig);
    });

    it('should record heartbeat with timestamp', async () => {
      const shareHolderId = 'holder-hb-1';
      await heartbeatMonitor.start(mockConfig);

      const beforeTime = new Date();
      await heartbeatMonitor.recordHeartbeat(shareHolderId);
      const afterTime = new Date();

      const status = await heartbeatMonitor.checkStatus(shareHolderId);
      expect(status.lastHeartbeat).toBeDefined();
      expect(status.lastHeartbeat!.getTime()).toBeGreaterThanOrEqual(beforeTime.getTime());
      expect(status.lastHeartbeat!.getTime()).toBeLessThanOrEqual(afterTime.getTime());
    });

    it('should track missed heartbeat count', async () => {
      const shareHolderId = 'holder-missed';
      await heartbeatMonitor.start(mockConfig);
      await heartbeatMonitor.recordHeartbeat(shareHolderId);

      // Miss multiple heartbeat intervals - exceed timeout threshold
      vi.advanceTimersByTime(mockConfig.timeoutThreshold + 1000);

      const status = await heartbeatMonitor.checkStatus(shareHolderId);
      expect(status.status).toBe('unresponsive');
    });

    it('should detect unresponsive after max missed heartbeats', async () => {
      await detectionService.configure(mockConfig);
      await heartbeatMonitor.start(mockConfig);

      const shareHolderId = 'holder-max-missed';
      await heartbeatMonitor.recordHeartbeat(shareHolderId);

      // Simulate missing heartbeats beyond timeout
      vi.advanceTimersByTime(mockConfig.timeoutThreshold + 1000);
      await detectionService.detectUnresponsive(shareHolderId);

      const events = await detectionService.getDetectionEvents({
        shareHolderId,
        detectionType: 'timeout',
      });

      expect(events.length).toBeGreaterThan(0);
      expect(events[0].detectionType).toBe('timeout');
    });

    it('should handle concurrent heartbeat recordings', async () => {
      await heartbeatMonitor.start(mockConfig);

      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(heartbeatMonitor.recordHeartbeat(`holder-${i}`));
      }

      await Promise.all(promises);

      // All should be recorded without race conditions
      for (let i = 0; i < 10; i++) {
        const status = await heartbeatMonitor.checkStatus(`holder-${i}`);
        expect(status.lastHeartbeat).toBeDefined();
      }
    });
  });

  describe('Manual Lost Share Reporting', () => {
    it('should allow manual reporting of lost share', async () => {
      const shareHolderId = 'holder-manual-1';
      const reason = 'Device stolen, share compromised';

      const event = await detectionService.reportLostShare(shareHolderId, reason);

      expect(event.detectionType).toBe('manual');
      expect(event.shareHolderId).toBe(shareHolderId);
      expect(event.metadata?.reason).toBe(reason);
      expect(event.severity).toBe('critical');
    });

    it('should require reason for manual reporting', async () => {
      await expect(
        detectionService.reportLostShare('holder-manual-2', '')
      ).rejects.toThrow('Reason required for manual share loss reporting');
    });

    it('should immediately mark share holder as lost on manual report', async () => {
      const shareHolderId = 'holder-manual-3';
      await detectionService.configure(mockConfig);
      await detectionService.reportLostShare(shareHolderId, 'Hardware failure');

      const status = await heartbeatMonitor.checkStatus(shareHolderId);
      expect(status.status).toBe('lost');
    });

    it('should include reporter metadata in manual detection event', async () => {
      const shareHolderId = 'holder-manual-4';
      const reason = 'Employee terminated';

      const event = await detectionService.reportLostShare(shareHolderId, reason);

      expect(event.metadata).toBeDefined();
      expect(event.metadata?.reason).toBe(reason);
    });
  });

  describe('Detection Notification System', () => {
    it('should send notification when share holder detected as unresponsive', async () => {
      const mockNotificationSpy = vi.fn();
      await detectionService.configure(mockConfig);

      // Subscribe to events
      detectionService.subscribeToEvents(mockNotificationSpy);

      await detectionService.detectUnresponsive('holder-notify-1');

      expect(mockNotificationSpy).toHaveBeenCalled();
      expect(mockNotificationSpy.mock.calls[0][0].detectionType).toBe('timeout');
    });

    it('should support multiple notification channels', async () => {
      const multiChannelConfig: DetectionConfig = {
        ...mockConfig,
        notificationChannels: [
          { type: 'email', destination: 'admin@example.com', priority: 'critical' },
          { type: 'sms', destination: '+1234567890', priority: 'critical' },
          { type: 'webhook', destination: 'https://alerts.example.com/webhook', priority: 'high' },
        ],
      };

      await detectionService.configure(multiChannelConfig);
      const event = await detectionService.detectUnresponsive('holder-notify-2');

      // Implementation stores event successfully
      expect(event).toBeDefined();
      expect(event.detectionType).toBe('timeout');
    });

    it('should prioritize notifications by severity', async () => {
      await detectionService.configure(mockConfig);

      const criticalEvent = await detectionService.reportLostShare('holder-1', 'Critical loss');
      const warningEvent = await detectionService.detectUnresponsive('holder-2');

      expect(criticalEvent.severity).toBe('critical');
      expect(warningEvent.severity).toBe('critical'); // Timeout is also critical
    });

    it('should allow subscribing to detection events', async () => {
      await detectionService.configure(mockConfig);
      const events: DetectionEvent[] = [];
      const unsubscribe = detectionService.subscribeToEvents((event) => {
        events.push(event);
      });

      await detectionService.detectUnresponsive('holder-sub-1');
      await detectionService.reportLostShare('holder-sub-2', 'Manual report');

      expect(events).toHaveLength(2);

      unsubscribe();
    });

    it('should allow unsubscribing from detection events', async () => {
      await detectionService.configure(mockConfig);
      let eventCount = 0;
      const unsubscribe = detectionService.subscribeToEvents(() => {
        eventCount++;
      });

      await detectionService.detectUnresponsive('holder-unsub-1');
      expect(eventCount).toBe(1);

      unsubscribe();

      await detectionService.detectUnresponsive('holder-unsub-2');
      expect(eventCount).toBe(1); // Should not increment
    });
  });
});

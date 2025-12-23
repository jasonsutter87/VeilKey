/**
 * Share holder detection and heartbeat monitoring
 *
 * Provides:
 * - Heartbeat monitoring for share holders
 * - Detection of unresponsive holders
 * - Manual reporting of lost shares
 * - Event notification system
 */

import type {
  ShareHolder,
  DetectionConfig,
  DetectionEvent,
  DetectionEventFilter,
  RecoveryStorage,
} from './types.js';

// =============================================================================
// Heartbeat Monitor
// =============================================================================

export class HeartbeatMonitorImpl {
  private storage: RecoveryStorage;
  private config: DetectionConfig | null = null;
  private intervalHandle: NodeJS.Timeout | null = null;
  private isRunning = false;

  constructor(storage: RecoveryStorage) {
    this.storage = storage;
  }

  async start(config: DetectionConfig): Promise<void> {
    this.config = config;
    this.isRunning = true;

    if (config.autoDetectionEnabled && config.heartbeatInterval > 0) {
      this.intervalHandle = setInterval(
        () => this.checkAllHolders(),
        config.heartbeatInterval
      );
    }
  }

  async stop(): Promise<void> {
    this.isRunning = false;
    if (this.intervalHandle) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
    }
  }

  async recordHeartbeat(shareHolderId: string): Promise<void> {
    let holder = await this.storage.getShareHolder(shareHolderId);

    if (!holder) {
      // Create new holder if doesn't exist
      holder = {
        id: shareHolderId,
        publicKey: '',
        status: 'active',
        lastHeartbeat: new Date(),
      };
      await this.storage.saveShareHolder(holder);
    } else {
      await this.storage.updateShareHolder(shareHolderId, {
        lastHeartbeat: new Date(),
        status: 'active',
      });
    }
  }

  async checkStatus(shareHolderId: string): Promise<ShareHolder> {
    let holder = await this.storage.getShareHolder(shareHolderId);

    if (!holder) {
      // Create with unresponsive status if never seen
      holder = {
        id: shareHolderId,
        publicKey: '',
        status: 'unresponsive',
      };
      await this.storage.saveShareHolder(holder);
      return holder;
    }

    if (!this.config) {
      return holder;
    }

    // Check if holder is unresponsive
    const now = Date.now();
    const lastHb = holder.lastHeartbeat?.getTime() || 0;
    const timeSinceHeartbeat = now - lastHb;

    if (timeSinceHeartbeat > this.config.timeoutThreshold && holder.status === 'active') {
      await this.storage.updateShareHolder(shareHolderId, {
        status: 'unresponsive',
      });
      holder.status = 'unresponsive';
    }

    return holder;
  }

  async getUnresponsiveHolders(): Promise<ShareHolder[]> {
    if (!this.config) {
      return [];
    }

    const allHolders = await this.storage.listShareHolders();
    const unresponsive: ShareHolder[] = [];
    const now = Date.now();

    for (const holder of allHolders) {
      const lastHb = holder.lastHeartbeat?.getTime() || 0;
      const timeSinceHeartbeat = now - lastHb;

      if (timeSinceHeartbeat > this.config.timeoutThreshold) {
        unresponsive.push(holder);
      }
    }

    return unresponsive;
  }

  private async checkAllHolders(): Promise<void> {
    if (!this.config) return;

    const holders = await this.storage.listShareHolders();
    for (const holder of holders) {
      await this.checkStatus(holder.id);
    }
  }
}

// =============================================================================
// Detection Service
// =============================================================================

export class DetectionServiceImpl {
  private storage: RecoveryStorage;
  private heartbeatMonitor: HeartbeatMonitorImpl;
  private config: DetectionConfig | null = null;
  private eventCallbacks: ((event: DetectionEvent) => void)[] = [];

  constructor(storage: RecoveryStorage, heartbeatMonitor: HeartbeatMonitorImpl) {
    this.storage = storage;
    this.heartbeatMonitor = heartbeatMonitor;
  }

  async configure(config: DetectionConfig): Promise<void> {
    this.config = config;
    await this.heartbeatMonitor.start(config);
  }

  async detectUnresponsive(shareHolderId: string): Promise<DetectionEvent> {
    if (!this.config) {
      throw new Error('DetectionService not configured');
    }

    // Check if holder exists, create if not
    let holder = await this.storage.getShareHolder(shareHolderId);
    if (!holder) {
      holder = {
        id: shareHolderId,
        publicKey: '',
        status: 'unresponsive',
        lastHeartbeat: new Date(Date.now() - this.config.timeoutThreshold - 1000),
      };
      await this.storage.saveShareHolder(holder);
    }

    // Update status to unresponsive
    await this.storage.updateShareHolder(shareHolderId, {
      status: 'unresponsive',
    });

    // Create detection event
    const event: DetectionEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      shareHolderId,
      detectionType: 'timeout',
      severity: 'critical',
      metadata: {},
      acknowledged: false,
    };

    await this.storage.saveDetectionEvent(event);
    this.notifySubscribers(event);

    return event;
  }

  async reportLostShare(shareHolderId: string, reason: string): Promise<DetectionEvent> {
    if (!reason || reason.trim() === '') {
      throw new Error('Reason required for manual share loss reporting');
    }

    // Update holder status to lost
    let holder = await this.storage.getShareHolder(shareHolderId);
    if (!holder) {
      holder = {
        id: shareHolderId,
        publicKey: '',
        status: 'lost',
      };
      await this.storage.saveShareHolder(holder);
    } else {
      await this.storage.updateShareHolder(shareHolderId, {
        status: 'lost',
      });
    }

    // Create manual detection event
    const event: DetectionEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      shareHolderId,
      detectionType: 'manual',
      severity: 'critical',
      metadata: { reason },
      acknowledged: false,
    };

    await this.storage.saveDetectionEvent(event);
    this.notifySubscribers(event);

    return event;
  }

  async getDetectionEvents(filter?: DetectionEventFilter): Promise<DetectionEvent[]> {
    return this.storage.getDetectionEvents(filter);
  }

  async acknowledgeEvent(eventId: string): Promise<void> {
    await this.storage.acknowledgeEvent(eventId);
  }

  subscribeToEvents(callback: (event: DetectionEvent) => void): () => void {
    this.eventCallbacks.push(callback);

    // Return unsubscribe function
    return () => {
      const index = this.eventCallbacks.indexOf(callback);
      if (index > -1) {
        this.eventCallbacks.splice(index, 1);
      }
    };
  }

  private notifySubscribers(event: DetectionEvent): void {
    for (const callback of this.eventCallbacks) {
      try {
        callback(event);
      } catch (error) {
        console.error('Error in detection event callback:', error);
      }
    }
  }
}

// Export interfaces for test compatibility
export interface HeartbeatMonitor {
  start(config: DetectionConfig): Promise<void>;
  stop(): Promise<void>;
  recordHeartbeat(shareHolderId: string): Promise<void>;
  checkStatus(shareHolderId: string): Promise<ShareHolder>;
  getUnresponsiveHolders(): Promise<ShareHolder[]>;
}

export interface DetectionService {
  configure(config: DetectionConfig): Promise<void>;
  detectUnresponsive(shareHolderId: string): Promise<DetectionEvent>;
  reportLostShare(shareHolderId: string, reason: string): Promise<DetectionEvent>;
  getDetectionEvents(filter?: DetectionEventFilter): Promise<DetectionEvent[]>;
  acknowledgeEvent(eventId: string): Promise<void>;
  subscribeToEvents(callback: (event: DetectionEvent) => void): () => void;
}

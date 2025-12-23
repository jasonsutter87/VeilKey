/**
 * Automatic Refresh Scheduler
 *
 * Manages automatic periodic refresh of shares to maintain proactive security.
 * Supports multiple refresh strategies and configurable intervals.
 */

import { refreshShares, refreshSharesPartial } from './refresh.js';
import { SECP256K1_ORDER } from '../shamir/index.js';
import type { ShareWithIndex } from '../shamir/types.js';
import type { FeldmanShare } from '../feldman/types.js';
import type { SchedulerConfig, RefreshResult, RefreshStrategy } from './types.js';

/**
 * Default refresh interval: 24 hours
 */
const DEFAULT_INTERVAL_MS = 24 * 60 * 60 * 1000;

/**
 * Automatic refresh scheduler for proactive security
 *
 * Periodically refreshes shares on a configurable schedule.
 * Supports different refresh strategies:
 * - full: Refresh all shares at once
 * - partial: Refresh a subset of shares each interval
 * - rotating: Rotate through shares, refreshing different ones each time
 *
 * @example
 * ```typescript
 * const scheduler = new RefreshScheduler({
 *   shares: original.shares,
 *   threshold: 3,
 *   intervalMs: 3600000, // 1 hour
 *   onRefresh: (result) => {
 *     console.log('Shares refreshed:', result.refreshId);
 *   },
 * });
 *
 * scheduler.start();
 * // ... later
 * scheduler.stop();
 * ```
 */
export class RefreshScheduler {
  private shares: ShareWithIndex[] | FeldmanShare[];
  private threshold: number;
  private prime: bigint;
  private verifiable: boolean;
  private intervalMs: number;
  private strategy: RefreshStrategy;
  private partialRefreshCount: number;
  private onRefresh?: (result: RefreshResult) => void;
  private onError?: (error: Error) => void;
  private autoUpdate: boolean;

  private intervalHandle?: NodeJS.Timeout;
  private running: boolean = false;
  private paused: boolean = false;
  private refreshCount: number = 0;
  private rotatingIndex: number = 0;

  constructor(config: SchedulerConfig) {
    this.shares = config.shares;
    this.threshold = config.threshold;
    this.prime = config.prime ?? SECP256K1_ORDER;
    this.verifiable = config.verifiable ?? false;
    this.intervalMs = config.intervalMs ?? DEFAULT_INTERVAL_MS;
    this.strategy = config.strategy ?? 'full';
    this.partialRefreshCount = config.partialRefreshCount ?? Math.ceil(this.shares.length / 2);
    this.onRefresh = config.onRefresh;
    this.onError = config.onError;
    this.autoUpdate = config.autoUpdate ?? true;

    this.validateConfig();
  }

  /**
   * Validates scheduler configuration
   */
  private validateConfig(): void {
    if (this.shares.length < this.threshold) {
      throw new Error(
        `Not enough shares: need at least ${this.threshold}, got ${this.shares.length}`
      );
    }

    if (this.threshold < 1) {
      throw new Error('Threshold must be at least 1');
    }

    if (this.intervalMs < 1000) {
      throw new Error('Interval must be at least 1000ms');
    }

    if (this.strategy === 'partial' || this.strategy === 'rotating') {
      if (this.partialRefreshCount < 1) {
        throw new Error('Partial refresh count must be at least 1');
      }
      if (this.partialRefreshCount > this.shares.length) {
        throw new Error(
          `Partial refresh count (${this.partialRefreshCount}) cannot exceed total shares (${this.shares.length})`
        );
      }
    }
  }

  /**
   * Starts the automatic refresh scheduler
   */
  start(): void {
    if (this.running) {
      return; // Already running
    }

    this.running = true;
    this.paused = false;

    this.scheduleNextRefresh();
  }

  /**
   * Schedules the next refresh
   */
  private scheduleNextRefresh(): void {
    if (this.intervalHandle) {
      clearTimeout(this.intervalHandle);
    }

    this.intervalHandle = setTimeout(() => {
      this.executeRefresh();
    }, this.intervalMs);
  }

  /**
   * Executes a refresh operation
   */
  private async executeRefresh(): Promise<void> {
    if (this.paused) {
      // If paused, reschedule without refreshing
      this.scheduleNextRefresh();
      return;
    }

    try {
      let result: RefreshResult;

      switch (this.strategy) {
        case 'full':
          result = this.performFullRefresh();
          break;
        case 'partial':
          result = this.performPartialRefresh();
          break;
        case 'rotating':
          result = this.performRotatingRefresh();
          break;
        default:
          throw new Error(`Unknown refresh strategy: ${this.strategy}`);
      }

      this.refreshCount++;

      // Update internal shares if auto-update is enabled
      if (this.autoUpdate) {
        this.updateShares(result);
      }

      // Notify callback
      if (this.onRefresh) {
        this.onRefresh(result);
      }
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      if (this.onError) {
        this.onError(err);
      } else {
        console.error('Refresh error:', err);
      }
    } finally {
      // Schedule next refresh if still running
      if (this.running) {
        this.scheduleNextRefresh();
      }
    }
  }

  /**
   * Performs a full refresh of all shares
   */
  private performFullRefresh(): RefreshResult {
    return refreshShares({
      shares: this.shares,
      threshold: this.threshold,
      prime: this.prime,
      verifiable: this.verifiable,
    });
  }

  /**
   * Performs a partial refresh of a subset of shares
   */
  private performPartialRefresh(): RefreshResult {
    // Select random indices to refresh
    const allIndices = this.shares.map((s) => Number(s.x));
    const shuffled = [...allIndices].sort(() => Math.random() - 0.5);
    const indicesToRefresh = shuffled.slice(0, this.partialRefreshCount);

    return refreshSharesPartial({
      shares: this.shares,
      threshold: this.threshold,
      prime: this.prime,
      verifiable: this.verifiable,
      indicesToRefresh,
    });
  }

  /**
   * Performs a rotating refresh (different shares each time)
   */
  private performRotatingRefresh(): RefreshResult {
    const allIndices = this.shares.map((s) => Number(s.x));

    // Select next batch of shares to refresh
    const indicesToRefresh: number[] = [];
    for (let i = 0; i < this.partialRefreshCount; i++) {
      const idx = (this.rotatingIndex + i) % allIndices.length;
      indicesToRefresh.push(allIndices[idx]!);
    }

    // Update rotating index for next time
    this.rotatingIndex = (this.rotatingIndex + this.partialRefreshCount) % allIndices.length;

    return refreshSharesPartial({
      shares: this.shares,
      threshold: this.threshold,
      prime: this.prime,
      verifiable: this.verifiable,
      indicesToRefresh,
    });
  }

  /**
   * Updates internal shares after refresh
   */
  private updateShares(result: RefreshResult): void {
    if (this.strategy === 'full') {
      // Replace all shares
      this.shares = result.shares;
    } else {
      // Update only refreshed shares (partial/rotating)
      const refreshedMap = new Map(
        result.shares.map((share) => [share.x.toString(), share])
      );

      this.shares = this.shares.map((share) => {
        const refreshed = refreshedMap.get(share.x.toString());
        return refreshed ?? share;
      });
    }
  }

  /**
   * Stops the scheduler
   */
  stop(): void {
    this.running = false;
    this.paused = false;

    if (this.intervalHandle) {
      clearTimeout(this.intervalHandle);
      this.intervalHandle = undefined;
    }
  }

  /**
   * Pauses the scheduler (stops refreshes but keeps timer running)
   */
  pause(): void {
    this.paused = true;
  }

  /**
   * Resumes the scheduler after pause
   */
  resume(): void {
    this.paused = false;
  }

  /**
   * Triggers an immediate refresh (doesn't affect schedule)
   */
  refreshNow(): void {
    this.executeRefresh();
  }

  /**
   * Checks if scheduler is running
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Checks if scheduler is paused
   */
  isPaused(): boolean {
    return this.paused;
  }

  /**
   * Gets the current shares
   */
  getCurrentShares(): ShareWithIndex[] | FeldmanShare[] {
    return [...this.shares];
  }

  /**
   * Gets the number of refreshes performed
   */
  getRefreshCount(): number {
    return this.refreshCount;
  }

  /**
   * Updates the refresh interval
   */
  setInterval(intervalMs: number): void {
    if (intervalMs < 1000) {
      throw new Error('Interval must be at least 1000ms');
    }

    this.intervalMs = intervalMs;

    // Reschedule if running
    if (this.running) {
      this.scheduleNextRefresh();
    }
  }

  /**
   * Updates the refresh strategy
   */
  setStrategy(strategy: RefreshStrategy, partialRefreshCount?: number): void {
    this.strategy = strategy;

    if (partialRefreshCount !== undefined) {
      if (partialRefreshCount < 1 || partialRefreshCount > this.shares.length) {
        throw new Error('Invalid partial refresh count');
      }
      this.partialRefreshCount = partialRefreshCount;
    }
  }

  /**
   * Gets scheduler status
   */
  getStatus(): {
    running: boolean;
    paused: boolean;
    refreshCount: number;
    strategy: RefreshStrategy;
    intervalMs: number;
    shareCount: number;
    threshold: number;
  } {
    return {
      running: this.running,
      paused: this.paused,
      refreshCount: this.refreshCount,
      strategy: this.strategy,
      intervalMs: this.intervalMs,
      shareCount: this.shares.length,
      threshold: this.threshold,
    };
  }
}

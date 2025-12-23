/**
 * In-Memory Storage for Key Groups
 *
 * Simple in-memory storage for demonstration purposes.
 * In production, use a proper database (PostgreSQL, Redis, etc.)
 */

import type { KeyGroup } from '../veilkey.js';

/**
 * In-memory key group storage
 */
class KeyGroupStorage {
  private groups: Map<string, KeyGroup> = new Map();

  /**
   * Store a key group
   */
  set(group: KeyGroup): void {
    this.groups.set(group.id, group);
  }

  /**
   * Retrieve a key group by ID
   */
  get(id: string): KeyGroup | undefined {
    return this.groups.get(id);
  }

  /**
   * Check if a key group exists
   */
  has(id: string): boolean {
    return this.groups.has(id);
  }

  /**
   * Delete a key group
   */
  delete(id: string): boolean {
    return this.groups.delete(id);
  }

  /**
   * Get all key group IDs
   */
  keys(): string[] {
    return Array.from(this.groups.keys());
  }

  /**
   * Get total number of stored groups
   */
  size(): number {
    return this.groups.size;
  }

  /**
   * Clear all stored groups
   */
  clear(): void {
    this.groups.clear();
  }
}

// Singleton instance
export const storage = new KeyGroupStorage();

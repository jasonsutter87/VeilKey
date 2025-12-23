/**
 * Storage backends for encrypted shares
 *
 * Provides both in-memory and file-based storage options.
 */

import { readFile, writeFile, mkdir } from 'fs/promises';
import { dirname } from 'path';
import type {
  StorageBackend,
  EncryptedShare,
  ShareHolder,
  ShareAssignment,
  AuditEntry,
} from './types.js';

// =============================================================================
// In-Memory Storage (Default)
// =============================================================================

/**
 * In-memory storage backend
 *
 * Stores all data in memory. Data is lost when the process exits.
 * Suitable for testing and development.
 */
export class MemoryStorage implements StorageBackend {
  private shares: Map<string, EncryptedShare> = new Map();
  private holders: Map<string, ShareHolder> = new Map();
  private assignments: Map<string, ShareAssignment> = new Map();
  private auditEntries: AuditEntry[] = [];

  async saveShare(share: EncryptedShare): Promise<void> {
    this.shares.set(share.id, share);
  }

  async getShare(shareId: string): Promise<EncryptedShare | null> {
    return this.shares.get(shareId) || null;
  }

  async listShares(): Promise<EncryptedShare[]> {
    return Array.from(this.shares.values());
  }

  async deleteShare(shareId: string): Promise<boolean> {
    return this.shares.delete(shareId);
  }

  async saveHolder(holder: ShareHolder): Promise<void> {
    this.holders.set(holder.id, holder);
  }

  async getHolder(holderId: string): Promise<ShareHolder | null> {
    return this.holders.get(holderId) || null;
  }

  async listHolders(): Promise<ShareHolder[]> {
    return Array.from(this.holders.values());
  }

  async saveAssignment(assignment: ShareAssignment): Promise<void> {
    this.assignments.set(assignment.id, assignment);
  }

  async getAssignmentsByHolder(holderId: string): Promise<ShareAssignment[]> {
    return Array.from(this.assignments.values()).filter(
      a => a.holderId === holderId
    );
  }

  async getAssignmentByShare(shareId: string): Promise<ShareAssignment | null> {
    const assignment = Array.from(this.assignments.values()).find(
      a => a.shareId === shareId
    );
    return assignment || null;
  }

  async saveAuditEntry(entry: AuditEntry): Promise<void> {
    this.auditEntries.push(entry);
  }

  async getAuditEntries(): Promise<AuditEntry[]> {
    return [...this.auditEntries];
  }

  async getLastAuditEntry(): Promise<AuditEntry | null> {
    if (this.auditEntries.length === 0) {
      return null;
    }
    return this.auditEntries[this.auditEntries.length - 1] ?? null;
  }

  /**
   * Clear all stored data (useful for testing)
   */
  clear(): void {
    this.shares.clear();
    this.holders.clear();
    this.assignments.clear();
    this.auditEntries = [];
  }
}

// =============================================================================
// File-Based Storage
// =============================================================================

/**
 * Data structure for file-based storage
 */
interface FileStorageData {
  shares: Record<string, EncryptedShare>;
  holders: Record<string, ShareHolder>;
  assignments: Record<string, ShareAssignment>;
  auditEntries: AuditEntry[];
  version: string;
}

/**
 * File-based storage backend
 *
 * Stores all data in a JSON file. Data persists across process restarts.
 * Suitable for production use with automatic backups.
 */
export class FileStorage implements StorageBackend {
  private filePath: string;
  private data: FileStorageData;
  private dirty: boolean = false;
  private saveTimer: NodeJS.Timeout | null = null;

  constructor(filePath: string) {
    this.filePath = filePath;
    this.data = {
      shares: {},
      holders: {},
      assignments: {},
      auditEntries: [],
      version: '1.0.0',
    };
  }

  /**
   * Initialize storage by loading from file
   */
  async init(): Promise<void> {
    try {
      const content = await readFile(this.filePath, 'utf-8');
      this.data = JSON.parse(content, this.reviver);
    } catch (error: any) {
      if (error.code === 'ENOENT') {
        // File doesn't exist yet - initialize with empty data
        await this.flush();
      } else {
        throw new Error(`Failed to load storage file: ${error.message}`);
      }
    }
  }

  /**
   * Custom JSON reviver to handle Date objects
   */
  private reviver(_key: string, value: any): any {
    if (typeof value === 'string') {
      // Check if it looks like an ISO date string
      if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)) {
        return new Date(value);
      }
    }
    return value;
  }

  /**
   * Schedule a deferred save to avoid excessive I/O
   */
  private scheduleSave(): void {
    this.dirty = true;
    if (this.saveTimer) {
      return;
    }
    this.saveTimer = setTimeout(() => {
      this.flush().catch(err => {
        console.error('Failed to save storage:', err);
      });
      this.saveTimer = null;
    }, 1000); // Save after 1 second of inactivity
  }

  /**
   * Immediately write data to file
   */
  async flush(): Promise<void> {
    if (!this.dirty && this.saveTimer === null) {
      return;
    }

    const json = JSON.stringify(this.data, null, 2);
    await mkdir(dirname(this.filePath), { recursive: true });
    await writeFile(this.filePath, json, 'utf-8');
    this.dirty = false;
  }

  async saveShare(share: EncryptedShare): Promise<void> {
    this.data.shares[share.id] = share;
    this.scheduleSave();
  }

  async getShare(shareId: string): Promise<EncryptedShare | null> {
    return this.data.shares[shareId] || null;
  }

  async listShares(): Promise<EncryptedShare[]> {
    return Object.values(this.data.shares);
  }

  async deleteShare(shareId: string): Promise<boolean> {
    if (shareId in this.data.shares) {
      delete this.data.shares[shareId];
      this.scheduleSave();
      return true;
    }
    return false;
  }

  async saveHolder(holder: ShareHolder): Promise<void> {
    this.data.holders[holder.id] = holder;
    this.scheduleSave();
  }

  async getHolder(holderId: string): Promise<ShareHolder | null> {
    return this.data.holders[holderId] || null;
  }

  async listHolders(): Promise<ShareHolder[]> {
    return Object.values(this.data.holders);
  }

  async saveAssignment(assignment: ShareAssignment): Promise<void> {
    this.data.assignments[assignment.id] = assignment;
    this.scheduleSave();
  }

  async getAssignmentsByHolder(holderId: string): Promise<ShareAssignment[]> {
    return Object.values(this.data.assignments).filter(
      a => a.holderId === holderId
    );
  }

  async getAssignmentByShare(shareId: string): Promise<ShareAssignment | null> {
    const assignment = Object.values(this.data.assignments).find(
      a => a.shareId === shareId
    );
    return assignment || null;
  }

  async saveAuditEntry(entry: AuditEntry): Promise<void> {
    this.data.auditEntries.push(entry);
    this.scheduleSave();
  }

  async getAuditEntries(): Promise<AuditEntry[]> {
    return [...this.data.auditEntries];
  }

  async getLastAuditEntry(): Promise<AuditEntry | null> {
    if (this.data.auditEntries.length === 0) {
      return null;
    }
    return this.data.auditEntries[this.data.auditEntries.length - 1] ?? null;
  }

  /**
   * Close the storage and ensure all data is written
   */
  async close(): Promise<void> {
    if (this.saveTimer) {
      clearTimeout(this.saveTimer);
      this.saveTimer = null;
    }
    await this.flush();
  }
}

// =============================================================================
// Factory Function
// =============================================================================

/**
 * Create a storage backend based on configuration
 *
 * @param type - Type of storage ('memory' or 'file')
 * @param filePath - Path to storage file (required for 'file' type)
 * @returns Storage backend instance
 */
export async function createStorage(
  type: 'memory' | 'file',
  filePath?: string
): Promise<StorageBackend> {
  if (type === 'file') {
    if (!filePath) {
      throw new Error('File path is required for file storage');
    }
    const storage = new FileStorage(filePath);
    await storage.init();
    return storage;
  }

  return new MemoryStorage();
}

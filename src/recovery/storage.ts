/**
 * In-memory storage for recovery operations
 *
 * This is a simple implementation for testing and development.
 * Production systems should use persistent storage.
 */

import type {
  RecoveryStorage,
  RecoveryRequest,
  RecoverySession,
  RecoveryAuthorization,
  ShareHolder,
  DetectionEvent,
  DetectionEventFilter,
  GeneratedShare,
  ShareMetadata,
  AuditRecord,
  ReportFilter,
  EscrowConfig,
} from './types.js';

export class InMemoryRecoveryStorage implements RecoveryStorage {
  private recoveryRequests = new Map<string, RecoveryRequest>();
  private recoverySessions = new Map<string, RecoverySession>();
  private authorizations = new Map<string, RecoveryAuthorization[]>();
  private shareHolders = new Map<string, ShareHolder>();
  private detectionEvents: DetectionEvent[] = [];
  private generatedShares = new Map<string, GeneratedShare>();
  private shareMetadata = new Map<string, ShareMetadata>();
  private auditRecords: AuditRecord[] = [];
  private escrowConfig: EscrowConfig | null = null;

  // Recovery Requests
  async saveRecoveryRequest(request: RecoveryRequest): Promise<void> {
    this.recoveryRequests.set(request.id, { ...request });
  }

  async getRecoveryRequest(id: string): Promise<RecoveryRequest | null> {
    const request = this.recoveryRequests.get(id);
    return request ? { ...request } : null;
  }

  async listRecoveryRequests(): Promise<RecoveryRequest[]> {
    return Array.from(this.recoveryRequests.values()).map(r => ({ ...r }));
  }

  // Recovery Sessions
  async saveRecoverySession(session: RecoverySession): Promise<void> {
    this.recoverySessions.set(session.id, { ...session });
  }

  async getRecoverySession(id: string): Promise<RecoverySession | null> {
    const session = this.recoverySessions.get(id);
    return session ? { ...session } : null;
  }

  // Authorizations
  async saveAuthorization(auth: RecoveryAuthorization): Promise<void> {
    const existing = this.authorizations.get(auth.recoveryId) || [];
    existing.push({ ...auth });
    this.authorizations.set(auth.recoveryId, existing);
  }

  async getAuthorizations(recoveryId: string): Promise<RecoveryAuthorization[]> {
    const auths = this.authorizations.get(recoveryId) || [];
    return auths.map(a => ({ ...a }));
  }

  // Share Holders
  async saveShareHolder(holder: ShareHolder): Promise<void> {
    this.shareHolders.set(holder.id, { ...holder });
  }

  async getShareHolder(id: string): Promise<ShareHolder | null> {
    const holder = this.shareHolders.get(id);
    return holder ? { ...holder } : null;
  }

  async listShareHolders(): Promise<ShareHolder[]> {
    return Array.from(this.shareHolders.values()).map(h => ({ ...h }));
  }

  async updateShareHolder(id: string, updates: Partial<ShareHolder>): Promise<void> {
    const existing = this.shareHolders.get(id);
    if (!existing) {
      throw new Error(`ShareHolder ${id} not found`);
    }
    this.shareHolders.set(id, { ...existing, ...updates });
  }

  // Detection Events
  async saveDetectionEvent(event: DetectionEvent): Promise<void> {
    this.detectionEvents.push({ ...event });
  }

  async getDetectionEvents(filter?: DetectionEventFilter): Promise<DetectionEvent[]> {
    let events = [...this.detectionEvents];

    if (filter) {
      if (filter.shareHolderId) {
        events = events.filter(e => e.shareHolderId === filter.shareHolderId);
      }
      if (filter.detectionType) {
        events = events.filter(e => e.detectionType === filter.detectionType);
      }
      if (filter.severity) {
        events = events.filter(e => e.severity === filter.severity);
      }
      if (filter.startDate) {
        events = events.filter(e => e.timestamp >= filter.startDate!);
      }
      if (filter.endDate) {
        events = events.filter(e => e.timestamp <= filter.endDate!);
      }
      if (filter.acknowledged !== undefined) {
        events = events.filter(e => e.acknowledged === filter.acknowledged);
      }
    }

    return events.map(e => ({ ...e }));
  }

  async acknowledgeEvent(eventId: string): Promise<void> {
    const event = this.detectionEvents.find(e => e.id === eventId);
    if (event) {
      event.acknowledged = true;
    }
  }

  // Generated Shares
  async saveGeneratedShare(share: GeneratedShare): Promise<void> {
    this.generatedShares.set(share.id, { ...share });
    this.shareMetadata.set(share.holderId, { ...share.metadata });
  }

  async getGeneratedShare(id: string): Promise<GeneratedShare | null> {
    const share = this.generatedShares.get(id);
    return share ? { ...share } : null;
  }

  async getShareMetadata(shareId: string): Promise<ShareMetadata | null> {
    const metadata = this.shareMetadata.get(shareId);
    return metadata ? { ...metadata } : null;
  }

  async updateShareMetadata(shareId: string, updates: Partial<ShareMetadata>): Promise<void> {
    const existing = this.shareMetadata.get(shareId);
    if (!existing) {
      throw new Error(`ShareMetadata for ${shareId} not found`);
    }
    this.shareMetadata.set(shareId, { ...existing, ...updates });
  }

  // Audit Records
  async saveAuditRecord(record: AuditRecord): Promise<void> {
    this.auditRecords.push({ ...record });
  }

  async getAuditRecords(filter?: ReportFilter): Promise<AuditRecord[]> {
    let records = [...this.auditRecords];

    if (filter) {
      if (filter.recoveryId) {
        records = records.filter(r => r.recoveryId === filter.recoveryId);
      }
      if (filter.eventType) {
        records = records.filter(r => r.eventType === filter.eventType);
      }
      if (filter.actor) {
        records = records.filter(r => r.actor === filter.actor);
      }
      if (filter.startDate) {
        records = records.filter(r => r.timestamp >= filter.startDate!);
      }
      if (filter.endDate) {
        records = records.filter(r => r.timestamp <= filter.endDate!);
      }
    }

    return records.map(r => ({ ...r }));
  }

  async getLastAuditRecord(): Promise<AuditRecord | null> {
    if (this.auditRecords.length === 0) {
      return null;
    }
    const last = this.auditRecords[this.auditRecords.length - 1]!;
    return { ...last };
  }

  // Escrow Config
  async saveEscrowConfig(config: EscrowConfig): Promise<void> {
    this.escrowConfig = { ...config };
  }

  async getEscrowConfig(): Promise<EscrowConfig | null> {
    return this.escrowConfig ? { ...this.escrowConfig } : null;
  }

  // Utility methods for testing
  clear(): void {
    this.recoveryRequests.clear();
    this.recoverySessions.clear();
    this.authorizations.clear();
    this.shareHolders.clear();
    this.detectionEvents = [];
    this.generatedShares.clear();
    this.shareMetadata.clear();
    this.auditRecords = [];
    this.escrowConfig = null;
  }
}

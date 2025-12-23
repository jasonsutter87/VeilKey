/**
 * Share Recovery Module for VeilKey Phase 3.3
 *
 * Provides comprehensive share recovery capabilities including:
 * - Lost share detection and monitoring
 * - Recovery protocol with authorization workflow
 * - Replacement share generation
 * - Audit trail and compliance reporting
 *
 * @module recovery
 */

// Export all types
export type {
  // Protocol types
  RecoveryRequest,
  RecoveryStatus,
  RecoveryAuthorization,
  RecoverySession,
  RecoveryStep,
  RecoveryParticipant,
  ParticipatingShare,
  EscrowConfig,

  // Detection types
  ShareHolder,
  DetectionConfig,
  NotificationChannel,
  DetectionEvent,
  DetectionEventFilter,

  // Generation types
  GeneratedShare,
  ShareMetadata,
  PublicParameters,
  ShareIndexAssignment,

  // Audit types
  RecoveryInitiationEvent,
  ParticipantConsentEvent,
  ShareDistributionEvent,
  AuditRecord,
  ReportFilter,
  ComplianceReport,
  ComplianceCheck,

  // Storage
  RecoveryStorage,
} from './types.js';

// Export storage implementation
export { InMemoryRecoveryStorage } from './storage.js';

// Export detection service and interfaces
export {
  HeartbeatMonitorImpl,
  DetectionServiceImpl,
  type HeartbeatMonitor,
  type DetectionService,
} from './detection.js';

// Export protocol implementation and interface
export {
  RecoveryProtocolImpl,
  type RecoveryProtocol,
} from './protocol.js';

// Export generation service and interface
export {
  ShareGenerationServiceImpl,
  type ShareGenerationService,
} from './generation.js';

// Export audit service and interface
export {
  RecoveryAuditServiceImpl,
  type RecoveryAuditService,
} from './audit.js';

/**
 * Create a complete recovery system with all components
 *
 * @returns Object containing all recovery services
 *
 * @example
 * ```typescript
 * const recovery = createRecoverySystem();
 *
 * // Configure detection
 * await recovery.detection.configure({
 *   heartbeatInterval: 30000,
 *   timeoutThreshold: 180000,
 *   maxMissedHeartbeats: 3,
 *   autoDetectionEnabled: true,
 *   notificationChannels: [],
 * });
 *
 * // Initiate recovery
 * const request = await recovery.protocol.initiateRecovery(
 *   'lost-holder-id',
 *   'admin-user',
 *   'Device failure'
 * );
 * ```
 */
export function createRecoverySystem() {
  const storage = new InMemoryRecoveryStorage();
  const heartbeatMonitor = new HeartbeatMonitorImpl(storage);
  const detection = new DetectionServiceImpl(storage, heartbeatMonitor);
  const protocol = new RecoveryProtocolImpl(storage);
  const generation = new ShareGenerationServiceImpl(storage);
  const audit = new RecoveryAuditServiceImpl(storage);

  return {
    storage,
    heartbeatMonitor,
    detection,
    protocol,
    generation,
    audit,
  };
}

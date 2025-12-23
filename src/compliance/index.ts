/**
 * VeilKey Compliance Module
 *
 * Provides enterprise compliance features including:
 * - SOC 2 Type II compliance framework
 * - Enhanced audit logging with tamper-proof hash chains
 * - Data residency controls for regulatory compliance
 * - Key escrow with M-of-N threshold recovery
 *
 * @module compliance
 */

// Types
export * from './types.js';

// SOC 2 Compliance
export { SOC2ComplianceManager, DEFAULT_SOC2_CONTROLS } from './soc2.js';

// Enhanced Audit Logging
export {
  EnhancedAuditLogger,
  AuditEventBuilder,
  type AuditQueryOptions,
  type AuditStatistics,
} from './audit.js';

// Data Residency
export {
  DataResidencyManager,
  type DataTransferRequest,
  type ResidencyValidationResult,
  type ResidencyViolation,
} from './data-residency.js';

// Key Escrow
export {
  KeyEscrowManager,
  createEscrowAgent,
  createEscrowConfig,
  type EscrowStatistics,
} from './key-escrow.js';

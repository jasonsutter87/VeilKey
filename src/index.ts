/**
 * @veilkey/core
 * Distributed Key Management & Threshold Cryptography
 *
 * "Trust no single party."
 *
 * VeilKey provides threshold cryptographic primitives where:
 * - No single party ever holds the complete private key
 * - t-of-n parties must cooperate for any sensitive operation
 * - Operations are mathematically verifiable
 *
 * Use Cases:
 * - VeilSign: Distributed signing authority for blind signatures
 * - TVS: Threshold decryption for secure vote tallying
 * - Crypto Wallets: Multi-party custody solutions
 * - Enterprise: Distributed key management
 */

// =============================================================================
// Main API
// =============================================================================

export { VeilKey } from './veilkey.js';
export type {
  VeilKeyConfig,
  KeyGroup,
  Share,
  Algorithm,
  PartialSignatureResult,
  PartialDecryptionResult,
} from './veilkey.js';

// =============================================================================
// Core Primitives
// =============================================================================

// Shamir Secret Sharing
export {
  ShamirSecretSharing,
  split as shamirSplit,
  combine as shamirCombine,
} from './shamir/index.js';

export type {
  Share as ShamirShare,
  ShareWithIndex,
  ShamirConfig,
  SplitResult,
} from './shamir/types.js';

// Feldman Verifiable Secret Sharing
export {
  FeldmanVSS,
  split as feldmanSplit,
  verify as feldmanVerify,
  combine as feldmanCombine,
  getPublicCommitment,
  verifyAll as feldmanVerifyAll,
} from './feldman/index.js';

export type {
  FeldmanShare,
  FeldmanCommitments,
  FeldmanConfig,
  FeldmanSplitResult,
  CurvePoint,
  VerificationResult,
} from './feldman/types.js';

// Threshold RSA
export { ThresholdRSA } from './rsa/index.js';

export type {
  ThresholdRSAKeyPair,
  ThresholdRSAConfig,
  RSAShare,
  PartialSignature,
  PartialDecryption,
  PartialProof,
  VerifiedPartial,
} from './rsa/types.js';

// Threshold BLS
export { ThresholdBLS } from './bls/index.js';

export type {
  ThresholdBLSKeyPair,
  ThresholdBLSConfig,
  BLSShare,
  BLSPoint,
  PartialBLSSignature,
  BLSSignature,
  AggregatedBLSSignature,
  BLSVerificationResult,
  BatchVerificationItem,
} from './bls/types.js';

// Threshold ECDSA
export { ThresholdECDSA } from './ecdsa/index.js';

export type {
  ThresholdECDSAKeyPair,
  ThresholdECDSAConfig,
  ECDSAShare,
  ECDSAPoint,
  ECDSAPresignature,
  PartialECDSASignature,
  ECDSASignature,
  ECDSAVerificationResult,
  ECDSACurve,
  BatchVerificationItem as ECDSABatchVerificationItem,
} from './ecdsa/types.js';

// =============================================================================
// Key Ceremony Tools
// =============================================================================

export { CeremonyCoordinator } from './ceremony/index.js';

export type {
  CeremonyConfig,
  CeremonyState,
  CeremonyResult,
  Participant,
  Commitment,
  CeremonyShare,
  AuditEntry,
  TransitionOptions,
} from './ceremony/index.js';

export {
  CeremonyPhase,
  ParticipantStatus,
  AuditEventType,
  CeremonyError,
} from './ceremony/index.js';

// =============================================================================
// Share Management
// =============================================================================

export { ShareManager } from './share-manager/index.js';

export type {
  ShareManagerConfig,
  EncryptedShare,
  ShareHolder,
  ShareAssignment,
  ShareMetadata,
  Role,
  Permission,
  AccessPolicy,
  AuditEntry as ShareAuditEntry,
  AuditEventType as ShareAuditEventType,
  AuditLog,
  StoreSharesOptions,
  GetShareOptions,
  ShareRetrievalResult,
  StorageBackend,
} from './share-manager/types.js';

export {
  MemoryStorage,
  FileStorage,
  createStorage,
} from './share-manager/storage.js';

export {
  AccessControl,
  DEFAULT_POLICIES,
} from './share-manager/access-control.js';

export { AuditLogger } from './share-manager/audit.js';

// =============================================================================
// Proactive Security
// =============================================================================

export {
  refreshShares,
  refreshSharesPartial,
  verifyRefreshPreservesSecret,
  verifyRefreshedShares,
  combineRefreshedShares,
  RefreshScheduler,
  RefreshAuditLog,
} from './proactive/index.js';

export type {
  RefreshConfig,
  RefreshResult,
  PartialRefreshConfig,
  RefreshVerificationResult,
  RefreshStrategy,
  SchedulerConfig,
  RefreshAuditEntry,
  AuditLogConfig,
  AuditLogQuery,
  AuditStatistics,
} from './proactive/types.js';

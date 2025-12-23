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

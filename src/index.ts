/**
 * @veilkey/core
 * Distributed Key Management & Threshold Cryptography
 *
 * "Trust no single party."
 */

// Core primitives
export { ShamirSecretSharing, split as shamirSplit, combine as shamirCombine } from './shamir/index.js';
export {
  FeldmanVSS,
  split as feldmanSplit,
  verify as feldmanVerify,
  combine as feldmanCombine,
  getPublicCommitment,
  verifyAll as feldmanVerifyAll,
} from './feldman/index.js';
export { ThresholdRSA } from './rsa/index.js';

// Types
export type {
  Share,
  ShareWithIndex,
  ShamirConfig,
  SplitResult,
} from './shamir/types.js';

export type {
  FeldmanShare,
  FeldmanCommitments,
  FeldmanConfig,
  FeldmanSplitResult,
  CurvePoint,
  VerificationResult,
} from './feldman/types.js';

export type {
  ThresholdRSAKeyPair,
  RSAShare,
  PartialSignature,
  ThresholdRSAConfig,
} from './rsa/types.js';

// Main VeilKey API
export { VeilKey } from './veilkey.js';
export type { VeilKeyConfig, KeyGroup, Algorithm } from './veilkey.js';

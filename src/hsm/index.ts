/**
 * VeilKey HSM Integration Module
 *
 * Provides Hardware Security Module integration for secure key storage
 * and cryptographic operations.
 *
 * @module hsm
 */

// Types
export * from './types.js';

// PKCS#11 Implementation
export { PKCS11Manager } from './pkcs11.js';

// AWS CloudHSM Implementation
export { CloudHSMManager } from './aws-cloudhsm.js';
export type {
  CloudHSMConfig,
  CloudHSMCluster,
  CloudHSMDevice,
  CloudHSMSession,
  CloudHSMKeyHandle,
  CloudHSMMetrics,
  CloudHSMBackup,
} from './aws-cloudhsm.js';

// Azure HSM Implementation
export { AzureHSMManager } from './azure-hsm.js';
export type {
  AzureHSMConfig,
  AzureHSMResource,
  AzureKeyVaultConfig,
  AzureHSMSession,
  AzureKeyHandle,
  AzureBackupResult,
  AzureAuditLog,
  AzureNetworkRule,
} from './azure-hsm.js';

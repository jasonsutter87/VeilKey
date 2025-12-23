/**
 * VeilKey Security Module
 *
 * Provides mutual TLS (mTLS) authentication, certificate management,
 * and security operations.
 *
 * @module security
 */

// Types
export * from './types.js';

// Certificate Management
export { CertificateManager } from './certificate.js';

// mTLS Service
export { MTLSServiceImpl } from './mtls.js';
export type { MTLSService } from './mtls.js';

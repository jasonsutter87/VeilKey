/**
 * VeilKey Security Module - Type Definitions
 *
 * Type definitions for mutual TLS (mTLS), certificates, and security operations.
 *
 * @module security/types
 */

/**
 * Certificate Request
 * Parameters for generating a new certificate
 */
export interface CertificateRequest {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  validityDays: number;
  keySize: 2048 | 4096;
  keyAlgorithm: 'RSA' | 'ECDSA';
  subjectAlternativeNames?: string[];
  extendedKeyUsage?: ('serverAuth' | 'clientAuth')[];
}

/**
 * Certificate Subject Information
 */
export interface CertificateSubject {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
}

/**
 * Certificate Status
 */
export type CertificateStatus = 'active' | 'expired' | 'revoked' | 'pending';

/**
 * X.509 Certificate
 */
export interface Certificate {
  id: string;
  serialNumber: string;
  subject: CertificateSubject;
  issuer: CertificateSubject;
  notBefore: Date;
  notAfter: Date;
  publicKey: string;
  privateKey?: string; // Only available during generation
  fingerprint: string;
  fingerprintAlgorithm: 'SHA-256' | 'SHA-384' | 'SHA-512';
  pem: string;
  status: CertificateStatus;
}

/**
 * Certificate Validation Result
 */
export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  expiresIn?: number; // days
}

/**
 * Certificate Revocation Reason
 */
export type RevocationReason =
  | 'keyCompromise'
  | 'affiliationChanged'
  | 'superseded'
  | 'cessationOfOperation'
  | 'certificateHold'
  | 'privilegeWithdrawn';

/**
 * Certificate Revocation Status
 */
export interface RevocationStatus {
  revoked: boolean;
  revokedAt?: Date;
  reason?: RevocationReason;
  checkedAt: Date;
  method: 'crl' | 'ocsp';
}

/**
 * Client Authentication Result
 */
export interface AuthenticationResult {
  authenticated: boolean;
  clientId?: string;
  validationErrors: string[];
  certificateFingerprint: string;
}

/**
 * Certificate Metadata
 */
export interface CertificateMetadata {
  id: string;
  createdAt: Date;
  rotatedFrom?: string;
  rotatedTo?: string;
  revocationDate?: Date;
  revocationReason?: RevocationReason;
  usage: string[];
}

/**
 * Certificate Store Entry
 * Internal storage structure for certificate management
 */
export interface CertificateStoreEntry {
  certificate: Certificate;
  metadata: CertificateMetadata;
}

/**
 * Revocation List Entry
 */
export interface RevocationListEntry {
  certificateId: string;
  serialNumber: string;
  revokedAt: Date;
  reason: RevocationReason;
}

/**
 * Certificate Error
 */
export class CertificateError extends Error {
  constructor(
    message: string,
    public readonly code: CertificateErrorCode,
    public readonly certificateId?: string
  ) {
    super(message);
    this.name = 'CertificateError';
  }
}

/**
 * Certificate Error Codes
 */
export enum CertificateErrorCode {
  GENERATION_FAILED = 'GENERATION_FAILED',
  VALIDATION_FAILED = 'VALIDATION_FAILED',
  EXPIRED = 'EXPIRED',
  NOT_YET_VALID = 'NOT_YET_VALID',
  REVOKED = 'REVOKED',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  CHAIN_VERIFICATION_FAILED = 'CHAIN_VERIFICATION_FAILED',
  PIN_MISMATCH = 'PIN_MISMATCH',
  NOT_FOUND = 'NOT_FOUND',
}

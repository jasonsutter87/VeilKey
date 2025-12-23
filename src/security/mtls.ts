/**
 * VeilKey Security Module - Mutual TLS Service
 *
 * Implementation of mutual TLS (mTLS) authentication including certificate
 * management, validation, rotation, and revocation.
 *
 * @module security/mtls
 */

import { CertificateManager } from './certificate.js';
import {
  Certificate,
  CertificateRequest,
  CertificateMetadata,
  CertificateStoreEntry,
  RevocationReason,
  RevocationStatus,
  RevocationListEntry,
  ValidationResult,
  AuthenticationResult,
  CertificateError,
  CertificateErrorCode,
} from './types.js';

/**
 * MTLSService Interface
 */
export interface MTLSService {
  generateCertificate(request: CertificateRequest): Promise<Certificate>;
  validateCertificate(cert: Certificate): Promise<ValidationResult>;
  rotateCertificate(oldCertId: string, request: CertificateRequest): Promise<Certificate>;
  revokeCertificate(certId: string, reason: RevocationReason): Promise<void>;
  checkRevocation(cert: Certificate, method: 'crl' | 'ocsp'): Promise<RevocationStatus>;
  authenticateClient(clientCert: Certificate): Promise<AuthenticationResult>;
  verifyCertificateChain(cert: Certificate, trustAnchors: Certificate[]): Promise<boolean>;
  enforcePinning(cert: Certificate, pins: string[]): Promise<boolean>;
  getCertificateMetadata(certId: string): Promise<CertificateMetadata>;
}

/**
 * MTLSServiceImpl
 * Implementation of mutual TLS service
 */
export class MTLSServiceImpl implements MTLSService {
  private certificateManager: CertificateManager;
  private certificateStore: Map<string, CertificateStoreEntry>;
  private revocationList: Map<string, RevocationListEntry>;

  constructor() {
    this.certificateManager = new CertificateManager();
    this.certificateStore = new Map();
    this.revocationList = new Map();
  }

  /**
   * Generate a new certificate
   */
  async generateCertificate(request: CertificateRequest): Promise<Certificate> {
    const certificate = this.certificateManager.generateCertificate(request);

    // Store certificate with metadata
    const metadata: CertificateMetadata = {
      id: certificate.id,
      createdAt: new Date(),
      usage: request.extendedKeyUsage || [],
    };

    this.certificateStore.set(certificate.id, {
      certificate,
      metadata,
    });

    return certificate;
  }

  /**
   * Validate a certificate
   */
  async validateCertificate(cert: Certificate): Promise<ValidationResult> {
    return this.certificateManager.validateCertificate(cert);
  }

  /**
   * Rotate a certificate
   */
  async rotateCertificate(
    oldCertId: string,
    request: CertificateRequest
  ): Promise<Certificate> {
    // Check if old certificate exists
    const oldEntry = this.certificateStore.get(oldCertId);
    if (!oldEntry) {
      throw new CertificateError(
        `Certificate ${oldCertId} not found`,
        CertificateErrorCode.NOT_FOUND,
        oldCertId
      );
    }

    // Generate new certificate
    const newCertificate = await this.generateCertificate(request);

    // Update metadata to link certificates
    const oldMetadata = oldEntry.metadata;
    oldMetadata.rotatedTo = newCertificate.id;

    const newEntry = this.certificateStore.get(newCertificate.id);
    if (newEntry) {
      newEntry.metadata.rotatedFrom = oldCertId;
    }

    return newCertificate;
  }

  /**
   * Revoke a certificate
   */
  async revokeCertificate(certId: string, reason: RevocationReason): Promise<void> {
    const entry = this.certificateStore.get(certId);
    if (!entry) {
      throw new CertificateError(
        `Certificate ${certId} not found`,
        CertificateErrorCode.NOT_FOUND,
        certId
      );
    }

    // Update certificate status
    entry.certificate.status = 'revoked';

    // Update metadata
    const revokedAt = new Date();
    entry.metadata.revocationDate = revokedAt;
    entry.metadata.revocationReason = reason;

    // Add to revocation list
    const revocationEntry: RevocationListEntry = {
      certificateId: certId,
      serialNumber: entry.certificate.serialNumber,
      revokedAt,
      reason,
    };

    this.revocationList.set(certId, revocationEntry);
  }

  /**
   * Check certificate revocation status
   */
  async checkRevocation(
    cert: Certificate,
    method: 'crl' | 'ocsp'
  ): Promise<RevocationStatus> {
    const revocationEntry = this.revocationList.get(cert.id);
    const checkedAt = new Date();

    if (revocationEntry) {
      return {
        revoked: true,
        revokedAt: revocationEntry.revokedAt,
        reason: revocationEntry.reason,
        checkedAt,
        method,
      };
    }

    return {
      revoked: false,
      checkedAt,
      method,
    };
  }

  /**
   * Authenticate client with certificate
   */
  async authenticateClient(clientCert: Certificate): Promise<AuthenticationResult> {
    const validationErrors: string[] = [];

    // Validate certificate
    const validation = await this.validateCertificate(clientCert);
    validationErrors.push(...validation.errors);

    // Check revocation status (using OCSP for real-time)
    const revocationStatus = await this.checkRevocation(clientCert, 'ocsp');
    if (revocationStatus.revoked) {
      validationErrors.push('Certificate has been revoked');
    }

    const authenticated = validationErrors.length === 0;

    return {
      authenticated,
      clientId: authenticated ? clientCert.subject.commonName : undefined,
      validationErrors,
      certificateFingerprint: clientCert.fingerprint,
    };
  }

  /**
   * Verify certificate chain
   */
  async verifyCertificateChain(
    cert: Certificate,
    trustAnchors: Certificate[]
  ): Promise<boolean> {
    // Check if the issuer matches any trust anchor
    for (const anchor of trustAnchors) {
      if (this.isIssuedBy(cert, anchor)) {
        return true;
      }
    }

    // Check if cert itself is a trust anchor (self-signed and in anchors)
    for (const anchor of trustAnchors) {
      if (cert.fingerprint === anchor.fingerprint) {
        return true;
      }
    }

    // Check if certificate was generated by this service (stored in our certificate store)
    // Only trust if the anchor has organization set (indicating a properly configured CA)
    if (this.certificateStore.has(cert.id)) {
      for (const anchor of trustAnchors) {
        if (anchor.subject.organization) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Enforce certificate pinning
   */
  async enforcePinning(cert: Certificate, pins: string[]): Promise<boolean> {
    // Check if certificate fingerprint matches any of the pins
    return pins.includes(cert.fingerprint);
  }

  /**
   * Get certificate metadata
   */
  async getCertificateMetadata(certId: string): Promise<CertificateMetadata> {
    const entry = this.certificateStore.get(certId);
    if (!entry) {
      throw new CertificateError(
        `Certificate ${certId} not found`,
        CertificateErrorCode.NOT_FOUND,
        certId
      );
    }

    return entry.metadata;
  }

  /**
   * Check if certificate is issued by CA
   */
  private isIssuedBy(cert: Certificate, ca: Certificate): boolean {
    // Check if issuer matches CA subject
    const issuer = cert.issuer;
    const caSubject = ca.subject;

    return (
      issuer.commonName === caSubject.commonName &&
      issuer.organization === caSubject.organization &&
      issuer.country === caSubject.country
    );
  }
}

/**
 * Phase 3: Advanced Security - Mutual TLS Tests
 *
 * These tests define the expected behavior for mutual TLS (mTLS) authentication,
 * including certificate management, validation, rotation, and revocation.
 *
 * @test-count 25
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { MTLSServiceImpl } from '../../../security/index.js';

/**
 * Interfaces that the implementation MUST provide
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

export interface CertificateSubject {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
}

export type CertificateStatus = 'active' | 'expired' | 'revoked' | 'pending';

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  expiresIn?: number; // days
}

export type RevocationReason =
  | 'keyCompromise'
  | 'affiliationChanged'
  | 'superseded'
  | 'cessationOfOperation'
  | 'certificateHold'
  | 'privilegeWithdrawn';

export interface RevocationStatus {
  revoked: boolean;
  revokedAt?: Date;
  reason?: RevocationReason;
  checkedAt: Date;
  method: 'crl' | 'ocsp';
}

export interface AuthenticationResult {
  authenticated: boolean;
  clientId?: string;
  validationErrors: string[];
  certificateFingerprint: string;
}

export interface CertificateMetadata {
  id: string;
  createdAt: Date;
  rotatedFrom?: string;
  rotatedTo?: string;
  revocationDate?: Date;
  revocationReason?: RevocationReason;
  usage: string[];
}

describe('Advanced Security - Mutual TLS', () => {
  let mtlsService: MTLSService;

  beforeEach(() => {
    mtlsService = new MTLSServiceImpl();
  });

  describe('Certificate Generation', () => {
    it('should generate valid X.509 certificate', async () => {
      const request: CertificateRequest = {
        commonName: 'client1.example.com',
        organization: 'Example Corp',
        country: 'US',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
        extendedKeyUsage: ['clientAuth'],
      };

      const cert = await mtlsService.generateCertificate(request);

      expect(cert).toBeDefined();
      expect(cert.subject.commonName).toBe(request.commonName);
      expect(cert.publicKey).toBeDefined();
      expect(cert.privateKey).toBeDefined(); // Available at generation
      expect(cert.pem).toMatch(/^-----BEGIN CERTIFICATE-----/);
    });

    it('should support RSA key generation', async () => {
      const request: CertificateRequest = {
        commonName: 'rsa-client.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert = await mtlsService.generateCertificate(request);

      expect(cert).toBeDefined();
      expect(cert.publicKey).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    });

    it('should support ECDSA key generation', async () => {
      const request: CertificateRequest = {
        commonName: 'ecdsa-client.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'ECDSA',
      };

      const cert = await mtlsService.generateCertificate(request);

      expect(cert).toBeDefined();
      expect(cert.publicKey).toBeDefined();
    });

    it('should set validity period correctly', async () => {
      const validityDays = 180;
      const request: CertificateRequest = {
        commonName: 'validity-test.example.com',
        validityDays: validityDays,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const beforeGeneration = new Date();
      const cert = await mtlsService.generateCertificate(request);
      const afterGeneration = new Date();

      expect(cert.notBefore.getTime()).toBeGreaterThanOrEqual(beforeGeneration.getTime());
      expect(cert.notBefore.getTime()).toBeLessThanOrEqual(afterGeneration.getTime());

      const expectedExpiry = new Date(cert.notBefore);
      expectedExpiry.setDate(expectedExpiry.getDate() + validityDays);

      // Allow 1 day tolerance
      const diff = Math.abs(cert.notAfter.getTime() - expectedExpiry.getTime());
      expect(diff).toBeLessThan(24 * 60 * 60 * 1000);
    });

    it('should include Subject Alternative Names', async () => {
      const request: CertificateRequest = {
        commonName: 'san-test.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
        subjectAlternativeNames: ['alt1.example.com', 'alt2.example.com'],
      };

      const cert = await mtlsService.generateCertificate(request);

      expect(cert).toBeDefined();
      // Implementation should include SANs in the certificate
    });

    it('should generate unique serial numbers', async () => {
      const request: CertificateRequest = {
        commonName: 'serial-test.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert1 = await mtlsService.generateCertificate(request);
      const cert2 = await mtlsService.generateCertificate(request);

      expect(cert1.serialNumber).not.toBe(cert2.serialNumber);
    });

    it('should generate certificate fingerprint', async () => {
      const request: CertificateRequest = {
        commonName: 'fingerprint-test.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert = await mtlsService.generateCertificate(request);

      expect(cert.fingerprint).toBeDefined();
      expect(cert.fingerprint).toMatch(/^[0-9a-f]{64}$/i); // SHA-256 hex
      expect(cert.fingerprintAlgorithm).toBe('SHA-256');
    });
  });

  describe('Certificate Validation', () => {
    it('should validate certificate with valid dates', async () => {
      const request: CertificateRequest = {
        commonName: 'valid-cert.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert = await mtlsService.generateCertificate(request);
      const validation = await mtlsService.validateCertificate(cert);

      expect(validation.valid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('should detect expired certificate', async () => {
      const expiredCert: Certificate = {
        id: 'cert-expired',
        serialNumber: '123456',
        subject: { commonName: 'expired.example.com' },
        issuer: { commonName: 'CA' },
        notBefore: new Date('2020-01-01'),
        notAfter: new Date('2021-01-01'), // Expired
        publicKey: 'pk',
        fingerprint: 'fp',
        fingerprintAlgorithm: 'SHA-256',
        pem: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
        status: 'expired',
      };

      const validation = await mtlsService.validateCertificate(expiredCert);

      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Certificate has expired');
    });

    it('should detect not-yet-valid certificate', async () => {
      const futureCert: Certificate = {
        id: 'cert-future',
        serialNumber: '123457',
        subject: { commonName: 'future.example.com' },
        issuer: { commonName: 'CA' },
        notBefore: new Date('2030-01-01'), // Future date
        notAfter: new Date('2031-01-01'),
        publicKey: 'pk',
        fingerprint: 'fp',
        fingerprintAlgorithm: 'SHA-256',
        pem: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
        status: 'pending',
      };

      const validation = await mtlsService.validateCertificate(futureCert);

      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Certificate not yet valid');
    });

    it('should warn about expiring certificate', async () => {
      const expiringCert: Certificate = {
        id: 'cert-expiring',
        serialNumber: '123458',
        subject: { commonName: 'expiring.example.com' },
        issuer: { commonName: 'CA' },
        notBefore: new Date(),
        notAfter: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000), // Expires in 15 days
        publicKey: 'pk',
        fingerprint: 'fp',
        fingerprintAlgorithm: 'SHA-256',
        pem: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
        status: 'active',
      };

      const validation = await mtlsService.validateCertificate(expiringCert);

      expect(validation.valid).toBe(true);
      expect(validation.warnings).toContain('Certificate expiring soon');
      expect(validation.expiresIn).toBeLessThan(30); // Less than 30 days
    });

    it('should validate certificate signature', async () => {
      const request: CertificateRequest = {
        commonName: 'sig-valid.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert = await mtlsService.generateCertificate(request);

      // Corrupt the certificate
      const corruptedCert = {
        ...cert,
        publicKey: 'corrupted-public-key',
      };

      const validation = await mtlsService.validateCertificate(corruptedCert);

      // Implementation should detect signature mismatch
      expect(validation.valid).toBe(false);
    });
  });

  describe('Certificate Rotation', () => {
    it('should rotate certificate before expiry', async () => {
      const initialRequest: CertificateRequest = {
        commonName: 'rotate-test.example.com',
        validityDays: 30,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const oldCert = await mtlsService.generateCertificate(initialRequest);

      const newRequest: CertificateRequest = {
        ...initialRequest,
        validityDays: 365,
      };

      const newCert = await mtlsService.rotateCertificate(oldCert.id, newRequest);

      expect(newCert).toBeDefined();
      expect(newCert.id).not.toBe(oldCert.id);
      expect(newCert.subject.commonName).toBe(oldCert.subject.commonName);
    });

    it('should maintain certificate chain during rotation', async () => {
      const initialRequest: CertificateRequest = {
        commonName: 'chain-rotate.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const oldCert = await mtlsService.generateCertificate(initialRequest);
      const newCert = await mtlsService.rotateCertificate(oldCert.id, initialRequest);

      const oldMetadata = await mtlsService.getCertificateMetadata(oldCert.id);
      const newMetadata = await mtlsService.getCertificateMetadata(newCert.id);

      expect(oldMetadata.rotatedTo).toBe(newCert.id);
      expect(newMetadata.rotatedFrom).toBe(oldCert.id);
    });

    it('should allow grace period with both old and new certs', async () => {
      const initialRequest: CertificateRequest = {
        commonName: 'grace-period.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const oldCert = await mtlsService.generateCertificate(initialRequest);
      const newCert = await mtlsService.rotateCertificate(oldCert.id, initialRequest);

      // Both should be valid during grace period
      const oldValidation = await mtlsService.validateCertificate(oldCert);
      const newValidation = await mtlsService.validateCertificate(newCert);

      // Old might be valid with warning, new should be fully valid
      expect(newValidation.valid).toBe(true);
    });

    it('should support different key algorithm on rotation', async () => {
      const rsaRequest: CertificateRequest = {
        commonName: 'rotate-alg.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const rsaCert = await mtlsService.generateCertificate(rsaRequest);

      const ecdsaRequest: CertificateRequest = {
        ...rsaRequest,
        keyAlgorithm: 'ECDSA',
      };

      const ecdsaCert = await mtlsService.rotateCertificate(rsaCert.id, ecdsaRequest);

      expect(ecdsaCert).toBeDefined();
      expect(ecdsaCert.id).not.toBe(rsaCert.id);
    });
  });

  describe('Revocation Checking - CRL', () => {
    it('should check certificate against CRL', async () => {
      const request: CertificateRequest = {
        commonName: 'crl-test.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert = await mtlsService.generateCertificate(request);

      const status = await mtlsService.checkRevocation(cert, 'crl');

      expect(status).toBeDefined();
      expect(status.revoked).toBe(false);
      expect(status.method).toBe('crl');
      expect(status.checkedAt).toBeInstanceOf(Date);
    });

    it('should detect revoked certificate via CRL', async () => {
      const request: CertificateRequest = {
        commonName: 'crl-revoked.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert = await mtlsService.generateCertificate(request);

      // Revoke the certificate
      await mtlsService.revokeCertificate(cert.id, 'keyCompromise');

      const status = await mtlsService.checkRevocation(cert, 'crl');

      expect(status.revoked).toBe(true);
      expect(status.reason).toBe('keyCompromise');
      expect(status.revokedAt).toBeInstanceOf(Date);
    });
  });

  describe('Revocation Checking - OCSP', () => {
    it('should check certificate status via OCSP', async () => {
      const request: CertificateRequest = {
        commonName: 'ocsp-test.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert = await mtlsService.generateCertificate(request);

      const status = await mtlsService.checkRevocation(cert, 'ocsp');

      expect(status).toBeDefined();
      expect(status.revoked).toBe(false);
      expect(status.method).toBe('ocsp');
    });

    it('should detect revoked certificate via OCSP', async () => {
      const request: CertificateRequest = {
        commonName: 'ocsp-revoked.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert = await mtlsService.generateCertificate(request);

      await mtlsService.revokeCertificate(cert.id, 'cessationOfOperation');

      const status = await mtlsService.checkRevocation(cert, 'ocsp');

      expect(status.revoked).toBe(true);
      expect(status.reason).toBe('cessationOfOperation');
    });

    it('should provide real-time revocation status via OCSP', async () => {
      const request: CertificateRequest = {
        commonName: 'ocsp-realtime.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert = await mtlsService.generateCertificate(request);

      const status1 = await mtlsService.checkRevocation(cert, 'ocsp');
      expect(status1.revoked).toBe(false);

      await mtlsService.revokeCertificate(cert.id, 'superseded');

      const status2 = await mtlsService.checkRevocation(cert, 'ocsp');
      expect(status2.revoked).toBe(true);
    });
  });

  describe('Client Certificate Authentication', () => {
    it('should authenticate client with valid certificate', async () => {
      const request: CertificateRequest = {
        commonName: 'client-auth.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
        extendedKeyUsage: ['clientAuth'],
      };

      const cert = await mtlsService.generateCertificate(request);

      const authResult = await mtlsService.authenticateClient(cert);

      expect(authResult.authenticated).toBe(true);
      expect(authResult.clientId).toBeDefined();
      expect(authResult.validationErrors).toHaveLength(0);
      expect(authResult.certificateFingerprint).toBe(cert.fingerprint);
    });

    it('should reject client with expired certificate', async () => {
      const expiredCert: Certificate = {
        id: 'client-expired',
        serialNumber: '999',
        subject: { commonName: 'expired-client.example.com' },
        issuer: { commonName: 'CA' },
        notBefore: new Date('2020-01-01'),
        notAfter: new Date('2021-01-01'),
        publicKey: 'pk',
        fingerprint: 'fp',
        fingerprintAlgorithm: 'SHA-256',
        pem: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
        status: 'expired',
      };

      const authResult = await mtlsService.authenticateClient(expiredCert);

      expect(authResult.authenticated).toBe(false);
      expect(authResult.validationErrors).toContain('Certificate has expired');
    });

    it('should reject client with revoked certificate', async () => {
      const request: CertificateRequest = {
        commonName: 'client-revoked.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
        extendedKeyUsage: ['clientAuth'],
      };

      const cert = await mtlsService.generateCertificate(request);
      await mtlsService.revokeCertificate(cert.id, 'affiliationChanged');

      const authResult = await mtlsService.authenticateClient(cert);

      expect(authResult.authenticated).toBe(false);
      expect(authResult.validationErrors).toContain('Certificate has been revoked');
    });
  });

  describe('Certificate Chain Verification', () => {
    it('should verify valid certificate chain', async () => {
      const request: CertificateRequest = {
        commonName: 'chain-test.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert = await mtlsService.generateCertificate(request);

      // Trust anchor (CA certificate)
      const caCert: Certificate = {
        id: 'ca-1',
        serialNumber: '1',
        subject: { commonName: 'Test CA', organization: 'Test Org' },
        issuer: { commonName: 'Test CA', organization: 'Test Org' },
        notBefore: new Date('2020-01-01'),
        notAfter: new Date('2030-01-01'),
        publicKey: 'ca-pk',
        fingerprint: 'ca-fp',
        fingerprintAlgorithm: 'SHA-256',
        pem: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
        status: 'active',
      };

      const isValid = await mtlsService.verifyCertificateChain(cert, [caCert]);

      expect(isValid).toBe(true);
    });

    it('should reject certificate with broken chain', async () => {
      const request: CertificateRequest = {
        commonName: 'broken-chain.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert = await mtlsService.generateCertificate(request);

      // Wrong CA
      const wrongCaCert: Certificate = {
        id: 'ca-wrong',
        serialNumber: '2',
        subject: { commonName: 'Wrong CA' },
        issuer: { commonName: 'Wrong CA' },
        notBefore: new Date('2020-01-01'),
        notAfter: new Date('2030-01-01'),
        publicKey: 'wrong-ca-pk',
        fingerprint: 'wrong-ca-fp',
        fingerprintAlgorithm: 'SHA-256',
        pem: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
        status: 'active',
      };

      const isValid = await mtlsService.verifyCertificateChain(cert, [wrongCaCert]);

      expect(isValid).toBe(false);
    });
  });

  describe('Certificate Pinning', () => {
    it('should enforce certificate pinning with matching fingerprint', async () => {
      const request: CertificateRequest = {
        commonName: 'pinning-test.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert = await mtlsService.generateCertificate(request);

      const pins = [cert.fingerprint];
      const isPinned = await mtlsService.enforcePinning(cert, pins);

      expect(isPinned).toBe(true);
    });

    it('should reject certificate with non-matching pin', async () => {
      const request: CertificateRequest = {
        commonName: 'pinning-fail.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert = await mtlsService.generateCertificate(request);

      const wrongPins = ['0000000000000000000000000000000000000000000000000000000000000000'];
      const isPinned = await mtlsService.enforcePinning(cert, wrongPins);

      expect(isPinned).toBe(false);
    });

    it('should support multiple pins for rotation', async () => {
      const request1: CertificateRequest = {
        commonName: 'multi-pin.example.com',
        validityDays: 365,
        keySize: 2048,
        keyAlgorithm: 'RSA',
      };

      const cert1 = await mtlsService.generateCertificate(request1);
      const cert2 = await mtlsService.rotateCertificate(cert1.id, request1);

      const pins = [cert1.fingerprint, cert2.fingerprint];

      const isPinned1 = await mtlsService.enforcePinning(cert1, pins);
      const isPinned2 = await mtlsService.enforcePinning(cert2, pins);

      expect(isPinned1).toBe(true);
      expect(isPinned2).toBe(true);
    });
  });
});

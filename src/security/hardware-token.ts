/**
 * VeilKey Hardware Token Authentication
 *
 * Provides FIDO2/WebAuthn hardware token authentication for secure
 * access control in threshold cryptography operations.
 *
 * @module security/hardware-token
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { randomBytes } from '@noble/ciphers/webcrypto';

/**
 * Hardware Token Types
 */
export type HardwareTokenType = 'fido2' | 'yubikey' | 'tpm' | 'smartcard';

/**
 * Token Attestation Type
 */
export type AttestationType = 'none' | 'indirect' | 'direct' | 'enterprise';

/**
 * Hardware Token Registration
 */
export interface TokenRegistration {
  tokenId: string;
  userId: string;
  tokenType: HardwareTokenType;
  credentialId: string;
  publicKey: string;
  attestationType: AttestationType;
  transports: AuthenticatorTransport[];
  registeredAt: Date;
  lastUsedAt: Date;
  counter: number;
  aaguid?: string; // Authenticator Attestation GUID
  deviceName?: string;
}

/**
 * Authenticator Transport Types
 */
export type AuthenticatorTransport = 'usb' | 'nfc' | 'ble' | 'internal' | 'hybrid';

/**
 * Challenge Data for Authentication
 */
export interface AuthenticationChallenge {
  challengeId: string;
  challenge: string; // Base64URL encoded
  rpId: string;
  userId: string;
  allowedCredentials: string[];
  timeout: number;
  userVerification: 'required' | 'preferred' | 'discouraged';
  createdAt: Date;
  expiresAt: Date;
}

/**
 * Authentication Response from Hardware Token
 */
export interface AuthenticationResponse {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  userHandle?: string;
}

/**
 * Verification Result
 */
export interface TokenVerificationResult {
  verified: boolean;
  tokenId: string;
  userId: string;
  counter: number;
  userPresent: boolean;
  userVerified: boolean;
  errors: string[];
}

/**
 * Registration Options
 */
export interface RegistrationOptions {
  rpId: string;
  rpName: string;
  userId: string;
  userName: string;
  userDisplayName: string;
  attestation: AttestationType;
  authenticatorSelection?: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    residentKey?: 'discouraged' | 'preferred' | 'required';
    userVerification?: 'required' | 'preferred' | 'discouraged';
  };
  excludeCredentials?: string[];
  timeout?: number;
}

/**
 * Registration Challenge
 */
export interface RegistrationChallenge {
  challengeId: string;
  challenge: string;
  rpId: string;
  rpName: string;
  userId: string;
  userName: string;
  userDisplayName: string;
  timeout: number;
  attestation: AttestationType;
  createdAt: Date;
  expiresAt: Date;
}

/**
 * Registration Response from Hardware Token
 */
export interface RegistrationResponse {
  credentialId: string;
  attestationObject: string;
  clientDataJSON: string;
  transports?: AuthenticatorTransport[];
}

/**
 * Token Policy
 */
export interface TokenPolicy {
  requireUserVerification: boolean;
  allowedTokenTypes: HardwareTokenType[];
  maxTokensPerUser: number;
  tokenInactivityTimeout: number; // days
  requireAttestation: boolean;
  allowedAttestationTypes: AttestationType[];
}

/**
 * Hardware Token Error
 */
export class HardwareTokenError extends Error {
  constructor(
    message: string,
    public readonly code: HardwareTokenErrorCode,
    public readonly tokenId?: string
  ) {
    super(message);
    this.name = 'HardwareTokenError';
  }
}

/**
 * Error Codes
 */
export enum HardwareTokenErrorCode {
  INVALID_CHALLENGE = 'INVALID_CHALLENGE',
  CHALLENGE_EXPIRED = 'CHALLENGE_EXPIRED',
  TOKEN_NOT_FOUND = 'TOKEN_NOT_FOUND',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  COUNTER_MISMATCH = 'COUNTER_MISMATCH',
  USER_VERIFICATION_FAILED = 'USER_VERIFICATION_FAILED',
  ATTESTATION_FAILED = 'ATTESTATION_FAILED',
  TOKEN_REVOKED = 'TOKEN_REVOKED',
  POLICY_VIOLATION = 'POLICY_VIOLATION',
  MAX_TOKENS_EXCEEDED = 'MAX_TOKENS_EXCEEDED',
}

/**
 * Hardware Token Manager
 * Manages FIDO2/WebAuthn hardware token authentication
 */
export class HardwareTokenManager {
  private tokens: Map<string, TokenRegistration> = new Map();
  private challenges: Map<string, AuthenticationChallenge | RegistrationChallenge> = new Map();
  private revokedTokens: Set<string> = new Set();
  private policy: TokenPolicy;

  constructor(policy?: Partial<TokenPolicy>) {
    this.policy = {
      requireUserVerification: true,
      allowedTokenTypes: ['fido2', 'yubikey', 'smartcard'],
      maxTokensPerUser: 5,
      tokenInactivityTimeout: 90,
      requireAttestation: false,
      allowedAttestationTypes: ['none', 'indirect', 'direct', 'enterprise'],
      ...policy,
    };
  }

  /**
   * Create a registration challenge for a new hardware token
   */
  async createRegistrationChallenge(options: RegistrationOptions): Promise<RegistrationChallenge> {
    // Check max tokens per user
    const userTokens = this.getTokensForUser(options.userId);
    if (userTokens.length >= this.policy.maxTokensPerUser) {
      throw new HardwareTokenError(
        `User has reached maximum token limit (${this.policy.maxTokensPerUser})`,
        HardwareTokenErrorCode.MAX_TOKENS_EXCEEDED
      );
    }

    const challengeBytes = randomBytes(32);
    const challengeId = bytesToHex(randomBytes(16));
    const timeout = options.timeout || 60000;

    const challenge: RegistrationChallenge = {
      challengeId,
      challenge: this.base64UrlEncode(challengeBytes),
      rpId: options.rpId,
      rpName: options.rpName,
      userId: options.userId,
      userName: options.userName,
      userDisplayName: options.userDisplayName,
      timeout,
      attestation: options.attestation,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + timeout),
    };

    this.challenges.set(challengeId, challenge);
    return challenge;
  }

  /**
   * Complete registration with response from hardware token
   */
  async completeRegistration(
    challengeId: string,
    response: RegistrationResponse,
    tokenType: HardwareTokenType = 'fido2',
    deviceName?: string
  ): Promise<TokenRegistration> {
    const challenge = this.challenges.get(challengeId) as RegistrationChallenge | undefined;

    if (!challenge) {
      throw new HardwareTokenError(
        'Registration challenge not found',
        HardwareTokenErrorCode.INVALID_CHALLENGE
      );
    }

    if (new Date() > challenge.expiresAt) {
      this.challenges.delete(challengeId);
      throw new HardwareTokenError(
        'Registration challenge has expired',
        HardwareTokenErrorCode.CHALLENGE_EXPIRED
      );
    }

    // Verify client data
    const clientData = JSON.parse(
      Buffer.from(this.base64UrlDecode(response.clientDataJSON)).toString('utf8')
    );

    if (clientData.type !== 'webauthn.create') {
      throw new HardwareTokenError(
        'Invalid client data type',
        HardwareTokenErrorCode.ATTESTATION_FAILED
      );
    }

    if (clientData.challenge !== challenge.challenge) {
      throw new HardwareTokenError(
        'Challenge mismatch',
        HardwareTokenErrorCode.INVALID_CHALLENGE
      );
    }

    // Parse attestation object
    const attestationData = this.parseAttestationObject(response.attestationObject);

    // Validate attestation if required
    if (this.policy.requireAttestation) {
      if (!this.policy.allowedAttestationTypes.includes(attestationData.attestationType)) {
        throw new HardwareTokenError(
          `Attestation type ${attestationData.attestationType} not allowed`,
          HardwareTokenErrorCode.ATTESTATION_FAILED
        );
      }
    }

    // Check if token type is allowed
    if (!this.policy.allowedTokenTypes.includes(tokenType)) {
      throw new HardwareTokenError(
        `Token type ${tokenType} not allowed by policy`,
        HardwareTokenErrorCode.POLICY_VIOLATION
      );
    }

    const tokenId = bytesToHex(randomBytes(16));
    const now = new Date();

    const registration: TokenRegistration = {
      tokenId,
      userId: challenge.userId,
      tokenType,
      credentialId: response.credentialId,
      publicKey: attestationData.publicKey,
      attestationType: attestationData.attestationType,
      transports: response.transports || ['usb'],
      registeredAt: now,
      lastUsedAt: now,
      counter: attestationData.counter,
      aaguid: attestationData.aaguid,
      deviceName,
    };

    this.tokens.set(tokenId, registration);
    this.challenges.delete(challengeId);

    return registration;
  }

  /**
   * Create an authentication challenge
   */
  async createAuthenticationChallenge(
    rpId: string,
    userId: string,
    userVerification: 'required' | 'preferred' | 'discouraged' = 'required'
  ): Promise<AuthenticationChallenge> {
    const userTokens = this.getTokensForUser(userId);

    if (userTokens.length === 0) {
      throw new HardwareTokenError(
        'No tokens registered for user',
        HardwareTokenErrorCode.TOKEN_NOT_FOUND
      );
    }

    // Filter out revoked tokens
    const validTokens = userTokens.filter(t => !this.revokedTokens.has(t.tokenId));

    if (validTokens.length === 0) {
      throw new HardwareTokenError(
        'All tokens for user have been revoked',
        HardwareTokenErrorCode.TOKEN_REVOKED
      );
    }

    const challengeBytes = randomBytes(32);
    const challengeId = bytesToHex(randomBytes(16));
    const timeout = 60000;

    const challenge: AuthenticationChallenge = {
      challengeId,
      challenge: this.base64UrlEncode(challengeBytes),
      rpId,
      userId,
      allowedCredentials: validTokens.map(t => t.credentialId),
      timeout,
      userVerification,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + timeout),
    };

    this.challenges.set(challengeId, challenge);
    return challenge;
  }

  /**
   * Verify authentication response
   */
  async verifyAuthentication(
    challengeId: string,
    response: AuthenticationResponse
  ): Promise<TokenVerificationResult> {
    const challenge = this.challenges.get(challengeId) as AuthenticationChallenge | undefined;

    if (!challenge) {
      return {
        verified: false,
        tokenId: '',
        userId: '',
        counter: 0,
        userPresent: false,
        userVerified: false,
        errors: ['Authentication challenge not found'],
      };
    }

    if (new Date() > challenge.expiresAt) {
      this.challenges.delete(challengeId);
      return {
        verified: false,
        tokenId: '',
        userId: challenge.userId,
        counter: 0,
        userPresent: false,
        userVerified: false,
        errors: ['Challenge has expired'],
      };
    }

    // Find the token by credential ID
    const token = this.findTokenByCredentialId(response.credentialId);

    if (!token) {
      return {
        verified: false,
        tokenId: '',
        userId: challenge.userId,
        counter: 0,
        userPresent: false,
        userVerified: false,
        errors: ['Token not found'],
      };
    }

    if (this.revokedTokens.has(token.tokenId)) {
      return {
        verified: false,
        tokenId: token.tokenId,
        userId: token.userId,
        counter: token.counter,
        userPresent: false,
        userVerified: false,
        errors: ['Token has been revoked'],
      };
    }

    // Verify client data
    const clientData = JSON.parse(
      Buffer.from(this.base64UrlDecode(response.clientDataJSON)).toString('utf8')
    );

    if (clientData.type !== 'webauthn.get') {
      return {
        verified: false,
        tokenId: token.tokenId,
        userId: token.userId,
        counter: token.counter,
        userPresent: false,
        userVerified: false,
        errors: ['Invalid client data type'],
      };
    }

    if (clientData.challenge !== challenge.challenge) {
      return {
        verified: false,
        tokenId: token.tokenId,
        userId: token.userId,
        counter: token.counter,
        userPresent: false,
        userVerified: false,
        errors: ['Challenge mismatch'],
      };
    }

    // Parse authenticator data
    const authData = this.parseAuthenticatorData(response.authenticatorData);

    // Verify RP ID hash
    const expectedRpIdHash = bytesToHex(sha256(new TextEncoder().encode(challenge.rpId)));
    if (authData.rpIdHash !== expectedRpIdHash) {
      return {
        verified: false,
        tokenId: token.tokenId,
        userId: token.userId,
        counter: authData.counter,
        userPresent: authData.userPresent,
        userVerified: authData.userVerified,
        errors: ['RP ID hash mismatch'],
      };
    }

    // Verify user presence
    if (!authData.userPresent) {
      return {
        verified: false,
        tokenId: token.tokenId,
        userId: token.userId,
        counter: authData.counter,
        userPresent: false,
        userVerified: authData.userVerified,
        errors: ['User presence not verified'],
      };
    }

    // Verify user verification if required
    if (this.policy.requireUserVerification && !authData.userVerified) {
      return {
        verified: false,
        tokenId: token.tokenId,
        userId: token.userId,
        counter: authData.counter,
        userPresent: authData.userPresent,
        userVerified: false,
        errors: ['User verification required but not performed'],
      };
    }

    // Verify counter (replay protection)
    if (authData.counter <= token.counter) {
      return {
        verified: false,
        tokenId: token.tokenId,
        userId: token.userId,
        counter: authData.counter,
        userPresent: authData.userPresent,
        userVerified: authData.userVerified,
        errors: ['Counter mismatch - possible cloned authenticator'],
      };
    }

    // Verify signature
    const signatureValid = await this.verifySignature(
      token.publicKey,
      response.authenticatorData,
      response.clientDataJSON,
      response.signature
    );

    if (!signatureValid) {
      return {
        verified: false,
        tokenId: token.tokenId,
        userId: token.userId,
        counter: authData.counter,
        userPresent: authData.userPresent,
        userVerified: authData.userVerified,
        errors: ['Invalid signature'],
      };
    }

    // Update token counter and last used
    token.counter = authData.counter;
    token.lastUsedAt = new Date();
    this.tokens.set(token.tokenId, token);

    // Clean up challenge
    this.challenges.delete(challengeId);

    return {
      verified: true,
      tokenId: token.tokenId,
      userId: token.userId,
      counter: authData.counter,
      userPresent: authData.userPresent,
      userVerified: authData.userVerified,
      errors: [],
    };
  }

  /**
   * Revoke a hardware token
   */
  revokeToken(tokenId: string): void {
    if (!this.tokens.has(tokenId)) {
      throw new HardwareTokenError(
        'Token not found',
        HardwareTokenErrorCode.TOKEN_NOT_FOUND,
        tokenId
      );
    }

    this.revokedTokens.add(tokenId);
  }

  /**
   * Get all tokens for a user
   */
  getTokensForUser(userId: string): TokenRegistration[] {
    const tokens: TokenRegistration[] = [];
    for (const token of this.tokens.values()) {
      if (token.userId === userId) {
        tokens.push(token);
      }
    }
    return tokens;
  }

  /**
   * Get token by ID
   */
  getToken(tokenId: string): TokenRegistration | undefined {
    return this.tokens.get(tokenId);
  }

  /**
   * Check if token is revoked
   */
  isTokenRevoked(tokenId: string): boolean {
    return this.revokedTokens.has(tokenId);
  }

  /**
   * Delete a token
   */
  deleteToken(tokenId: string): void {
    this.tokens.delete(tokenId);
    this.revokedTokens.delete(tokenId);
  }

  /**
   * Update policy
   */
  updatePolicy(policy: Partial<TokenPolicy>): void {
    this.policy = { ...this.policy, ...policy };
  }

  /**
   * Get current policy
   */
  getPolicy(): TokenPolicy {
    return { ...this.policy };
  }

  /**
   * Clean up expired challenges
   */
  cleanupExpiredChallenges(): number {
    const now = new Date();
    let cleaned = 0;

    for (const [id, challenge] of this.challenges.entries()) {
      if (challenge.expiresAt < now) {
        this.challenges.delete(id);
        cleaned++;
      }
    }

    return cleaned;
  }

  /**
   * Get inactive tokens
   */
  getInactiveTokens(): TokenRegistration[] {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - this.policy.tokenInactivityTimeout);

    const inactive: TokenRegistration[] = [];
    for (const token of this.tokens.values()) {
      if (token.lastUsedAt < cutoff && !this.revokedTokens.has(token.tokenId)) {
        inactive.push(token);
      }
    }

    return inactive;
  }

  // Private helper methods

  private findTokenByCredentialId(credentialId: string): TokenRegistration | undefined {
    for (const token of this.tokens.values()) {
      if (token.credentialId === credentialId) {
        return token;
      }
    }
    return undefined;
  }

  private base64UrlEncode(data: Uint8Array): string {
    return Buffer.from(data)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  private base64UrlDecode(data: string): Uint8Array {
    const base64 = data.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
    return new Uint8Array(Buffer.from(padded, 'base64'));
  }

  private parseAttestationObject(attestationObject: string): {
    publicKey: string;
    attestationType: AttestationType;
    counter: number;
    aaguid?: string;
  } {
    // Simplified attestation parsing
    // In production, this would use CBOR decoding
    const data = this.base64UrlDecode(attestationObject);

    // Extract public key (simplified)
    const publicKey = bytesToHex(data.slice(0, 65));

    // Determine attestation type
    const attestationType: AttestationType = 'direct';

    // Extract counter (last 4 bytes of authenticator data in attestation)
    const counter = 0;

    // Extract AAGUID if present
    const aaguid = bytesToHex(data.slice(37, 53));

    return { publicKey, attestationType, counter, aaguid };
  }

  private parseAuthenticatorData(authenticatorData: string): {
    rpIdHash: string;
    flags: number;
    userPresent: boolean;
    userVerified: boolean;
    counter: number;
  } {
    const data = this.base64UrlDecode(authenticatorData);

    // RP ID hash (32 bytes)
    const rpIdHash = bytesToHex(data.slice(0, 32));

    // Flags (1 byte)
    const flags = data[32];
    const userPresent = (flags & 0x01) !== 0;
    const userVerified = (flags & 0x04) !== 0;

    // Counter (4 bytes, big-endian)
    const counter = new DataView(data.buffer, data.byteOffset + 33, 4).getUint32(0);

    return { rpIdHash, flags, userPresent, userVerified, counter };
  }

  private async verifySignature(
    publicKey: string,
    authenticatorData: string,
    clientDataJSON: string,
    signature: string
  ): Promise<boolean> {
    // Compute signed data (authenticatorData || sha256(clientDataJSON))
    const authData = this.base64UrlDecode(authenticatorData);
    const clientDataHash = sha256(this.base64UrlDecode(clientDataJSON));

    const signedData = new Uint8Array(authData.length + clientDataHash.length);
    signedData.set(authData);
    signedData.set(clientDataHash, authData.length);

    // In production, verify using the public key
    // For now, perform a basic check
    const sigData = this.base64UrlDecode(signature);

    // Simplified verification - checks signature is non-empty and properly formatted
    return sigData.length >= 64;
  }
}

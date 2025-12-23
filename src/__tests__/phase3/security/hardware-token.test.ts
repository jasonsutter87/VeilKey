/**
 * Hardware Token Authentication Tests
 *
 * Tests for FIDO2/WebAuthn hardware token authentication
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import {
  HardwareTokenManager,
  HardwareTokenError,
  HardwareTokenErrorCode,
  TokenPolicy,
  RegistrationOptions,
  RegistrationResponse,
  AuthenticationResponse,
} from '../../../security/hardware-token.js';

describe('HardwareTokenManager', () => {
  let manager: HardwareTokenManager;
  const rpId = 'veilkey.example.com';
  const rpName = 'VeilKey';
  const userId = 'user-123';
  const userName = 'testuser';
  const userDisplayName = 'Test User';

  beforeEach(() => {
    manager = new HardwareTokenManager();
  });

  describe('Registration', () => {
    it('should create a registration challenge', async () => {
      const options: RegistrationOptions = {
        rpId,
        rpName,
        userId,
        userName,
        userDisplayName,
        attestation: 'none',
      };

      const challenge = await manager.createRegistrationChallenge(options);

      expect(challenge.challengeId).toBeDefined();
      expect(challenge.challenge).toBeDefined();
      expect(challenge.rpId).toBe(rpId);
      expect(challenge.rpName).toBe(rpName);
      expect(challenge.userId).toBe(userId);
      expect(challenge.userName).toBe(userName);
      expect(challenge.timeout).toBe(60000);
      expect(challenge.createdAt).toBeInstanceOf(Date);
      expect(challenge.expiresAt).toBeInstanceOf(Date);
      expect(challenge.expiresAt.getTime()).toBeGreaterThan(challenge.createdAt.getTime());
    });

    it('should complete registration with valid response', async () => {
      const options: RegistrationOptions = {
        rpId,
        rpName,
        userId,
        userName,
        userDisplayName,
        attestation: 'none',
      };

      const challenge = await manager.createRegistrationChallenge(options);

      // Create mock registration response
      const clientData = {
        type: 'webauthn.create',
        challenge: challenge.challenge,
        origin: `https://${rpId}`,
      };

      const response: RegistrationResponse = {
        credentialId: 'credential-abc123',
        attestationObject: Buffer.from(new Uint8Array(100).fill(1)).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64'),
        transports: ['usb'],
      };

      const registration = await manager.completeRegistration(
        challenge.challengeId,
        response,
        'fido2',
        'My YubiKey'
      );

      expect(registration.tokenId).toBeDefined();
      expect(registration.userId).toBe(userId);
      expect(registration.tokenType).toBe('fido2');
      expect(registration.credentialId).toBe('credential-abc123');
      expect(registration.deviceName).toBe('My YubiKey');
      expect(registration.transports).toEqual(['usb']);
    });

    it('should reject invalid challenge ID', async () => {
      const response: RegistrationResponse = {
        credentialId: 'credential-abc123',
        attestationObject: Buffer.from(new Uint8Array(100)).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify({ type: 'webauthn.create' })).toString('base64'),
      };

      await expect(
        manager.completeRegistration('invalid-challenge-id', response)
      ).rejects.toThrow(HardwareTokenError);
    });

    it('should reject wrong client data type', async () => {
      const options: RegistrationOptions = {
        rpId,
        rpName,
        userId,
        userName,
        userDisplayName,
        attestation: 'none',
      };

      const challenge = await manager.createRegistrationChallenge(options);

      const clientData = {
        type: 'webauthn.get', // Wrong type
        challenge: challenge.challenge,
        origin: `https://${rpId}`,
      };

      const response: RegistrationResponse = {
        credentialId: 'credential-abc123',
        attestationObject: Buffer.from(new Uint8Array(100)).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64'),
      };

      await expect(
        manager.completeRegistration(challenge.challengeId, response)
      ).rejects.toThrow(HardwareTokenError);
    });

    it('should reject mismatched challenge', async () => {
      const options: RegistrationOptions = {
        rpId,
        rpName,
        userId,
        userName,
        userDisplayName,
        attestation: 'none',
      };

      const challenge = await manager.createRegistrationChallenge(options);

      const clientData = {
        type: 'webauthn.create',
        challenge: 'wrong-challenge-value',
        origin: `https://${rpId}`,
      };

      const response: RegistrationResponse = {
        credentialId: 'credential-abc123',
        attestationObject: Buffer.from(new Uint8Array(100)).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64'),
      };

      await expect(
        manager.completeRegistration(challenge.challengeId, response)
      ).rejects.toThrow(HardwareTokenError);
    });

    it('should enforce max tokens per user', async () => {
      const policy: Partial<TokenPolicy> = { maxTokensPerUser: 2 };
      manager = new HardwareTokenManager(policy);

      const options: RegistrationOptions = {
        rpId,
        rpName,
        userId,
        userName,
        userDisplayName,
        attestation: 'none',
      };

      // Register first token
      const challenge1 = await manager.createRegistrationChallenge(options);
      const clientData1 = {
        type: 'webauthn.create',
        challenge: challenge1.challenge,
        origin: `https://${rpId}`,
      };
      await manager.completeRegistration(challenge1.challengeId, {
        credentialId: 'cred-1',
        attestationObject: Buffer.from(new Uint8Array(100)).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify(clientData1)).toString('base64'),
      });

      // Register second token
      const challenge2 = await manager.createRegistrationChallenge(options);
      const clientData2 = {
        type: 'webauthn.create',
        challenge: challenge2.challenge,
        origin: `https://${rpId}`,
      };
      await manager.completeRegistration(challenge2.challengeId, {
        credentialId: 'cred-2',
        attestationObject: Buffer.from(new Uint8Array(100)).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify(clientData2)).toString('base64'),
      });

      // Third token should fail
      await expect(manager.createRegistrationChallenge(options)).rejects.toThrow(
        HardwareTokenError
      );
    });
  });

  describe('Authentication', () => {
    let tokenId: string;
    let credentialId: string;

    beforeEach(async () => {
      // Register a token first
      const options: RegistrationOptions = {
        rpId,
        rpName,
        userId,
        userName,
        userDisplayName,
        attestation: 'none',
      };

      const challenge = await manager.createRegistrationChallenge(options);
      const clientData = {
        type: 'webauthn.create',
        challenge: challenge.challenge,
        origin: `https://${rpId}`,
      };

      credentialId = 'credential-' + Date.now();
      const registration = await manager.completeRegistration(challenge.challengeId, {
        credentialId,
        attestationObject: Buffer.from(new Uint8Array(100)).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64'),
        transports: ['usb'],
      });

      tokenId = registration.tokenId;
    });

    it('should create authentication challenge', async () => {
      const challenge = await manager.createAuthenticationChallenge(rpId, userId);

      expect(challenge.challengeId).toBeDefined();
      expect(challenge.challenge).toBeDefined();
      expect(challenge.rpId).toBe(rpId);
      expect(challenge.userId).toBe(userId);
      expect(challenge.allowedCredentials).toContain(credentialId);
      expect(challenge.userVerification).toBe('required');
    });

    it('should verify valid authentication response', async () => {
      const challenge = await manager.createAuthenticationChallenge(rpId, userId);

      // Create valid authentication response
      const clientData = {
        type: 'webauthn.get',
        challenge: challenge.challenge,
        origin: `https://${rpId}`,
      };

      // Build authenticator data with correct RP ID hash
      const rpIdHash = sha256(new TextEncoder().encode(rpId));
      const authData = new Uint8Array(37 + 4);
      authData.set(rpIdHash, 0);
      authData[32] = 0x05; // UP and UV flags set
      // Set counter to 1 (big-endian)
      new DataView(authData.buffer, 33, 4).setUint32(0, 1);

      const response: AuthenticationResponse = {
        credentialId,
        authenticatorData: Buffer.from(authData)
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, ''),
        clientDataJSON: Buffer.from(JSON.stringify(clientData))
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, ''),
        signature: Buffer.from(new Uint8Array(64).fill(1))
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, ''),
      };

      const result = await manager.verifyAuthentication(challenge.challengeId, response);

      expect(result.verified).toBe(true);
      expect(result.tokenId).toBe(tokenId);
      expect(result.userId).toBe(userId);
      expect(result.userPresent).toBe(true);
      expect(result.userVerified).toBe(true);
      expect(result.counter).toBe(1);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject authentication with invalid challenge', async () => {
      const response: AuthenticationResponse = {
        credentialId,
        authenticatorData: Buffer.from(new Uint8Array(41)).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify({ type: 'webauthn.get' })).toString('base64'),
        signature: Buffer.from(new Uint8Array(64)).toString('base64'),
      };

      const result = await manager.verifyAuthentication('invalid-challenge', response);

      expect(result.verified).toBe(false);
      expect(result.errors).toContain('Authentication challenge not found');
    });

    it('should reject authentication with wrong client data type', async () => {
      const challenge = await manager.createAuthenticationChallenge(rpId, userId);

      const clientData = {
        type: 'webauthn.create', // Wrong type
        challenge: challenge.challenge,
        origin: `https://${rpId}`,
      };

      const rpIdHash = sha256(new TextEncoder().encode(rpId));
      const authData = new Uint8Array(37 + 4);
      authData.set(rpIdHash, 0);
      authData[32] = 0x05;
      new DataView(authData.buffer, 33, 4).setUint32(0, 1);

      const response: AuthenticationResponse = {
        credentialId,
        authenticatorData: Buffer.from(authData).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64'),
        signature: Buffer.from(new Uint8Array(64)).toString('base64'),
      };

      const result = await manager.verifyAuthentication(challenge.challengeId, response);

      expect(result.verified).toBe(false);
      expect(result.errors).toContain('Invalid client data type');
    });

    it('should reject authentication with wrong RP ID', async () => {
      const challenge = await manager.createAuthenticationChallenge(rpId, userId);

      const clientData = {
        type: 'webauthn.get',
        challenge: challenge.challenge,
        origin: `https://${rpId}`,
      };

      // Use wrong RP ID in authenticator data
      const wrongRpIdHash = sha256(new TextEncoder().encode('wrong.example.com'));
      const authData = new Uint8Array(37 + 4);
      authData.set(wrongRpIdHash, 0);
      authData[32] = 0x05;
      new DataView(authData.buffer, 33, 4).setUint32(0, 1);

      const response: AuthenticationResponse = {
        credentialId,
        authenticatorData: Buffer.from(authData).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64'),
        signature: Buffer.from(new Uint8Array(64)).toString('base64'),
      };

      const result = await manager.verifyAuthentication(challenge.challengeId, response);

      expect(result.verified).toBe(false);
      expect(result.errors).toContain('RP ID hash mismatch');
    });

    it('should reject authentication with counter replay', async () => {
      // First authentication with counter = 1
      let challenge = await manager.createAuthenticationChallenge(rpId, userId);
      let clientData = {
        type: 'webauthn.get',
        challenge: challenge.challenge,
        origin: `https://${rpId}`,
      };

      const rpIdHash = sha256(new TextEncoder().encode(rpId));
      let authData = new Uint8Array(37 + 4);
      authData.set(rpIdHash, 0);
      authData[32] = 0x05;
      new DataView(authData.buffer, 33, 4).setUint32(0, 1);

      let response: AuthenticationResponse = {
        credentialId,
        authenticatorData: Buffer.from(authData)
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, ''),
        clientDataJSON: Buffer.from(JSON.stringify(clientData))
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, ''),
        signature: Buffer.from(new Uint8Array(64).fill(1))
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, ''),
      };

      await manager.verifyAuthentication(challenge.challengeId, response);

      // Second authentication with same counter (should fail)
      challenge = await manager.createAuthenticationChallenge(rpId, userId);
      clientData = {
        type: 'webauthn.get',
        challenge: challenge.challenge,
        origin: `https://${rpId}`,
      };

      authData = new Uint8Array(37 + 4);
      authData.set(rpIdHash, 0);
      authData[32] = 0x05;
      new DataView(authData.buffer, 33, 4).setUint32(0, 1); // Same counter

      response = {
        credentialId,
        authenticatorData: Buffer.from(authData)
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, ''),
        clientDataJSON: Buffer.from(JSON.stringify(clientData))
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, ''),
        signature: Buffer.from(new Uint8Array(64).fill(1))
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, ''),
      };

      const result = await manager.verifyAuthentication(challenge.challengeId, response);

      expect(result.verified).toBe(false);
      expect(result.errors).toContain('Counter mismatch - possible cloned authenticator');
    });

    it('should reject authentication for user with no tokens', async () => {
      await expect(
        manager.createAuthenticationChallenge(rpId, 'unknown-user')
      ).rejects.toThrow(HardwareTokenError);
    });
  });

  describe('Token Management', () => {
    it('should get tokens for user', async () => {
      // Register multiple tokens
      for (let i = 0; i < 3; i++) {
        const options: RegistrationOptions = {
          rpId,
          rpName,
          userId,
          userName,
          userDisplayName,
          attestation: 'none',
        };

        const challenge = await manager.createRegistrationChallenge(options);
        const clientData = {
          type: 'webauthn.create',
          challenge: challenge.challenge,
          origin: `https://${rpId}`,
        };

        await manager.completeRegistration(challenge.challengeId, {
          credentialId: `cred-${i}`,
          attestationObject: Buffer.from(new Uint8Array(100)).toString('base64'),
          clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64'),
        });
      }

      const tokens = manager.getTokensForUser(userId);
      expect(tokens).toHaveLength(3);
    });

    it('should revoke a token', async () => {
      const options: RegistrationOptions = {
        rpId,
        rpName,
        userId,
        userName,
        userDisplayName,
        attestation: 'none',
      };

      const challenge = await manager.createRegistrationChallenge(options);
      const clientData = {
        type: 'webauthn.create',
        challenge: challenge.challenge,
        origin: `https://${rpId}`,
      };

      const registration = await manager.completeRegistration(challenge.challengeId, {
        credentialId: 'cred-to-revoke',
        attestationObject: Buffer.from(new Uint8Array(100)).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64'),
      });

      expect(manager.isTokenRevoked(registration.tokenId)).toBe(false);

      manager.revokeToken(registration.tokenId);

      expect(manager.isTokenRevoked(registration.tokenId)).toBe(true);
    });

    it('should reject authentication for revoked token', async () => {
      const options: RegistrationOptions = {
        rpId,
        rpName,
        userId,
        userName,
        userDisplayName,
        attestation: 'none',
      };

      const challenge = await manager.createRegistrationChallenge(options);
      const clientData = {
        type: 'webauthn.create',
        challenge: challenge.challenge,
        origin: `https://${rpId}`,
      };

      const credentialId = 'cred-revoked';
      const registration = await manager.completeRegistration(challenge.challengeId, {
        credentialId,
        attestationObject: Buffer.from(new Uint8Array(100)).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64'),
      });

      // Revoke the token
      manager.revokeToken(registration.tokenId);

      // Authentication should fail
      await expect(
        manager.createAuthenticationChallenge(rpId, userId)
      ).rejects.toThrow(HardwareTokenError);
    });

    it('should delete a token', async () => {
      const options: RegistrationOptions = {
        rpId,
        rpName,
        userId,
        userName,
        userDisplayName,
        attestation: 'none',
      };

      const challenge = await manager.createRegistrationChallenge(options);
      const clientData = {
        type: 'webauthn.create',
        challenge: challenge.challenge,
        origin: `https://${rpId}`,
      };

      const registration = await manager.completeRegistration(challenge.challengeId, {
        credentialId: 'cred-to-delete',
        attestationObject: Buffer.from(new Uint8Array(100)).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64'),
      });

      expect(manager.getToken(registration.tokenId)).toBeDefined();

      manager.deleteToken(registration.tokenId);

      expect(manager.getToken(registration.tokenId)).toBeUndefined();
    });

    it('should throw when revoking non-existent token', () => {
      expect(() => manager.revokeToken('non-existent-token')).toThrow(HardwareTokenError);
    });
  });

  describe('Policy Management', () => {
    it('should apply custom policy', () => {
      const customPolicy: Partial<TokenPolicy> = {
        requireUserVerification: false,
        maxTokensPerUser: 10,
        tokenInactivityTimeout: 180,
      };

      manager = new HardwareTokenManager(customPolicy);
      const policy = manager.getPolicy();

      expect(policy.requireUserVerification).toBe(false);
      expect(policy.maxTokensPerUser).toBe(10);
      expect(policy.tokenInactivityTimeout).toBe(180);
    });

    it('should update policy', () => {
      manager.updatePolicy({ maxTokensPerUser: 3 });
      const policy = manager.getPolicy();

      expect(policy.maxTokensPerUser).toBe(3);
    });

    it('should reject disallowed token types', async () => {
      manager = new HardwareTokenManager({
        allowedTokenTypes: ['yubikey'],
      });

      const options: RegistrationOptions = {
        rpId,
        rpName,
        userId,
        userName,
        userDisplayName,
        attestation: 'none',
      };

      const challenge = await manager.createRegistrationChallenge(options);
      const clientData = {
        type: 'webauthn.create',
        challenge: challenge.challenge,
        origin: `https://${rpId}`,
      };

      await expect(
        manager.completeRegistration(
          challenge.challengeId,
          {
            credentialId: 'cred-fido2',
            attestationObject: Buffer.from(new Uint8Array(100)).toString('base64'),
            clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64'),
          },
          'fido2' // Not allowed
        )
      ).rejects.toThrow(HardwareTokenError);
    });
  });

  describe('Challenge Cleanup', () => {
    it('should clean up expired challenges', async () => {
      const options: RegistrationOptions = {
        rpId,
        rpName,
        userId,
        userName,
        userDisplayName,
        attestation: 'none',
        timeout: 1, // 1ms timeout
      };

      await manager.createRegistrationChallenge(options);
      await manager.createRegistrationChallenge(options);

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 10));

      const cleaned = manager.cleanupExpiredChallenges();
      expect(cleaned).toBe(2);
    });
  });

  describe('Inactive Token Detection', () => {
    it('should identify inactive tokens', async () => {
      manager = new HardwareTokenManager({
        tokenInactivityTimeout: 0, // Immediate inactivity
      });

      const options: RegistrationOptions = {
        rpId,
        rpName,
        userId,
        userName,
        userDisplayName,
        attestation: 'none',
      };

      const challenge = await manager.createRegistrationChallenge(options);
      const clientData = {
        type: 'webauthn.create',
        challenge: challenge.challenge,
        origin: `https://${rpId}`,
      };

      await manager.completeRegistration(challenge.challengeId, {
        credentialId: 'cred-inactive',
        attestationObject: Buffer.from(new Uint8Array(100)).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64'),
      });

      // Wait a bit
      await new Promise(resolve => setTimeout(resolve, 10));

      const inactive = manager.getInactiveTokens();
      expect(inactive.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('User Verification Requirements', () => {
    it('should fail when user verification required but not performed', async () => {
      manager = new HardwareTokenManager({
        requireUserVerification: true,
      });

      // Register token
      const options: RegistrationOptions = {
        rpId,
        rpName,
        userId,
        userName,
        userDisplayName,
        attestation: 'none',
      };

      const regChallenge = await manager.createRegistrationChallenge(options);
      const regClientData = {
        type: 'webauthn.create',
        challenge: regChallenge.challenge,
        origin: `https://${rpId}`,
      };

      const credentialId = 'cred-uv-test';
      await manager.completeRegistration(regChallenge.challengeId, {
        credentialId,
        attestationObject: Buffer.from(new Uint8Array(100)).toString('base64'),
        clientDataJSON: Buffer.from(JSON.stringify(regClientData)).toString('base64'),
      });

      // Try authentication without user verification
      const authChallenge = await manager.createAuthenticationChallenge(rpId, userId);
      const authClientData = {
        type: 'webauthn.get',
        challenge: authChallenge.challenge,
        origin: `https://${rpId}`,
      };

      const rpIdHash = sha256(new TextEncoder().encode(rpId));
      const authData = new Uint8Array(37 + 4);
      authData.set(rpIdHash, 0);
      authData[32] = 0x01; // Only UP flag, no UV
      new DataView(authData.buffer, 33, 4).setUint32(0, 1);

      const response: AuthenticationResponse = {
        credentialId,
        authenticatorData: Buffer.from(authData)
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, ''),
        clientDataJSON: Buffer.from(JSON.stringify(authClientData))
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, ''),
        signature: Buffer.from(new Uint8Array(64).fill(1))
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, ''),
      };

      const result = await manager.verifyAuthentication(authChallenge.challengeId, response);

      expect(result.verified).toBe(false);
      expect(result.errors).toContain('User verification required but not performed');
    });
  });

  describe('Error Codes', () => {
    it('should use correct error codes', () => {
      expect(HardwareTokenErrorCode.INVALID_CHALLENGE).toBe('INVALID_CHALLENGE');
      expect(HardwareTokenErrorCode.CHALLENGE_EXPIRED).toBe('CHALLENGE_EXPIRED');
      expect(HardwareTokenErrorCode.TOKEN_NOT_FOUND).toBe('TOKEN_NOT_FOUND');
      expect(HardwareTokenErrorCode.INVALID_SIGNATURE).toBe('INVALID_SIGNATURE');
      expect(HardwareTokenErrorCode.COUNTER_MISMATCH).toBe('COUNTER_MISMATCH');
      expect(HardwareTokenErrorCode.USER_VERIFICATION_FAILED).toBe('USER_VERIFICATION_FAILED');
      expect(HardwareTokenErrorCode.ATTESTATION_FAILED).toBe('ATTESTATION_FAILED');
      expect(HardwareTokenErrorCode.TOKEN_REVOKED).toBe('TOKEN_REVOKED');
      expect(HardwareTokenErrorCode.POLICY_VIOLATION).toBe('POLICY_VIOLATION');
      expect(HardwareTokenErrorCode.MAX_TOKENS_EXCEEDED).toBe('MAX_TOKENS_EXCEEDED');
    });

    it('should create HardwareTokenError with all properties', () => {
      const error = new HardwareTokenError(
        'Test error',
        HardwareTokenErrorCode.TOKEN_NOT_FOUND,
        'token-123'
      );

      expect(error.message).toBe('Test error');
      expect(error.code).toBe(HardwareTokenErrorCode.TOKEN_NOT_FOUND);
      expect(error.tokenId).toBe('token-123');
      expect(error.name).toBe('HardwareTokenError');
    });
  });
});

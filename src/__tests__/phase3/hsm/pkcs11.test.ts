import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

/**
 * PKCS#11 HSM Integration Test Suite
 *
 * These are TDD tests defining the contract for PKCS#11 HSM integration.
 * Implementation does not exist yet - tests will initially fail/skip.
 *
 * PKCS#11 is the Cryptographic Token Interface Standard used by most HSMs.
 */

// Type definitions for expected PKCS#11 interfaces
interface PKCS11Session {
  handle: bigint;
  state: 'RO_PUBLIC' | 'RO_USER' | 'RW_PUBLIC' | 'RW_USER' | 'RW_SO';
  deviceInfo: PKCS11DeviceInfo;
}

interface PKCS11DeviceInfo {
  slotId: number;
  manufacturerId: string;
  model: string;
  serialNumber: string;
  firmwareVersion: string;
  flags: {
    tokenPresent: boolean;
    removableDevice: boolean;
    hwSlot: boolean;
  };
}

interface PKCS11Credentials {
  pin: string;
  userType: 'USER' | 'SO'; // Security Officer
}

interface PKCS11KeyHandle {
  handle: bigint;
  type: 'RSA' | 'EC' | 'AES';
  id: Uint8Array;
  label: string;
  extractable: boolean;
  sensitive: boolean;
}

interface PKCS11SignatureOptions {
  mechanism: 'RSA_PKCS' | 'RSA_PSS' | 'ECDSA' | 'SHA256_RSA_PKCS';
  hashAlgorithm?: 'SHA256' | 'SHA384' | 'SHA512';
}

interface PKCS11DecryptionOptions {
  mechanism: 'RSA_PKCS' | 'RSA_OAEP' | 'AES_GCM';
  iv?: Uint8Array;
  aad?: Uint8Array;
}

interface PKCS11Manager {
  initialize(libraryPath: string): Promise<void>;
  finalize(): Promise<void>;
  getSlots(tokenPresent?: boolean): Promise<number[]>;
  getSlotInfo(slotId: number): Promise<PKCS11DeviceInfo>;

  openSession(slotId: number, flags?: { readWrite?: boolean }): Promise<PKCS11Session>;
  closeSession(session: PKCS11Session): Promise<void>;
  closeAllSessions(slotId: number): Promise<void>;

  login(session: PKCS11Session, credentials: PKCS11Credentials): Promise<void>;
  logout(session: PKCS11Session): Promise<void>;

  generateKeyPair(
    session: PKCS11Session,
    algorithm: string,
    options: {
      keySize?: number;
      label?: string;
      id?: Uint8Array;
      extractable?: boolean;
      sensitive?: boolean;
    }
  ): Promise<{ publicKey: PKCS11KeyHandle; privateKey: PKCS11KeyHandle }>;

  storeShare(
    session: PKCS11Session,
    shareData: Uint8Array,
    metadata: {
      label: string;
      id: Uint8Array;
      sensitive?: boolean;
    }
  ): Promise<PKCS11KeyHandle>;

  retrieveShare(
    session: PKCS11Session,
    handle: PKCS11KeyHandle
  ): Promise<Uint8Array>;

  sign(
    session: PKCS11Session,
    keyHandle: PKCS11KeyHandle,
    data: Uint8Array,
    options: PKCS11SignatureOptions
  ): Promise<Uint8Array>;

  decrypt(
    session: PKCS11Session,
    keyHandle: PKCS11KeyHandle,
    ciphertext: Uint8Array,
    options: PKCS11DecryptionOptions
  ): Promise<Uint8Array>;

  findObjects(
    session: PKCS11Session,
    template: {
      class?: 'PUBLIC_KEY' | 'PRIVATE_KEY' | 'SECRET_KEY' | 'DATA';
      label?: string;
      id?: Uint8Array;
      keyType?: string;
    }
  ): Promise<PKCS11KeyHandle[]>;

  deleteObject(session: PKCS11Session, handle: PKCS11KeyHandle): Promise<void>;

  getAccessToken(session: PKCS11Session): Promise<string>;
}

// Mock PKCS#11 library path
const MOCK_PKCS11_LIB = '/usr/lib/softhsm/libsofthsm2.so';

describe('PKCS#11 HSM Integration', () => {
  let pkcs11: PKCS11Manager;
  let session: PKCS11Session | null = null;

  beforeEach(async () => {
    // This will be the actual implementation import
    // For now, we expect it to not exist
    try {
      const { PKCS11Manager: Manager } = await import('../../../hsm/pkcs11');
      pkcs11 = new Manager();
    } catch {
      // Expected to fail - implementation doesn't exist yet
      pkcs11 = {} as PKCS11Manager;
    }
  });

  afterEach(async () => {
    if (session && pkcs11.closeSession && pkcs11.isInitialized?.()) {
      try {
        await pkcs11.closeSession(session);
      } catch {
        // Session may already be closed
      }
    }
    if (pkcs11.finalize && pkcs11.isInitialized?.()) {
      await pkcs11.finalize();
    }
  });

  describe('Session Management', () => {
    it('should initialize PKCS#11 library', async () => {
      await expect(pkcs11.initialize(MOCK_PKCS11_LIB)).resolves.not.toThrow();
    });

    it('should finalize PKCS#11 library', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      await expect(pkcs11.finalize()).resolves.not.toThrow();
    });

    it('should list available slots', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);

      expect(Array.isArray(slots)).toBe(true);
      expect(slots.length).toBeGreaterThan(0);
    });

    it('should get slot information', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      const slotInfo = await pkcs11.getSlotInfo(slots[0]);

      expect(slotInfo).toBeDefined();
      expect(slotInfo.manufacturerId).toBeDefined();
      expect(slotInfo.model).toBeDefined();
      expect(slotInfo.serialNumber).toBeDefined();
      expect(slotInfo.flags.tokenPresent).toBe(true);
    });

    it('should open a read-only session', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);

      session = await pkcs11.openSession(slots[0], { readWrite: false });

      expect(session).toBeDefined();
      expect(session.handle).toBeDefined();
      expect(['RO_PUBLIC', 'RO_USER']).toContain(session.state);
    });

    it('should open a read-write session', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);

      session = await pkcs11.openSession(slots[0], { readWrite: true });

      expect(session).toBeDefined();
      expect(session.handle).toBeDefined();
      expect(['RW_PUBLIC', 'RW_USER', 'RW_SO']).toContain(session.state);
    });

    it('should close a session', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0]);

      await expect(pkcs11.closeSession(session)).resolves.not.toThrow();
      session = null;
    });

    it('should close all sessions for a slot', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);

      const session1 = await pkcs11.openSession(slots[0]);
      const session2 = await pkcs11.openSession(slots[0]);

      await expect(pkcs11.closeAllSessions(slots[0])).resolves.not.toThrow();
      session = null;
    });

    it('should login with user PIN', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });

      await expect(
        pkcs11.login(session, { pin: '1234', userType: 'USER' })
      ).resolves.not.toThrow();

      expect(['RW_USER']).toContain(session.state);
    });

    it('should logout from session', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      await expect(pkcs11.logout(session)).resolves.not.toThrow();
      expect(['RW_PUBLIC']).toContain(session.state);
    });

    it('should reject invalid PIN', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });

      await expect(
        pkcs11.login(session, { pin: 'wrong', userType: 'USER' })
      ).rejects.toThrow(/authentication failed|invalid PIN/i);
    });
  });

  describe('Key Generation', () => {
    it('should generate RSA key pair in HSM', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      const keyPair = await pkcs11.generateKeyPair(session, 'RSA', {
        keySize: 2048,
        label: 'test-rsa-key',
        extractable: false,
        sensitive: true,
      });

      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey.type).toBe('RSA');
      expect(keyPair.privateKey.type).toBe('RSA');
      expect(keyPair.privateKey.extractable).toBe(false);
      expect(keyPair.privateKey.sensitive).toBe(true);
    });

    it('should generate EC key pair in HSM', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      const keyPair = await pkcs11.generateKeyPair(session, 'EC', {
        label: 'test-ec-key',
        extractable: false,
        sensitive: true,
      });

      expect(keyPair.publicKey.type).toBe('EC');
      expect(keyPair.privateKey.type).toBe('EC');
    });

    it('should assign custom ID to generated key', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      const customId = new Uint8Array([1, 2, 3, 4, 5]);
      const keyPair = await pkcs11.generateKeyPair(session, 'RSA', {
        keySize: 2048,
        id: customId,
        label: 'custom-id-key',
      });

      expect(keyPair.publicKey.id).toEqual(customId);
      expect(keyPair.privateKey.id).toEqual(customId);
    });
  });

  describe('Share Storage', () => {
    it('should store share data in HSM slot', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      const shareData = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const shareId = new Uint8Array([0, 0, 0, 1]);

      const handle = await pkcs11.storeShare(session, shareData, {
        label: 'threshold-share-1',
        id: shareId,
        sensitive: true,
      });

      expect(handle).toBeDefined();
      expect(handle.label).toBe('threshold-share-1');
      expect(handle.id).toEqual(shareId);
    });

    it('should retrieve stored share data', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      const originalData = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const handle = await pkcs11.storeShare(session, originalData, {
        label: 'threshold-share-2',
        id: new Uint8Array([0, 0, 0, 2]),
        sensitive: false,
      });

      const retrievedData = await pkcs11.retrieveShare(session, handle);
      expect(retrievedData).toEqual(originalData);
    });

    it('should prevent retrieval of sensitive shares without auth', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      const authSession = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(authSession, { pin: '1234', userType: 'USER' });

      const sensitiveData = new Uint8Array([9, 9, 9, 9]);
      const handle = await pkcs11.storeShare(authSession, sensitiveData, {
        label: 'sensitive-share',
        id: new Uint8Array([0, 0, 0, 3]),
        sensitive: true,
      });

      await pkcs11.logout(authSession);

      await expect(
        pkcs11.retrieveShare(authSession, handle)
      ).rejects.toThrow(/not authorized|user not logged in/i);

      session = authSession;
    });

    it('should store multiple shares in different slots', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      const shares = [
        { data: new Uint8Array([1, 1, 1]), id: new Uint8Array([0, 0, 1]) },
        { data: new Uint8Array([2, 2, 2]), id: new Uint8Array([0, 0, 2]) },
        { data: new Uint8Array([3, 3, 3]), id: new Uint8Array([0, 0, 3]) },
      ];

      const handles = await Promise.all(
        shares.map((share, idx) =>
          pkcs11.storeShare(session!, share.data, {
            label: `share-${idx}`,
            id: share.id,
          })
        )
      );

      expect(handles).toHaveLength(3);
      handles.forEach((handle, idx) => {
        expect(handle.id).toEqual(shares[idx].id);
      });
    });
  });

  describe('Signing Operations', () => {
    it('should sign data using HSM private key with RSA-PKCS', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      const keyPair = await pkcs11.generateKeyPair(session, 'RSA', {
        keySize: 2048,
        label: 'signing-key',
      });

      const message = new TextEncoder().encode('Sign this message');
      const signature = await pkcs11.sign(session, keyPair.privateKey, message, {
        mechanism: 'RSA_PKCS',
        hashAlgorithm: 'SHA256',
      });

      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBeGreaterThan(0);
    });

    it('should sign data using HSM private key with RSA-PSS', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      const keyPair = await pkcs11.generateKeyPair(session, 'RSA', {
        keySize: 2048,
        label: 'signing-key-pss',
      });

      const message = new TextEncoder().encode('Sign with PSS');
      const signature = await pkcs11.sign(session, keyPair.privateKey, message, {
        mechanism: 'RSA_PSS',
        hashAlgorithm: 'SHA256',
      });

      expect(signature).toBeInstanceOf(Uint8Array);
    });

    it('should reject signing without authentication', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      const tempSession = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(tempSession, { pin: '1234', userType: 'USER' });

      const keyPair = await pkcs11.generateKeyPair(tempSession, 'RSA', {
        keySize: 2048,
        label: 'protected-key',
        sensitive: true,
      });

      await pkcs11.logout(tempSession);

      const message = new TextEncoder().encode('Try to sign');
      await expect(
        pkcs11.sign(tempSession, keyPair.privateKey, message, {
          mechanism: 'RSA_PKCS',
        })
      ).rejects.toThrow(/not authorized|user not logged in/i);

      session = tempSession;
    });
  });

  describe('Decryption Operations', () => {
    it('should decrypt data using HSM private key with RSA-PKCS', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      const keyPair = await pkcs11.generateKeyPair(session, 'RSA', {
        keySize: 2048,
        label: 'decryption-key',
      });

      // In real implementation, this would be encrypted with the public key
      const ciphertext = new Uint8Array(256); // Mock encrypted data

      const plaintext = await pkcs11.decrypt(session, keyPair.privateKey, ciphertext, {
        mechanism: 'RSA_PKCS',
      });

      expect(plaintext).toBeInstanceOf(Uint8Array);
    });

    it('should decrypt data using HSM private key with RSA-OAEP', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      const keyPair = await pkcs11.generateKeyPair(session, 'RSA', {
        keySize: 2048,
        label: 'decryption-key-oaep',
      });

      const ciphertext = new Uint8Array(256);
      const plaintext = await pkcs11.decrypt(session, keyPair.privateKey, ciphertext, {
        mechanism: 'RSA_OAEP',
      });

      expect(plaintext).toBeInstanceOf(Uint8Array);
    });

    it('should reject decryption without authentication', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      const tempSession = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(tempSession, { pin: '1234', userType: 'USER' });

      const keyPair = await pkcs11.generateKeyPair(tempSession, 'RSA', {
        keySize: 2048,
        label: 'protected-decrypt-key',
        sensitive: true,
      });

      await pkcs11.logout(tempSession);

      const ciphertext = new Uint8Array(256);
      await expect(
        pkcs11.decrypt(tempSession, keyPair.privateKey, ciphertext, {
          mechanism: 'RSA_PKCS',
        })
      ).rejects.toThrow(/not authorized|user not logged in/i);

      session = tempSession;
    });
  });

  describe('Key Enumeration', () => {
    it('should find all keys in HSM', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      // Create some keys
      await pkcs11.generateKeyPair(session, 'RSA', {
        keySize: 2048,
        label: 'key-1',
      });
      await pkcs11.generateKeyPair(session, 'RSA', {
        keySize: 2048,
        label: 'key-2',
      });

      const allKeys = await pkcs11.findObjects(session, {});
      expect(allKeys.length).toBeGreaterThanOrEqual(4); // 2 pairs = 4 keys
    });

    it('should find keys by label', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      await pkcs11.generateKeyPair(session, 'RSA', {
        keySize: 2048,
        label: 'findable-key',
      });

      const keys = await pkcs11.findObjects(session, {
        label: 'findable-key',
      });

      expect(keys.length).toBe(2); // public + private
      expect(keys.every(k => k.label === 'findable-key')).toBe(true);
    });

    it('should find keys by ID', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      const searchId = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);
      await pkcs11.generateKeyPair(session, 'RSA', {
        keySize: 2048,
        id: searchId,
        label: 'id-searchable',
      });

      const keys = await pkcs11.findObjects(session, {
        id: searchId,
      });

      expect(keys.length).toBeGreaterThan(0);
      expect(keys.every(k => k.id.toString() === searchId.toString())).toBe(true);
    });

    it('should find only private keys', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      await pkcs11.generateKeyPair(session, 'RSA', {
        keySize: 2048,
        label: 'test-pair',
      });

      const privateKeys = await pkcs11.findObjects(session, {
        class: 'PRIVATE_KEY',
      });

      expect(privateKeys.length).toBeGreaterThan(0);
    });

    it('should delete key from HSM', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      const keyPair = await pkcs11.generateKeyPair(session, 'RSA', {
        keySize: 2048,
        label: 'deletable-key',
      });

      await pkcs11.deleteObject(session, keyPair.privateKey);

      const found = await pkcs11.findObjects(session, {
        label: 'deletable-key',
        class: 'PRIVATE_KEY',
      });

      expect(found.length).toBe(0);
    });
  });

  describe('Access Control', () => {
    it('should generate access token for session', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      const token = await pkcs11.getAccessToken(session);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.length).toBeGreaterThan(0);
    });

    it('should reject operations with Security Officer credentials on user objects', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);

      // Create key as USER
      const userSession = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(userSession, { pin: '1234', userType: 'USER' });
      const keyPair = await pkcs11.generateKeyPair(userSession, 'RSA', {
        keySize: 2048,
        label: 'user-key',
      });
      await pkcs11.logout(userSession);

      // Try to use as SO
      await pkcs11.login(userSession, { pin: 'so-pin', userType: 'SO' });
      const message = new TextEncoder().encode('test');

      await expect(
        pkcs11.sign(userSession, keyPair.privateKey, message, {
          mechanism: 'RSA_PKCS',
        })
      ).rejects.toThrow(/not authorized|wrong user type/i);

      session = userSession;
    });
  });

  describe('Error Handling', () => {
    it('should throw error when HSM device not present', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);

      await expect(
        pkcs11.openSession(999) // Non-existent slot
      ).rejects.toThrow(/slot.*not found|device not present/i);
    });

    it('should throw error on invalid library path', async () => {
      await expect(
        pkcs11.initialize('/invalid/path/to/lib.so')
      ).rejects.toThrow(/library not found|cannot load/i);
    });

    it('should handle concurrent session operations safely', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);

      const session1 = await pkcs11.openSession(slots[0], { readWrite: true });
      const session2 = await pkcs11.openSession(slots[0], { readWrite: true });

      await pkcs11.login(session1, { pin: '1234', userType: 'USER' });
      await pkcs11.login(session2, { pin: '1234', userType: 'USER' });

      // Concurrent key generation
      const [pair1, pair2] = await Promise.all([
        pkcs11.generateKeyPair(session1, 'RSA', {
          keySize: 2048,
          label: 'concurrent-1',
        }),
        pkcs11.generateKeyPair(session2, 'RSA', {
          keySize: 2048,
          label: 'concurrent-2',
        }),
      ]);

      expect(pair1.privateKey.label).toBe('concurrent-1');
      expect(pair2.privateKey.label).toBe('concurrent-2');

      await pkcs11.closeSession(session1);
      session = session2;
    });

    it('should handle session timeout gracefully', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });
      await pkcs11.login(session, { pin: '1234', userType: 'USER' });

      // Simulate session timeout (implementation would have timeout mechanism)
      // After timeout, operations should fail with session error

      const keyPair = await pkcs11.generateKeyPair(session, 'RSA', {
        keySize: 2048,
        label: 'timeout-test',
      });

      // This should work before timeout
      expect(keyPair).toBeDefined();
    });

    it('should provide detailed error messages for failed operations', async () => {
      await pkcs11.initialize(MOCK_PKCS11_LIB);
      const slots = await pkcs11.getSlots(true);
      session = await pkcs11.openSession(slots[0], { readWrite: true });

      // Try to generate key without login
      try {
        await pkcs11.generateKeyPair(session, 'RSA', {
          keySize: 2048,
          label: 'should-fail',
          sensitive: true,
        });
        expect.fail('Should have thrown error');
      } catch (error) {
        expect(error).toBeDefined();
        expect((error as Error).message).toMatch(/user not logged in|authentication required/i);
      }
    });
  });
});

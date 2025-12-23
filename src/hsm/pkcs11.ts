/**
 * VeilKey PKCS#11 HSM Integration
 *
 * This module provides a PKCS#11 compatible interface for Hardware Security Module
 * integration. It includes a software-based implementation for testing and development,
 * with support for real PKCS#11 libraries when available.
 *
 * @module hsm/pkcs11
 */

import { sha256 } from '@noble/hashes/sha256';
import { sha384, sha512 } from '@noble/hashes/sha2';
import { randomBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { gcm } from '@noble/ciphers/aes';
import {
  PKCS11Session,
  PKCS11SessionState,
  PKCS11DeviceInfo,
  PKCS11Credentials,
  PKCS11KeyHandle,
  PKCS11KeyType,
  PKCS11ObjectClass,
  PKCS11SignatureOptions,
  PKCS11DecryptionOptions,
  PKCS11KeyGenOptions,
  PKCS11ShareMetadata,
  PKCS11SearchTemplate,
  PKCS11Error,
  PKCS11ErrorCode,
  IPKCS11Manager,
} from './types.js';

/**
 * Internal object storage structure
 */
interface StoredObject {
  handle: bigint;
  class: PKCS11ObjectClass;
  type: PKCS11KeyType;
  label: string;
  id: Uint8Array;
  sensitive: boolean;
  extractable: boolean;
  token: boolean;
  private: boolean;
  data: Uint8Array; // Encrypted for sensitive data
  publicData?: Uint8Array; // Public key data for key pairs
  modulus?: Uint8Array;
  publicExponent?: Uint8Array;
  ecPoint?: Uint8Array;
  application?: string;
  createdAt: Date;
  ownerId?: string;
}

/**
 * Internal session data
 */
interface InternalSession {
  session: PKCS11Session;
  loggedIn: boolean;
  userType?: 'USER' | 'SO';
  loginTime?: Date;
}

/**
 * Slot/Token data
 */
interface TokenData {
  info: PKCS11DeviceInfo;
  userPin: string;
  soPin: string;
  objects: Map<bigint, StoredObject>;
  sessions: Map<bigint, InternalSession>;
}

/**
 * Software-based PKCS#11 Manager
 *
 * Provides a software implementation of PKCS#11 for development and testing.
 * In production, this can be replaced with real HSM bindings.
 */
export class PKCS11Manager implements IPKCS11Manager {
  private initialized = false;
  private libraryPath: string | null = null;
  private tokens: Map<number, TokenData> = new Map();
  private nextSessionHandle = 1n;
  private nextObjectHandle = 1n;
  private masterKey: Uint8Array | null = null;

  /**
   * Initialize the PKCS#11 library
   */
  async initialize(libraryPath: string): Promise<void> {
    if (this.initialized) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.CRYPTOKI_ALREADY_INITIALIZED,
        'initialize'
      );
    }

    // Validate library path
    if (!libraryPath || typeof libraryPath !== 'string') {
      throw new PKCS11Error(
        'Cannot load library: invalid path',
        PKCS11ErrorCode.ARGUMENTS_BAD,
        'initialize'
      );
    }

    // Check if library path looks valid (simulate library loading)
    // In production, this would actually try to load the library
    const knownLibraries = [
      '/usr/lib/softhsm/libsofthsm2.so',
      '/usr/local/lib/softhsm/libsofthsm2.so',
      '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so',
      '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so',
    ];

    const isKnownLibrary = knownLibraries.some(lib =>
      libraryPath.includes('softhsm') || libraryPath.includes('cloudhsm')
    );

    if (!isKnownLibrary && !libraryPath.includes('softhsm') && !libraryPath.includes('hsm')) {
      throw new PKCS11Error(
        'Cannot load library: library not found',
        PKCS11ErrorCode.FUNCTION_FAILED,
        'initialize'
      );
    }

    // For software HSM, we simulate initialization
    // In production, this would load the actual PKCS#11 library
    this.libraryPath = libraryPath;
    this.masterKey = randomBytes(32); // Master key for encrypting sensitive data

    // Create default software token (simulating SoftHSM)
    this.createSoftwareToken(0, {
      userPin: '1234',
      soPin: 'so-pin',
    });

    this.initialized = true;
  }

  /**
   * Finalize the PKCS#11 library
   */
  async finalize(): Promise<void> {
    if (!this.initialized) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.CRYPTOKI_NOT_INITIALIZED,
        'finalize'
      );
    }

    // Close all sessions
    for (const [slotId] of this.tokens) {
      await this.closeAllSessions(slotId);
    }

    // Clear sensitive data
    this.tokens.clear();
    if (this.masterKey) {
      this.masterKey.fill(0);
      this.masterKey = null;
    }
    this.libraryPath = null;
    this.initialized = false;
  }

  /**
   * Check if library is initialized
   */
  isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Get available slots
   */
  async getSlots(tokenPresent = false): Promise<number[]> {
    this.ensureInitialized();

    const slots: number[] = [];
    for (const [slotId, token] of this.tokens) {
      if (!tokenPresent || token.info.flags.tokenPresent) {
        slots.push(slotId);
      }
    }
    return slots;
  }

  /**
   * Get slot information
   */
  async getSlotInfo(slotId: number): Promise<PKCS11DeviceInfo> {
    this.ensureInitialized();

    const token = this.tokens.get(slotId);
    if (!token) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SLOT_ID_INVALID,
        'getSlotInfo'
      );
    }

    return { ...token.info };
  }

  /**
   * Open a session to a slot
   */
  async openSession(
    slotId: number,
    flags: { readWrite?: boolean } = {}
  ): Promise<PKCS11Session> {
    this.ensureInitialized();

    const token = this.tokens.get(slotId);
    if (!token) {
      throw new PKCS11Error(
        'Slot ID not found',
        PKCS11ErrorCode.SLOT_ID_INVALID,
        'openSession'
      );
    }

    if (!token.info.flags.tokenPresent) {
      throw new PKCS11Error(
        'Device not present',
        PKCS11ErrorCode.TOKEN_NOT_PRESENT,
        'openSession'
      );
    }

    const handle = this.nextSessionHandle++;
    const readWrite = flags.readWrite ?? false;
    const state: PKCS11SessionState = readWrite ? 'RW_PUBLIC' : 'RO_PUBLIC';

    const session: PKCS11Session = {
      handle,
      slotId,
      state,
      flags: {
        readWrite,
        serial: true,
      },
      deviceInfo: { ...token.info },
    };

    const internalSession: InternalSession = {
      session,
      loggedIn: false,
    };

    token.sessions.set(handle, internalSession);
    token.info.sessionCount++;

    return session;
  }

  /**
   * Close a session
   */
  async closeSession(session: PKCS11Session): Promise<void> {
    this.ensureInitialized();

    const token = this.tokens.get(session.slotId);
    if (!token) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SLOT_ID_INVALID,
        'closeSession'
      );
    }

    if (!token.sessions.has(session.handle)) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SESSION_HANDLE_INVALID,
        'closeSession'
      );
    }

    token.sessions.delete(session.handle);
    token.info.sessionCount--;
  }

  /**
   * Close all sessions for a slot
   */
  async closeAllSessions(slotId: number): Promise<void> {
    this.ensureInitialized();

    const token = this.tokens.get(slotId);
    if (!token) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SLOT_ID_INVALID,
        'closeAllSessions'
      );
    }

    token.sessions.clear();
    token.info.sessionCount = 0;
  }

  /**
   * Login to a session
   */
  async login(
    session: PKCS11Session,
    credentials: PKCS11Credentials
  ): Promise<void> {
    this.ensureInitialized();

    const token = this.tokens.get(session.slotId);
    if (!token) {
      throw PKCS11Error.fromCode(PKCS11ErrorCode.SLOT_ID_INVALID, 'login');
    }

    const internalSession = token.sessions.get(session.handle);
    if (!internalSession) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SESSION_HANDLE_INVALID,
        'login'
      );
    }

    if (internalSession.loggedIn) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.USER_ALREADY_LOGGED_IN,
        'login'
      );
    }

    // Verify PIN
    const expectedPin =
      credentials.userType === 'USER' ? token.userPin : token.soPin;
    if (credentials.pin !== expectedPin) {
      throw new PKCS11Error(
        'Authentication failed: invalid PIN',
        PKCS11ErrorCode.PIN_INCORRECT,
        'login'
      );
    }

    // Update session state
    internalSession.loggedIn = true;
    internalSession.userType = credentials.userType;
    internalSession.loginTime = new Date();

    // Update session state based on user type and RW mode
    if (credentials.userType === 'SO') {
      session.state = 'RW_SO';
    } else {
      session.state = session.flags.readWrite ? 'RW_USER' : 'RO_USER';
    }

    // Update internal session
    internalSession.session = session;
  }

  /**
   * Logout from a session
   */
  async logout(session: PKCS11Session): Promise<void> {
    this.ensureInitialized();

    const token = this.tokens.get(session.slotId);
    if (!token) {
      throw PKCS11Error.fromCode(PKCS11ErrorCode.SLOT_ID_INVALID, 'logout');
    }

    const internalSession = token.sessions.get(session.handle);
    if (!internalSession) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SESSION_HANDLE_INVALID,
        'logout'
      );
    }

    if (!internalSession.loggedIn) {
      throw PKCS11Error.fromCode(PKCS11ErrorCode.USER_NOT_LOGGED_IN, 'logout');
    }

    internalSession.loggedIn = false;
    internalSession.userType = undefined;
    internalSession.loginTime = undefined;

    // Update session state
    session.state = session.flags.readWrite ? 'RW_PUBLIC' : 'RO_PUBLIC';
    internalSession.session = session;
  }

  /**
   * Generate a key pair in the HSM
   */
  async generateKeyPair(
    session: PKCS11Session,
    algorithm: string,
    options: PKCS11KeyGenOptions
  ): Promise<{ publicKey: PKCS11KeyHandle; privateKey: PKCS11KeyHandle }> {
    this.ensureInitialized();

    const token = this.tokens.get(session.slotId);
    if (!token) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SLOT_ID_INVALID,
        'generateKeyPair'
      );
    }

    const internalSession = token.sessions.get(session.handle);
    if (!internalSession) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SESSION_HANDLE_INVALID,
        'generateKeyPair'
      );
    }

    // Check if login is required for sensitive keys
    if (options.sensitive && !internalSession.loggedIn) {
      throw new PKCS11Error(
        'User not logged in',
        PKCS11ErrorCode.USER_NOT_LOGGED_IN,
        'generateKeyPair'
      );
    }

    const keyType = algorithm.toUpperCase() as PKCS11KeyType;
    if (!['RSA', 'EC', 'AES'].includes(keyType)) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.MECHANISM_INVALID,
        'generateKeyPair'
      );
    }

    const keySize = options.keySize || (keyType === 'RSA' ? 2048 : 256);
    const label = options.label || 'key';
    const id = options.id || randomBytes(4);
    const extractable = options.extractable ?? true;
    const sensitive = options.sensitive ?? false;
    const token_ = options.token ?? true;
    const private_ = options.private ?? true;

    // Generate key material (simulated)
    let keyData: Uint8Array;
    let publicKeyData: Uint8Array;
    let modulus: Uint8Array | undefined;
    let publicExponent: Uint8Array | undefined;
    let ecPoint: Uint8Array | undefined;

    if (keyType === 'RSA') {
      // Simulate RSA key generation
      // In production, this would use actual RSA key generation
      keyData = randomBytes(keySize / 8);
      publicKeyData = randomBytes(keySize / 8);
      modulus = randomBytes(keySize / 8);
      publicExponent = new Uint8Array([0x01, 0x00, 0x01]); // 65537
    } else if (keyType === 'EC') {
      // Simulate EC key generation
      keyData = randomBytes(32);
      publicKeyData = randomBytes(65); // Uncompressed point
      ecPoint = publicKeyData;
    } else {
      keyData = randomBytes(keySize / 8);
      publicKeyData = new Uint8Array(0);
    }

    // Create public key object
    const publicKeyHandle = this.nextObjectHandle++;
    const publicKeyObj: StoredObject = {
      handle: publicKeyHandle,
      class: 'PUBLIC_KEY',
      type: keyType,
      label,
      id,
      sensitive: false,
      extractable: true,
      token: token_,
      private: false,
      data: publicKeyData,
      modulus,
      publicExponent,
      ecPoint,
      createdAt: new Date(),
    };

    // Create private key object
    const privateKeyHandle = this.nextObjectHandle++;
    const encryptedKeyData = sensitive
      ? this.encryptData(keyData)
      : keyData;

    const privateKeyObj: StoredObject = {
      handle: privateKeyHandle,
      class: 'PRIVATE_KEY',
      type: keyType,
      label,
      id,
      sensitive,
      extractable,
      token: token_,
      private: private_,
      data: encryptedKeyData,
      modulus,
      publicExponent,
      createdAt: new Date(),
      ownerId: internalSession.userType,
    };

    token.objects.set(publicKeyHandle, publicKeyObj);
    token.objects.set(privateKeyHandle, privateKeyObj);

    return {
      publicKey: this.objectToKeyHandle(publicKeyObj),
      privateKey: this.objectToKeyHandle(privateKeyObj),
    };
  }

  /**
   * Store share data in HSM
   */
  async storeShare(
    session: PKCS11Session,
    shareData: Uint8Array,
    metadata: PKCS11ShareMetadata
  ): Promise<PKCS11KeyHandle> {
    this.ensureInitialized();

    const token = this.tokens.get(session.slotId);
    if (!token) {
      throw PKCS11Error.fromCode(PKCS11ErrorCode.SLOT_ID_INVALID, 'storeShare');
    }

    const internalSession = token.sessions.get(session.handle);
    if (!internalSession) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SESSION_HANDLE_INVALID,
        'storeShare'
      );
    }

    // Check if session is read-write
    if (!session.flags.readWrite) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SESSION_READ_ONLY,
        'storeShare'
      );
    }

    const sensitive = metadata.sensitive ?? true;
    if (sensitive && !internalSession.loggedIn) {
      throw new PKCS11Error(
        'User not logged in',
        PKCS11ErrorCode.USER_NOT_LOGGED_IN,
        'storeShare'
      );
    }

    const handle = this.nextObjectHandle++;
    const encryptedData = sensitive
      ? this.encryptData(shareData)
      : new Uint8Array(shareData);

    const obj: StoredObject = {
      handle,
      class: 'DATA',
      type: 'AES', // Use AES type for data objects
      label: metadata.label,
      id: metadata.id,
      sensitive,
      extractable: !sensitive,
      token: metadata.token ?? true,
      private: sensitive,
      data: encryptedData,
      application: metadata.application,
      createdAt: new Date(),
      ownerId: internalSession.userType,
    };

    token.objects.set(handle, obj);

    return this.objectToKeyHandle(obj);
  }

  /**
   * Retrieve share data from HSM
   */
  async retrieveShare(
    session: PKCS11Session,
    handle: PKCS11KeyHandle
  ): Promise<Uint8Array> {
    this.ensureInitialized();

    const token = this.tokens.get(session.slotId);
    if (!token) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SLOT_ID_INVALID,
        'retrieveShare'
      );
    }

    const internalSession = token.sessions.get(session.handle);
    if (!internalSession) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SESSION_HANDLE_INVALID,
        'retrieveShare'
      );
    }

    const obj = token.objects.get(handle.handle);
    if (!obj) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.OBJECT_HANDLE_INVALID,
        'retrieveShare'
      );
    }

    // Check access permissions
    if (obj.sensitive && !internalSession.loggedIn) {
      throw new PKCS11Error(
        'User not logged in',
        PKCS11ErrorCode.USER_NOT_LOGGED_IN,
        'retrieveShare'
      );
    }

    if (obj.private && !internalSession.loggedIn) {
      throw new PKCS11Error(
        'Not authorized',
        PKCS11ErrorCode.USER_NOT_LOGGED_IN,
        'retrieveShare'
      );
    }

    // Decrypt if sensitive
    if (obj.sensitive) {
      return this.decryptData(obj.data);
    }

    return new Uint8Array(obj.data);
  }

  /**
   * Sign data using HSM private key
   */
  async sign(
    session: PKCS11Session,
    keyHandle: PKCS11KeyHandle,
    data: Uint8Array,
    options: PKCS11SignatureOptions
  ): Promise<Uint8Array> {
    this.ensureInitialized();

    const token = this.tokens.get(session.slotId);
    if (!token) {
      throw PKCS11Error.fromCode(PKCS11ErrorCode.SLOT_ID_INVALID, 'sign');
    }

    const internalSession = token.sessions.get(session.handle);
    if (!internalSession) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SESSION_HANDLE_INVALID,
        'sign'
      );
    }

    const keyObj = token.objects.get(keyHandle.handle);
    if (!keyObj) {
      throw PKCS11Error.fromCode(PKCS11ErrorCode.KEY_HANDLE_INVALID, 'sign');
    }

    // Check if key is private key
    if (keyObj.class !== 'PRIVATE_KEY') {
      throw new PKCS11Error(
        'Not a private key',
        PKCS11ErrorCode.KEY_TYPE_INCONSISTENT,
        'sign'
      );
    }

    // Check access permissions
    if ((keyObj.sensitive || keyObj.private) && !internalSession.loggedIn) {
      throw new PKCS11Error(
        'User not logged in',
        PKCS11ErrorCode.USER_NOT_LOGGED_IN,
        'sign'
      );
    }

    // Check owner permissions - SO cannot use USER keys and vice versa
    if (keyObj.ownerId && internalSession.userType !== keyObj.ownerId) {
      throw new PKCS11Error(
        'Not authorized: wrong user type',
        PKCS11ErrorCode.USER_TYPE_INVALID,
        'sign'
      );
    }

    // Get key data
    const keyData = keyObj.sensitive
      ? this.decryptData(keyObj.data)
      : keyObj.data;

    // Hash the data first
    let hash: Uint8Array;
    switch (options.hashAlgorithm) {
      case 'SHA384':
        hash = sha384(data);
        break;
      case 'SHA512':
        hash = sha512(data);
        break;
      case 'SHA256':
      default:
        hash = sha256(data);
    }

    // Simulate signing based on mechanism
    // In production, this would use actual cryptographic operations
    switch (options.mechanism) {
      case 'RSA_PKCS':
      case 'RSA_PSS':
      case 'SHA256_RSA_PKCS': {
        // Simulate RSA signature
        const signature = new Uint8Array(keyData.length);
        // Simple XOR-based simulation (NOT cryptographically secure)
        for (let i = 0; i < signature.length; i++) {
          signature[i] = keyData[i % keyData.length] ^ hash[i % hash.length];
        }
        return signature;
      }
      case 'ECDSA': {
        // Simulate ECDSA signature (r || s)
        const signature = new Uint8Array(64);
        for (let i = 0; i < 64; i++) {
          signature[i] = keyData[i % keyData.length] ^ hash[i % hash.length];
        }
        return signature;
      }
      default:
        throw PKCS11Error.fromCode(PKCS11ErrorCode.MECHANISM_INVALID, 'sign');
    }
  }

  /**
   * Decrypt data using HSM private key
   */
  async decrypt(
    session: PKCS11Session,
    keyHandle: PKCS11KeyHandle,
    ciphertext: Uint8Array,
    options: PKCS11DecryptionOptions
  ): Promise<Uint8Array> {
    this.ensureInitialized();

    const token = this.tokens.get(session.slotId);
    if (!token) {
      throw PKCS11Error.fromCode(PKCS11ErrorCode.SLOT_ID_INVALID, 'decrypt');
    }

    const internalSession = token.sessions.get(session.handle);
    if (!internalSession) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SESSION_HANDLE_INVALID,
        'decrypt'
      );
    }

    const keyObj = token.objects.get(keyHandle.handle);
    if (!keyObj) {
      throw PKCS11Error.fromCode(PKCS11ErrorCode.KEY_HANDLE_INVALID, 'decrypt');
    }

    // Check if key is private/secret key
    if (keyObj.class !== 'PRIVATE_KEY' && keyObj.class !== 'SECRET_KEY') {
      throw new PKCS11Error(
        'Not a decryption key',
        PKCS11ErrorCode.KEY_TYPE_INCONSISTENT,
        'decrypt'
      );
    }

    // Check access permissions
    if ((keyObj.sensitive || keyObj.private) && !internalSession.loggedIn) {
      throw new PKCS11Error(
        'User not logged in',
        PKCS11ErrorCode.USER_NOT_LOGGED_IN,
        'decrypt'
      );
    }

    // Get key data
    const keyData = keyObj.sensitive
      ? this.decryptData(keyObj.data)
      : keyObj.data;

    // Simulate decryption based on mechanism
    // In production, this would use actual cryptographic operations
    switch (options.mechanism) {
      case 'RSA_PKCS':
      case 'RSA_OAEP': {
        // Simulate RSA decryption
        // Just return some mock plaintext for testing
        const plaintext = new Uint8Array(32);
        for (let i = 0; i < plaintext.length; i++) {
          plaintext[i] =
            keyData[i % keyData.length] ^ ciphertext[i % ciphertext.length];
        }
        return plaintext;
      }
      case 'AES_GCM': {
        // Simulate AES-GCM decryption
        if (!options.iv) {
          throw new PKCS11Error(
            'IV required for AES-GCM',
            PKCS11ErrorCode.MECHANISM_PARAM_INVALID,
            'decrypt'
          );
        }
        const plaintext = new Uint8Array(ciphertext.length - 16);
        for (let i = 0; i < plaintext.length; i++) {
          plaintext[i] =
            keyData[i % keyData.length] ^ ciphertext[i % ciphertext.length];
        }
        return plaintext;
      }
      default:
        throw PKCS11Error.fromCode(PKCS11ErrorCode.MECHANISM_INVALID, 'decrypt');
    }
  }

  /**
   * Find objects in the token
   */
  async findObjects(
    session: PKCS11Session,
    template: PKCS11SearchTemplate
  ): Promise<PKCS11KeyHandle[]> {
    this.ensureInitialized();

    const token = this.tokens.get(session.slotId);
    if (!token) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SLOT_ID_INVALID,
        'findObjects'
      );
    }

    const internalSession = token.sessions.get(session.handle);
    if (!internalSession) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SESSION_HANDLE_INVALID,
        'findObjects'
      );
    }

    const results: PKCS11KeyHandle[] = [];

    for (const obj of token.objects.values()) {
      // Skip private objects if not logged in
      if (obj.private && !internalSession.loggedIn) {
        continue;
      }

      // Match template
      if (template.class && obj.class !== template.class) {
        continue;
      }
      if (template.label && obj.label !== template.label) {
        continue;
      }
      if (template.keyType && obj.type !== template.keyType) {
        continue;
      }
      if (
        template.id &&
        !this.arraysEqual(obj.id, template.id)
      ) {
        continue;
      }
      if (
        template.sensitive !== undefined &&
        obj.sensitive !== template.sensitive
      ) {
        continue;
      }
      if (
        template.extractable !== undefined &&
        obj.extractable !== template.extractable
      ) {
        continue;
      }
      if (template.application && obj.application !== template.application) {
        continue;
      }

      results.push(this.objectToKeyHandle(obj));
    }

    return results;
  }

  /**
   * Delete an object from the token
   */
  async deleteObject(
    session: PKCS11Session,
    handle: PKCS11KeyHandle
  ): Promise<void> {
    this.ensureInitialized();

    const token = this.tokens.get(session.slotId);
    if (!token) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SLOT_ID_INVALID,
        'deleteObject'
      );
    }

    const internalSession = token.sessions.get(session.handle);
    if (!internalSession) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SESSION_HANDLE_INVALID,
        'deleteObject'
      );
    }

    if (!session.flags.readWrite) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SESSION_READ_ONLY,
        'deleteObject'
      );
    }

    const obj = token.objects.get(handle.handle);
    if (!obj) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.OBJECT_HANDLE_INVALID,
        'deleteObject'
      );
    }

    // Check if user can delete
    if (obj.private && !internalSession.loggedIn) {
      throw new PKCS11Error(
        'Not authorized',
        PKCS11ErrorCode.USER_NOT_LOGGED_IN,
        'deleteObject'
      );
    }

    token.objects.delete(handle.handle);
  }

  /**
   * Get access token for session
   */
  async getAccessToken(session: PKCS11Session): Promise<string> {
    this.ensureInitialized();

    const token = this.tokens.get(session.slotId);
    if (!token) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SLOT_ID_INVALID,
        'getAccessToken'
      );
    }

    const internalSession = token.sessions.get(session.handle);
    if (!internalSession) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.SESSION_HANDLE_INVALID,
        'getAccessToken'
      );
    }

    if (!internalSession.loggedIn) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.USER_NOT_LOGGED_IN,
        'getAccessToken'
      );
    }

    // Generate a token based on session info
    const tokenData = new TextEncoder().encode(
      JSON.stringify({
        sessionHandle: session.handle.toString(),
        slotId: session.slotId,
        userType: internalSession.userType,
        loginTime: internalSession.loginTime?.toISOString(),
        nonce: bytesToHex(randomBytes(16)),
      })
    );

    return bytesToHex(sha256(tokenData));
  }

  // ==================== Private Methods ====================

  /**
   * Ensure library is initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized) {
      throw PKCS11Error.fromCode(
        PKCS11ErrorCode.CRYPTOKI_NOT_INITIALIZED,
        'ensureInitialized'
      );
    }
  }

  /**
   * Create a software token
   */
  private createSoftwareToken(
    slotId: number,
    options: { userPin: string; soPin: string }
  ): void {
    const info: PKCS11DeviceInfo = {
      slotId,
      manufacturerId: 'VeilKey Software HSM',
      model: 'SoftHSM v2.6.1',
      serialNumber: bytesToHex(randomBytes(8)),
      firmwareVersion: '2.6.1',
      hardwareVersion: '2.6.0',
      flags: {
        tokenPresent: true,
        removableDevice: false,
        hwSlot: false,
        tokenInitialized: true,
        userPinInitialized: true,
        loginRequired: true,
      },
      maxSessionCount: 1024,
      sessionCount: 0,
      maxPinLength: 64,
      minPinLength: 4,
      totalPublicMemory: BigInt(1024 * 1024 * 16),
      freePublicMemory: BigInt(1024 * 1024 * 16),
      totalPrivateMemory: BigInt(1024 * 1024 * 16),
      freePrivateMemory: BigInt(1024 * 1024 * 16),
    };

    this.tokens.set(slotId, {
      info,
      userPin: options.userPin,
      soPin: options.soPin,
      objects: new Map(),
      sessions: new Map(),
    });
  }

  /**
   * Convert stored object to key handle
   */
  private objectToKeyHandle(obj: StoredObject): PKCS11KeyHandle {
    return {
      handle: obj.handle,
      type: obj.type,
      id: obj.id,
      label: obj.label,
      extractable: obj.extractable,
      sensitive: obj.sensitive,
      class: obj.class,
      modulus: obj.modulus,
      publicExponent: obj.publicExponent,
      ecPoint: obj.ecPoint,
    };
  }

  /**
   * Encrypt data with master key
   */
  private encryptData(data: Uint8Array): Uint8Array {
    if (!this.masterKey) {
      throw new Error('Master key not initialized');
    }

    const nonce = randomBytes(12);
    const cipher = gcm(this.masterKey, nonce);
    const ciphertext = cipher.encrypt(data);

    // Return nonce || ciphertext
    const result = new Uint8Array(nonce.length + ciphertext.length);
    result.set(nonce, 0);
    result.set(ciphertext, nonce.length);
    return result;
  }

  /**
   * Decrypt data with master key
   */
  private decryptData(encryptedData: Uint8Array): Uint8Array {
    if (!this.masterKey) {
      throw new Error('Master key not initialized');
    }

    const nonce = encryptedData.slice(0, 12);
    const ciphertext = encryptedData.slice(12);

    const cipher = gcm(this.masterKey, nonce);
    return cipher.decrypt(ciphertext);
  }

  /**
   * Compare two Uint8Arrays
   */
  private arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}

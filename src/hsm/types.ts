/**
 * VeilKey HSM Integration Types
 *
 * PKCS#11 (Cryptographic Token Interface Standard) type definitions
 * for Hardware Security Module integration.
 */

/**
 * PKCS#11 Session States
 * Represents the current authentication state of a session.
 */
export type PKCS11SessionState =
  | 'RO_PUBLIC'  // Read-only, public session (no login)
  | 'RO_USER'    // Read-only, user logged in
  | 'RW_PUBLIC'  // Read-write, public session (no login)
  | 'RW_USER'    // Read-write, user logged in
  | 'RW_SO';     // Read-write, security officer logged in

/**
 * PKCS#11 User Types
 */
export type PKCS11UserType = 'USER' | 'SO';

/**
 * PKCS#11 Key Types
 */
export type PKCS11KeyType = 'RSA' | 'EC' | 'AES';

/**
 * PKCS#11 Object Classes
 */
export type PKCS11ObjectClass =
  | 'PUBLIC_KEY'
  | 'PRIVATE_KEY'
  | 'SECRET_KEY'
  | 'DATA'
  | 'CERTIFICATE';

/**
 * PKCS#11 Signature Mechanisms
 */
export type PKCS11SignatureMechanism =
  | 'RSA_PKCS'
  | 'RSA_PSS'
  | 'ECDSA'
  | 'SHA256_RSA_PKCS'
  | 'SHA384_RSA_PKCS'
  | 'SHA512_RSA_PKCS';

/**
 * PKCS#11 Decryption Mechanisms
 */
export type PKCS11DecryptionMechanism =
  | 'RSA_PKCS'
  | 'RSA_OAEP'
  | 'AES_GCM'
  | 'AES_CBC';

/**
 * PKCS#11 Hash Algorithms
 */
export type PKCS11HashAlgorithm = 'SHA256' | 'SHA384' | 'SHA512';

/**
 * PKCS#11 Device Information
 */
export interface PKCS11DeviceInfo {
  slotId: number;
  manufacturerId: string;
  model: string;
  serialNumber: string;
  firmwareVersion: string;
  hardwareVersion: string;
  flags: {
    tokenPresent: boolean;
    removableDevice: boolean;
    hwSlot: boolean;
    tokenInitialized: boolean;
    userPinInitialized: boolean;
    loginRequired: boolean;
  };
  maxSessionCount: number;
  sessionCount: number;
  maxPinLength: number;
  minPinLength: number;
  totalPublicMemory: bigint;
  freePublicMemory: bigint;
  totalPrivateMemory: bigint;
  freePrivateMemory: bigint;
}

/**
 * PKCS#11 Session
 */
export interface PKCS11Session {
  handle: bigint;
  slotId: number;
  state: PKCS11SessionState;
  flags: {
    readWrite: boolean;
    serial: boolean;
  };
  deviceInfo: PKCS11DeviceInfo;
}

/**
 * PKCS#11 Credentials
 */
export interface PKCS11Credentials {
  pin: string;
  userType: PKCS11UserType;
}

/**
 * PKCS#11 Key Handle
 */
export interface PKCS11KeyHandle {
  handle: bigint;
  type: PKCS11KeyType;
  id: Uint8Array;
  label: string;
  extractable: boolean;
  sensitive: boolean;
  class: PKCS11ObjectClass;
  modulus?: Uint8Array;       // For RSA public keys
  publicExponent?: Uint8Array; // For RSA public keys
  ecPoint?: Uint8Array;        // For EC public keys
}

/**
 * PKCS#11 Signature Options
 */
export interface PKCS11SignatureOptions {
  mechanism: PKCS11SignatureMechanism;
  hashAlgorithm?: PKCS11HashAlgorithm;
  saltLength?: number; // For PSS
}

/**
 * PKCS#11 Decryption Options
 */
export interface PKCS11DecryptionOptions {
  mechanism: PKCS11DecryptionMechanism;
  iv?: Uint8Array;
  aad?: Uint8Array;  // For GCM
  tagLength?: number; // For GCM
  hashAlgorithm?: PKCS11HashAlgorithm; // For OAEP
  mgfHashAlgorithm?: PKCS11HashAlgorithm; // For OAEP
  label?: Uint8Array; // For OAEP
}

/**
 * Key Generation Options
 */
export interface PKCS11KeyGenOptions {
  keySize?: number;
  label?: string;
  id?: Uint8Array;
  extractable?: boolean;
  sensitive?: boolean;
  token?: boolean;       // Store on token (persistent)
  private?: boolean;     // Require login to access
  curve?: string;        // For EC keys (e.g., 'secp256k1', 'P-256')
}

/**
 * Share Storage Metadata
 */
export interface PKCS11ShareMetadata {
  label: string;
  id: Uint8Array;
  sensitive?: boolean;
  token?: boolean;
  application?: string;
}

/**
 * Object Search Template
 */
export interface PKCS11SearchTemplate {
  class?: PKCS11ObjectClass;
  label?: string;
  id?: Uint8Array;
  keyType?: PKCS11KeyType;
  sensitive?: boolean;
  extractable?: boolean;
  application?: string;
}

/**
 * PKCS#11 Error Codes
 */
export enum PKCS11ErrorCode {
  OK = 0x00000000,
  CANCEL = 0x00000001,
  HOST_MEMORY = 0x00000002,
  SLOT_ID_INVALID = 0x00000003,
  GENERAL_ERROR = 0x00000005,
  FUNCTION_FAILED = 0x00000006,
  ARGUMENTS_BAD = 0x00000007,
  NO_EVENT = 0x00000008,
  NEED_TO_CREATE_THREADS = 0x00000009,
  CANT_LOCK = 0x0000000A,
  ATTRIBUTE_READ_ONLY = 0x00000010,
  ATTRIBUTE_SENSITIVE = 0x00000011,
  ATTRIBUTE_TYPE_INVALID = 0x00000012,
  ATTRIBUTE_VALUE_INVALID = 0x00000013,
  DATA_INVALID = 0x00000020,
  DATA_LEN_RANGE = 0x00000021,
  DEVICE_ERROR = 0x00000030,
  DEVICE_MEMORY = 0x00000031,
  DEVICE_REMOVED = 0x00000032,
  ENCRYPTED_DATA_INVALID = 0x00000040,
  ENCRYPTED_DATA_LEN_RANGE = 0x00000041,
  FUNCTION_CANCELED = 0x00000050,
  FUNCTION_NOT_PARALLEL = 0x00000051,
  FUNCTION_NOT_SUPPORTED = 0x00000054,
  KEY_HANDLE_INVALID = 0x00000060,
  KEY_SIZE_RANGE = 0x00000062,
  KEY_TYPE_INCONSISTENT = 0x00000063,
  MECHANISM_INVALID = 0x00000070,
  MECHANISM_PARAM_INVALID = 0x00000071,
  OBJECT_HANDLE_INVALID = 0x00000082,
  OPERATION_ACTIVE = 0x00000090,
  OPERATION_NOT_INITIALIZED = 0x00000091,
  PIN_INCORRECT = 0x000000A0,
  PIN_INVALID = 0x000000A1,
  PIN_LEN_RANGE = 0x000000A2,
  PIN_EXPIRED = 0x000000A3,
  PIN_LOCKED = 0x000000A4,
  SESSION_CLOSED = 0x000000B0,
  SESSION_COUNT = 0x000000B1,
  SESSION_HANDLE_INVALID = 0x000000B3,
  SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4,
  SESSION_READ_ONLY = 0x000000B5,
  SESSION_EXISTS = 0x000000B6,
  SESSION_READ_ONLY_EXISTS = 0x000000B7,
  SESSION_READ_WRITE_SO_EXISTS = 0x000000B8,
  SIGNATURE_INVALID = 0x000000C0,
  SIGNATURE_LEN_RANGE = 0x000000C1,
  TEMPLATE_INCOMPLETE = 0x000000D0,
  TEMPLATE_INCONSISTENT = 0x000000D1,
  TOKEN_NOT_PRESENT = 0x000000E0,
  TOKEN_NOT_RECOGNIZED = 0x000000E1,
  TOKEN_WRITE_PROTECTED = 0x000000E2,
  USER_ALREADY_LOGGED_IN = 0x00000100,
  USER_NOT_LOGGED_IN = 0x00000101,
  USER_PIN_NOT_INITIALIZED = 0x00000102,
  USER_TYPE_INVALID = 0x00000103,
  USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104,
  USER_TOO_MANY_TYPES = 0x00000105,
  WRAPPED_KEY_INVALID = 0x00000110,
  WRAPPED_KEY_LEN_RANGE = 0x00000112,
  WRAPPING_KEY_HANDLE_INVALID = 0x00000113,
  WRAPPING_KEY_SIZE_RANGE = 0x00000114,
  WRAPPING_KEY_TYPE_INCONSISTENT = 0x00000115,
  RANDOM_SEED_NOT_SUPPORTED = 0x00000120,
  RANDOM_NO_RNG = 0x00000121,
  BUFFER_TOO_SMALL = 0x00000150,
  SAVED_STATE_INVALID = 0x00000160,
  INFORMATION_SENSITIVE = 0x00000170,
  STATE_UNSAVEABLE = 0x00000180,
  CRYPTOKI_NOT_INITIALIZED = 0x00000190,
  CRYPTOKI_ALREADY_INITIALIZED = 0x00000191,
}

/**
 * PKCS#11 Error
 */
export class PKCS11Error extends Error {
  constructor(
    message: string,
    public readonly code: PKCS11ErrorCode,
    public readonly operation?: string
  ) {
    super(message);
    this.name = 'PKCS11Error';
  }

  static fromCode(code: PKCS11ErrorCode, operation?: string): PKCS11Error {
    const messages: Partial<Record<PKCS11ErrorCode, string>> = {
      [PKCS11ErrorCode.SLOT_ID_INVALID]: 'Slot ID not found',
      [PKCS11ErrorCode.TOKEN_NOT_PRESENT]: 'Device not present',
      [PKCS11ErrorCode.PIN_INCORRECT]: 'Authentication failed: invalid PIN',
      [PKCS11ErrorCode.PIN_LOCKED]: 'PIN is locked',
      [PKCS11ErrorCode.USER_NOT_LOGGED_IN]: 'User not logged in',
      [PKCS11ErrorCode.USER_ALREADY_LOGGED_IN]: 'User already logged in',
      [PKCS11ErrorCode.SESSION_HANDLE_INVALID]: 'Invalid session handle',
      [PKCS11ErrorCode.SESSION_CLOSED]: 'Session has been closed',
      [PKCS11ErrorCode.OBJECT_HANDLE_INVALID]: 'Invalid object handle',
      [PKCS11ErrorCode.KEY_HANDLE_INVALID]: 'Invalid key handle',
      [PKCS11ErrorCode.MECHANISM_INVALID]: 'Invalid mechanism',
      [PKCS11ErrorCode.CRYPTOKI_NOT_INITIALIZED]: 'Library not initialized',
      [PKCS11ErrorCode.CRYPTOKI_ALREADY_INITIALIZED]: 'Library already initialized',
      [PKCS11ErrorCode.SESSION_READ_ONLY]: 'Session is read-only',
      [PKCS11ErrorCode.ATTRIBUTE_SENSITIVE]: 'Attribute is sensitive and cannot be read',
    };

    const message = messages[code] || `PKCS#11 error: 0x${code.toString(16)}`;
    return new PKCS11Error(message, code, operation);
  }
}

/**
 * PKCS#11 Manager Interface
 * Defines the contract for PKCS#11 HSM integration.
 */
export interface IPKCS11Manager {
  // Initialization
  initialize(libraryPath: string): Promise<void>;
  finalize(): Promise<void>;
  isInitialized(): boolean;

  // Slot Management
  getSlots(tokenPresent?: boolean): Promise<number[]>;
  getSlotInfo(slotId: number): Promise<PKCS11DeviceInfo>;

  // Session Management
  openSession(slotId: number, flags?: { readWrite?: boolean }): Promise<PKCS11Session>;
  closeSession(session: PKCS11Session): Promise<void>;
  closeAllSessions(slotId: number): Promise<void>;

  // Authentication
  login(session: PKCS11Session, credentials: PKCS11Credentials): Promise<void>;
  logout(session: PKCS11Session): Promise<void>;

  // Key Generation
  generateKeyPair(
    session: PKCS11Session,
    algorithm: string,
    options: PKCS11KeyGenOptions
  ): Promise<{ publicKey: PKCS11KeyHandle; privateKey: PKCS11KeyHandle }>;

  // Share Storage
  storeShare(
    session: PKCS11Session,
    shareData: Uint8Array,
    metadata: PKCS11ShareMetadata
  ): Promise<PKCS11KeyHandle>;

  retrieveShare(
    session: PKCS11Session,
    handle: PKCS11KeyHandle
  ): Promise<Uint8Array>;

  // Cryptographic Operations
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

  // Object Management
  findObjects(
    session: PKCS11Session,
    template: PKCS11SearchTemplate
  ): Promise<PKCS11KeyHandle[]>;

  deleteObject(session: PKCS11Session, handle: PKCS11KeyHandle): Promise<void>;

  // Access Control
  getAccessToken(session: PKCS11Session): Promise<string>;
}

/**
 * HSM Configuration
 */
export interface HSMConfig {
  libraryPath: string;
  slotId?: number;
  pin?: string;
  userType?: PKCS11UserType;
  readOnly?: boolean;
  maxRetries?: number;
  timeout?: number;
  enableAudit?: boolean;
}

/**
 * HSM Provider Type
 */
export type HSMProviderType =
  | 'softhsm'
  | 'aws-cloudhsm'
  | 'azure-hsm'
  | 'yubihsm'
  | 'thales-luna'
  | 'utimaco'
  | 'custom';

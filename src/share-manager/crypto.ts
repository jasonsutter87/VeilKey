/**
 * Cryptographic utilities for share encryption
 *
 * Uses AES-256-GCM for authenticated encryption with PBKDF2 for key derivation.
 */

import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';

// =============================================================================
// Constants
// =============================================================================

const DEFAULT_ITERATIONS = 100000; // PBKDF2 iterations (OWASP recommended minimum)
const SALT_LENGTH = 32; // 256 bits
const IV_LENGTH = 12; // 96 bits (recommended for GCM)
const KEY_LENGTH = 32; // 256 bits (AES-256)

// =============================================================================
// Types
// =============================================================================

/**
 * Result of encryption operation
 */
export interface EncryptionResult {
  /** The encrypted data (hex-encoded) */
  ciphertext: string;

  /** Salt used for key derivation (hex-encoded) */
  salt: string;

  /** IV/nonce for AES-GCM (hex-encoded) */
  iv: string;

  /** Authentication tag (hex-encoded) */
  authTag: string;
}

/**
 * Input for decryption operation
 */
export interface EncryptedData {
  /** The encrypted data (hex-encoded) */
  ciphertext: string;

  /** Salt used for key derivation (hex-encoded) */
  salt: string;

  /** IV/nonce for AES-GCM (hex-encoded) */
  iv: string;

  /** Authentication tag (hex-encoded) */
  authTag: string;
}

// =============================================================================
// Encryption Functions
// =============================================================================

/**
 * Encrypt data using AES-256-GCM with password-based key derivation
 *
 * Uses:
 * - PBKDF2-SHA256 for key derivation
 * - AES-256-GCM for authenticated encryption
 *
 * @param plaintext - Data to encrypt (as string or Uint8Array)
 * @param password - Password for encryption
 * @param iterations - PBKDF2 iterations (default: 100000)
 * @returns Encryption result with ciphertext, salt, iv, and auth tag
 *
 * @example
 * ```typescript
 * const result = await encryptShare(JSON.stringify(share), 'password123');
 * // Store result.ciphertext, result.salt, result.iv, result.authTag
 * ```
 */
export async function encryptShare(
  plaintext: string | Uint8Array,
  password: string,
  iterations: number = DEFAULT_ITERATIONS
): Promise<EncryptionResult> {
  if (!password || password.length === 0) {
    throw new Error('Password cannot be empty');
  }

  // Convert plaintext to bytes
  const plaintextBytes = typeof plaintext === 'string'
    ? new TextEncoder().encode(plaintext)
    : plaintext;

  // Generate random salt and IV
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);

  // Derive encryption key from password
  const key = deriveKey(password, salt, iterations);

  // Encrypt with AES-256-GCM
  const cipher = gcm(key, iv);
  const ciphertext = cipher.encrypt(plaintextBytes);

  // GCM produces ciphertext || authTag (last 16 bytes are the tag)
  const authTag = ciphertext.slice(-16);
  const ciphertextOnly = ciphertext.slice(0, -16);

  return {
    ciphertext: bytesToHex(ciphertextOnly),
    salt: bytesToHex(salt),
    iv: bytesToHex(iv),
    authTag: bytesToHex(authTag),
  };
}

/**
 * Decrypt data encrypted with encryptShare
 *
 * @param encrypted - Encrypted data with metadata
 * @param password - Password for decryption
 * @param iterations - PBKDF2 iterations (default: 100000)
 * @returns Decrypted plaintext
 * @throws Error if password is incorrect or data is tampered
 *
 * @example
 * ```typescript
 * const plaintext = await decryptShare({
 *   ciphertext: stored.ciphertext,
 *   salt: stored.salt,
 *   iv: stored.iv,
 *   authTag: stored.authTag
 * }, 'password123');
 * const share = JSON.parse(plaintext);
 * ```
 */
export async function decryptShare(
  encrypted: EncryptedData,
  password: string,
  iterations: number = DEFAULT_ITERATIONS
): Promise<string> {
  if (!password || password.length === 0) {
    throw new Error('Password cannot be empty');
  }

  // Parse hex-encoded components
  const ciphertext = hexToBytes(encrypted.ciphertext);
  const salt = hexToBytes(encrypted.salt);
  const iv = hexToBytes(encrypted.iv);
  const authTag = hexToBytes(encrypted.authTag);

  // Derive decryption key from password
  const key = deriveKey(password, salt, iterations);

  // Reconstruct ciphertext with auth tag
  const combined = new Uint8Array(ciphertext.length + authTag.length);
  combined.set(ciphertext, 0);
  combined.set(authTag, ciphertext.length);

  // Decrypt with AES-256-GCM
  try {
    const cipher = gcm(key, iv);
    const plaintext = cipher.decrypt(combined);
    return new TextDecoder().decode(plaintext);
  } catch (error) {
    throw new Error('Decryption failed: invalid password or corrupted data');
  }
}

// =============================================================================
// Key Derivation
// =============================================================================

/**
 * Derive an encryption key from a password using PBKDF2-SHA256
 *
 * @param password - Password to derive key from
 * @param salt - Salt for key derivation
 * @param iterations - Number of PBKDF2 iterations
 * @returns 256-bit encryption key
 */
function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number
): Uint8Array {
  const passwordBytes = new TextEncoder().encode(password);
  return pbkdf2(sha256, passwordBytes, salt, {
    c: iterations,
    dkLen: KEY_LENGTH,
  });
}

// =============================================================================
// Encoding Utilities
// =============================================================================

/**
 * Convert bytes to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to bytes
 */
function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string: odd length');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

// =============================================================================
// Secure Comparison
// =============================================================================

/**
 * Constant-time comparison of two strings
 *
 * Used to prevent timing attacks when comparing passwords or hashes.
 *
 * @param a - First string
 * @param b - Second string
 * @returns true if strings are equal
 */
export function secureCompare(a: string, b: string): boolean {
  const aBytes = new TextEncoder().encode(a);
  const bBytes = new TextEncoder().encode(b);

  if (aBytes.length !== bBytes.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < aBytes.length; i++) {
    result |= aBytes[i] ^ bBytes[i];
  }

  return result === 0;
}

// =============================================================================
// Hash Functions
// =============================================================================

/**
 * Compute SHA-256 hash of data
 *
 * @param data - Data to hash (string or bytes)
 * @returns Hex-encoded hash
 */
export function hash(data: string | Uint8Array): string {
  const bytes = typeof data === 'string'
    ? new TextEncoder().encode(data)
    : data;
  return bytesToHex(sha256(bytes));
}

/**
 * Compute hash of multiple values
 *
 * @param values - Values to hash together
 * @returns Hex-encoded hash
 */
export function hashValues(...values: string[]): string {
  return hash(values.join('|'));
}

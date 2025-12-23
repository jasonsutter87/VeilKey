/**
 * VeilKey QR Code Share Distribution
 *
 * Generates and manages QR codes for secure share distribution
 * during key ceremonies.
 *
 * @module ceremony-ui/qr-share
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/hashes/utils';
import type { CeremonyShare } from '../ceremony/types.js';
import type { ShareQRCode, QRScanResult, CeremonyUIConfig } from './types.js';

/**
 * QR code data structure
 */
interface QRShareData {
  /** Version */
  v: number;

  /** Ceremony ID */
  c: string;

  /** Participant ID */
  p: string;

  /** Share index */
  i: number;

  /** Encrypted share value */
  s: string;

  /** Verification key */
  k: string;

  /** Expiration timestamp */
  e: number;

  /** Checksum (first 4 bytes of hash) */
  x: string;
}

/**
 * QR code generation options
 */
export interface QRGenerationOptions {
  /** Error correction level */
  errorCorrection: 'L' | 'M' | 'Q' | 'H';

  /** QR code size in pixels */
  size: number;

  /** Expiration time in minutes */
  expirationMinutes: number;

  /** Encryption key (32 bytes hex) */
  encryptionKey?: string;

  /** Include logo/branding */
  includeLogo: boolean;

  /** Dark color */
  darkColor: string;

  /** Light color */
  lightColor: string;
}

const DEFAULT_OPTIONS: QRGenerationOptions = {
  errorCorrection: 'M',
  size: 256,
  expirationMinutes: 30,
  includeLogo: false,
  darkColor: '#000000',
  lightColor: '#ffffff',
};

/**
 * QR Share Manager
 *
 * Manages QR code generation and validation for share distribution.
 */
export class QRShareManager {
  private options: QRGenerationOptions;
  private encryptionKey: Uint8Array;
  private generatedCodes: Map<string, ShareQRCode> = new Map();
  private scannedCodes: Set<string> = new Set();

  constructor(options: Partial<QRGenerationOptions> = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };

    // Generate or use provided encryption key
    if (options.encryptionKey) {
      this.encryptionKey = hexToBytes(options.encryptionKey);
    } else {
      this.encryptionKey = randomBytes(32);
    }
  }

  /**
   * Generate QR code for a share
   */
  generateQRCode(
    ceremonyId: string,
    share: CeremonyShare
  ): ShareQRCode {
    // Encrypt the share value
    const encryptedShare = this.encryptShareValue(share.value);

    // Calculate expiration
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + this.options.expirationMinutes);

    // Build QR data
    const qrData: QRShareData = {
      v: 1,
      c: ceremonyId,
      p: share.participantId,
      i: share.index,
      s: encryptedShare,
      k: share.verificationKey,
      e: expiresAt.getTime(),
      x: '', // Will be calculated
    };

    // Calculate checksum
    qrData.x = this.calculateChecksum(qrData);

    // Generate QR code data URL
    const dataUrl = this.generateQRDataUrl(qrData);

    // Create verification code (last 4 chars of participant ID hash)
    const verificationCode = bytesToHex(
      sha256(new TextEncoder().encode(share.participantId))
    ).slice(-4).toUpperCase();

    const qrCode: ShareQRCode = {
      participantId: share.participantId,
      dataUrl,
      encryptedShare,
      shareIndex: share.index,
      expiresAt,
      scanned: false,
      verificationCode,
    };

    this.generatedCodes.set(share.participantId, qrCode);
    return qrCode;
  }

  /**
   * Generate QR codes for all shares
   */
  generateAllQRCodes(
    ceremonyId: string,
    shares: CeremonyShare[]
  ): ShareQRCode[] {
    return shares.map(share => this.generateQRCode(ceremonyId, share));
  }

  /**
   * Parse and validate a scanned QR code
   */
  parseQRCode(qrContent: string): QRScanResult {
    try {
      const data = JSON.parse(qrContent) as QRShareData;

      // Validate version
      if (data.v !== 1) {
        return {
          success: false,
          error: `Unsupported QR code version: ${data.v}`,
        };
      }

      // Validate checksum
      const expectedChecksum = this.calculateChecksum({ ...data, x: '' });
      if (data.x !== expectedChecksum) {
        return {
          success: false,
          error: 'Invalid checksum - QR code may be corrupted',
        };
      }

      // Check expiration
      if (Date.now() > data.e) {
        return {
          success: false,
          error: 'QR code has expired',
        };
      }

      // Check if already scanned
      const scanKey = `${data.c}:${data.p}:${data.i}`;
      if (this.scannedCodes.has(scanKey)) {
        return {
          success: false,
          error: 'This QR code has already been scanned',
        };
      }

      // Mark as scanned
      this.scannedCodes.add(scanKey);

      // Update generated code status
      const generated = this.generatedCodes.get(data.p);
      if (generated) {
        generated.scanned = true;
      }

      return {
        success: true,
        participantId: data.p,
        shareIndex: data.i,
      };
    } catch {
      return {
        success: false,
        error: 'Invalid QR code format',
      };
    }
  }

  /**
   * Decrypt share value from QR data
   */
  decryptShareValue(encryptedShare: string): string {
    const data = hexToBytes(encryptedShare);

    // Extract nonce (first 12 bytes) and ciphertext
    const nonce = data.slice(0, 12);
    const ciphertext = data.slice(12);

    const cipher = gcm(this.encryptionKey, nonce);
    const decrypted = cipher.decrypt(ciphertext);

    return new TextDecoder().decode(decrypted);
  }

  /**
   * Get all generated QR codes
   */
  getAllQRCodes(): ShareQRCode[] {
    return Array.from(this.generatedCodes.values());
  }

  /**
   * Get QR code for participant
   */
  getQRCodeForParticipant(participantId: string): ShareQRCode | undefined {
    return this.generatedCodes.get(participantId);
  }

  /**
   * Check if QR code has been scanned
   */
  isScanned(participantId: string): boolean {
    const code = this.generatedCodes.get(participantId);
    return code?.scanned ?? false;
  }

  /**
   * Get scan statistics
   */
  getScanStats(): { total: number; scanned: number; pending: number; expired: number } {
    const codes = this.getAllQRCodes();
    const now = Date.now();

    let scanned = 0;
    let expired = 0;

    for (const code of codes) {
      if (code.scanned) {
        scanned++;
      } else if (code.expiresAt.getTime() < now) {
        expired++;
      }
    }

    return {
      total: codes.length,
      scanned,
      pending: codes.length - scanned - expired,
      expired,
    };
  }

  /**
   * Regenerate expired QR code
   */
  regenerateQRCode(
    ceremonyId: string,
    share: CeremonyShare
  ): ShareQRCode {
    // Remove old code
    this.generatedCodes.delete(share.participantId);

    // Generate new code
    return this.generateQRCode(ceremonyId, share);
  }

  /**
   * Get encryption key (for secure transmission to coordinator)
   */
  getEncryptionKey(): string {
    return bytesToHex(this.encryptionKey);
  }

  /**
   * Encrypt share value
   */
  private encryptShareValue(value: string): string {
    const nonce = randomBytes(12);
    const plaintext = new TextEncoder().encode(value);

    const cipher = gcm(this.encryptionKey, nonce);
    const ciphertext = cipher.encrypt(plaintext);

    // Combine nonce and ciphertext
    const combined = new Uint8Array(nonce.length + ciphertext.length);
    combined.set(nonce);
    combined.set(ciphertext, nonce.length);

    return bytesToHex(combined);
  }

  /**
   * Calculate checksum for QR data
   */
  private calculateChecksum(data: Omit<QRShareData, 'x'> & { x?: string }): string {
    const content = JSON.stringify({
      v: data.v,
      c: data.c,
      p: data.p,
      i: data.i,
      s: data.s,
      k: data.k,
      e: data.e,
    });

    return bytesToHex(sha256(new TextEncoder().encode(content))).slice(0, 8);
  }

  /**
   * Generate QR code data URL
   *
   * Note: This is a simplified implementation. In production,
   * use a proper QR code library like 'qrcode' or 'qr-image'.
   */
  private generateQRDataUrl(data: QRShareData): string {
    const jsonData = JSON.stringify(data);

    // In a real implementation, this would generate an actual QR code
    // For now, we create a placeholder that includes the data
    const svg = this.createPlaceholderQRSVG(jsonData);

    return `data:image/svg+xml;base64,${btoa(svg)}`;
  }

  /**
   * Create placeholder QR SVG
   *
   * In production, replace with actual QR code generation.
   */
  private createPlaceholderQRSVG(data: string): string {
    const size = this.options.size;
    const moduleCount = 25; // Simplified
    const moduleSize = size / moduleCount;

    // Generate a pattern based on data hash
    const hash = sha256(new TextEncoder().encode(data));
    const bits: boolean[][] = [];

    for (let row = 0; row < moduleCount; row++) {
      bits[row] = [];
      for (let col = 0; col < moduleCount; col++) {
        const byteIndex = (row * moduleCount + col) % hash.length;
        const bitIndex = (row * moduleCount + col) % 8;
        bits[row][col] = ((hash[byteIndex] >> bitIndex) & 1) === 1;
      }
    }

    // Add finder patterns (simplified)
    this.addFinderPattern(bits, 0, 0);
    this.addFinderPattern(bits, moduleCount - 7, 0);
    this.addFinderPattern(bits, 0, moduleCount - 7);

    // Generate SVG
    let rects = '';
    for (let row = 0; row < moduleCount; row++) {
      for (let col = 0; col < moduleCount; col++) {
        if (bits[row][col]) {
          rects += `<rect x="${col * moduleSize}" y="${row * moduleSize}" width="${moduleSize}" height="${moduleSize}" fill="${this.options.darkColor}"/>`;
        }
      }
    }

    return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">
  <rect width="100%" height="100%" fill="${this.options.lightColor}"/>
  ${rects}
</svg>`;
  }

  /**
   * Add finder pattern to QR matrix
   */
  private addFinderPattern(bits: boolean[][], startRow: number, startCol: number): void {
    const pattern = [
      [1, 1, 1, 1, 1, 1, 1],
      [1, 0, 0, 0, 0, 0, 1],
      [1, 0, 1, 1, 1, 0, 1],
      [1, 0, 1, 1, 1, 0, 1],
      [1, 0, 1, 1, 1, 0, 1],
      [1, 0, 0, 0, 0, 0, 1],
      [1, 1, 1, 1, 1, 1, 1],
    ];

    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        if (startRow + r < bits.length && startCol + c < bits[0].length) {
          bits[startRow + r][startCol + c] = pattern[r][c] === 1;
        }
      }
    }
  }
}

/**
 * Create a QR share manager with default options
 */
export function createQRShareManager(
  options?: Partial<QRGenerationOptions>
): QRShareManager {
  return new QRShareManager(options);
}

/**
 * Generate a single QR code for a share
 */
export function generateShareQRCode(
  ceremonyId: string,
  share: CeremonyShare,
  options?: Partial<QRGenerationOptions>
): ShareQRCode {
  const manager = new QRShareManager(options);
  return manager.generateQRCode(ceremonyId, share);
}

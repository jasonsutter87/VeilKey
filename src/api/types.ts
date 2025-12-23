/**
 * API Types for VeilKey REST API
 *
 * Request and response schemas for all API endpoints
 */

import { z } from 'zod';
import type { Algorithm } from '../veilkey.js';

// =============================================================================
// Request Schemas
// =============================================================================

/**
 * Schema for creating a new key group
 */
export const CreateGroupSchema = z.object({
  threshold: z.number().int().positive(),
  parties: z.number().int().positive(),
  algorithm: z.enum(['RSA-2048', 'RSA-4096']),
}).refine(
  (data) => data.threshold <= data.parties,
  { message: 'Threshold cannot exceed number of parties' }
);

export type CreateGroupRequest = z.infer<typeof CreateGroupSchema>;

/**
 * Schema for partial signing request
 */
export const PartialSignSchema = z.object({
  message: z.string(),
  shareIndex: z.number().int().positive(),
});

export type PartialSignRequest = z.infer<typeof PartialSignSchema>;

/**
 * Schema for combining signatures
 */
export const CombineSignaturesSchema = z.object({
  message: z.string(),
  partials: z.array(z.object({
    index: z.number().int().positive(),
    partial: z.string(),
  })).min(1),
});

export type CombineSignaturesRequest = z.infer<typeof CombineSignaturesSchema>;

/**
 * Schema for signature verification
 */
export const VerifySignatureSchema = z.object({
  message: z.string(),
  signature: z.string(),
});

export type VerifySignatureRequest = z.infer<typeof VerifySignatureSchema>;

/**
 * Schema for partial decryption request
 */
export const PartialDecryptSchema = z.object({
  ciphertext: z.string(),
  shareIndex: z.number().int().positive(),
});

export type PartialDecryptRequest = z.infer<typeof PartialDecryptSchema>;

/**
 * Schema for combining decryptions
 */
export const CombineDecryptionsSchema = z.object({
  ciphertext: z.string(),
  partials: z.array(z.object({
    index: z.number().int().positive(),
    partial: z.string(),
  })).min(1),
});

export type CombineDecryptionsRequest = z.infer<typeof CombineDecryptionsSchema>;

// =============================================================================
// Response Types
// =============================================================================

/**
 * Share information (excludes sensitive share value)
 */
export interface ShareInfo {
  index: number;
  verificationKey: string;
}

/**
 * Key group response (public information only)
 */
export interface KeyGroupResponse {
  id: string;
  publicKey: string;
  algorithm: Algorithm;
  threshold: number;
  parties: number;
  shareInfo: ShareInfo[];
  delta: string;
  createdAt: string;
}

/**
 * Key group with shares (returned only on creation)
 */
export interface KeyGroupWithShares {
  id: string;
  publicKey: string;
  algorithm: Algorithm;
  threshold: number;
  parties: number;
  shares: Array<{
    index: number;
    value: string;
    verificationKey: string;
  }>;
  delta: string;
  createdAt: string;
}

/**
 * Partial signature response
 */
export interface PartialSignatureResponse {
  index: number;
  partial: string;
}

/**
 * Combined signature response
 */
export interface CombineSignaturesResponse {
  signature: string;
}

/**
 * Signature verification response
 */
export interface VerifySignatureResponse {
  valid: boolean;
}

/**
 * Partial decryption response
 */
export interface PartialDecryptionResponse {
  index: number;
  partial: string;
}

/**
 * Combined decryption response
 */
export interface CombineDecryptionsResponse {
  plaintext: string;
}

/**
 * Health check response
 */
export interface HealthResponse {
  status: 'healthy';
  timestamp: string;
  version: string;
}

/**
 * Error response
 */
export interface ErrorResponse {
  error: {
    message: string;
    code?: string;
    statusCode: number;
  };
}

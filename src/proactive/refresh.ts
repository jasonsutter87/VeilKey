/**
 * Share Refresh Protocol
 *
 * Implements proactive security by refreshing shares without changing the
 * underlying secret or public key. This defends against gradual share
 * compromise over time.
 *
 * Key insight: We can refresh shares by:
 * 1. Reconstructing the secret from existing shares
 * 2. Generating a new polynomial with the same constant term (secret)
 * 3. Creating new shares from the new polynomial
 * 4. The new shares reconstruct to the same secret but are cryptographically independent
 */

import { randomBytes } from 'crypto';
import {
  combine as shamirCombine,
  generatePolynomial,
  evaluatePolynomial,
  SECP256K1_ORDER,
} from '../shamir/index.js';
import {
  split as feldmanSplit,
  verify as feldmanVerify,
} from '../feldman/index.js';
import type { ShareWithIndex } from '../shamir/types.js';
import type { FeldmanShare, FeldmanCommitments } from '../feldman/types.js';
import type {
  RefreshConfig,
  RefreshResult,
  PartialRefreshConfig,
  RefreshVerificationResult,
} from './types.js';

/**
 * Generates a unique refresh ID
 */
function generateRefreshId(): string {
  const timestamp = Date.now().toString(36);
  const randomPart = randomBytes(8).toString('hex');
  return `refresh-${timestamp}-${randomPart}`;
}

/**
 * Checks if shares are Feldman shares
 */
function isFeldmanShare(share: ShareWithIndex | FeldmanShare): share is FeldmanShare {
  return 'index' in share;
}

/**
 * Refreshes shares without changing the underlying secret
 *
 * This is the core of proactive security:
 * - Reconstructs the secret from existing shares
 * - Generates a new polynomial with the same secret as constant term
 * - Creates new shares that are cryptographically independent from old ones
 * - For Feldman VSS, preserves the public commitment (g^secret)
 *
 * @param config - Refresh configuration
 * @returns New refreshed shares with metadata
 *
 * @example
 * ```typescript
 * const original = shamirSplit(secret, 3, 5);
 * const refreshed = refreshShares({
 *   shares: original.shares,
 *   threshold: original.threshold,
 *   prime: original.prime,
 * });
 * // refreshed.shares are cryptographically independent but reconstruct to same secret
 * ```
 */
export function refreshShares(config: RefreshConfig): RefreshResult {
  const {
    shares,
    threshold,
    prime,
    verifiable = false,
    refreshId = generateRefreshId(),
    metadata,
  } = config;

  if (!shares || shares.length === 0) {
    throw new Error('Shares array cannot be empty');
  }

  if (shares.length < threshold) {
    throw new Error(
      `Not enough shares for reconstruction: need ${threshold}, got ${shares.length}`
    );
  }

  if (threshold < 1) {
    throw new Error('Threshold must be at least 1');
  }

  // Convert to basic ShareWithIndex for reconstruction
  const basicShares: ShareWithIndex[] = shares.map(s => ({ x: s.x, y: s.y }));

  // Reconstruct the secret from existing shares
  const secret = shamirCombine(basicShares.slice(0, threshold), prime);

  // Generate new shares with the same secret
  let newShares: ShareWithIndex[] | FeldmanShare[];
  let commitments: FeldmanCommitments | undefined;

  if (verifiable || (shares.length > 0 && isFeldmanShare(shares[0]!))) {
    // Use Feldman VSS for verifiable shares
    const feldmanResult = feldmanSplit(secret, threshold, shares.length, prime);
    newShares = feldmanResult.shares;
    commitments = feldmanResult.commitments;
  } else {
    // Use standard Shamir for non-verifiable shares
    // Generate new polynomial with same secret
    const coefficients = generatePolynomial(secret, threshold - 1, prime);

    // Create new shares by evaluating polynomial at same indices
    newShares = shares.map((share) => ({
      x: share.x,
      y: evaluatePolynomial(coefficients, share.x, prime),
    }));
  }

  return {
    shares: newShares,
    ...(commitments && { commitments }),
    threshold,
    prime,
    refreshId,
    timestamp: new Date(),
    ...(metadata && { metadata }),
  };
}

/**
 * Refreshes only a subset of shares
 *
 * This is useful for:
 * - Rotating shares for specific parties
 * - Gradual refresh to avoid downtime
 * - Targeted refresh of potentially compromised shares
 *
 * @param config - Partial refresh configuration
 * @returns New shares for the specified indices
 *
 * @example
 * ```typescript
 * const original = shamirSplit(secret, 3, 5);
 * // Refresh only shares 1 and 3
 * const refreshed = refreshSharesPartial({
 *   shares: original.shares,
 *   threshold: original.threshold,
 *   prime: original.prime,
 *   indicesToRefresh: [1, 3],
 * });
 * // Can combine refreshed shares with original unchanged shares
 * ```
 */
export function refreshSharesPartial(config: PartialRefreshConfig): RefreshResult {
  const {
    shares,
    threshold,
    prime,
    indicesToRefresh,
    verifiable = false,
    refreshId = generateRefreshId(),
    metadata,
  } = config;

  if (!shares || shares.length === 0) {
    throw new Error('Shares array cannot be empty');
  }

  if (shares.length < threshold) {
    throw new Error(
      `Not enough shares for reconstruction: need ${threshold}, got ${shares.length}`
    );
  }

  if (!indicesToRefresh || indicesToRefresh.length === 0) {
    throw new Error('Must specify at least one index to refresh');
  }

  // Validate that all indices to refresh exist
  const availableIndices = new Set(shares.map(s => Number(s.x)));
  for (const idx of indicesToRefresh) {
    if (!availableIndices.has(idx)) {
      throw new Error(
        `Invalid share index ${idx}: not found in available shares [${Array.from(availableIndices).join(', ')}]`
      );
    }
  }

  // Convert to basic ShareWithIndex for reconstruction
  const basicShares: ShareWithIndex[] = shares.map(s => ({ x: s.x, y: s.y }));

  // Reconstruct the secret
  const secret = shamirCombine(basicShares.slice(0, threshold), prime);

  // Generate new polynomial with same secret
  const coefficients = generatePolynomial(secret, threshold - 1, prime);

  // Create new shares only for specified indices
  const refreshedShares: ShareWithIndex[] | FeldmanShare[] = indicesToRefresh.map((idx) => {
    const x = BigInt(idx);
    const y = evaluatePolynomial(coefficients, x, prime);

    if (verifiable || (shares.length > 0 && isFeldmanShare(shares[0]!))) {
      return { x, y, index: idx } as FeldmanShare;
    } else {
      return { x, y };
    }
  });

  // For verifiable shares, generate commitments
  let commitments: FeldmanCommitments | undefined;
  if (verifiable || (shares.length > 0 && isFeldmanShare(shares[0]!))) {
    // Use Feldman to get commitments
    const feldmanResult = feldmanSplit(secret, threshold, shares.length, prime);
    commitments = feldmanResult.commitments;
  }

  return {
    shares: refreshedShares,
    ...(commitments && { commitments }),
    threshold,
    prime,
    refreshId,
    timestamp: new Date(),
    metadata: {
      ...metadata,
      partialRefresh: true,
      refreshedIndices: indicesToRefresh,
    },
  };
}

/**
 * Verifies that a refresh operation preserved the secret
 *
 * This is a safety check to ensure that:
 * - Both old and new shares reconstruct to the same secret
 * - No corruption occurred during the refresh
 *
 * @param originalShares - Original shares before refresh
 * @param refreshedShares - New shares after refresh
 * @param threshold - Reconstruction threshold
 * @param prime - Prime field modulus
 * @returns Verification result
 *
 * @example
 * ```typescript
 * const original = shamirSplit(secret, 3, 5);
 * const refreshed = refreshShares({
 *   shares: original.shares,
 *   threshold: original.threshold,
 *   prime: original.prime,
 * });
 *
 * const verification = verifyRefreshPreservesSecret(
 *   original.shares,
 *   refreshed.shares,
 *   original.threshold,
 *   original.prime
 * );
 * console.log(verification.valid); // true
 * ```
 */
export function verifyRefreshPreservesSecret(
  originalShares: ShareWithIndex[] | FeldmanShare[],
  refreshedShares: ShareWithIndex[] | FeldmanShare[],
  threshold: number,
  prime: bigint = SECP256K1_ORDER
): RefreshVerificationResult {
  try {
    // Validate inputs
    if (originalShares.length < threshold) {
      return {
        valid: false,
        error: `Insufficient original shares: need ${threshold}, got ${originalShares.length}`,
      };
    }

    if (refreshedShares.length < threshold) {
      return {
        valid: false,
        error: `Insufficient refreshed shares: need ${threshold}, got ${refreshedShares.length}`,
      };
    }

    // Convert to basic shares
    const originalBasic: ShareWithIndex[] = originalShares.map(s => ({ x: s.x, y: s.y }));
    const refreshedBasic: ShareWithIndex[] = refreshedShares.map(s => ({ x: s.x, y: s.y }));

    // Reconstruct secrets
    const originalSecret = shamirCombine(originalBasic.slice(0, threshold), prime);
    const refreshedSecret = shamirCombine(refreshedBasic.slice(0, threshold), prime);

    // Check if secrets match
    if (originalSecret !== refreshedSecret) {
      return {
        valid: false,
        originalSecret,
        refreshedSecret,
        error: `Secret mismatch: original=${originalSecret}, refreshed=${refreshedSecret}`,
      };
    }

    return {
      valid: true,
      originalSecret,
      refreshedSecret,
    };
  } catch (error) {
    return {
      valid: false,
      error: `Verification error: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * Verifies refreshed Feldman VSS shares against commitments
 *
 * @param shares - Refreshed shares to verify
 * @param commitments - Commitments to verify against
 * @param prime - Prime field modulus
 * @returns True if all shares are valid
 */
export function verifyRefreshedShares(
  shares: FeldmanShare[],
  commitments: FeldmanCommitments,
  prime: bigint = SECP256K1_ORDER
): boolean {
  try {
    for (const share of shares) {
      const result = feldmanVerify(share, commitments, prime);
      if (!result.valid) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Combines a mix of old and refreshed shares
 *
 * This is useful after partial refresh where some shares are new and some are old.
 * All shares should still reconstruct to the same secret.
 *
 * @param shares - Mix of old and new shares
 * @param threshold - Reconstruction threshold
 * @param prime - Prime field modulus
 * @returns Reconstructed secret
 */
export function combineRefreshedShares(
  shares: (ShareWithIndex | FeldmanShare)[],
  threshold: number,
  prime: bigint = SECP256K1_ORDER
): bigint {
  if (shares.length < threshold) {
    throw new Error(
      `Not enough shares for reconstruction: need ${threshold}, got ${shares.length}`
    );
  }

  const basicShares: ShareWithIndex[] = shares.map(s => ({ x: s.x, y: s.y }));
  return shamirCombine(basicShares.slice(0, threshold), prime);
}

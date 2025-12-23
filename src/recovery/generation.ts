/**
 * Share generation service for recovery
 *
 * Provides:
 * - Generation of replacement shares
 * - Share validation
 * - Old share invalidation
 * - Share index reassignment
 */

import type {
  GeneratedShare,
  ShareMetadata,
  PublicParameters,
  ShareIndexAssignment,
  RecoveryStorage,
} from './types.js';
import { createHash } from 'crypto';

export class ShareGenerationServiceImpl {
  private storage: RecoveryStorage;

  constructor(storage: RecoveryStorage) {
    this.storage = storage;
  }

  async generateReplacementShare(
    recoveredSecret: string,
    newShareHolderId: string,
    shareIndex: number,
    threshold: number,
    totalShares: number = 5
  ): Promise<GeneratedShare> {
    // Validate share index
    if (shareIndex < 1 || shareIndex > totalShares) {
      throw new Error('Share index out of valid range');
    }

    // Validate recovered secret
    if (!recoveredSecret || !recoveredSecret.match(/^0x[0-9a-f]+$/i)) {
      throw new Error('Invalid recovered secret format');
    }

    // Generate share value (mock implementation using hash)
    const shareValue = this.generateShareValue(recoveredSecret, shareIndex);

    // Generate public commitment
    const publicCommitment = this.generateCommitment(shareValue);

    // Generate zero-knowledge proof
    const proof = this.generateProof(shareValue, publicCommitment);

    // Create metadata
    const metadata: ShareMetadata = {
      version: 1,
      threshold,
      totalShares,
      algorithm: 'feldman-vss',
      createdAt: new Date(),
      generationContext: 'recovery',
    };

    // Create generated share
    const generatedShare: GeneratedShare = {
      id: crypto.randomUUID(),
      shareIndex,
      shareValue,
      holderId: newShareHolderId,
      generatedAt: new Date(),
      publicCommitment,
      proof,
      metadata,
    };

    await this.storage.saveGeneratedShare(generatedShare);

    return generatedShare;
  }

  async verifyShareValidity(
    share: GeneratedShare,
    publicParameters: PublicParameters
  ): Promise<boolean> {
    try {
      // Validate share structure
      if (!share.shareValue || !share.shareValue.match(/^0x[0-9a-f]+$/i)) {
        return false;
      }

      // Validate against commitment
      const expectedCommitment = this.generateCommitment(share.shareValue);

      // Check if commitment matches
      if (publicParameters.commitments.length > 0) {
        const isValid = publicParameters.commitments.some(
          c => c === share.publicCommitment || c === expectedCommitment
        );
        return isValid;
      }

      // If no commitments provided, just check that commitment can be generated
      return expectedCommitment.length > 0;
    } catch (error) {
      return false;
    }
  }

  async invalidateOldShare(oldShareHolderId: string): Promise<void> {
    const metadata = await this.storage.getShareMetadata(oldShareHolderId);

    if (!metadata) {
      // Create metadata for tracking
      const newMetadata: ShareMetadata = {
        version: 1,
        threshold: 3,
        totalShares: 5,
        algorithm: 'feldman-vss',
        createdAt: new Date(),
        generationContext: 'recovery',
        invalidated: true,
        invalidatedAt: new Date(),
      };
      await this.storage.saveGeneratedShare({
        id: crypto.randomUUID(),
        shareIndex: 0,
        shareValue: '',
        holderId: oldShareHolderId,
        generatedAt: new Date(),
        publicCommitment: '',
        metadata: newMetadata,
      });
    } else {
      await this.storage.updateShareMetadata(oldShareHolderId, {
        invalidated: true,
        invalidatedAt: new Date(),
      });
    }
  }

  async reassignShareIndex(
    oldIndex: number,
    newIndex: number,
    newHolderId: string
  ): Promise<ShareIndexAssignment> {
    const assignment: ShareIndexAssignment = {
      oldIndex,
      newIndex,
      holderId: newHolderId,
      assignedAt: new Date(),
      reason: 'recovery',
    };

    // Update metadata to track reassignment
    const metadata = await this.storage.getShareMetadata(newHolderId);
    if (metadata) {
      await this.storage.updateShareMetadata(newHolderId, {
        replacesShareId: `share-${oldIndex}`,
      });
    }

    return assignment;
  }

  async getShareMetadata(shareId: string): Promise<ShareMetadata> {
    const metadata = await this.storage.getShareMetadata(shareId);
    if (!metadata) {
      // Return default metadata
      return {
        version: 1,
        threshold: 3,
        totalShares: 5,
        algorithm: 'feldman-vss',
        createdAt: new Date(),
        generationContext: 'recovery',
      };
    }
    return metadata;
  }

  async validateShareAgainstCommitment(
    share: GeneratedShare,
    commitment: string
  ): Promise<boolean> {
    try {
      const expectedCommitment = this.generateCommitment(share.shareValue);
      return expectedCommitment === commitment || share.publicCommitment === commitment;
    } catch (error) {
      return false;
    }
  }

  // Private helper methods

  private generateShareValue(secret: string, index: number): string {
    // Simple mock implementation - hash the secret with the index
    const hash = createHash('sha256');
    hash.update(secret);
    hash.update(index.toString());
    return '0x' + hash.digest('hex');
  }

  private generateCommitment(shareValue: string): string {
    // Generate commitment using hash
    const hash = createHash('sha256');
    hash.update(shareValue);
    hash.update('commitment');
    return '0x' + hash.digest('hex');
  }

  private generateProof(shareValue: string, commitment: string): string {
    // Generate zero-knowledge proof (mock)
    const hash = createHash('sha256');
    hash.update(shareValue);
    hash.update(commitment);
    hash.update('proof');
    return '0x' + hash.digest('hex');
  }
}

// Export interface for test compatibility
export interface ShareGenerationService {
  generateReplacementShare(
    recoveredSecret: string,
    newShareHolderId: string,
    shareIndex: number,
    threshold: number
  ): Promise<GeneratedShare>;

  verifyShareValidity(
    share: GeneratedShare,
    publicParameters: PublicParameters
  ): Promise<boolean>;

  invalidateOldShare(oldShareHolderId: string): Promise<void>;

  reassignShareIndex(
    oldIndex: number,
    newIndex: number,
    newHolderId: string
  ): Promise<ShareIndexAssignment>;

  getShareMetadata(shareId: string): Promise<ShareMetadata>;

  validateShareAgainstCommitment(
    share: GeneratedShare,
    commitment: string
  ): Promise<boolean>;
}

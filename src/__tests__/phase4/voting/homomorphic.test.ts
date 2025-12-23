/**
 * Homomorphic Vote Tallying Tests
 *
 * Tests for additively homomorphic encryption used in vote tallying.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  HomomorphicTallyManager,
  createHomomorphicTallyManager,
  encryptVote,
  type HomomorphicPublicKey,
  type HomomorphicKeyShare,
} from '../../../voting/homomorphic.js';

describe('HomomorphicTallyManager', () => {
  let manager: HomomorphicTallyManager;

  beforeEach(() => {
    manager = createHomomorphicTallyManager('election-1');
  });

  describe('key generation', () => {
    it('should generate threshold key pair', () => {
      const { publicKey, keyShares } = manager.generateKeyPair(2, 3);

      expect(publicKey.keyId).toHaveLength(16);
      expect(publicKey.threshold).toBe(2);
      expect(publicKey.totalTrustees).toBe(3);
      expect(publicKey.publicKey).toHaveLength(66); // Compressed point

      expect(keyShares).toHaveLength(3);
    });

    it('should generate distinct key shares', () => {
      const { keyShares } = manager.generateKeyPair(2, 3);

      const shareValues = keyShares.map(s => s.share);
      const uniqueShares = new Set(shareValues);

      expect(uniqueShares.size).toBe(3);
    });

    it('should include Feldman commitments', () => {
      const { keyShares } = manager.generateKeyPair(2, 3);

      for (const share of keyShares) {
        expect(share.commitment).toHaveLength(2); // t commitments
        expect(share.commitment[0]).toHaveLength(66);
      }
    });

    it('should reject invalid threshold', () => {
      expect(() => manager.generateKeyPair(0, 3)).toThrow('Invalid threshold');
      expect(() => manager.generateKeyPair(4, 3)).toThrow('Invalid threshold');
    });

    it('should allow threshold equal to total', () => {
      const { publicKey, keyShares } = manager.generateKeyPair(3, 3);

      expect(publicKey.threshold).toBe(3);
      expect(keyShares).toHaveLength(3);
    });
  });

  describe('vote encryption', () => {
    let publicKey: HomomorphicPublicKey;
    let keyShares: HomomorphicKeyShare[];

    beforeEach(() => {
      const result = manager.generateKeyPair(2, 3);
      publicKey = result.publicKey;
      keyShares = result.keyShares;
    });

    it('should encrypt a vote for value 0', () => {
      const encryptedVote = manager.encryptVote('option-a', 0);

      expect(encryptedVote.c1).toHaveLength(66);
      expect(encryptedVote.c2).toHaveLength(66);
      expect(encryptedVote.optionId).toBe('option-a');
      expect(encryptedVote.proof).toBeDefined();
    });

    it('should encrypt a vote for value 1', () => {
      const encryptedVote = manager.encryptVote('option-b', 1);

      expect(encryptedVote.c1).toHaveLength(66);
      expect(encryptedVote.c2).toHaveLength(66);
      expect(encryptedVote.optionId).toBe('option-b');
    });

    it('should produce different ciphertexts for same value', () => {
      const vote1 = manager.encryptVote('option-a', 1);
      const vote2 = manager.encryptVote('option-a', 1);

      expect(vote1.c1).not.toBe(vote2.c1);
      expect(vote1.c2).not.toBe(vote2.c2);
    });

    it('should track encrypted votes', () => {
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-b', 1);

      const counts = manager.getVoteCounts();
      expect(counts.get('option-a')).toBe(2);
      expect(counts.get('option-b')).toBe(1);
    });

    it('should generate valid vote proof', () => {
      const vote = manager.encryptVote('option-a', 1);

      expect(vote.proof).toBeDefined();
      expect(vote.proof!.type).toBe('disjunctive-chaum-pedersen');
      expect(vote.proof!.proof0.a).toHaveLength(66);
      expect(vote.proof!.proof1.a).toHaveLength(66);
    });

    it('should encrypt without proof when specified', () => {
      const vote = manager.encryptVote('option-a', 1, false);

      expect(vote.proof).toBeUndefined();
    });

    it('should throw without public key', () => {
      const newManager = createHomomorphicTallyManager('election-2');

      expect(() => newManager.encryptVote('option-a', 1)).toThrow('Public key not set');
    });
  });

  describe('vote proof verification', () => {
    beforeEach(() => {
      manager.generateKeyPair(2, 3);
    });

    it('should verify valid proof for vote 0', () => {
      const vote = manager.encryptVote('option-a', 0);

      expect(manager.verifyVoteProof(vote)).toBe(true);
    });

    it('should verify valid proof for vote 1', () => {
      const vote = manager.encryptVote('option-a', 1);

      expect(manager.verifyVoteProof(vote)).toBe(true);
    });

    it('should reject vote without proof', () => {
      const vote = manager.encryptVote('option-a', 1, false);

      expect(manager.verifyVoteProof(vote)).toBe(false);
    });

    it('should verify multiple votes', () => {
      for (let i = 0; i < 10; i++) {
        const vote = manager.encryptVote('option-a', (i % 2) as 0 | 1);
        expect(manager.verifyVoteProof(vote)).toBe(true);
      }
    });
  });

  describe('vote aggregation', () => {
    beforeEach(() => {
      manager.generateKeyPair(2, 3);
    });

    it('should aggregate votes for single option', () => {
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 0);

      const tallies = manager.aggregateVotes();

      expect(tallies.size).toBe(1);
      expect(tallies.get('option-a')!.voteCount).toBe(3);
    });

    it('should aggregate votes for multiple options', () => {
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-b', 1);
      manager.encryptVote('option-a', 1);

      const tallies = manager.aggregateVotes();

      expect(tallies.size).toBe(2);
      expect(tallies.get('option-a')!.voteCount).toBe(2);
      expect(tallies.get('option-b')!.voteCount).toBe(1);
    });

    it('should produce valid encrypted tally', () => {
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 1);

      const tallies = manager.aggregateVotes();
      const tally = tallies.get('option-a')!;

      expect(tally.c1Sum).toHaveLength(66);
      expect(tally.c2Sum).toHaveLength(66);
    });
  });

  describe('decryption shares', () => {
    let keyShares: HomomorphicKeyShare[];

    beforeEach(() => {
      const result = manager.generateKeyPair(2, 3);
      keyShares = result.keyShares;

      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 1);
      manager.aggregateVotes();
    });

    it('should generate decryption share', () => {
      const share = manager.generateDecryptionShare('option-a', keyShares[0]);

      expect(share.trusteeId).toBe('trustee-1');
      expect(share.index).toBe(1);
      expect(share.partialDecryption).toHaveLength(66);
      expect(share.proof).toBeDefined();
    });

    it('should generate different shares for different trustees', () => {
      const share1 = manager.generateDecryptionShare('option-a', keyShares[0]);
      const share2 = manager.generateDecryptionShare('option-a', keyShares[1]);

      expect(share1.partialDecryption).not.toBe(share2.partialDecryption);
    });

    it('should include decryption proof', () => {
      const share = manager.generateDecryptionShare('option-a', keyShares[0]);

      expect(share.proof.commitment).toBeDefined();
      expect(share.proof.challenge).toHaveLength(64);
      expect(share.proof.response).toHaveLength(64);
    });

    it('should throw for unknown option', () => {
      expect(() => manager.generateDecryptionShare('unknown', keyShares[0])).toThrow(
        'No tally for option'
      );
    });
  });

  describe('tally decryption', () => {
    let keyShares: HomomorphicKeyShare[];

    beforeEach(() => {
      const result = manager.generateKeyPair(2, 3);
      keyShares = result.keyShares;
    });

    it('should decrypt tally with correct count', () => {
      // Cast 3 votes for option-a (total = 3)
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 1);

      manager.aggregateVotes();

      // Get threshold decryption shares
      manager.generateDecryptionShare('option-a', keyShares[0]);
      manager.generateDecryptionShare('option-a', keyShares[1]);

      const decrypted = manager.decryptTally('option-a');

      expect(decrypted.count).toBe(3);
      expect(decrypted.optionId).toBe('option-a');
      expect(decrypted.shares).toHaveLength(2);
    });

    it('should decrypt tally with zero votes', () => {
      manager.encryptVote('option-a', 0);
      manager.encryptVote('option-a', 0);

      manager.aggregateVotes();

      manager.generateDecryptionShare('option-a', keyShares[0]);
      manager.generateDecryptionShare('option-a', keyShares[1]);

      const decrypted = manager.decryptTally('option-a');

      expect(decrypted.count).toBe(0);
    });

    it('should decrypt tally with mixed votes', () => {
      // 5 yes votes, 3 no votes = 5 total
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 0);
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 0);
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 0);
      manager.encryptVote('option-a', 1);

      manager.aggregateVotes();

      manager.generateDecryptionShare('option-a', keyShares[0]);
      manager.generateDecryptionShare('option-a', keyShares[1]);

      const decrypted = manager.decryptTally('option-a');

      expect(decrypted.count).toBe(5);
    });

    it('should work with different threshold combinations', () => {
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 1);

      manager.aggregateVotes();

      // Use shares 1 and 3 instead of 1 and 2
      manager.generateDecryptionShare('option-a', keyShares[0]);
      manager.generateDecryptionShare('option-a', keyShares[2]);

      const decrypted = manager.decryptTally('option-a');

      expect(decrypted.count).toBe(2);
    });

    it('should throw with insufficient shares', () => {
      manager.encryptVote('option-a', 1);
      manager.aggregateVotes();

      // Only 1 share, but threshold is 2
      manager.generateDecryptionShare('option-a', keyShares[0]);

      expect(() => manager.decryptTally('option-a')).toThrow('Not enough decryption shares');
    });

    it('should include verification data', () => {
      manager.encryptVote('option-a', 1);
      manager.aggregateVotes();

      manager.generateDecryptionShare('option-a', keyShares[0]);
      manager.generateDecryptionShare('option-a', keyShares[1]);

      const decrypted = manager.decryptTally('option-a');

      expect(decrypted.verification.combinedShare).toHaveLength(66);
      expect(decrypted.verification.resultPoint).toHaveLength(66);
    });
  });

  describe('multiple options', () => {
    let keyShares: HomomorphicKeyShare[];

    beforeEach(() => {
      const result = manager.generateKeyPair(2, 3);
      keyShares = result.keyShares;
    });

    it('should decrypt multiple options correctly', () => {
      // Option A: 3 votes
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 1);

      // Option B: 2 votes
      manager.encryptVote('option-b', 1);
      manager.encryptVote('option-b', 1);

      // Option C: 0 votes
      manager.encryptVote('option-c', 0);

      manager.aggregateVotes();

      for (const optionId of ['option-a', 'option-b', 'option-c']) {
        manager.generateDecryptionShare(optionId, keyShares[0]);
        manager.generateDecryptionShare(optionId, keyShares[1]);
      }

      expect(manager.decryptTally('option-a').count).toBe(3);
      expect(manager.decryptTally('option-b').count).toBe(2);
      expect(manager.decryptTally('option-c').count).toBe(0);
    });
  });

  describe('external votes', () => {
    let publicKey: HomomorphicPublicKey;

    beforeEach(() => {
      const result = manager.generateKeyPair(2, 3);
      publicKey = result.publicKey;
    });

    it('should accept externally encrypted votes', () => {
      const externalVote = encryptVote('option-a', 1, publicKey);

      manager.addEncryptedVote(externalVote);

      expect(manager.getVoteCounts().get('option-a')).toBe(1);
    });

    it('should aggregate external votes correctly', () => {
      const vote1 = encryptVote('option-a', 1, publicKey);
      const vote2 = encryptVote('option-a', 1, publicKey);

      manager.addEncryptedVote(vote1);
      manager.addEncryptedVote(vote2);

      manager.aggregateVotes();

      const tally = manager.getEncryptedTally('option-a');
      expect(tally!.voteCount).toBe(2);
    });
  });

  describe('manager operations', () => {
    it('should set public key', () => {
      const other = createHomomorphicTallyManager('other');
      const { publicKey } = other.generateKeyPair(2, 3);

      manager.setPublicKey(publicKey);

      expect(manager.getPublicKey()).toEqual(publicKey);
    });

    it('should clear votes', () => {
      manager.generateKeyPair(2, 3);
      manager.encryptVote('option-a', 1);

      expect(manager.getVoteCounts().get('option-a')).toBe(1);

      manager.clear();

      expect(manager.getVoteCounts().size).toBe(0);
    });

    it('should get encrypted votes', () => {
      manager.generateKeyPair(2, 3);
      manager.encryptVote('option-a', 1);
      manager.encryptVote('option-a', 0);

      const votes = manager.getEncryptedVotes('option-a');

      expect(votes).toHaveLength(2);
    });
  });
});

describe('factory functions', () => {
  it('should create manager', () => {
    const manager = createHomomorphicTallyManager('test');

    expect(manager).toBeInstanceOf(HomomorphicTallyManager);
  });

  it('should encrypt vote standalone', () => {
    const manager = createHomomorphicTallyManager('test');
    const { publicKey } = manager.generateKeyPair(2, 3);

    const vote = encryptVote('option-a', 1, publicKey);

    expect(vote.c1).toHaveLength(66);
    expect(vote.c2).toHaveLength(66);
    expect(vote.proof).toBeDefined();
  });
});

describe('election simulation', () => {
  it('should simulate complete election flow', () => {
    // Setup
    const manager = createHomomorphicTallyManager('election-2024');
    const { publicKey, keyShares } = manager.generateKeyPair(3, 5);

    // Voting phase - 100 voters
    const options = ['candidate-a', 'candidate-b', 'candidate-c'];
    const expectedCounts = { 'candidate-a': 0, 'candidate-b': 0, 'candidate-c': 0 };

    for (let i = 0; i < 100; i++) {
      // Each voter votes for exactly one candidate
      const choice = i % 3;
      for (let j = 0; j < 3; j++) {
        const voteValue = j === choice ? 1 : 0;
        manager.encryptVote(options[j], voteValue as 0 | 1);
        if (voteValue === 1) {
          expectedCounts[options[j] as keyof typeof expectedCounts]++;
        }
      }
    }

    // Aggregation
    manager.aggregateVotes();

    // Decryption - use trustees 0, 2, 4 (indices 1, 3, 5)
    for (const option of options) {
      manager.generateDecryptionShare(option, keyShares[0]);
      manager.generateDecryptionShare(option, keyShares[2]);
      manager.generateDecryptionShare(option, keyShares[4]);
    }

    // Verify results
    for (const option of options) {
      const result = manager.decryptTally(option);
      expect(result.count).toBe(expectedCounts[option as keyof typeof expectedCounts]);
    }

    // Final tally should be: A=34, B=33, C=33
    expect(manager.decryptTally('candidate-a').count).toBe(34);
    expect(manager.decryptTally('candidate-b').count).toBe(33);
    expect(manager.decryptTally('candidate-c').count).toBe(33);
  });
});

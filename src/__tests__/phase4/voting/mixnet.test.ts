/**
 * Verifiable Shuffle (Mix-net) Tests
 *
 * Tests for the re-encryption mixnet implementation.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  MixServer,
  MixnetChain,
  createMixServer,
  createMixnetChain,
  createMixnetCiphertext,
  votesToMixnetFormat,
  verifyShuffleProof,
  type MixnetCiphertext,
  type MixResult,
} from '../../../voting/mixnet.js';
import {
  HomomorphicTallyManager,
  createHomomorphicTallyManager,
} from '../../../voting/homomorphic.js';

describe('MixServer', () => {
  let server: MixServer;
  let manager: HomomorphicTallyManager;
  let publicKey: string;

  beforeEach(() => {
    server = createMixServer('server-1', 1);
    manager = createHomomorphicTallyManager('election-1');
    const result = manager.generateKeyPair(2, 3);
    publicKey = result.publicKey.publicKey;
    server.setElectionPublicKey(publicKey);
  });

  describe('configuration', () => {
    it('should create server with config', () => {
      const config = server.getConfig();

      expect(config.id).toBe('server-1');
      expect(config.position).toBe(1);
      expect(config.publicKey).toHaveLength(64);
    });

    it('should accept election public key', () => {
      const newServer = createMixServer('server-2', 2);
      expect(() => newServer.shuffle([], 'session')).toThrow('Election public key not set');

      newServer.setElectionPublicKey(publicKey);
      expect(() => newServer.shuffle([], 'session')).toThrow('Cannot shuffle empty list');
    });
  });

  describe('shuffle operation', () => {
    let inputs: MixnetCiphertext[];

    beforeEach(() => {
      // Create encrypted votes
      manager.setPublicKey(manager.getPublicKey()!);
      const votes = [
        manager.encryptVote('option-a', 1, false),
        manager.encryptVote('option-a', 1, false),
        manager.encryptVote('option-a', 0, false),
        manager.encryptVote('option-a', 1, false),
      ];

      inputs = votesToMixnetFormat(votes);
    });

    it('should shuffle ciphertexts', () => {
      const result = server.shuffle(inputs, 'session-1');

      expect(result.outputs).toHaveLength(4);
      expect(result.proof).toBeDefined();
      expect(result.inputCommitment).toHaveLength(64);
      expect(result.outputCommitment).toHaveLength(64);
    });

    it('should produce different outputs than inputs', () => {
      const result = server.shuffle(inputs, 'session-1');

      // Outputs should be re-encrypted (different ciphertexts)
      const inputC1s = inputs.map(i => i.c1);
      const outputC1s = result.outputs.map(o => o.c1);

      // At least some should be different
      const allSame = inputC1s.every((c1, i) => c1 === outputC1s[i]);
      expect(allSame).toBe(false);
    });

    it('should preserve number of ciphertexts', () => {
      const result = server.shuffle(inputs, 'session-1');
      expect(result.outputs.length).toBe(inputs.length);
    });

    it('should assign unique IDs to outputs', () => {
      const result = server.shuffle(inputs, 'session-1');
      const ids = result.outputs.map(o => o.id);
      const uniqueIds = new Set(ids);

      expect(uniqueIds.size).toBe(result.outputs.length);
    });

    it('should generate different shuffles each time', () => {
      const result1 = server.shuffle(inputs, 'session-1');
      const result2 = server.shuffle(inputs, 'session-2');

      // Outputs should be different (different randomness)
      const allSame = result1.outputs.every(
        (o, i) => o.c1 === result2.outputs[i].c1 && o.c2 === result2.outputs[i].c2
      );
      expect(allSame).toBe(false);
    });
  });

  describe('shuffle proof', () => {
    let inputs: MixnetCiphertext[];

    beforeEach(() => {
      manager.setPublicKey(manager.getPublicKey()!);
      const votes = [
        manager.encryptVote('option-a', 1, false),
        manager.encryptVote('option-a', 1, false),
        manager.encryptVote('option-a', 0, false),
        manager.encryptVote('option-a', 1, false),
        manager.encryptVote('option-a', 0, false),
        manager.encryptVote('option-a', 1, false),
      ];
      inputs = votesToMixnetFormat(votes);
    });

    it('should generate shuffle proof', () => {
      const result = server.shuffle(inputs, 'session-1');
      const proof = result.proof;

      expect(proof.serverId).toBe('server-1');
      expect(proof.inputCommitment).toHaveLength(64);
      expect(proof.outputCommitment).toHaveLength(64);
      expect(proof.reencryptionCommitments).toHaveLength(6);
      expect(proof.timestamp).toBeInstanceOf(Date);
    });

    it('should include partial responses', () => {
      const result = server.shuffle(inputs, 'session-1');
      const proof = result.proof;

      // Should have some challenged positions
      expect(proof.challenges.length).toBeGreaterThan(0);
      expect(proof.responses.length).toBeGreaterThan(0);

      // Each response should have required fields
      for (const response of proof.responses) {
        expect(response.inputIndex).toBeGreaterThanOrEqual(0);
        expect(response.outputIndex).toBeGreaterThanOrEqual(0);
        expect(response.reencryptionFactor).toHaveLength(64);
      }
    });

    it('should generate verifiable proof', () => {
      const result = server.shuffle(inputs, 'session-1');

      const isValid = verifyShuffleProof(result.proof, publicKey);
      expect(isValid).toBe(true);
    });
  });
});

describe('MixnetChain', () => {
  let chain: MixnetChain;
  let manager: HomomorphicTallyManager;
  let publicKey: string;
  let inputs: MixnetCiphertext[];

  beforeEach(() => {
    chain = createMixnetChain(3); // 3 servers
    manager = createHomomorphicTallyManager('election-1');
    const result = manager.generateKeyPair(2, 3);
    publicKey = result.publicKey.publicKey;
    chain.setElectionPublicKey(publicKey);

    manager.setPublicKey(manager.getPublicKey()!);
    const votes = [
      manager.encryptVote('option-a', 1, false),
      manager.encryptVote('option-a', 1, false),
      manager.encryptVote('option-a', 0, false),
      manager.encryptVote('option-a', 1, false),
    ];
    inputs = votesToMixnetFormat(votes);
  });

  describe('chain configuration', () => {
    it('should create chain with servers', () => {
      expect(chain.getServerCount()).toBe(3);
    });

    it('should add servers', () => {
      const newChain = new MixnetChain();
      expect(newChain.getServerCount()).toBe(0);

      newChain.addServer(createMixServer('server-1', 1));
      expect(newChain.getServerCount()).toBe(1);
    });

    it('should throw without election key', () => {
      const newChain = createMixnetChain(3);

      expect(() => newChain.mix(inputs, 'session')).toThrow('Election public key not set');
    });

    it('should throw with no servers', () => {
      const emptyChain = new MixnetChain();
      emptyChain.setElectionPublicKey(publicKey);

      expect(() => emptyChain.mix(inputs, 'session')).toThrow('No mix servers');
    });
  });

  describe('chain mixing', () => {
    it('should mix through all servers', () => {
      const result = chain.mix(inputs, 'session-1');

      expect(result.outputs).toHaveLength(4);
      expect(result.proof).toBeDefined();
    });

    it('should preserve input count', () => {
      const result = chain.mix(inputs, 'session-1');
      expect(result.outputs.length).toBe(inputs.length);
    });

    it('should generate mix results for each server', () => {
      chain.mix(inputs, 'session-1');
      const results = chain.getMixResults();

      expect(results).toHaveLength(3);
    });

    it('should chain commitments between servers', () => {
      chain.mix(inputs, 'session-1');
      const results = chain.getMixResults();

      // Output of server i should match input of server i+1
      for (let i = 0; i < results.length - 1; i++) {
        expect(results[i].outputCommitment).toBe(results[i + 1].inputCommitment);
      }
    });
  });

  describe('chain verification', () => {
    it('should verify valid chain', () => {
      chain.mix(inputs, 'session-1');

      expect(chain.verifyChain()).toBe(true);
    });

    it('should return false for empty results', () => {
      expect(chain.verifyChain()).toBe(false);
    });
  });
});

describe('verifyShuffleProof', () => {
  let manager: HomomorphicTallyManager;
  let publicKey: string;
  let server: MixServer;

  beforeEach(() => {
    manager = createHomomorphicTallyManager('election-1');
    const result = manager.generateKeyPair(2, 3);
    publicKey = result.publicKey.publicKey;

    server = createMixServer('server-1', 1);
    server.setElectionPublicKey(publicKey);
  });

  it('should verify valid proof', () => {
    manager.setPublicKey(manager.getPublicKey()!);
    const votes = votesToMixnetFormat([
      manager.encryptVote('option-a', 1, false),
      manager.encryptVote('option-a', 1, false),
    ]);

    const result = server.shuffle(votes, 'session-1');

    expect(verifyShuffleProof(result.proof, publicKey)).toBe(true);
  });

  it('should reject proof with wrong commitments', () => {
    manager.setPublicKey(manager.getPublicKey()!);
    const votes = votesToMixnetFormat([
      manager.encryptVote('option-a', 1, false),
      manager.encryptVote('option-a', 1, false),
    ]);

    const result = server.shuffle(votes, 'session-1');

    // Tamper with commitment
    const tamperedProof = {
      ...result.proof,
      reencryptionCommitments: result.proof.reencryptionCommitments.map(() => 'a'.repeat(66)),
    };

    expect(verifyShuffleProof(tamperedProof, publicKey)).toBe(false);
  });

  it('should reject proof with invalid response', () => {
    manager.setPublicKey(manager.getPublicKey()!);
    const votes = votesToMixnetFormat([
      manager.encryptVote('option-a', 1, false),
      manager.encryptVote('option-a', 1, false),
      manager.encryptVote('option-a', 1, false),
    ]);

    const result = server.shuffle(votes, 'session-1');

    // Tamper with response
    const tamperedProof = {
      ...result.proof,
      responses: result.proof.responses.map(r => ({
        ...r,
        reencryptionFactor: 'b'.repeat(64),
      })),
    };

    expect(verifyShuffleProof(tamperedProof, publicKey)).toBe(false);
  });
});

describe('utility functions', () => {
  describe('createMixnetCiphertext', () => {
    it('should create ciphertext with components', () => {
      const ct = createMixnetCiphertext('c1value', 'c2value', 'id-1');

      expect(ct.c1).toBe('c1value');
      expect(ct.c2).toBe('c2value');
      expect(ct.id).toBe('id-1');
    });

    it('should allow undefined id', () => {
      const ct = createMixnetCiphertext('c1', 'c2');

      expect(ct.id).toBeUndefined();
    });
  });

  describe('votesToMixnetFormat', () => {
    it('should convert votes to mixnet format', () => {
      const votes = [
        { c1: 'a', c2: 'b' },
        { c1: 'c', c2: 'd' },
      ];

      const mixnetVotes = votesToMixnetFormat(votes);

      expect(mixnetVotes).toHaveLength(2);
      expect(mixnetVotes[0].c1).toBe('a');
      expect(mixnetVotes[0].id).toBe('vote-0');
      expect(mixnetVotes[1].id).toBe('vote-1');
    });
  });

  describe('createMixServer', () => {
    it('should create server with config', () => {
      const server = createMixServer('my-server', 2, 'custom-key');

      expect(server.getConfig().id).toBe('my-server');
      expect(server.getConfig().position).toBe(2);
      expect(server.getConfig().publicKey).toBe('custom-key');
    });

    it('should generate key if not provided', () => {
      const server = createMixServer('server-x', 1);

      expect(server.getConfig().publicKey).toHaveLength(64);
    });
  });

  describe('createMixnetChain', () => {
    it('should create chain with specified servers', () => {
      const chain = createMixnetChain(5);

      expect(chain.getServerCount()).toBe(5);
    });
  });
});

describe('integration with homomorphic tallying', () => {
  it('should shuffle and decrypt correctly', () => {
    // Setup election
    const manager = createHomomorphicTallyManager('election-1');
    const { publicKey, keyShares } = manager.generateKeyPair(2, 3);

    // Create mix-net
    const chain = createMixnetChain(3);
    chain.setElectionPublicKey(publicKey.publicKey);

    // Cast votes
    const voteData = [1, 1, 0, 1, 0, 1, 1, 0, 0, 1] as const;
    const expectedSum = voteData.filter(v => v === 1).length;

    manager.setPublicKey(publicKey);
    const votes = voteData.map(v => manager.encryptVote('option-a', v as 0 | 1, false));

    // Mix the votes
    const mixnetVotes = votesToMixnetFormat(votes);
    const mixResult = chain.mix(mixnetVotes, 'election-session');

    // Verify mix chain
    expect(chain.verifyChain()).toBe(true);

    // Add mixed votes to manager for tallying
    manager.clear();
    for (const output of mixResult.outputs) {
      manager.addEncryptedVote({
        c1: output.c1,
        c2: output.c2,
        optionId: 'option-a',
      });
    }

    // Aggregate and decrypt
    manager.aggregateVotes();
    manager.generateDecryptionShare('option-a', keyShares[0]);
    manager.generateDecryptionShare('option-a', keyShares[1]);

    const result = manager.decryptTally('option-a');

    expect(result.count).toBe(expectedSum);
  });

  it('should handle large number of votes', () => {
    const manager = createHomomorphicTallyManager('election-2');
    const { publicKey, keyShares } = manager.generateKeyPair(2, 3);

    const chain = createMixnetChain(2);
    chain.setElectionPublicKey(publicKey.publicKey);

    // 50 votes
    const numVotes = 50;
    manager.setPublicKey(publicKey);
    const votes = Array.from({ length: numVotes }, (_, i) =>
      manager.encryptVote('option-a', (i % 2) as 0 | 1, false)
    );

    const mixResult = chain.mix(votesToMixnetFormat(votes), 'session');

    expect(mixResult.outputs).toHaveLength(numVotes);
    expect(chain.verifyChain()).toBe(true);
  });
});

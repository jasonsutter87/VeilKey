/**
 * Merkle Tree Tests
 *
 * Tests for Merkle tree construction, proof generation, and verification
 * for the Trustless Voting System.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  MerkleTree,
  SparseMerkleTree,
  createMerkleTree,
  hashData,
  verifyMerkleProof,
  type MerkleProof,
} from '../../../voting/merkle.js';

describe('MerkleTree', () => {
  let tree: MerkleTree;

  beforeEach(() => {
    tree = new MerkleTree();
  });

  describe('construction', () => {
    it('should create empty tree', () => {
      expect(tree.getLeaves()).toHaveLength(0);
    });

    it('should add single leaf', () => {
      const index = tree.addLeaf('hello');
      expect(index).toBe(0);
      expect(tree.getLeaves()).toHaveLength(1);
    });

    it('should add multiple leaves', () => {
      tree.addLeaf('leaf1');
      tree.addLeaf('leaf2');
      tree.addLeaf('leaf3');

      expect(tree.getLeaves()).toHaveLength(3);
    });

    it('should add leaves in batch', () => {
      const indices = tree.addLeaves(['a', 'b', 'c', 'd']);

      expect(indices).toEqual([0, 1, 2, 3]);
      expect(tree.getLeaves()).toHaveLength(4);
    });

    it('should throw when building empty tree', () => {
      expect(() => tree.build()).toThrow('Cannot build tree with no leaves');
    });

    it('should build tree with single leaf', () => {
      tree.addLeaf('single');
      const root = tree.build();

      expect(root).toHaveLength(64); // SHA-256 = 32 bytes = 64 hex
    });

    it('should build tree with power-of-2 leaves', () => {
      tree.addLeaves(['a', 'b', 'c', 'd']);
      const root = tree.build();

      expect(root).toHaveLength(64);
    });

    it('should build tree with non-power-of-2 leaves', () => {
      tree.addLeaves(['a', 'b', 'c']);
      const root = tree.build();

      expect(root).toHaveLength(64);
    });

    it('should handle Uint8Array input', () => {
      const data = new Uint8Array([1, 2, 3, 4]);
      tree.addLeaf(data);
      const root = tree.build();

      expect(root).toHaveLength(64);
    });

    it('should produce deterministic root', () => {
      tree.addLeaves(['a', 'b', 'c', 'd']);
      const root1 = tree.build();

      const tree2 = new MerkleTree();
      tree2.addLeaves(['a', 'b', 'c', 'd']);
      const root2 = tree2.build();

      expect(root1).toBe(root2);
    });

    it('should produce different roots for different data', () => {
      tree.addLeaves(['a', 'b']);
      const root1 = tree.build();

      const tree2 = new MerkleTree();
      tree2.addLeaves(['a', 'c']);
      const root2 = tree2.build();

      expect(root1).not.toBe(root2);
    });
  });

  describe('root calculation', () => {
    it('should auto-build when getting root', () => {
      tree.addLeaves(['a', 'b', 'c', 'd']);
      const root = tree.getRoot();

      expect(root).toHaveLength(64);
    });

    it('should invalidate root on new leaf', () => {
      tree.addLeaves(['a', 'b']);
      const root1 = tree.getRoot();

      tree.addLeaf('c');
      const root2 = tree.getRoot();

      expect(root1).not.toBe(root2);
    });
  });

  describe('proof generation', () => {
    beforeEach(() => {
      tree.addLeaves(['leaf0', 'leaf1', 'leaf2', 'leaf3']);
      tree.build();
    });

    it('should generate proof for first leaf', () => {
      const proof = tree.getProof(0);

      expect(proof.leafIndex).toBe(0);
      expect(proof.leafHash).toHaveLength(64);
      expect(proof.siblings.length).toBeGreaterThan(0);
      expect(proof.root).toBe(tree.getRoot());
    });

    it('should generate proof for last leaf', () => {
      const proof = tree.getProof(3);

      expect(proof.leafIndex).toBe(3);
      expect(proof.root).toBe(tree.getRoot());
    });

    it('should generate proof for middle leaf', () => {
      const proof = tree.getProof(1);

      expect(proof.leafIndex).toBe(1);
      expect(proof.root).toBe(tree.getRoot());
    });

    it('should throw for invalid index', () => {
      expect(() => tree.getProof(-1)).toThrow('Invalid leaf index');
      expect(() => tree.getProof(4)).toThrow('Invalid leaf index');
    });

    it('should generate multiple proofs', () => {
      const proofs = tree.getProofs([0, 2]);

      expect(proofs).toHaveLength(2);
      expect(proofs[0].leafIndex).toBe(0);
      expect(proofs[1].leafIndex).toBe(2);
    });

    it('should include correct sibling positions', () => {
      const proof = tree.getProof(0);

      for (const sibling of proof.siblings) {
        expect(['left', 'right']).toContain(sibling.position);
        expect(sibling.hash).toHaveLength(64);
      }
    });
  });

  describe('proof verification', () => {
    beforeEach(() => {
      tree.addLeaves(['vote1', 'vote2', 'vote3', 'vote4']);
      tree.build();
    });

    it('should verify valid proof', () => {
      const proof = tree.getProof(0);
      const isValid = tree.verify(proof);

      expect(isValid).toBe(true);
    });

    it('should verify all leaf proofs', () => {
      for (let i = 0; i < 4; i++) {
        const proof = tree.getProof(i);
        expect(tree.verify(proof)).toBe(true);
      }
    });

    it('should reject proof with wrong leaf hash', () => {
      const proof = tree.getProof(0);
      proof.leafHash = 'a'.repeat(64); // Wrong hash

      expect(tree.verify(proof)).toBe(false);
    });

    it('should reject proof with wrong root', () => {
      const proof = tree.getProof(0);
      proof.root = 'b'.repeat(64); // Wrong root

      expect(tree.verify(proof)).toBe(false);
    });

    it('should reject proof with modified sibling', () => {
      const proof = tree.getProof(0);
      if (proof.siblings.length > 0) {
        proof.siblings[0].hash = 'c'.repeat(64);
      }

      expect(tree.verify(proof)).toBe(false);
    });

    it('should verify using static method', () => {
      const proof = tree.getProof(1);
      const isValid = MerkleTree.verifyProof(proof);

      expect(isValid).toBe(true);
    });
  });

  describe('leaf operations', () => {
    beforeEach(() => {
      tree.addLeaves(['a', 'b', 'c']);
      tree.build();
    });

    it('should get leaf by index', () => {
      const leaf = tree.getLeaf(0);

      expect(leaf).toBeDefined();
      expect(leaf?.hash).toHaveLength(64);
      expect(leaf?.index).toBe(0);
    });

    it('should return undefined for invalid index', () => {
      expect(tree.getLeaf(99)).toBeUndefined();
    });

    it('should get leaf by hash', () => {
      const leaf = tree.getLeaf(1);
      const foundLeaf = tree.getLeafByHash(leaf!.hash);

      expect(foundLeaf).toBeDefined();
      expect(foundLeaf?.index).toBe(1);
    });

    it('should return undefined for unknown hash', () => {
      expect(tree.getLeafByHash('unknown')).toBeUndefined();
    });

    it('should check if leaf exists', () => {
      const leaf = tree.getLeaf(0);

      expect(tree.containsLeaf(leaf!.hash)).toBe(true);
      expect(tree.containsLeaf('nonexistent')).toBe(false);
    });
  });

  describe('tree statistics', () => {
    it('should calculate stats for small tree', () => {
      tree.addLeaves(['a', 'b', 'c', 'd']);
      const stats = tree.getStats();

      expect(stats.leafCount).toBe(4);
      expect(stats.height).toBe(3); // 2 levels + root
      expect(stats.nodeCount).toBe(7); // 4 + 2 + 1
      expect(stats.root).toHaveLength(64);
    });

    it('should calculate stats for odd leaf count', () => {
      tree.addLeaves(['a', 'b', 'c']);
      const stats = tree.getStats();

      expect(stats.leafCount).toBe(3);
      expect(stats.height).toBe(3);
    });
  });

  describe('layer access', () => {
    beforeEach(() => {
      tree.addLeaves(['a', 'b', 'c', 'd']);
      tree.build();
    });

    it('should get leaf layer', () => {
      const layer = tree.getLayer(0);

      expect(layer).toHaveLength(4);
    });

    it('should get intermediate layer', () => {
      const layer = tree.getLayer(1);

      expect(layer).toHaveLength(2);
    });

    it('should get root layer', () => {
      const layer = tree.getLayer(2);

      expect(layer).toHaveLength(1);
      expect(layer[0].hash).toBe(tree.getRoot());
    });

    it('should throw for invalid layer', () => {
      expect(() => tree.getLayer(-1)).toThrow('Invalid layer level');
      expect(() => tree.getLayer(10)).toThrow('Invalid layer level');
    });
  });

  describe('options', () => {
    it('should sort leaves when configured', () => {
      const sortedTree = new MerkleTree({ sortLeaves: true });
      sortedTree.addLeaves(['c', 'a', 'b']);
      sortedTree.build();

      const unsortedTree = new MerkleTree({ sortLeaves: false });
      unsortedTree.addLeaves(['c', 'a', 'b']);
      unsortedTree.build();

      // Different order should produce different roots
      expect(sortedTree.getRoot()).not.toBe(unsortedTree.getRoot());
    });

    it('should handle duplicateOdd option', () => {
      const dupTree = new MerkleTree({ duplicateOdd: true });
      dupTree.addLeaves(['a', 'b', 'c']);
      dupTree.build();

      const noDupTree = new MerkleTree({ duplicateOdd: false });
      noDupTree.addLeaves(['a', 'b', 'c']);
      noDupTree.build();

      // Different handling may produce different roots
      // Both should work correctly
      expect(dupTree.getRoot()).toHaveLength(64);
      expect(noDupTree.getRoot()).toHaveLength(64);
    });
  });

  describe('serialization', () => {
    it('should export tree state', () => {
      tree.addLeaves(['a', 'b', 'c', 'd']);
      tree.build();

      const exported = tree.export();

      expect(exported.leaves).toHaveLength(4);
      expect(exported.root).toBe(tree.getRoot());
      expect(exported.options).toBeDefined();
    });

    it('should import tree state', () => {
      tree.addLeaves(['a', 'b', 'c', 'd']);
      tree.build();

      const exported = tree.export();
      const imported = MerkleTree.import(exported);

      expect(imported.getRoot()).toBe(tree.getRoot());
      expect(imported.getLeaves()).toHaveLength(4);
    });

    it('should preserve verification after import', () => {
      tree.addLeaves(['a', 'b', 'c', 'd']);
      tree.build();

      const proof = tree.getProof(2);
      const exported = tree.export();
      const imported = MerkleTree.import(exported);

      expect(imported.verify(proof)).toBe(true);
    });
  });
});

describe('SparseMerkleTree', () => {
  let tree: SparseMerkleTree;

  beforeEach(() => {
    tree = new SparseMerkleTree(16); // 16 levels deep
  });

  describe('construction', () => {
    it('should create tree with specified depth', () => {
      expect(tree.getDepth()).toBe(16);
    });

    it('should have default root for empty tree', () => {
      const root = tree.getRoot();

      expect(root).toHaveLength(64);
    });

    it('should reject invalid depth', () => {
      expect(() => new SparseMerkleTree(0)).toThrow('Depth must be');
      expect(() => new SparseMerkleTree(257)).toThrow('Depth must be');
    });

    it('should accept depth 1', () => {
      const smallTree = new SparseMerkleTree(1);
      expect(smallTree.getDepth()).toBe(1);
    });

    it('should accept depth 256', () => {
      const largeTree = new SparseMerkleTree(256);
      expect(largeTree.getDepth()).toBe(256);
    });
  });

  describe('leaf operations', () => {
    it('should set leaf at index', () => {
      tree.set(0n, 'value0');

      expect(tree.get(0n)).toHaveLength(64);
    });

    it('should set leaf at large index', () => {
      tree.set(1000n, 'value1000');

      expect(tree.get(1000n)).toHaveLength(64);
      expect(tree.getLeafCount()).toBe(1);
    });

    it('should update root when setting leaf', () => {
      const emptyRoot = tree.getRoot();

      tree.set(0n, 'value');
      const newRoot = tree.getRoot();

      expect(newRoot).not.toBe(emptyRoot);
    });

    it('should track leaf count', () => {
      expect(tree.getLeafCount()).toBe(0);

      tree.set(0n, 'a');
      tree.set(100n, 'b');
      tree.set(1000n, 'c');

      expect(tree.getLeafCount()).toBe(3);
    });

    it('should return undefined for unset leaf', () => {
      expect(tree.get(999n)).toBeUndefined();
    });

    it('should reject out of range index', () => {
      const maxIndex = (1n << 16n) - 1n;

      expect(() => tree.set(-1n, 'value')).toThrow('Index out of range');
      expect(() => tree.set(maxIndex + 1n, 'value')).toThrow('Index out of range');
    });

    it('should accept max valid index', () => {
      const maxIndex = (1n << 16n) - 1n;
      tree.set(maxIndex, 'value');

      expect(tree.get(maxIndex)).toHaveLength(64);
    });
  });

  describe('proof generation', () => {
    beforeEach(() => {
      tree.set(0n, 'voter0');
      tree.set(5n, 'voter5');
      tree.set(100n, 'voter100');
    });

    it('should generate proof for existing leaf', () => {
      const proof = tree.getProof(0n);

      expect(proof.leafIndex).toBe(0);
      expect(proof.leafHash).toHaveLength(64);
      expect(proof.siblings).toHaveLength(16);
      expect(proof.root).toBe(tree.getRoot());
    });

    it('should generate proof for non-existing leaf', () => {
      const proof = tree.getProof(999n);

      expect(proof.leafIndex).toBe(999);
      // Leaf hash is default empty hash
      expect(proof.leafHash).toHaveLength(64);
      expect(proof.siblings).toHaveLength(16);
    });

    it('should include sibling positions', () => {
      const proof = tree.getProof(5n);

      for (const sibling of proof.siblings) {
        expect(['left', 'right']).toContain(sibling.position);
        expect(sibling.hash).toHaveLength(64);
      }
    });
  });

  describe('proof verification', () => {
    beforeEach(() => {
      tree.set(0n, 'ballot0');
      tree.set(1n, 'ballot1');
      tree.set(2n, 'ballot2');
    });

    it('should verify valid proof for existing leaf', () => {
      const proof = tree.getProof(0n);
      const isValid = tree.verify(proof);

      expect(isValid).toBe(true);
    });

    it('should verify proof for all set leaves', () => {
      for (let i = 0n; i <= 2n; i++) {
        const proof = tree.getProof(i);
        expect(tree.verify(proof)).toBe(true);
      }
    });

    it('should verify proof for empty leaf', () => {
      const proof = tree.getProof(999n);
      const isValid = tree.verify(proof);

      expect(isValid).toBe(true);
    });

    it('should reject tampered proof', () => {
      const proof = tree.getProof(0n);
      proof.leafHash = 'a'.repeat(64); // Valid hex but wrong hash

      expect(tree.verify(proof)).toBe(false);
    });
  });

  describe('sparse nature', () => {
    it('should efficiently handle sparse data', () => {
      // Set only a few leaves out of 2^16 possible
      tree.set(0n, 'first');
      tree.set(65535n, 'last');

      expect(tree.getLeafCount()).toBe(2);

      // Both should have valid proofs
      expect(tree.verify(tree.getProof(0n))).toBe(true);
      expect(tree.verify(tree.getProof(65535n))).toBe(true);
    });

    it('should produce different roots for different data', () => {
      tree.set(0n, 'a');
      const root1 = tree.getRoot();

      const tree2 = new SparseMerkleTree(16);
      tree2.set(0n, 'b');
      const root2 = tree2.getRoot();

      expect(root1).not.toBe(root2);
    });

    it('should handle updates to same index', () => {
      tree.set(0n, 'original');
      const root1 = tree.getRoot();

      tree.set(0n, 'updated');
      const root2 = tree.getRoot();

      expect(root1).not.toBe(root2);
      expect(tree.getLeafCount()).toBe(1);
    });
  });
});

describe('utility functions', () => {
  describe('createMerkleTree', () => {
    it('should create and build tree from data', () => {
      const tree = createMerkleTree(['a', 'b', 'c', 'd']);

      expect(tree.getRoot()).toHaveLength(64);
      expect(tree.getLeaves()).toHaveLength(4);
    });

    it('should accept options', () => {
      const tree = createMerkleTree(['c', 'a', 'b'], { sortLeaves: true });

      expect(tree.getRoot()).toHaveLength(64);
    });
  });

  describe('hashData', () => {
    it('should hash string data', () => {
      const hash = hashData('hello');

      expect(hash).toHaveLength(64);
    });

    it('should hash Uint8Array data', () => {
      const hash = hashData(new Uint8Array([1, 2, 3]));

      expect(hash).toHaveLength(64);
    });

    it('should produce consistent hashes', () => {
      const hash1 = hashData('test');
      const hash2 = hashData('test');

      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different data', () => {
      const hash1 = hashData('a');
      const hash2 = hashData('b');

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyMerkleProof', () => {
    it('should verify proof without tree instance', () => {
      const tree = createMerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(0);

      expect(verifyMerkleProof(proof)).toBe(true);
    });

    it('should reject invalid proof', () => {
      const tree = createMerkleTree(['a', 'b', 'c', 'd']);
      const proof = tree.getProof(0);
      proof.root = 'invalid'.repeat(8);

      expect(verifyMerkleProof(proof)).toBe(false);
    });
  });
});

describe('voting system integration', () => {
  it('should store encrypted ballots', () => {
    const tree = new MerkleTree();

    // Simulate encrypted ballot data
    const ballots = [
      JSON.stringify({ id: 'ballot1', ciphertext: 'enc1', nonce: 'n1' }),
      JSON.stringify({ id: 'ballot2', ciphertext: 'enc2', nonce: 'n2' }),
      JSON.stringify({ id: 'ballot3', ciphertext: 'enc3', nonce: 'n3' }),
    ];

    tree.addLeaves(ballots);
    tree.build();

    expect(tree.getRoot()).toHaveLength(64);
  });

  it('should generate audit proof for ballot', () => {
    const tree = new MerkleTree();

    const ballotData = JSON.stringify({
      id: 'my-ballot',
      ciphertext: 'encrypted-vote',
      timestamp: Date.now(),
    });

    const index = tree.addLeaf(ballotData);
    tree.addLeaves(['other1', 'other2', 'other3']);
    tree.build();

    const proof = tree.getProof(index);

    // Voter can verify their ballot is included
    expect(MerkleTree.verifyProof(proof)).toBe(true);
    expect(proof.root).toBe(tree.getRoot());
  });

  it('should detect tampering with ballot', () => {
    const tree = new MerkleTree();
    tree.addLeaves(['ballot1', 'ballot2', 'ballot3']);
    tree.build();

    const originalProof = tree.getProof(1);

    // Simulate tampering
    const tamperedTree = new MerkleTree();
    tamperedTree.addLeaves(['ballot1', 'tampered', 'ballot3']);
    tamperedTree.build();

    // Original proof should not verify against tampered tree root
    const tamperedProof = { ...originalProof, root: tamperedTree.getRoot() };
    expect(MerkleTree.verifyProof(tamperedProof)).toBe(false);
  });

  it('should support voter registry with sparse tree', () => {
    // Voter IDs can be assigned to specific indices
    const registry = new SparseMerkleTree(20); // Supports 2^20 voters

    // Register voters at their assigned indices
    registry.set(12345n, 'voter_commitment_hash_1');
    registry.set(67890n, 'voter_commitment_hash_2');

    // Generate proof that voter 12345 is registered
    const proof = registry.getProof(12345n);
    expect(registry.verify(proof)).toBe(true);

    // Non-registered voter has empty proof
    const emptyProof = registry.getProof(99999n);
    expect(registry.get(99999n)).toBeUndefined();
    expect(registry.verify(emptyProof)).toBe(true); // Valid proof of emptiness
  });
});

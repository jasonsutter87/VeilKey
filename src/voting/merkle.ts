/**
 * VeilKey Merkle Tree Utilities
 *
 * Provides Merkle tree construction, proof generation, and verification
 * for vote storage and audit trails in the Trustless Voting System.
 *
 * @module voting/merkle
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

/**
 * Merkle node in the tree
 */
export interface MerkleNode {
  hash: string;
  left?: MerkleNode;
  right?: MerkleNode;
  data?: Uint8Array;
  index?: number;
}

/**
 * Merkle proof for a leaf
 */
export interface MerkleProof {
  /** Leaf index (0-based) */
  leafIndex: number;

  /** Leaf hash */
  leafHash: string;

  /** Sibling hashes from leaf to root */
  siblings: MerkleProofSibling[];

  /** Root hash */
  root: string;
}

/**
 * Sibling in a Merkle proof
 */
export interface MerkleProofSibling {
  /** Sibling hash */
  hash: string;

  /** Position: 'left' or 'right' */
  position: 'left' | 'right';
}

/**
 * Merkle tree statistics
 */
export interface MerkleTreeStats {
  /** Total number of leaves */
  leafCount: number;

  /** Tree height (levels) */
  height: number;

  /** Total nodes in tree */
  nodeCount: number;

  /** Root hash */
  root: string;
}

/**
 * Options for Merkle tree construction
 */
export interface MerkleTreeOptions {
  /** Hash function to use (default: SHA-256) */
  hashFunction?: (data: Uint8Array) => Uint8Array;

  /** Sort leaves before building (for deterministic trees) */
  sortLeaves?: boolean;

  /** Duplicate last leaf for odd counts (vs using leaf as-is) */
  duplicateOdd?: boolean;
}

const DEFAULT_OPTIONS: Required<MerkleTreeOptions> = {
  hashFunction: sha256,
  sortLeaves: false,
  duplicateOdd: true,
};

/**
 * Merkle Tree
 *
 * Efficient implementation supporting:
 * - Incremental leaf addition
 * - Proof generation and verification
 * - Sparse tree support
 * - Audit trail integration
 */
export class MerkleTree {
  private options: Required<MerkleTreeOptions>;
  private leaves: MerkleNode[] = [];
  private root: MerkleNode | null = null;
  private layers: MerkleNode[][] = [];

  constructor(options: MerkleTreeOptions = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
  }

  /**
   * Add a leaf to the tree
   */
  addLeaf(data: Uint8Array | string): number {
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hash = bytesToHex(this.options.hashFunction(bytes));

    const node: MerkleNode = {
      hash,
      data: bytes,
      index: this.leaves.length,
    };

    this.leaves.push(node);
    this.root = null; // Invalidate cached root
    this.layers = [];

    return node.index!;
  }

  /**
   * Add multiple leaves at once
   */
  addLeaves(dataItems: (Uint8Array | string)[]): number[] {
    return dataItems.map(data => this.addLeaf(data));
  }

  /**
   * Build the tree (or rebuild after modifications)
   */
  build(): string {
    if (this.leaves.length === 0) {
      throw new Error('Cannot build tree with no leaves');
    }

    // Sort leaves if configured
    let sortedLeaves = [...this.leaves];
    if (this.options.sortLeaves) {
      sortedLeaves = sortedLeaves.sort((a, b) => a.hash.localeCompare(b.hash));
      // Update indices after sorting
      sortedLeaves.forEach((leaf, i) => (leaf.index = i));
    }

    // Build layers from bottom up
    this.layers = [sortedLeaves];
    let currentLayer = sortedLeaves;

    while (currentLayer.length > 1) {
      const nextLayer: MerkleNode[] = [];

      for (let i = 0; i < currentLayer.length; i += 2) {
        const left = currentLayer[i];
        const right = currentLayer[i + 1] || (this.options.duplicateOdd ? left : null);

        if (right) {
          const combined = this.hashPair(left.hash, right.hash);
          nextLayer.push({
            hash: combined,
            left,
            right: right === left ? undefined : right,
          });
        } else {
          // Promote odd node as-is
          nextLayer.push({
            hash: left.hash,
            left,
          });
        }
      }

      this.layers.push(nextLayer);
      currentLayer = nextLayer;
    }

    this.root = currentLayer[0];
    return this.root.hash;
  }

  /**
   * Get the root hash
   */
  getRoot(): string {
    if (!this.root) {
      this.build();
    }
    return this.root!.hash;
  }

  /**
   * Generate a proof for a leaf at the given index
   */
  getProof(leafIndex: number): MerkleProof {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error(`Invalid leaf index: ${leafIndex}`);
    }

    if (!this.root) {
      this.build();
    }

    const siblings: MerkleProofSibling[] = [];
    let currentIndex = leafIndex;

    for (let layerIndex = 0; layerIndex < this.layers.length - 1; layerIndex++) {
      const layer = this.layers[layerIndex];
      const isRightNode = currentIndex % 2 === 1;
      const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;

      if (siblingIndex < layer.length) {
        siblings.push({
          hash: layer[siblingIndex].hash,
          position: isRightNode ? 'left' : 'right',
        });
      } else if (this.options.duplicateOdd) {
        // Odd node duplicates itself
        siblings.push({
          hash: layer[currentIndex].hash,
          position: 'right',
        });
      }

      currentIndex = Math.floor(currentIndex / 2);
    }

    return {
      leafIndex,
      leafHash: this.leaves[leafIndex].hash,
      siblings,
      root: this.root!.hash,
    };
  }

  /**
   * Generate proofs for multiple leaves
   */
  getProofs(leafIndices: number[]): MerkleProof[] {
    return leafIndices.map(index => this.getProof(index));
  }

  /**
   * Verify a proof
   */
  verify(proof: MerkleProof): boolean {
    return MerkleTree.verifyProof(proof, this.options.hashFunction);
  }

  /**
   * Static method to verify a proof without a tree instance
   */
  static verifyProof(
    proof: MerkleProof,
    hashFunction: (data: Uint8Array) => Uint8Array = sha256
  ): boolean {
    let currentHash = proof.leafHash;

    for (const sibling of proof.siblings) {
      const left = sibling.position === 'left' ? sibling.hash : currentHash;
      const right = sibling.position === 'left' ? currentHash : sibling.hash;

      const combined = new Uint8Array(64);
      combined.set(hexToBytes(left), 0);
      combined.set(hexToBytes(right), 32);

      currentHash = bytesToHex(hashFunction(combined));
    }

    return currentHash === proof.root;
  }

  /**
   * Get leaf by index
   */
  getLeaf(index: number): MerkleNode | undefined {
    return this.leaves[index];
  }

  /**
   * Get leaf by hash
   */
  getLeafByHash(hash: string): MerkleNode | undefined {
    return this.leaves.find(leaf => leaf.hash === hash);
  }

  /**
   * Get all leaves
   */
  getLeaves(): MerkleNode[] {
    return [...this.leaves];
  }

  /**
   * Get tree statistics
   */
  getStats(): MerkleTreeStats {
    if (!this.root) {
      this.build();
    }

    let nodeCount = 0;
    for (const layer of this.layers) {
      nodeCount += layer.length;
    }

    return {
      leafCount: this.leaves.length,
      height: this.layers.length,
      nodeCount,
      root: this.root!.hash,
    };
  }

  /**
   * Get a specific layer of the tree
   */
  getLayer(level: number): MerkleNode[] {
    if (!this.root) {
      this.build();
    }

    if (level < 0 || level >= this.layers.length) {
      throw new Error(`Invalid layer level: ${level}`);
    }

    return [...this.layers[level]];
  }

  /**
   * Check if a leaf exists in the tree
   */
  containsLeaf(hash: string): boolean {
    return this.leaves.some(leaf => leaf.hash === hash);
  }

  /**
   * Export tree state for serialization
   */
  export(): {
    leaves: string[];
    root: string;
    options: MerkleTreeOptions;
  } {
    return {
      leaves: this.leaves.map(l => bytesToHex(l.data!)),
      root: this.getRoot(),
      options: {
        sortLeaves: this.options.sortLeaves,
        duplicateOdd: this.options.duplicateOdd,
      },
    };
  }

  /**
   * Import tree state
   */
  static import(data: {
    leaves: string[];
    options?: MerkleTreeOptions;
  }): MerkleTree {
    const tree = new MerkleTree(data.options);
    // Import expects hex-encoded leaf data from export()
    for (const hexLeaf of data.leaves) {
      tree.addLeafBytes(hexToBytes(hexLeaf));
    }
    tree.build();
    return tree;
  }

  /**
   * Add a leaf as raw bytes (used for import)
   */
  private addLeafBytes(bytes: Uint8Array): number {
    const hash = bytesToHex(this.options.hashFunction(bytes));

    const node: MerkleNode = {
      hash,
      data: bytes,
      index: this.leaves.length,
    };

    this.leaves.push(node);
    this.root = null;
    this.layers = [];

    return node.index!;
  }

  /**
   * Hash two nodes together
   */
  private hashPair(left: string, right: string): string {
    const combined = new Uint8Array(64);
    combined.set(hexToBytes(left), 0);
    combined.set(hexToBytes(right), 32);
    return bytesToHex(this.options.hashFunction(combined));
  }
}

/**
 * Sparse Merkle Tree
 *
 * Fixed-depth tree with efficient proofs for sparse data.
 * Useful for large voter registries with known maximum size.
 */
export class SparseMerkleTree {
  private depth: number;
  private hashFunction: (data: Uint8Array) => Uint8Array;
  private leaves: Map<bigint, string> = new Map();
  private defaultHashes: string[];
  private root: string;
  // Cache for intermediate node hashes at each level
  private nodeCache: Map<bigint, string>[] = [];

  constructor(depth: number, hashFunction: (data: Uint8Array) => Uint8Array = sha256) {
    if (depth < 1 || depth > 256) {
      throw new Error('Depth must be between 1 and 256');
    }

    this.depth = depth;
    this.hashFunction = hashFunction;

    // Precompute default hashes for empty subtrees
    this.defaultHashes = this.computeDefaultHashes();
    this.root = this.defaultHashes[depth];

    // Initialize node cache for each level
    for (let i = 0; i <= depth; i++) {
      this.nodeCache[i] = new Map();
    }
  }

  /**
   * Set a leaf at the given index
   */
  set(index: bigint, value: Uint8Array | string): void {
    const maxIndex = (1n << BigInt(this.depth)) - 1n;
    if (index < 0n || index > maxIndex) {
      throw new Error(`Index out of range: ${index}`);
    }

    const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
    const hash = bytesToHex(this.hashFunction(bytes));

    this.leaves.set(index, hash);
    this.rebuildTree();
  }

  /**
   * Get the value hash at an index
   */
  get(index: bigint): string | undefined {
    return this.leaves.get(index);
  }

  /**
   * Get the root hash
   */
  getRoot(): string {
    return this.root;
  }

  /**
   * Generate a proof for an index
   */
  getProof(index: bigint): MerkleProof {
    const siblings: MerkleProofSibling[] = [];
    let currentIndex = index;

    for (let level = 0; level < this.depth; level++) {
      const isRight = (currentIndex & 1n) === 1n;
      const siblingIndex = isRight ? currentIndex - 1n : currentIndex + 1n;

      const siblingHash = this.getNodeHash(siblingIndex, level);
      siblings.push({
        hash: siblingHash,
        position: isRight ? 'left' : 'right',
      });

      currentIndex = currentIndex >> 1n;
    }

    const leafHash = this.leaves.get(index) ?? this.defaultHashes[0];

    return {
      leafIndex: Number(index),
      leafHash,
      siblings,
      root: this.root,
    };
  }

  /**
   * Verify a proof
   */
  verify(proof: MerkleProof): boolean {
    return MerkleTree.verifyProof(proof, this.hashFunction);
  }

  /**
   * Get tree depth
   */
  getDepth(): number {
    return this.depth;
  }

  /**
   * Get number of non-empty leaves
   */
  getLeafCount(): number {
    return this.leaves.size;
  }

  /**
   * Compute default hashes for empty subtrees
   */
  private computeDefaultHashes(): string[] {
    const hashes: string[] = [];

    // Level 0: empty leaf
    hashes[0] = bytesToHex(this.hashFunction(new Uint8Array(0)));

    // Each level: hash of two children
    for (let i = 1; i <= this.depth; i++) {
      const child = hashes[i - 1];
      const combined = new Uint8Array(64);
      combined.set(hexToBytes(child), 0);
      combined.set(hexToBytes(child), 32);
      hashes[i] = bytesToHex(this.hashFunction(combined));
    }

    return hashes;
  }

  /**
   * Get hash for a node at given index and level
   */
  private getNodeHash(index: bigint, level: number): string {
    if (level === 0) {
      return this.leaves.get(index) ?? this.defaultHashes[0];
    }

    // Check cache first
    const cached = this.nodeCache[level].get(index);
    if (cached !== undefined) {
      return cached;
    }

    // Return default hash for empty subtree
    return this.defaultHashes[level];
  }

  /**
   * Rebuild the tree from current leaves, caching all intermediate nodes
   */
  private rebuildTree(): void {
    // Clear caches
    for (let i = 0; i <= this.depth; i++) {
      this.nodeCache[i].clear();
    }

    if (this.leaves.size === 0) {
      this.root = this.defaultHashes[this.depth];
      return;
    }

    // Cache level 0 (leaves)
    for (const [index, hash] of this.leaves) {
      this.nodeCache[0].set(index, hash);
    }

    // Build from leaves up, caching each level
    let affectedIndices = new Set<bigint>(this.leaves.keys());

    for (let level = 0; level < this.depth; level++) {
      const parentIndices = new Set<bigint>();

      for (const index of affectedIndices) {
        const parentIndex = index >> 1n;
        if (parentIndices.has(parentIndex)) continue;
        parentIndices.add(parentIndex);

        const leftIndex = parentIndex << 1n;
        const rightIndex = leftIndex + 1n;

        const left = this.getNodeHash(leftIndex, level);
        const right = this.getNodeHash(rightIndex, level);

        const combined = new Uint8Array(64);
        combined.set(hexToBytes(left), 0);
        combined.set(hexToBytes(right), 32);

        const parentHash = bytesToHex(this.hashFunction(combined));
        this.nodeCache[level + 1].set(parentIndex, parentHash);
      }

      affectedIndices = parentIndices;
    }

    this.root = this.nodeCache[this.depth].get(0n) ?? this.defaultHashes[this.depth];
  }
}

/**
 * Create a Merkle tree from data items
 */
export function createMerkleTree(
  data: (Uint8Array | string)[],
  options?: MerkleTreeOptions
): MerkleTree {
  const tree = new MerkleTree(options);
  tree.addLeaves(data);
  tree.build();
  return tree;
}

/**
 * Hash data using SHA-256 (utility function)
 */
export function hashData(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return bytesToHex(sha256(bytes));
}

/**
 * Verify a Merkle proof (standalone function)
 */
export function verifyMerkleProof(proof: MerkleProof): boolean {
  return MerkleTree.verifyProof(proof);
}

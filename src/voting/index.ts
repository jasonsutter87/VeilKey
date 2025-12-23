/**
 * VeilKey Voting Module
 *
 * Cryptographic primitives for trustless voting systems including:
 * - Merkle tree storage and proofs
 * - Homomorphic vote tallying
 * - Verifiable shuffle (mix-net)
 * - Zero-knowledge voter eligibility proofs
 *
 * @module voting
 */

// Types
export * from './types.js';

// Merkle tree utilities
export {
  MerkleTree,
  SparseMerkleTree,
  createMerkleTree,
  hashData,
  verifyMerkleProof,
  type MerkleNode,
  type MerkleProof,
  type MerkleProofSibling,
  type MerkleTreeStats,
  type MerkleTreeOptions,
} from './merkle.js';

// Homomorphic vote tallying
export {
  HomomorphicTallyManager,
  createHomomorphicTallyManager,
  encryptVote,
  type HomomorphicPublicKey,
  type HomomorphicKeyShare,
  type EncryptedVote,
  type VoteProof,
  type ChaumPedersenProof,
  type EncryptedTally,
  type TallyDecryptionShare,
  type DecryptionProof,
  type DecryptedTally,
} from './homomorphic.js';

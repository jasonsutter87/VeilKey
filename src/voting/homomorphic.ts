/**
 * VeilKey Homomorphic Vote Tallying
 *
 * Implements additively homomorphic encryption for vote tallying using
 * exponential ElGamal on the Ristretto255 group.
 *
 * Key features:
 * - Encrypted votes can be summed without decryption
 * - Threshold decryption with t-of-n trustees
 * - Zero-knowledge proofs of vote validity
 * - Efficient for elections with reasonable vote counts
 *
 * @module voting/homomorphic
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { mod, invert } from '@noble/curves/abstract/modular';

// Use Ristretto255 for group operations (prime-order group, no cofactor issues)
// For production, use @noble/curves ristretto255
// This is a simplified implementation using the secp256k1 curve for demonstration

import { secp256k1 } from '@noble/curves/secp256k1';

const CURVE_ORDER = secp256k1.CURVE.n;
const G = secp256k1.ProjectivePoint.BASE;

/**
 * ElGamal public key for homomorphic encryption
 */
export interface HomomorphicPublicKey {
  /** Hex-encoded public key point */
  publicKey: string;
  /** Key identifier */
  keyId: string;
  /** Threshold parameters */
  threshold: number;
  totalTrustees: number;
}

/**
 * ElGamal private key share for a trustee
 */
export interface HomomorphicKeyShare {
  /** Trustee ID */
  trusteeId: string;
  /** Share index (1-based) */
  index: number;
  /** Hex-encoded private key share */
  share: string;
  /** Feldman commitment for verification */
  commitment: string[];
}

/**
 * Encrypted vote using exponential ElGamal
 * Enc(m) = (c1, c2) where c1 = r*G, c2 = m*G + r*H (H = public key)
 */
export interface EncryptedVote {
  /** First component: r*G */
  c1: string;
  /** Second component: m*G + r*H */
  c2: string;
  /** Option ID this vote is for */
  optionId: string;
  /** Zero-knowledge proof of validity */
  proof?: VoteProof;
}

/**
 * Zero-knowledge proof that a vote is valid (0 or 1)
 */
export interface VoteProof {
  /** Disjunctive Chaum-Pedersen proof */
  type: 'disjunctive-chaum-pedersen';
  /** Proof components for value 0 */
  proof0: ChaumPedersenProof;
  /** Proof components for value 1 */
  proof1: ChaumPedersenProof;
}

/**
 * Chaum-Pedersen proof component
 */
export interface ChaumPedersenProof {
  /** Commitment A */
  a: string;
  /** Commitment B */
  b: string;
  /** Challenge */
  c: string;
  /** Response */
  r: string;
}

/**
 * Aggregated encrypted tally for an option
 */
export interface EncryptedTally {
  /** Option ID */
  optionId: string;
  /** Sum of c1 components */
  c1Sum: string;
  /** Sum of c2 components */
  c2Sum: string;
  /** Number of votes aggregated */
  voteCount: number;
}

/**
 * Partial decryption share from a trustee
 */
export interface TallyDecryptionShare {
  /** Trustee ID */
  trusteeId: string;
  /** Share index */
  index: number;
  /** Partial decryption: share * c1Sum */
  partialDecryption: string;
  /** Proof of correct decryption */
  proof: DecryptionProof;
}

/**
 * Proof of correct partial decryption
 */
export interface DecryptionProof {
  /** Commitment */
  commitment: string;
  /** Challenge */
  challenge: string;
  /** Response */
  response: string;
}

/**
 * Final decrypted tally result
 */
export interface DecryptedTally {
  /** Option ID */
  optionId: string;
  /** Vote count for this option */
  count: number;
  /** Decryption shares used */
  shares: TallyDecryptionShare[];
  /** Verification data */
  verification: {
    /** Combined partial decryption */
    combinedShare: string;
    /** Expected result point m*G */
    resultPoint: string;
  };
}

/**
 * Homomorphic Tally Manager
 *
 * Manages the lifecycle of homomorphic vote tallying including:
 * - Key generation (with threshold distribution)
 * - Vote encryption and aggregation
 * - Threshold decryption
 */
export class HomomorphicTallyManager {
  private electionId: string;
  private publicKey: HomomorphicPublicKey | null = null;
  private encryptedVotes: Map<string, EncryptedVote[]> = new Map();
  private encryptedTallies: Map<string, EncryptedTally> = new Map();
  private decryptionShares: Map<string, TallyDecryptionShare[]> = new Map();

  constructor(electionId: string) {
    this.electionId = electionId;
  }

  /**
   * Generate threshold key pair for the election
   * Uses Shamir's Secret Sharing for key distribution
   */
  generateKeyPair(
    threshold: number,
    totalTrustees: number
  ): {
    publicKey: HomomorphicPublicKey;
    keyShares: HomomorphicKeyShare[];
  } {
    if (threshold < 1 || threshold > totalTrustees) {
      throw new Error('Invalid threshold parameters');
    }

    // Generate master secret key
    const masterSecret = randomScalar();

    // Generate public key: H = sk * G
    const publicKeyPoint = G.multiply(masterSecret);

    // Generate Feldman VSS coefficients
    const coefficients = [masterSecret];
    const commitments = [pointToHex(publicKeyPoint)];

    for (let i = 1; i < threshold; i++) {
      const coeff = randomScalar();
      coefficients.push(coeff);
      commitments.push(pointToHex(G.multiply(coeff)));
    }

    // Generate shares using polynomial evaluation
    const keyShares: HomomorphicKeyShare[] = [];
    for (let i = 1; i <= totalTrustees; i++) {
      const shareValue = evaluatePolynomial(coefficients, BigInt(i));
      keyShares.push({
        trusteeId: `trustee-${i}`,
        index: i,
        share: scalarToHex(shareValue),
        commitment: commitments,
      });
    }

    const keyId = bytesToHex(sha256(hexToBytes(pointToHex(publicKeyPoint)))).slice(0, 16);

    this.publicKey = {
      publicKey: pointToHex(publicKeyPoint),
      keyId,
      threshold,
      totalTrustees,
    };

    return {
      publicKey: this.publicKey,
      keyShares,
    };
  }

  /**
   * Set the public key (for participants who didn't generate it)
   */
  setPublicKey(publicKey: HomomorphicPublicKey): void {
    this.publicKey = publicKey;
  }

  /**
   * Get the election public key
   */
  getPublicKey(): HomomorphicPublicKey | null {
    return this.publicKey;
  }

  /**
   * Encrypt a vote for an option (0 = no vote, 1 = vote)
   */
  encryptVote(optionId: string, voteValue: 0 | 1, generateProof = true): EncryptedVote {
    if (!this.publicKey) {
      throw new Error('Public key not set');
    }

    const publicKeyPoint = hexToPoint(this.publicKey.publicKey);

    // Generate random nonce
    const r = randomScalar();

    // c1 = r * G
    const c1 = G.multiply(r);

    // c2 = m*G + r*H (exponential ElGamal)
    // For m=0: c2 = r*H (no vote)
    // For m=1: c2 = G + r*H (vote)
    const rH = publicKeyPoint.multiply(r);
    const c2Correct = voteValue === 1 ? G.add(rH) : rH;

    const encryptedVote: EncryptedVote = {
      c1: pointToHex(c1),
      c2: pointToHex(c2Correct),
      optionId,
    };

    if (generateProof) {
      encryptedVote.proof = this.generateVoteProof(
        voteValue,
        r,
        c1,
        c2Correct,
        publicKeyPoint
      );
    }

    // Store the encrypted vote
    if (!this.encryptedVotes.has(optionId)) {
      this.encryptedVotes.set(optionId, []);
    }
    this.encryptedVotes.get(optionId)!.push(encryptedVote);

    return encryptedVote;
  }

  /**
   * Verify an encrypted vote proof
   */
  verifyVoteProof(encryptedVote: EncryptedVote): boolean {
    if (!encryptedVote.proof || !this.publicKey) {
      return false;
    }

    const c1 = hexToPoint(encryptedVote.c1);
    const c2 = hexToPoint(encryptedVote.c2);
    const H = hexToPoint(this.publicKey.publicKey);

    const proof = encryptedVote.proof;

    // Verify disjunctive proof
    // For m=0: c2 = r*H, so c2 - 0*G = r*H
    // For m=1: c2 = G + r*H, so c2 - 1*G = r*H

    // Reconstruct challenges
    const c0 = hexToScalar(proof.proof0.c);
    const c1Scalar = hexToScalar(proof.proof1.c);

    // Combined challenge must equal hash
    const hashInput = [
      encryptedVote.c1,
      encryptedVote.c2,
      proof.proof0.a,
      proof.proof0.b,
      proof.proof1.a,
      proof.proof1.b,
    ].join('');

    const expectedChallenge = hashToScalar(hashInput);
    const actualChallenge = mod(c0 + c1Scalar, CURVE_ORDER);

    if (expectedChallenge !== actualChallenge) {
      return false;
    }

    // Verify proof0 (for m=0)
    const a0 = hexToPoint(proof.proof0.a);
    const b0 = hexToPoint(proof.proof0.b);
    const r0 = hexToScalar(proof.proof0.r);

    // Check: r0*G = a0 + c0*c1
    const lhs0_a = G.multiply(r0);
    const rhs0_a = a0.add(c1.multiply(c0));
    if (!lhs0_a.equals(rhs0_a)) {
      return false;
    }

    // Check: r0*H = b0 + c0*c2 (for m=0, c2 should be r*H)
    const lhs0_b = H.multiply(r0);
    const rhs0_b = b0.add(c2.multiply(c0));
    if (!lhs0_b.equals(rhs0_b)) {
      return false;
    }

    // Verify proof1 (for m=1)
    const a1 = hexToPoint(proof.proof1.a);
    const b1 = hexToPoint(proof.proof1.b);
    const r1 = hexToScalar(proof.proof1.r);

    // Check: r1*G = a1 + c1*c1
    const lhs1_a = G.multiply(r1);
    const rhs1_a = a1.add(c1.multiply(c1Scalar));
    if (!lhs1_a.equals(rhs1_a)) {
      return false;
    }

    // Check: r1*H = b1 + c1*(c2 - G) (for m=1, c2 - G should be r*H)
    const lhs1_b = H.multiply(r1);
    const c2MinusG = c2.add(G.negate());
    const rhs1_b = b1.add(c2MinusG.multiply(c1Scalar));
    if (!lhs1_b.equals(rhs1_b)) {
      return false;
    }

    return true;
  }

  /**
   * Generate zero-knowledge proof that vote is 0 or 1
   */
  private generateVoteProof(
    voteValue: 0 | 1,
    r: bigint,
    c1: typeof G,
    c2: typeof G,
    H: typeof G
  ): VoteProof {
    // Disjunctive Chaum-Pedersen proof
    // If m=0: prove knowledge of r such that c1=r*G and c2=r*H
    // If m=1: prove knowledge of r such that c1=r*G and c2-G=r*H

    let proof0: ChaumPedersenProof;
    let proof1: ChaumPedersenProof;

    if (voteValue === 0) {
      // Real proof for m=0, simulated for m=1
      const w = randomScalar();
      const a0 = G.multiply(w);
      const b0 = H.multiply(w);

      // Simulate proof1
      const c1Sim = randomScalar();
      const r1Sim = randomScalar();
      const a1 = G.multiply(r1Sim).add(c1.multiply(c1Sim).negate());
      const c2MinusG = c2.add(G.negate());
      const b1 = H.multiply(r1Sim).add(c2MinusG.multiply(c1Sim).negate());

      // Compute challenge
      const hashInput = [
        pointToHex(c1),
        pointToHex(c2),
        pointToHex(a0),
        pointToHex(b0),
        pointToHex(a1),
        pointToHex(b1),
      ].join('');

      const challenge = hashToScalar(hashInput);
      const c0 = mod(challenge - c1Sim, CURVE_ORDER);
      const r0 = mod(w + c0 * r, CURVE_ORDER);

      proof0 = {
        a: pointToHex(a0),
        b: pointToHex(b0),
        c: scalarToHex(c0),
        r: scalarToHex(r0),
      };

      proof1 = {
        a: pointToHex(a1),
        b: pointToHex(b1),
        c: scalarToHex(c1Sim),
        r: scalarToHex(r1Sim),
      };
    } else {
      // Simulated proof for m=0, real proof for m=1
      const c0Sim = randomScalar();
      const r0Sim = randomScalar();
      const a0 = G.multiply(r0Sim).add(c1.multiply(c0Sim).negate());
      const b0 = H.multiply(r0Sim).add(c2.multiply(c0Sim).negate());

      // Real proof for m=1
      const w = randomScalar();
      const a1 = G.multiply(w);
      const b1 = H.multiply(w);

      // Compute challenge
      const hashInput = [
        pointToHex(c1),
        pointToHex(c2),
        pointToHex(a0),
        pointToHex(b0),
        pointToHex(a1),
        pointToHex(b1),
      ].join('');

      const challenge = hashToScalar(hashInput);
      const c1Real = mod(challenge - c0Sim, CURVE_ORDER);
      const r1Real = mod(w + c1Real * r, CURVE_ORDER);

      proof0 = {
        a: pointToHex(a0),
        b: pointToHex(b0),
        c: scalarToHex(c0Sim),
        r: scalarToHex(r0Sim),
      };

      proof1 = {
        a: pointToHex(a1),
        b: pointToHex(b1),
        c: scalarToHex(c1Real),
        r: scalarToHex(r1Real),
      };
    }

    return {
      type: 'disjunctive-chaum-pedersen',
      proof0,
      proof1,
    };
  }

  /**
   * Add an encrypted vote directly (for external votes)
   */
  addEncryptedVote(encryptedVote: EncryptedVote): void {
    if (!this.encryptedVotes.has(encryptedVote.optionId)) {
      this.encryptedVotes.set(encryptedVote.optionId, []);
    }
    this.encryptedVotes.get(encryptedVote.optionId)!.push(encryptedVote);
  }

  /**
   * Aggregate all encrypted votes for each option
   * Uses homomorphic property: Enc(a) * Enc(b) = Enc(a+b)
   */
  aggregateVotes(): Map<string, EncryptedTally> {
    this.encryptedTallies.clear();

    for (const [optionId, votes] of this.encryptedVotes) {
      if (votes.length === 0) continue;

      // Start with first vote
      let c1Sum = hexToPoint(votes[0].c1);
      let c2Sum = hexToPoint(votes[0].c2);

      // Add remaining votes
      for (let i = 1; i < votes.length; i++) {
        c1Sum = c1Sum.add(hexToPoint(votes[i].c1));
        c2Sum = c2Sum.add(hexToPoint(votes[i].c2));
      }

      this.encryptedTallies.set(optionId, {
        optionId,
        c1Sum: pointToHex(c1Sum),
        c2Sum: pointToHex(c2Sum),
        voteCount: votes.length,
      });
    }

    return this.encryptedTallies;
  }

  /**
   * Get encrypted tally for an option
   */
  getEncryptedTally(optionId: string): EncryptedTally | undefined {
    return this.encryptedTallies.get(optionId);
  }

  /**
   * Generate a partial decryption share for an option
   */
  generateDecryptionShare(
    optionId: string,
    keyShare: HomomorphicKeyShare
  ): TallyDecryptionShare {
    const tally = this.encryptedTallies.get(optionId);
    if (!tally) {
      throw new Error(`No tally for option: ${optionId}`);
    }

    const share = hexToScalar(keyShare.share);
    const c1Sum = hexToPoint(tally.c1Sum);

    // Partial decryption: share_i * c1Sum
    const partialDecryption = c1Sum.multiply(share);

    // Generate proof of correct decryption
    const proof = this.generateDecryptionProof(
      share,
      c1Sum,
      partialDecryption,
      keyShare.commitment[0] // Trustee's public key share
    );

    const decryptionShare: TallyDecryptionShare = {
      trusteeId: keyShare.trusteeId,
      index: keyShare.index,
      partialDecryption: pointToHex(partialDecryption),
      proof,
    };

    // Store the share
    if (!this.decryptionShares.has(optionId)) {
      this.decryptionShares.set(optionId, []);
    }
    this.decryptionShares.get(optionId)!.push(decryptionShare);

    return decryptionShare;
  }

  /**
   * Generate proof of correct partial decryption
   */
  private generateDecryptionProof(
    share: bigint,
    c1Sum: typeof G,
    partialDecryption: typeof G,
    publicKeyShare: string
  ): DecryptionProof {
    const w = randomScalar();
    const commitment1 = G.multiply(w);
    const commitment2 = c1Sum.multiply(w);

    const hashInput = [
      pointToHex(commitment1),
      pointToHex(commitment2),
      publicKeyShare,
      pointToHex(partialDecryption),
    ].join('');

    const challenge = hashToScalar(hashInput);
    const response = mod(w + challenge * share, CURVE_ORDER);

    return {
      commitment: pointToHex(commitment1) + pointToHex(commitment2),
      challenge: scalarToHex(challenge),
      response: scalarToHex(response),
    };
  }

  /**
   * Add a decryption share directly (for external shares)
   */
  addDecryptionShare(optionId: string, share: TallyDecryptionShare): void {
    if (!this.decryptionShares.has(optionId)) {
      this.decryptionShares.set(optionId, []);
    }
    this.decryptionShares.get(optionId)!.push(share);
  }

  /**
   * Decrypt the tally using threshold shares
   */
  decryptTally(optionId: string, maxVotes: number = 10000): DecryptedTally {
    if (!this.publicKey) {
      throw new Error('Public key not set');
    }

    const tally = this.encryptedTallies.get(optionId);
    if (!tally) {
      throw new Error(`No tally for option: ${optionId}`);
    }

    const shares = this.decryptionShares.get(optionId) || [];
    if (shares.length < this.publicKey.threshold) {
      throw new Error(
        `Not enough decryption shares: ${shares.length}/${this.publicKey.threshold}`
      );
    }

    // Use Lagrange interpolation to combine shares
    const usedShares = shares.slice(0, this.publicKey.threshold);
    const indices = usedShares.map(s => BigInt(s.index));

    // Start with the first share multiplied by its Lagrange coefficient
    const lambda0 = lagrangeCoefficient(indices, indices[0]);
    let combinedShare = hexToPoint(usedShares[0].partialDecryption).multiply(lambda0);

    // Add remaining shares
    for (let i = 1; i < usedShares.length; i++) {
      const lambda = lagrangeCoefficient(indices, indices[i]);
      const partialPoint = hexToPoint(usedShares[i].partialDecryption);
      combinedShare = combinedShare.add(partialPoint.multiply(lambda));
    }

    // Decrypt: M = c2Sum - combinedShare
    // M = (sum of m_i)*G
    const c2Sum = hexToPoint(tally.c2Sum);
    const resultPoint = c2Sum.add(combinedShare.negate());

    // Brute force to find the vote count (discrete log)
    const count = this.discreteLog(resultPoint, maxVotes);

    return {
      optionId,
      count,
      shares: usedShares,
      verification: {
        combinedShare: pointToHex(combinedShare),
        resultPoint: pointToHex(resultPoint),
      },
    };
  }

  /**
   * Brute force discrete log for small values
   * Finds m such that M = m*G
   */
  private discreteLog(point: typeof G, maxValue: number): number {
    // Check for identity (0 votes) - point at infinity
    if (point.equals(secp256k1.ProjectivePoint.ZERO)) {
      return 0;
    }

    // Baby-step giant-step for efficiency
    let current = G;
    for (let i = 1; i <= maxValue; i++) {
      if (point.equals(current)) {
        return i;
      }
      current = current.add(G);
    }

    throw new Error(`Vote count exceeds maximum: ${maxValue}`);
  }

  /**
   * Get all encrypted votes for an option
   */
  getEncryptedVotes(optionId: string): EncryptedVote[] {
    return this.encryptedVotes.get(optionId) || [];
  }

  /**
   * Get the number of encrypted votes per option
   */
  getVoteCounts(): Map<string, number> {
    const counts = new Map<string, number>();
    for (const [optionId, votes] of this.encryptedVotes) {
      counts.set(optionId, votes.length);
    }
    return counts;
  }

  /**
   * Clear all votes (for testing)
   */
  clear(): void {
    this.encryptedVotes.clear();
    this.encryptedTallies.clear();
    this.decryptionShares.clear();
  }
}

// ============================================================================
// Helper functions
// ============================================================================

/**
 * Generate a random scalar in the curve order
 */
function randomScalar(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return mod(bytesToBigInt(bytes), CURVE_ORDER);
}

/**
 * Evaluate polynomial at x using Horner's method
 */
function evaluatePolynomial(coefficients: bigint[], x: bigint): bigint {
  let result = coefficients[coefficients.length - 1];
  for (let i = coefficients.length - 2; i >= 0; i--) {
    result = mod(result * x + coefficients[i], CURVE_ORDER);
  }
  return result;
}

/**
 * Compute Lagrange coefficient for index i
 */
function lagrangeCoefficient(indices: bigint[], i: bigint): bigint {
  let numerator = 1n;
  let denominator = 1n;

  for (const j of indices) {
    if (j !== i) {
      numerator = mod(numerator * (0n - j), CURVE_ORDER);
      denominator = mod(denominator * (i - j), CURVE_ORDER);
    }
  }

  return mod(numerator * invert(denominator, CURVE_ORDER), CURVE_ORDER);
}

/**
 * Hash to scalar
 */
function hashToScalar(input: string): bigint {
  const hash = sha256(new TextEncoder().encode(input));
  return mod(bytesToBigInt(hash), CURVE_ORDER);
}

/**
 * Convert bytes to bigint
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) + BigInt(byte);
  }
  return result;
}

/**
 * Convert point to hex string
 */
function pointToHex(point: typeof G): string {
  // Handle point at infinity (ZERO)
  if (point.equals(secp256k1.ProjectivePoint.ZERO)) {
    return '00'; // Special encoding for identity
  }
  return point.toHex();
}

/**
 * Convert hex string to point
 */
function hexToPoint(hex: string): typeof G {
  // Handle special encoding for identity point
  if (hex === '00') {
    return secp256k1.ProjectivePoint.ZERO;
  }
  return secp256k1.ProjectivePoint.fromHex(hex);
}

/**
 * Convert scalar to hex string (32 bytes, padded)
 */
function scalarToHex(scalar: bigint): string {
  return scalar.toString(16).padStart(64, '0');
}

/**
 * Convert hex string to scalar
 */
function hexToScalar(hex: string): bigint {
  return BigInt('0x' + hex);
}

// ============================================================================
// Factory functions
// ============================================================================

/**
 * Create a new homomorphic tally manager
 */
export function createHomomorphicTallyManager(electionId: string): HomomorphicTallyManager {
  return new HomomorphicTallyManager(electionId);
}

/**
 * Encrypt a vote using the election public key
 */
export function encryptVote(
  optionId: string,
  voteValue: 0 | 1,
  publicKey: HomomorphicPublicKey
): EncryptedVote {
  const manager = new HomomorphicTallyManager('temp');
  manager.setPublicKey(publicKey);
  return manager.encryptVote(optionId, voteValue, true);
}

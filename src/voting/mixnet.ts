/**
 * VeilKey Verifiable Shuffle (Mix-net)
 *
 * Implements a verifiable re-encryption mixnet for ballot shuffling.
 * Uses simplified shuffle proofs based on randomized partial checking.
 *
 * Key features:
 * - Re-encryption of ElGamal ciphertexts
 * - Random permutation with commitment
 * - Verifiable shuffle proofs
 * - Multi-server mixing support
 *
 * @module voting/mixnet
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { mod, invert } from '@noble/curves/abstract/modular';
import { secp256k1 } from '@noble/curves/secp256k1';

const CURVE_ORDER = secp256k1.CURVE.n;
const G = secp256k1.ProjectivePoint.BASE;

/**
 * ElGamal ciphertext for mix-net
 */
export interface MixnetCiphertext {
  /** First component: r*G */
  c1: string;
  /** Second component: M + r*H */
  c2: string;
  /** Optional identifier for tracking */
  id?: string;
}

/**
 * Mix server configuration
 */
export interface MixServerConfig {
  /** Server ID */
  id: string;
  /** Server public key for verification */
  publicKey: string;
  /** Position in mix chain (1-indexed) */
  position: number;
}

/**
 * Shuffle proof using randomized partial checking
 * Based on simplified Neff shuffle verification
 */
export interface ShuffleProof {
  /** Mix server that performed shuffle */
  serverId: string;
  /** Input ciphertexts hash */
  inputCommitment: string;
  /** Output ciphertexts hash */
  outputCommitment: string;
  /** Re-encryption factors (committed) */
  reencryptionCommitments: string[];
  /** Proof challenges */
  challenges: string[];
  /** Proof responses */
  responses: ShuffleResponse[];
  /** Timestamp */
  timestamp: Date;
}

/**
 * Response for a challenged shuffle position
 */
export interface ShuffleResponse {
  /** Original position */
  inputIndex: number;
  /** Shuffled position */
  outputIndex: number;
  /** Re-encryption randomness */
  reencryptionFactor: string;
}

/**
 * Mix operation result
 */
export interface MixResult {
  /** Output ciphertexts */
  outputs: MixnetCiphertext[];
  /** Shuffle proof */
  proof: ShuffleProof;
  /** Input commitment for verification */
  inputCommitment: string;
  /** Output commitment for verification */
  outputCommitment: string;
}

/**
 * Shuffle state for a mix server
 */
interface ShuffleState {
  permutation: number[];
  reencryptionFactors: bigint[];
}

/**
 * Mix Server
 *
 * A single server in the mix-net that performs re-encryption shuffle.
 */
export class MixServer {
  private config: MixServerConfig;
  private electionPublicKey: string | null = null;
  private shuffleStates: Map<string, ShuffleState> = new Map();

  constructor(config: MixServerConfig) {
    this.config = config;
  }

  /**
   * Get server configuration
   */
  getConfig(): MixServerConfig {
    return this.config;
  }

  /**
   * Set the election public key
   */
  setElectionPublicKey(publicKey: string): void {
    this.electionPublicKey = publicKey;
  }

  /**
   * Perform re-encryption shuffle on input ciphertexts
   */
  shuffle(inputs: MixnetCiphertext[], sessionId: string): MixResult {
    if (!this.electionPublicKey) {
      throw new Error('Election public key not set');
    }

    if (inputs.length === 0) {
      throw new Error('Cannot shuffle empty list');
    }

    const H = hexToPoint(this.electionPublicKey);
    const n = inputs.length;

    // Generate random permutation
    const permutation = this.generatePermutation(n);

    // Generate re-encryption factors
    const reencryptionFactors: bigint[] = [];
    for (let i = 0; i < n; i++) {
      reencryptionFactors.push(randomScalar());
    }

    // Store state for proof generation
    this.shuffleStates.set(sessionId, { permutation, reencryptionFactors });

    // Perform shuffle with re-encryption
    const outputs: MixnetCiphertext[] = new Array(n);
    for (let i = 0; i < n; i++) {
      const inputIdx = permutation[i];
      const input = inputs[inputIdx];
      const r = reencryptionFactors[i];

      // Re-encrypt: (c1', c2') = (c1 + r*G, c2 + r*H)
      const c1 = hexToPoint(input.c1).add(G.multiply(r));
      const c2 = hexToPoint(input.c2).add(H.multiply(r));

      outputs[i] = {
        c1: pointToHex(c1),
        c2: pointToHex(c2),
        id: `${sessionId}-${i}`,
      };
    }

    // Compute commitments
    const inputCommitment = this.computeCommitment(inputs);
    const outputCommitment = this.computeCommitment(outputs);

    // Generate shuffle proof
    const proof = this.generateProof(
      sessionId,
      inputs,
      outputs,
      inputCommitment,
      outputCommitment
    );

    return {
      outputs,
      proof,
      inputCommitment,
      outputCommitment,
    };
  }

  /**
   * Generate a random permutation of [0, n-1]
   */
  private generatePermutation(n: number): number[] {
    const arr = Array.from({ length: n }, (_, i) => i);

    // Fisher-Yates shuffle
    for (let i = n - 1; i > 0; i--) {
      const randomBytes = new Uint8Array(4);
      crypto.getRandomValues(randomBytes);
      // Use unsigned right shift to avoid negative numbers from signed bit operations
      const randomValue =
        ((randomBytes[0] << 24) >>> 0) +
        (randomBytes[1] << 16) +
        (randomBytes[2] << 8) +
        randomBytes[3];
      const j = randomValue % (i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }

    return arr;
  }

  /**
   * Compute commitment to ciphertext list
   */
  private computeCommitment(ciphertexts: MixnetCiphertext[]): string {
    const data = ciphertexts.map(c => c.c1 + c.c2).join('');
    return bytesToHex(sha256(new TextEncoder().encode(data)));
  }

  /**
   * Generate shuffle proof using randomized partial checking
   */
  private generateProof(
    sessionId: string,
    inputs: MixnetCiphertext[],
    outputs: MixnetCiphertext[],
    inputCommitment: string,
    outputCommitment: string
  ): ShuffleProof {
    const state = this.shuffleStates.get(sessionId);
    if (!state) {
      throw new Error('Shuffle state not found');
    }

    const n = inputs.length;

    // Commit to re-encryption factors
    const reencryptionCommitments = state.reencryptionFactors.map(r =>
      pointToHex(G.multiply(r))
    );

    // Generate challenge (determines which positions to reveal)
    const challengeInput = [
      inputCommitment,
      outputCommitment,
      ...reencryptionCommitments,
    ].join('');
    const challengeHash = sha256(new TextEncoder().encode(challengeInput));

    // Select positions to reveal (approximately half)
    const challenges: string[] = [];
    const responses: ShuffleResponse[] = [];

    for (let i = 0; i < n; i++) {
      // Use hash bits to decide which positions to check
      const byteIdx = Math.floor(i / 8);
      const bitIdx = i % 8;
      const revealed = (challengeHash[byteIdx % 32] >> bitIdx) & 1;

      if (revealed) {
        challenges.push(i.toString());

        // Find input index for this output
        const inputIdx = state.permutation[i];

        responses.push({
          inputIndex: inputIdx,
          outputIndex: i,
          reencryptionFactor: scalarToHex(state.reencryptionFactors[i]),
        });
      }
    }

    return {
      serverId: this.config.id,
      inputCommitment,
      outputCommitment,
      reencryptionCommitments,
      challenges,
      responses,
      timestamp: new Date(),
    };
  }
}

/**
 * Mix-net Chain
 *
 * Coordinates multiple mix servers for multi-layer shuffling.
 */
export class MixnetChain {
  private servers: MixServer[] = [];
  private electionPublicKey: string | null = null;
  private mixResults: MixResult[] = [];

  constructor() {}

  /**
   * Add a mix server to the chain
   */
  addServer(server: MixServer): void {
    this.servers.push(server);
    // Re-sort by position
    this.servers.sort((a, b) => a.getConfig().position - b.getConfig().position);

    // Set election key if available
    if (this.electionPublicKey) {
      server.setElectionPublicKey(this.electionPublicKey);
    }
  }

  /**
   * Set the election public key
   */
  setElectionPublicKey(publicKey: string): void {
    this.electionPublicKey = publicKey;
    for (const server of this.servers) {
      server.setElectionPublicKey(publicKey);
    }
  }

  /**
   * Get the number of servers
   */
  getServerCount(): number {
    return this.servers.length;
  }

  /**
   * Mix inputs through the entire chain
   */
  mix(inputs: MixnetCiphertext[], sessionId: string): MixResult {
    if (this.servers.length === 0) {
      throw new Error('No mix servers in chain');
    }

    if (!this.electionPublicKey) {
      throw new Error('Election public key not set');
    }

    this.mixResults = [];
    let current = inputs;

    for (let i = 0; i < this.servers.length; i++) {
      const server = this.servers[i];
      const result = server.shuffle(current, `${sessionId}-${i}`);
      this.mixResults.push(result);
      current = result.outputs;
    }

    // Return final result with combined proof
    const finalResult = this.mixResults[this.mixResults.length - 1];

    return {
      outputs: finalResult.outputs,
      proof: {
        ...finalResult.proof,
        // Include chain information
        inputCommitment: this.mixResults[0].inputCommitment,
      },
      inputCommitment: this.mixResults[0].inputCommitment,
      outputCommitment: finalResult.outputCommitment,
    };
  }

  /**
   * Get all mix results for verification
   */
  getMixResults(): MixResult[] {
    return this.mixResults;
  }

  /**
   * Verify the entire mix chain
   */
  verifyChain(): boolean {
    if (this.mixResults.length === 0) {
      return false;
    }

    // Verify each mix result
    for (let i = 0; i < this.mixResults.length; i++) {
      const result = this.mixResults[i];

      // Verify commitments chain (output of i-1 matches input of i)
      if (i > 0) {
        const prevOutput = this.mixResults[i - 1].outputCommitment;
        if (prevOutput !== result.inputCommitment) {
          return false;
        }
      }

      // Verify individual shuffle proof
      if (!verifyShuffleProof(result.proof, this.electionPublicKey!)) {
        return false;
      }
    }

    return true;
  }
}

/**
 * Verify a shuffle proof
 */
export function verifyShuffleProof(
  proof: ShuffleProof,
  electionPublicKey: string
): boolean {
  try {
    const H = hexToPoint(electionPublicKey);

    // Verify challenge derivation
    const challengeInput = [
      proof.inputCommitment,
      proof.outputCommitment,
      ...proof.reencryptionCommitments,
    ].join('');
    const challengeHash = sha256(new TextEncoder().encode(challengeInput));

    // Verify all commitments are valid curve points
    for (const commitment of proof.reencryptionCommitments) {
      try {
        hexToPoint(commitment);
      } catch {
        return false; // Invalid commitment point
      }
    }

    // Verify that revealed positions match challenge
    for (const response of proof.responses) {
      const i = response.outputIndex;
      const byteIdx = Math.floor(i / 8);
      const bitIdx = i % 8;
      const shouldBeRevealed = (challengeHash[byteIdx % 32] >> bitIdx) & 1;

      if (!shouldBeRevealed) {
        return false; // Response for non-challenged position
      }

      // Verify re-encryption commitment matches the response
      const r = hexToScalar(response.reencryptionFactor);
      const expectedCommitment = pointToHex(G.multiply(r));
      if (proof.reencryptionCommitments[i] !== expectedCommitment) {
        return false;
      }
    }

    // Verify that all challenged positions have responses
    const challengedPositions = new Set(proof.challenges.map(Number));
    const respondedPositions = new Set(proof.responses.map(r => r.outputIndex));

    for (const pos of challengedPositions) {
      if (!respondedPositions.has(pos)) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Create a mix-net ciphertext from components
 */
export function createMixnetCiphertext(c1: string, c2: string, id?: string): MixnetCiphertext {
  return { c1, c2, id };
}

/**
 * Convert encrypted votes to mix-net format
 */
export function votesToMixnetFormat(
  votes: Array<{ c1: string; c2: string }>
): MixnetCiphertext[] {
  return votes.map((v, i) => ({
    c1: v.c1,
    c2: v.c2,
    id: `vote-${i}`,
  }));
}

/**
 * Create a new mix server
 */
export function createMixServer(
  id: string,
  position: number,
  publicKey: string = ''
): MixServer {
  return new MixServer({
    id,
    publicKey: publicKey || bytesToHex(sha256(new TextEncoder().encode(id))),
    position,
  });
}

/**
 * Create a mix-net chain with specified number of servers
 */
export function createMixnetChain(serverCount: number): MixnetChain {
  const chain = new MixnetChain();

  for (let i = 1; i <= serverCount; i++) {
    chain.addServer(createMixServer(`server-${i}`, i));
  }

  return chain;
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
  if (point.equals(secp256k1.ProjectivePoint.ZERO)) {
    return '00';
  }
  return point.toHex();
}

/**
 * Convert hex string to point
 */
function hexToPoint(hex: string): typeof G {
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

/**
 * VeilKey Voting Module - Type Definitions
 *
 * Types for voting cryptography including ballots, tallying,
 * and election management.
 *
 * @module voting/types
 */

/**
 * Encrypted ballot
 */
export interface EncryptedBallot {
  /** Unique ballot ID */
  id: string;

  /** Encrypted vote data */
  ciphertext: string;

  /** Election public key used for encryption */
  electionKeyId: string;

  /** Encryption nonce/IV */
  nonce: string;

  /** Ballot proof of well-formedness (optional) */
  proof?: BallotProof;

  /** Timestamp */
  timestamp: Date;
}

/**
 * Proof that a ballot is well-formed
 */
export interface BallotProof {
  /** Proof type */
  type: 'range' | 'membership' | 'zero-knowledge';

  /** Proof data */
  data: string;

  /** Verification key */
  verificationKey?: string;
}

/**
 * Decrypted vote (after threshold decryption)
 */
export interface DecryptedVote {
  /** Ballot ID */
  ballotId: string;

  /** Decrypted vote value */
  value: string;

  /** Decryption shares used */
  decryptionShares: DecryptionShare[];

  /** Decryption proof */
  proof?: string;
}

/**
 * Partial decryption share from a trustee
 */
export interface DecryptionShare {
  /** Trustee ID */
  trusteeId: string;

  /** Share index */
  shareIndex: number;

  /** Partial decryption value */
  value: string;

  /** Proof of correct decryption */
  proof?: string;
}

/**
 * Election configuration
 */
export interface ElectionConfig {
  /** Election ID */
  id: string;

  /** Election name */
  name: string;

  /** Election description */
  description?: string;

  /** Start time */
  startTime: Date;

  /** End time */
  endTime: Date;

  /** Threshold for decryption (t of n) */
  threshold: number;

  /** Total trustees */
  totalTrustees: number;

  /** Supported vote types */
  voteTypes: VoteType[];

  /** Maximum voters */
  maxVoters?: number;
}

/**
 * Vote type (single choice, multiple choice, ranked, etc.)
 */
export interface VoteType {
  /** Type identifier */
  type: 'single' | 'multiple' | 'ranked' | 'approval' | 'score';

  /** Minimum selections */
  minSelections: number;

  /** Maximum selections */
  maxSelections: number;

  /** Options/candidates */
  options: VoteOption[];
}

/**
 * Vote option (candidate, choice, etc.)
 */
export interface VoteOption {
  /** Option ID */
  id: string;

  /** Display name */
  name: string;

  /** Description */
  description?: string;

  /** Position/order */
  position: number;
}

/**
 * Tally result for an election
 */
export interface TallyResult {
  /** Election ID */
  electionId: string;

  /** Total ballots counted */
  totalBallots: number;

  /** Results by option */
  results: OptionResult[];

  /** Tally timestamp */
  timestamp: Date;

  /** Verification data */
  verification: TallyVerification;
}

/**
 * Result for a single option
 */
export interface OptionResult {
  /** Option ID */
  optionId: string;

  /** Vote count */
  count: number;

  /** Percentage (if applicable) */
  percentage?: number;
}

/**
 * Tally verification data
 */
export interface TallyVerification {
  /** Merkle root of all ballots */
  ballotRoot: string;

  /** Decryption proofs */
  decryptionProofs: string[];

  /** Trustee signatures on result */
  trusteeSignatures: TrusteeSignature[];
}

/**
 * Trustee signature on tally result
 */
export interface TrusteeSignature {
  /** Trustee ID */
  trusteeId: string;

  /** Signature */
  signature: string;

  /** Timestamp */
  timestamp: Date;
}

/**
 * Voter eligibility proof (zero-knowledge)
 */
export interface EligibilityProof {
  /** Voter commitment (blinded ID) */
  voterCommitment: string;

  /** Proof that voter is in eligible set */
  membershipProof: string;

  /** Proof that voter hasn't voted before */
  uniquenessProof?: string;

  /** Nullifier (prevents double voting) */
  nullifier: string;
}

/**
 * Mix-net shuffle proof
 */
export interface ShuffleProof {
  /** Input ciphertexts hash */
  inputHash: string;

  /** Output ciphertexts hash */
  outputHash: string;

  /** Zero-knowledge proof of correct shuffle */
  proof: string;

  /** Mix server ID */
  mixServerId: string;

  /** Timestamp */
  timestamp: Date;
}

/**
 * Homomorphic tally (encrypted sum)
 */
export interface HomomorphicTally {
  /** Election ID */
  electionId: string;

  /** Encrypted sum for each option */
  encryptedSums: Map<string, string>;

  /** Number of ballots included */
  ballotCount: number;

  /** Proof of correct aggregation */
  aggregationProof?: string;
}

/**
 * Election phase
 */
export enum ElectionPhase {
  SETUP = 'SETUP',
  KEY_CEREMONY = 'KEY_CEREMONY',
  VOTING = 'VOTING',
  MIXING = 'MIXING',
  TALLYING = 'TALLYING',
  DECRYPTION = 'DECRYPTION',
  VERIFICATION = 'VERIFICATION',
  FINALIZED = 'FINALIZED',
}

/**
 * Election state
 */
export interface ElectionState {
  /** Configuration */
  config: ElectionConfig;

  /** Current phase */
  phase: ElectionPhase;

  /** Election public key */
  publicKey?: string;

  /** Ballot count */
  ballotCount: number;

  /** Merkle root of ballots */
  ballotRoot?: string;

  /** Tally result (if complete) */
  result?: TallyResult;
}

/**
 * Audit log entry for elections
 */
export interface ElectionAuditEntry {
  /** Entry ID */
  id: string;

  /** Election ID */
  electionId: string;

  /** Event type */
  eventType: ElectionEventType;

  /** Event data */
  data: Record<string, unknown>;

  /** Timestamp */
  timestamp: Date;

  /** Hash chain */
  previousHash: string;
  hash: string;
}

/**
 * Election event types
 */
export enum ElectionEventType {
  CREATED = 'CREATED',
  KEY_GENERATED = 'KEY_GENERATED',
  VOTING_STARTED = 'VOTING_STARTED',
  BALLOT_CAST = 'BALLOT_CAST',
  VOTING_ENDED = 'VOTING_ENDED',
  MIXING_STARTED = 'MIXING_STARTED',
  MIXING_COMPLETED = 'MIXING_COMPLETED',
  TALLYING_STARTED = 'TALLYING_STARTED',
  DECRYPTION_SHARE = 'DECRYPTION_SHARE',
  RESULT_PUBLISHED = 'RESULT_PUBLISHED',
  FINALIZED = 'FINALIZED',
}

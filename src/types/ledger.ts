/**
 * @file src/types/ledger.ts
 * @description Core domain contracts for CyberProof BD.
 * Defines canonical block structures, evidence metadata, security events,
 * role-based access controls, and cryptographic verification reports.
 */

export type UserRole = 'admin' | 'investigator' | 'auditor';

export interface UserSession {
  userId: string;
  username: string;
  email: string;
  role: UserRole;
  organization: string;
}

export type EntryType =
  | 'GENESIS'
  | 'EVIDENCE_REGISTERED'
  | 'EVIDENCE_VERIFIED'
  | 'SECURITY_EVENT'
  | 'CHECKPOINT';

export type EventSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type EventCategory =
  | 'MALWARE_DETECTION'
  | 'UNAUTHORIZED_ACCESS'
  | 'DATA_EXFILTRATION'
  | 'INTEGRITY_VIOLATION'
  | 'SYSTEM_ANOMALY';

/**
 * Immutable Digital Evidence metadata stored in the operational vault
 * and committed to the ledger by its sha256_fingerprint.
 */
export interface EvidenceRecord {
  evidenceId: string;
  caseId: string;
  filename: string;
  fileSizeBytes: number;
  mimeType: string;
  sha256Fingerprint: string;
  custodianId: string;
  custodianName: string;
  acquiredAt: string; // ISO-8601 UTC
  registeredAt: string; // ISO-8601 UTC
  description: string;
  tags: string[];
}

/**
 * Security Event record committed to the ledger.
 */
export interface SecurityEventRecord {
  eventId: string;
  timestamp: string; // ISO-8601 UTC
  severity: EventSeverity;
  category: EventCategory;
  sourceIp?: string;
  destinationIp?: string;
  sourceHost?: string;
  actor?: string;
  title: string;
  description: string;
  evidenceRefId?: string; // Links event to registered evidence
  metadata: Record<string, unknown>;
}

/**
 * The Canonical Ledger Block.
 * Every field participates in deterministic serialization.
 */
export interface LedgerBlock {
  index: number;
  timestamp: string; // ISO-8601 UTC
  entryType: EntryType;
  entryId: string; // UUIDv4
  previousHash: string; // 64-char hex, or 64 zeros for Genesis
  payloadHash: string; // SHA-256 of canonically serialized payload
  blockHash: string; // SHA-256 of canonical header (index + timestamp + entryType + entryId + prevHash + payloadHash)
  payload: Record<string, unknown>;
  signature?: string; // Optional Ed25519 signature by authority
  signerPublicKey?: string;
}

/**
 * Report generated when verifying evidence against the ledger.
 */
export interface VerificationResult {
  verified: boolean;
  checkedAt: string;
  evidenceId?: string;
  computedHash: string;
  registeredHash?: string;
  status: 'MATCH' | 'TAMPERED' | 'NOT_FOUND';
  ledgerIndex?: number;
  blockHash?: string;
  discrepancies: string[];
}

/**
 * Full Ledger Audit & Integrity Report.
 */
export interface LedgerAuditReport {
  isValid: boolean;
  totalBlocks: number;
  checkedAt: string;
  genesisBlockHash: string;
  latestBlockHash: string;
  violations: {
    blockIndex: number;
    reason: string;
    expectedHash: string;
    actualHash: string;
  }[];
}

/**
 * Court-Admissible Forensic Certificate.
 */
export interface ForensicEvidenceCertificate {
  certificateId: string;
  issuedAt: string;
  issuingAuthority: {
    name: string;
    organization: string;
    publicKeyFingerprint: string;
  };
  evidenceSubject: {
    evidenceId: string;
    caseId: string;
    filename: string;
    fileSizeBytes: number;
    mimeType: string;
    sha256Fingerprint: string;
    custodian: string;
    acquiredAt: string;
    registeredAt: string;
  };
  ledgerAnchorProof: {
    blockIndex: number;
    entryType: string;
    blockHash: string;
    previousHash: string;
    payloadHash: string;
    committedTimestamp: string;
  };
  checkpointProof?: {
    checkpointId: string;
    authoritySignature: string;
    anchoredBlockHash: string;
  };
  integrityVerdict: {
    status: 'AUTHENTIC_AND_VERIFIED' | 'COMPROMISED' | 'PENDING';
    byteMatchConfirmed: boolean;
    chainContinuityConfirmed: boolean;
  };
  certificateSignature: string;
}


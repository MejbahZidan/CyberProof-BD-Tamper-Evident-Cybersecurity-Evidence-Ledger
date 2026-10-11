/**
 * @file server/store/evidenceVault.ts
 * @description Digital Evidence Vault Service for CyberProof BD.
 * Handles server-side byte ingestion, SHA-256 fingerprinting, secure local vault storage,
 * and immutable commitment of evidence records to the ledger.
 */

import fs from 'node:fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { sha256 } from '../crypto.ts';
import { ledgerStore } from './ledgerStore.ts';
import type {
  EvidenceRecord,
  VerificationResult,
} from '../../src/types/ledger.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const VAULT_DIR = path.resolve(__dirname, '../../data/vault');

export class EvidenceVault {
  constructor() {
    this.ensureVaultDirectory();
    this.seedDefaultEvidenceIfEmpty();
  }

  private ensureVaultDirectory() {
    if (!fs.existsSync(VAULT_DIR)) {
      fs.mkdirSync(VAULT_DIR, { recursive: true });
    }
  }

  /**
   * Seeds realistic synthetic forensic evidence for demonstrations if vault is empty
   */
  private async seedDefaultEvidenceIfEmpty() {
    const existing = ledgerStore.getAllEvidence();
    if (existing.length > 0) return;

    // Seed 1: Suspicious Memory Dump Excerpt
    const sample1Content = Buffer.from(
      'CYBERPROOF-FORENSIC-CAPTURE::HOST:PROD-SRV-01::TIMESTAMP:2026-10-10T22:15:00Z::PROCESS_ID:4102::SUSPICIOUS_PAYLOAD:INJECT_PAYLOAD_X86_64_STAGER',
      'utf-8'
    );
    await this.registerEvidence({
      caseId: 'CASE-2026-001',
      filename: 'memory_dump_pid4102.raw',
      mimeType: 'application/octet-stream',
      fileBytes: sample1Content,
      custodianId: 'usr-investigator-01',
      custodianName: 'fatima.forensics',
      acquiredAt: '2026-10-10T22:15:00.000Z',
      description: 'Volatile memory extraction from compromised authentication server.',
      tags: ['MEMORY', 'PID-4102', 'CRITICAL'],
    });

    // Seed 2: Network Traffic Capture Log
    const sample2Content = Buffer.from(
      'PCAP-DUMP-HEADER::FLOW:192.168.10.45:443->198.51.100.24:8443::BYTES:4289012::ALERT:UNUSUAL_EXTERNAL_EXFILTRATION_BEACON',
      'utf-8'
    );
    await this.registerEvidence({
      caseId: 'CASE-2026-001',
      filename: 'network_exfil_traffic.pcap',
      mimeType: 'application/vnd.tcpdump.pcap',
      fileBytes: sample2Content,
      custodianId: 'usr-investigator-01',
      custodianName: 'fatima.forensics',
      acquiredAt: '2026-10-10T23:30:00.000Z',
      description: 'Firewall tap egress capture showing encrypted beaconing channel.',
      tags: ['NETWORK', 'PCAP', 'EXFILTRATION'],
    });
  }

  /**
   * Registers a digital evidence file.
   * 1. Computes SHA-256 directly on server-side bytes (never trusts frontend).
   * 2. Sanitizes filename and writes to local vault storage.
   * 3. Creates immutable metadata record.
   * 4. Commits record to Ledger as an EVIDENCE_REGISTERED block.
   */
  public async registerEvidence(params: {
    caseId: string;
    filename: string;
    mimeType: string;
    fileBytes: Buffer;
    custodianId: string;
    custodianName: string;
    acquiredAt: string;
    description: string;
    tags: string[];
  }): Promise<{ record: EvidenceRecord; ledgerIndex: number }> {
    const evidenceId = `evid-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    // 1. Independent Server-Side SHA-256 Computation
    const sha256Fingerprint = sha256(params.fileBytes);
    const fileSizeBytes = params.fileBytes.length;

    // 2. Safe local file persistence in vault
    const safeExt = path.extname(params.filename) || '.bin';
    const vaultFilePath = path.join(VAULT_DIR, `${evidenceId}${safeExt}`);
    fs.writeFileSync(vaultFilePath, params.fileBytes);

    // 3. Assemble Metadata
    const record: EvidenceRecord = {
      evidenceId,
      caseId: params.caseId.trim(),
      filename: path.basename(params.filename).trim(),
      fileSizeBytes,
      mimeType: params.mimeType,
      sha256Fingerprint,
      custodianId: params.custodianId,
      custodianName: params.custodianName,
      acquiredAt: params.acquiredAt,
      registeredAt: new Date().toISOString(),
      description: params.description.trim(),
      tags: params.tags,
    };

    // Save to evidence operational store
    ledgerStore.saveEvidenceRecord(record);

    // 4. Commit to Append-Only Cryptographic Ledger
    const blockPayload = {
      action: 'EVIDENCE_REGISTERED',
      evidenceId: record.evidenceId,
      caseId: record.caseId,
      filename: record.filename,
      fileSizeBytes: record.fileSizeBytes,
      sha256Fingerprint: record.sha256Fingerprint,
      custodian: record.custodianName,
      registeredAt: record.registeredAt,
    };

    const block = await ledgerStore.appendBlock(
      'EVIDENCE_REGISTERED',
      evidenceId,
      blockPayload
    );

    return { record, ledgerIndex: block.index };
  }

  /**
   * Verifies candidate file bytes against a registered evidence record.
   * Independently computes SHA-256 of candidate bytes and checks against ledger fingerprint.
   * Records verification result to ledger as an EVIDENCE_VERIFIED block.
   */
  public async verifyEvidence(
    evidenceId: string,
    candidateBytes: Buffer,
    verifierUsername: string
  ): Promise<VerificationResult> {
    const record = ledgerStore.getEvidenceById(evidenceId);
    const computedHash = sha256(candidateBytes);

    if (!record) {
      return {
        verified: false,
        checkedAt: new Date().toISOString(),
        evidenceId,
        computedHash,
        status: 'NOT_FOUND',
        discrepancies: [`Evidence record with ID '${evidenceId}' does not exist in vault.`],
      };
    }

    const isMatch = computedHash === record.sha256Fingerprint;
    const discrepancies: string[] = [];

    if (!isMatch) {
      discrepancies.push(
        `Fingerprint mismatch: computed '${computedHash}' does not match registered ledger hash '${record.sha256Fingerprint}'`
      );
      if (candidateBytes.length !== record.fileSizeBytes) {
        discrepancies.push(
          `File size mismatch: candidate is ${candidateBytes.length} bytes, original was ${record.fileSizeBytes} bytes`
        );
      }
    }

    // Commit verification attempt to ledger for auditable provenance
    const verificationPayload = {
      action: 'EVIDENCE_VERIFICATION_ATTEMPT',
      evidenceId: record.evidenceId,
      verifier: verifierUsername,
      candidateHash: computedHash,
      registeredHash: record.sha256Fingerprint,
      result: isMatch ? 'MATCH' : 'TAMPERED',
      checkedAt: new Date().toISOString(),
    };

    const block = await ledgerStore.appendBlock(
      'EVIDENCE_VERIFIED',
      `verif-${Date.now()}`,
      verificationPayload
    );

    return {
      verified: isMatch,
      checkedAt: new Date().toISOString(),
      evidenceId: record.evidenceId,
      computedHash,
      registeredHash: record.sha256Fingerprint,
      status: isMatch ? 'MATCH' : 'TAMPERED',
      ledgerIndex: block.index,
      blockHash: block.blockHash,
      discrepancies,
    };
  }

  /**
   * Retrieves the raw bytes of a stored evidence file
   */
  public getStoredFileBytes(evidenceId: string): Buffer | null {
    const record = ledgerStore.getEvidenceById(evidenceId);
    if (!record) return null;

    const safeExt = path.extname(record.filename) || '.bin';
    const filePath = path.join(VAULT_DIR, `${evidenceId}${safeExt}`);
    if (fs.existsSync(filePath)) {
      return fs.readFileSync(filePath);
    }
    return null;
  }

  /**
   * SIMULATION ATTACK:
   * Deliberately flips one byte in the stored file on disk to simulate
   * an unauthorized modification by an attacker or corrupted sector.
   */
  public simulateFileTampering(evidenceId: string): boolean {
    const record = ledgerStore.getEvidenceById(evidenceId);
    if (!record) return false;

    const safeExt = path.extname(record.filename) || '.bin';
    const filePath = path.join(VAULT_DIR, `${evidenceId}${safeExt}`);
    if (!fs.existsSync(filePath)) return false;

    const bytes = fs.readFileSync(filePath);
    // Flip first byte or append altered byte
    if (bytes.length > 0) {
      bytes[0] = bytes[0] ^ 0xff; // Invert bits of first byte
    }
    fs.writeFileSync(filePath, bytes);
    return true;
  }
}

export const evidenceVault = new EvidenceVault();

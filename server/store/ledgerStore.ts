/**
 * @file server/store/ledgerStore.ts
 * @description Concurrency-safe, persistent Ledger Store for CyberProof BD.
 * Manages the append-only ledger chain, forensic evidence records, and security events.
 * Persists data to JSON storage with startup integrity verification.
 */

import fs from 'node:fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { sha256, hashCanonicalObject } from '../crypto.ts';
import type {
  LedgerBlock,
  EvidenceRecord,
  SecurityEventRecord,
  EntryType,
  LedgerAuditReport,
} from '../../src/types/ledger.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../../data');

// Files for persistent state
const LEDGER_FILE = path.join(DATA_DIR, 'ledger.json');
const EVIDENCE_FILE = path.join(DATA_DIR, 'evidence.json');
const EVENTS_FILE = path.join(DATA_DIR, 'events.json');

export class LedgerStore {
  private chain: LedgerBlock[] = [];
  private evidenceMap: Map<string, EvidenceRecord> = new Map();
  private eventsList: SecurityEventRecord[] = [];
  private isAppending = false; // Mutex flag for concurrency protection

  constructor() {
    this.ensureDataDirectory();
    this.loadState();
  }

  private ensureDataDirectory() {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
  }

  /**
   * Initializes or loads persisted ledger state from disk.
   * Runs startup verification to catch any offline disk corruption.
   */
  private loadState() {
    // 1. Load Ledger Chain
    if (fs.existsSync(LEDGER_FILE)) {
      try {
        const raw = fs.readFileSync(LEDGER_FILE, 'utf-8');
        this.chain = JSON.parse(raw);
        console.log(`[LedgerStore] Loaded ${this.chain.length} blocks from ${LEDGER_FILE}`);
      } catch (err) {
        console.error('[LedgerStore] Error reading ledger file, reinitializing:', err);
        this.chain = [];
      }
    }

    if (this.chain.length === 0) {
      // Create and commit Genesis block
      const genesis = this.generateGenesisBlock();
      this.chain.push(genesis);
      this.saveLedger();
    }

    // Verify integrity immediately on startup
    const audit = this.verifyFullChain();
    if (!audit.isValid) {
      console.warn('[LedgerStore] WARNING: Chain integrity violation detected at startup!', audit.violations);
    } else {
      console.log(`[LedgerStore] Chain integrity verified. Latest block: #${this.chain[this.chain.length - 1].index}`);
    }

    // 2. Load Evidence Map
    if (fs.existsSync(EVIDENCE_FILE)) {
      try {
        const raw = fs.readFileSync(EVIDENCE_FILE, 'utf-8');
        const items: EvidenceRecord[] = JSON.parse(raw);
        items.forEach((item) => this.evidenceMap.set(item.evidenceId, item));
      } catch (err) {
        console.error('[LedgerStore] Error reading evidence file:', err);
      }
    }

    // 3. Load Events List
    if (fs.existsSync(EVENTS_FILE)) {
      try {
        const raw = fs.readFileSync(EVENTS_FILE, 'utf-8');
        this.eventsList = JSON.parse(raw);
      } catch (err) {
        console.error('[LedgerStore] Error reading events file:', err);
      }
    }
  }

  private saveLedger() {
    fs.writeFileSync(LEDGER_FILE, JSON.stringify(this.chain, null, 2), 'utf-8');
  }

  private saveEvidence() {
    const list = Array.from(this.evidenceMap.values());
    fs.writeFileSync(EVIDENCE_FILE, JSON.stringify(list, null, 2), 'utf-8');
  }

  private saveEvents() {
    fs.writeFileSync(EVENTS_FILE, JSON.stringify(this.eventsList, null, 2), 'utf-8');
  }

  /**
   * Generates the immutable Genesis Block (#0)
   */
  private generateGenesisBlock(): LedgerBlock {
    const genesisPayload = {
      message: 'CyberProof BD Genesis Block - Immutable Evidence Ledger Initialized',
      architecture: 'Tamper-Evident Hash Chain',
      standard: 'SHA-256 Canonical JSON RFC-8785',
      authority: 'CyberProof Forensic Authority BD',
      createdAt: '2026-10-11T00:00:00.000Z',
    };

    const payloadHash = hashCanonicalObject(genesisPayload);
    const previousHash = '0'.repeat(64);
    const index = 0;
    const timestamp = '2026-10-11T00:00:00.000Z';
    const entryType: EntryType = 'GENESIS';
    const entryId = '00000000-0000-4000-8000-000000000000';

    const header = {
      index,
      timestamp,
      entryType,
      entryId,
      previousHash,
      payloadHash,
    };
    const blockHash = hashCanonicalObject(header);

    return {
      index,
      timestamp,
      entryType,
      entryId,
      previousHash,
      payloadHash,
      blockHash,
      payload: genesisPayload,
    };
  }

  /**
   * Concurrency-safe Append operation.
   * Acquires lock, computes deterministic hashes, links to previous block,
   * updates in-memory chain, and flushes atomically to persistent storage.
   */
  public async appendBlock(
    entryType: EntryType,
    entryId: string,
    payload: Record<string, unknown>,
    signature?: string
  ): Promise<LedgerBlock> {
    while (this.isAppending) {
      // Yield to avoid race conditions
      await new Promise((resolve) => setTimeout(resolve, 5));
    }

    this.isAppending = true;
    try {
      const latestBlock = this.chain[this.chain.length - 1];
      const index = latestBlock.index + 1;
      const timestamp = new Date().toISOString();
      const previousHash = latestBlock.blockHash;

      // 1. Canonical payload hashing
      const payloadHash = hashCanonicalObject(payload);

      // 2. Canonical block header hashing
      const header = {
        index,
        timestamp,
        entryType,
        entryId,
        previousHash,
        payloadHash,
      };
      const blockHash = hashCanonicalObject(header);

      const newBlock: LedgerBlock = {
        index,
        timestamp,
        entryType,
        entryId,
        previousHash,
        payloadHash,
        blockHash,
        payload,
        signature,
      };

      this.chain.push(newBlock);
      this.saveLedger();
      return newBlock;
    } finally {
      this.isAppending = false;
    }
  }

  /**
   * Verifies the entire ledger from Genesis to head.
   * Checks:
   * 1. Genesis block validity.
   * 2. Recalculates every payload_hash from payload.
   * 3. Recalculates every block_hash from canonical header.
   * 4. Verifies unbroken pointer linkage (block[N].previousHash === block[N-1].blockHash).
   * 5. Verifies monotonic sequence numbers (block[N].index === N).
   */
  public verifyFullChain(): LedgerAuditReport {
    const violations: LedgerAuditReport['violations'] = [];

    if (this.chain.length === 0) {
      return {
        isValid: false,
        totalBlocks: 0,
        checkedAt: new Date().toISOString(),
        genesisBlockHash: '',
        latestBlockHash: '',
        violations: [{
          blockIndex: 0,
          reason: 'Chain is empty. Missing Genesis Block.',
          expectedHash: '',
          actualHash: '',
        }],
      };
    }

    // Check Genesis Block
    const genesis = this.chain[0];
    if (genesis.index !== 0 || genesis.previousHash !== '0'.repeat(64)) {
      violations.push({
        blockIndex: 0,
        reason: 'Genesis block pointer violation: previousHash must be 64 zeros and index must be 0.',
        expectedHash: '0'.repeat(64),
        actualHash: genesis.previousHash,
      });
    }

    for (let i = 0; i < this.chain.length; i++) {
      const current = this.chain[i];

      // A. Verify Sequence Index
      if (current.index !== i) {
        violations.push({
          blockIndex: i,
          reason: `Sequence index broken. Expected index ${i}, found ${current.index}`,
          expectedHash: String(i),
          actualHash: String(current.index),
        });
      }

      // B. Recalculate and verify Payload Hash
      const recomputedPayloadHash = hashCanonicalObject(current.payload);
      if (recomputedPayloadHash !== current.payloadHash) {
        violations.push({
          blockIndex: i,
          reason: `Payload hash mismatch: Block payload was modified or tampered with.`,
          expectedHash: current.payloadHash,
          actualHash: recomputedPayloadHash,
        });
      }

      // C. Recalculate and verify Block Hash
      const header = {
        index: current.index,
        timestamp: current.timestamp,
        entryType: current.entryType,
        entryId: current.entryId,
        previousHash: current.previousHash,
        payloadHash: current.payloadHash,
      };
      const recomputedBlockHash = hashCanonicalObject(header);
      if (recomputedBlockHash !== current.blockHash) {
        violations.push({
          blockIndex: i,
          reason: `Block header hash mismatch: Block header or fields were modified.`,
          expectedHash: current.blockHash,
          actualHash: recomputedBlockHash,
        });
      }

      // D. Verify Previous Hash link for all blocks after Genesis
      if (i > 0) {
        const prev = this.chain[i - 1];
        if (current.previousHash !== prev.blockHash) {
          violations.push({
            blockIndex: i,
            reason: `Broken chain pointer: previousHash does not match Block #${i - 1} blockHash.`,
            expectedHash: prev.blockHash,
            actualHash: current.previousHash,
          });
        }
      }
    }

    return {
      isValid: violations.length === 0,
      totalBlocks: this.chain.length,
      checkedAt: new Date().toISOString(),
      genesisBlockHash: this.chain[0].blockHash,
      latestBlockHash: this.chain[this.chain.length - 1].blockHash,
      violations,
    };
  }

  // --- Read Operations ---
  public getBlocks(): LedgerBlock[] {
    return [...this.chain];
  }

  public getBlockByIndex(index: number): LedgerBlock | undefined {
    return this.chain[index];
  }

  public getLatestBlock(): LedgerBlock {
    return this.chain[this.chain.length - 1];
  }

  // --- Evidence Operations ---
  public saveEvidenceRecord(record: EvidenceRecord) {
    this.evidenceMap.set(record.evidenceId, record);
    this.saveEvidence();
  }

  public getEvidenceById(id: string): EvidenceRecord | undefined {
    return this.evidenceMap.get(id);
  }

  public getAllEvidence(): EvidenceRecord[] {
    return Array.from(this.evidenceMap.values());
  }

  // --- Security Event Operations ---
  public saveSecurityEvent(event: SecurityEventRecord) {
    this.eventsList.unshift(event);
    this.saveEvents();
  }

  public getAllEvents(): SecurityEventRecord[] {
    return [...this.eventsList];
  }

  /**
   * SIMULATION UTILITY FOR TESTING:
   * Deliberately modifies a block's payload to test tamper detection in Phase 5.
   */
  public simulateTampering(blockIndex: number, fakeField: string, fakeValue: unknown): boolean {
    if (blockIndex < 0 || blockIndex >= this.chain.length) return false;
    this.chain[blockIndex].payload[fakeField] = fakeValue;
    this.saveLedger();
    return true;
  }
}

// Global Singleton Instance
export const ledgerStore = new LedgerStore();

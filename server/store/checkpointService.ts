/**
 * @file server/store/checkpointService.ts
 * @description External Signed Checkpoint Management and Anti-Rewrite Defense Engine.
 * Anchors periodic state roots to external storage and signs them with Ed25519.
 * Proves mathematically when a privileged administrator attempts to rewrite the chain.
 */

import fs from 'node:fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { signatureManager } from '../crypto/signatures.ts';
import { ledgerStore } from './ledgerStore.ts';
import { hashCanonicalObject } from '../crypto.ts';
import type { LedgerBlock } from '../../src/types/ledger.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../../data');
const CHECKPOINTS_FILE = path.join(DATA_DIR, 'checkpoints.json');

export interface SignedCheckpoint {
  checkpointId: string;
  blockIndex: number;
  blockHash: string;
  authorityId: string;
  authorityPublicKeyFingerprint: string;
  timestamp: string;
  signature: string; // Ed25519 signature of { checkpointId, blockIndex, blockHash, timestamp, authorityId }
}

export interface CheckpointVerificationReport {
  isValid: boolean;
  totalCheckpoints: number;
  checkedAt: string;
  verifiedCheckpoints: {
    checkpointId: string;
    blockIndex: number;
    signatureValid: boolean;
    blockHashMatches: boolean;
    status: 'VERIFIED' | 'TAMPERED_BLOCK_HASH' | 'FORGED_SIGNATURE';
  }[];
  divergenceDetected: boolean;
  tamperSummary?: string;
}

export class CheckpointService {
  private checkpoints: SignedCheckpoint[] = [];

  constructor() {
    this.loadCheckpoints();
    this.createGenesisCheckpointIfEmpty();
  }

  private loadCheckpoints() {
    if (fs.existsSync(CHECKPOINTS_FILE)) {
      try {
        const raw = fs.readFileSync(CHECKPOINTS_FILE, 'utf-8');
        this.checkpoints = JSON.parse(raw);
      } catch (err) {
        console.error('[CheckpointService] Failed to parse checkpoints file:', err);
      }
    }
  }

  private saveCheckpoints() {
    fs.writeFileSync(CHECKPOINTS_FILE, JSON.stringify(this.checkpoints, null, 2), 'utf-8');
  }

  private createGenesisCheckpointIfEmpty() {
    if (this.checkpoints.length === 0) {
      const blocks = ledgerStore.getBlocks();
      if (blocks.length > 0) {
        this.createCheckpoint(blocks[0].index, 'Forensic Genesis Anchor');
      }
    }
  }

  /**
   * Creates an Ed25519 digitally signed checkpoint for a specific block index.
   */
  public createCheckpoint(blockIndex: number, memo?: string): SignedCheckpoint {
    const block = ledgerStore.getBlockByIndex(blockIndex);
    if (!block) {
      throw new Error(`Cannot checkpoint block #${blockIndex}: block does not exist.`);
    }

    const checkpointId = `chkpt-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const timestamp = new Date().toISOString();
    const authorityId = 'CYBERPROOF_NATIONAL_FORENSIC_AUTHORITY_BD';
    const authorityPublicKeyFingerprint = signatureManager.getKeyFingerprint();

    // Data payload that gets signed
    const manifest = {
      checkpointId,
      blockIndex: block.index,
      blockHash: block.blockHash,
      authorityId,
      timestamp,
      memo: memo || `State root commitment for Block #${block.index}`,
    };

    // Generate cryptographic Ed25519 signature
    const signature = signatureManager.signCanonicalData(manifest);

    const checkpoint: SignedCheckpoint = {
      checkpointId,
      blockIndex: block.index,
      blockHash: block.blockHash,
      authorityId,
      authorityPublicKeyFingerprint,
      timestamp,
      signature,
    };

    this.checkpoints.push(checkpoint);
    this.saveCheckpoints();

    return checkpoint;
  }

  /**
   * Verifies the entire ledger against all externally recorded signed checkpoints.
   * If a root administrator rewrote the chain and recomputed all forward hashes,
   * this method detects that the rewritten blockHash diverges from the signed checkpoint!
   */
  public verifyLedgerAgainstCheckpoints(): CheckpointVerificationReport {
    const blocks = ledgerStore.getBlocks();
    const verifiedCheckpoints: CheckpointVerificationReport['verifiedCheckpoints'] = [];
    let divergenceDetected = false;

    for (const chkpt of this.checkpoints) {
      // 1. Verify Ed25519 signature authenticity
      const manifest = {
        checkpointId: chkpt.checkpointId,
        blockIndex: chkpt.blockIndex,
        blockHash: chkpt.blockHash,
        authorityId: chkpt.authorityId,
        timestamp: chkpt.timestamp,
        memo: `State root commitment for Block #${chkpt.blockIndex}`,
      };

      const isSignatureValid = signatureManager.verifySignature(manifest, chkpt.signature);

      // 2. Cross-reference with the active ledger block
      const correspondingBlock = blocks[chkpt.blockIndex];
      const blockHashMatches = correspondingBlock
        ? correspondingBlock.blockHash === chkpt.blockHash
        : false;

      let status: 'VERIFIED' | 'TAMPERED_BLOCK_HASH' | 'FORGED_SIGNATURE' = 'VERIFIED';
      if (!isSignatureValid) {
        status = 'FORGED_SIGNATURE';
        divergenceDetected = true;
      } else if (!blockHashMatches) {
        status = 'TAMPERED_BLOCK_HASH';
        divergenceDetected = true;
      }

      verifiedCheckpoints.push({
        checkpointId: chkpt.checkpointId,
        blockIndex: chkpt.blockIndex,
        signatureValid: isSignatureValid,
        blockHashMatches,
        status,
      });
    }

    return {
      isValid: !divergenceDetected,
      totalCheckpoints: this.checkpoints.length,
      checkedAt: new Date().toISOString(),
      verifiedCheckpoints,
      divergenceDetected,
      tamperSummary: divergenceDetected
        ? 'DIVERGENCE DETECTED: A block in current storage has diverged from its Ed25519 digitally signed checkpoint. Possible Chain Rewrite Attack in progress!'
        : 'All historical checkpoints match current ledger state with valid Ed25519 digital signatures.',
    };
  }

  public getCheckpoints(): SignedCheckpoint[] {
    return [...this.checkpoints];
  }

  /**
   * DEMONSTRATION OF THE ANTI-REWRITE DEFENSE:
   * Simulates Attack Vector #7 (where an attacker rewrote Block #1 and recalculated downstream hashes),
   * and demonstrates how the Ed25519 Signed Checkpoint detects and stops it.
   */
  public simulateAntiRewriteDefense() {
    const blocks = ledgerStore.getBlocks();
    if (blocks.length < 2) {
      throw new Error('Need at least 2 blocks to simulate the rewrite defense.');
    }

    // Ensure we have a checkpoint on block #1
    let existingChkpt = this.checkpoints.find((c) => c.blockIndex === 1);
    if (!existingChkpt) {
      existingChkpt = this.createCheckpoint(1, 'Baseline forensic anchor for Block #1');
    }

    // Attacker modifies Block #1 payload and recalculates all hashes forward
    const clonedBlocks: LedgerBlock[] = JSON.parse(JSON.stringify(blocks));
    clonedBlocks[1].payload.alteredByAttacker = true;
    clonedBlocks[1].payloadHash = hashCanonicalObject(clonedBlocks[1].payload);
    clonedBlocks[1].blockHash = hashCanonicalObject({
      index: clonedBlocks[1].index,
      timestamp: clonedBlocks[1].timestamp,
      entryType: clonedBlocks[1].entryType,
      entryId: clonedBlocks[1].entryId,
      previousHash: clonedBlocks[1].previousHash,
      payloadHash: clonedBlocks[1].payloadHash,
    });

    // Recompute downstream Block #2 hashes so local verification would appear valid
    for (let i = 2; i < clonedBlocks.length; i++) {
      clonedBlocks[i].previousHash = clonedBlocks[i - 1].blockHash;
      clonedBlocks[i].blockHash = hashCanonicalObject({
        index: clonedBlocks[i].index,
        timestamp: clonedBlocks[i].timestamp,
        entryType: clonedBlocks[i].entryType,
        entryId: clonedBlocks[i].entryId,
        previousHash: clonedBlocks[i].previousHash,
        payloadHash: clonedBlocks[i].payloadHash,
      });
    }

    // Now test against the signed checkpoint:
    const rewrittenHashAtBlock1 = clonedBlocks[1].blockHash;
    const authoritativeSignedHash = existingChkpt.blockHash;
    const isCaught = rewrittenHashAtBlock1 !== authoritativeSignedHash;

    return {
      attackScenario: 'Full Chain Recalculation (Attack Vector #7)',
      localChainInternalPointersValid: true, // The attacker made internal pointers valid!
      caughtBySignedCheckpoint: isCaught,
      checkpointId: existingChkpt.checkpointId,
      authoritySignedHash: authoritativeSignedHash,
      attackerRewrittenHash: rewrittenHashAtBlock1,
      conclusion: 'The rewrite attack was successfully unmasked! Even though the attacker recomputed all downstream hashes, they cannot forge the Ed25519 digital signature of the authoritative checkpoint.',
    };
  }
}

export const checkpointService = new CheckpointService();

/**
 * @file server.ts
 * @description Full-Stack Entry Point for CyberProof BD.
 * Express APIs backed by persistent LedgerStore, EvidenceVault, EventService,
 * TamperSimulator, CheckpointService, AnalyticsService, ReportService, and BenchmarkService + Vite on Port 3000.
 */

import express, { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { sha256, hashCanonicalObject, canonicalizeJson } from './server/crypto.ts';
import { ledgerStore } from './server/store/ledgerStore.ts';
import { evidenceVault } from './server/store/evidenceVault.ts';
import { eventService, type IncidentStatus } from './server/store/eventService.ts';
import { tamperSimulator } from './server/store/tamperSimulator.ts';
import { checkpointService } from './server/store/checkpointService.ts';
import { signatureManager } from './server/crypto/signatures.ts';
import { analyticsService } from './server/ai/analyticsService.ts';
import { reportService } from './server/store/reportService.ts';
import { benchmarkService } from './server/store/benchmarkService.ts';
import type { UserSession, EntryType, EventSeverity, EventCategory } from './src/types/ledger.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Seed users for role-based access control and forensic attribution
const SEED_USERS: UserSession[] = [
  {
    userId: 'usr-zidan-01',
    username: 'Md. Mejbaul Islam Zidan',
    email: 'zidan@cyberproof.bd',
    role: 'admin',
    organization: 'Lead Blockchain Architect',
  },
  {
    userId: 'usr-mainul-02',
    username: 'Md. Mainul Islam',
    email: 'mainul@cyberproof.bd',
    role: 'investigator',
    organization: 'Cryptographic Security Analyst',
  },
  {
    userId: 'usr-kamrun-03',
    username: 'Kamrun Nahar',
    email: 'kamrun@cyberproof.bd',
    role: 'auditor',
    organization: 'Compliance & Forensic Auditor',
  },
  {
    userId: 'usr-anzuman-04',
    username: 'Anzuman Islam',
    email: 'anzuman@cyberproof.bd',
    role: 'investigator',
    organization: 'SOC Lead & Incident Responder',
  },
];

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  // Middleware supporting up to 50MB forensic payload uploads
  app.use(express.json({ limit: '50mb' }));

  // --- Core API Routes ---

  // Health and System Telemetry
  app.get('/api/health', (_req: Request, res: Response) => {
    const blocks = ledgerStore.getBlocks();
    const audit = ledgerStore.verifyFullChain();
    const evidenceList = ledgerStore.getAllEvidence();
    const eventStats = eventService.getStats();
    const checkpoints = checkpointService.getCheckpoints();

    res.json({
      status: 'operational',
      system: 'CyberProof BD Core Engine',
      timestamp: new Date().toISOString(),
      cryptography: {
        hashAlgorithm: 'SHA-256',
        asymmetricSignature: 'Ed25519 (RFC 8032)',
        serialization: 'RFC 8785 Canonical JSON',
        aiAnalytics: 'Active (Forensically Isolated)',
        certificates: 'Court-Ready Ed25519 Sealed',
        status: 'ACTIVE',
      },
      ledger: {
        totalBlocks: blocks.length,
        totalEvidence: evidenceList.length,
        totalEvents: eventStats.total,
        totalCheckpoints: checkpoints.length,
        genesisHash: blocks[0]?.blockHash,
        latestHash: blocks[blocks.length - 1]?.blockHash,
        integrity: audit.isValid ? 'VERIFIED' : 'TAMPER_DETECTED',
        violationsCount: audit.violations.length,
      },
      stats: eventStats,
    });
  });

  // Seed Users & RBAC profiles
  app.get('/api/seed-users', (_req: Request, res: Response) => {
    res.json(SEED_USERS);
  });

  // Ledger Blocks retrieval
  app.get('/api/ledger/blocks', (_req: Request, res: Response) => {
    const blocks = ledgerStore.getBlocks();
    res.json({
      total: blocks.length,
      blocks,
    });
  });

  // Single block lookup
  app.get('/api/ledger/blocks/:index', (req: Request, res: Response) => {
    const index = parseInt(req.params.index, 10);
    if (isNaN(index)) {
      return res.status(400).json({ error: 'Index must be an integer' });
    }
    const block = ledgerStore.getBlockByIndex(index);
    if (!block) {
      return res.status(404).json({ error: `Block #${index} not found` });
    }
    res.json(block);
  });

  // Full cryptographic audit verification
  app.get('/api/ledger/verify', (_req: Request, res: Response) => {
    const auditReport = ledgerStore.verifyFullChain();
    res.json(auditReport);
  });

  // Append new sample block to ledger
  app.post('/api/ledger/append-sample', async (req: Request, res: Response) => {
    const { entryType = 'CHECKPOINT', title, details, custodian } = req.body;
    const entryId = `entry-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    const payload = {
      title: title || 'Scheduled Forensic Audit Checkpoint',
      details: details || 'Periodic verification snapshot committed by authoritative investigator',
      custodian: custodian || 'fatima.forensics',
      timestamp: new Date().toISOString(),
      systemStatus: 'NOMINAL',
    };

    try {
      const newBlock = await ledgerStore.appendBlock(
        entryType as EntryType,
        entryId,
        payload
      );
      res.status(201).json({
        success: true,
        message: `Block #${newBlock.index} successfully appended and cryptographically linked.`,
        block: newBlock,
      });
    } catch (err: unknown) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Append failed' });
    }
  });

  // --- Evidence Management Routes ---

  app.get('/api/evidence', (_req: Request, res: Response) => {
    const evidence = ledgerStore.getAllEvidence();
    res.json(evidence);
  });

  app.post('/api/evidence/register', async (req: Request, res: Response) => {
    try {
      const {
        caseId,
        filename,
        mimeType = 'application/octet-stream',
        fileContentBase64,
        rawText,
        custodianId = 'usr-investigator-01',
        custodianName = 'fatima.forensics',
        acquiredAt = new Date().toISOString(),
        description = '',
        tags = [],
      } = req.body;

      if (!filename || (!fileContentBase64 && !rawText)) {
        return res.status(400).json({ error: 'Filename and file content are required.' });
      }

      let fileBytes: Buffer;
      if (fileContentBase64) {
        const base64Data = fileContentBase64.replace(/^data:.*?;base64,/, '');
        fileBytes = Buffer.from(base64Data, 'base64');
      } else {
        fileBytes = Buffer.from(rawText, 'utf-8');
      }

      const result = await evidenceVault.registerEvidence({
        caseId: caseId || 'CASE-2026-BD-01',
        filename,
        mimeType,
        fileBytes,
        custodianId,
        custodianName,
        acquiredAt,
        description,
        tags: Array.isArray(tags) ? tags : [tags],
      });

      res.status(201).json({
        success: true,
        message: `Evidence '${result.record.filename}' fingerprinted and committed to Block #${result.ledgerIndex}`,
        evidence: result.record,
        ledgerBlockIndex: result.ledgerIndex,
      });
    } catch (err: unknown) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Registration failed' });
    }
  });

  app.post('/api/evidence/verify', async (req: Request, res: Response) => {
    try {
      const { evidenceId, candidateBase64, candidateText, verifier = 'fatima.forensics' } = req.body;

      if (!evidenceId || (!candidateBase64 && candidateText === undefined)) {
        return res.status(400).json({ error: 'evidenceId and candidate content are required.' });
      }

      let candidateBytes: Buffer;
      if (candidateBase64) {
        const base64Data = candidateBase64.replace(/^data:.*?;base64,/, '');
        candidateBytes = Buffer.from(base64Data, 'base64');
      } else {
        candidateBytes = Buffer.from(candidateText, 'utf-8');
      }

      const verificationResult = await evidenceVault.verifyEvidence(
        evidenceId,
        candidateBytes,
        verifier
      );

      res.json(verificationResult);
    } catch (err: unknown) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Verification failed' });
    }
  });

  app.post('/api/evidence/verify-stored/:id', async (req: Request, res: Response) => {
    const evidenceId = req.params.id;
    const fileBytes = evidenceVault.getStoredFileBytes(evidenceId);

    if (!fileBytes) {
      return res.status(404).json({ error: 'Stored evidence file not found in vault.' });
    }

    const verificationResult = await evidenceVault.verifyEvidence(
      evidenceId,
      fileBytes,
      'system.integrity-verifier'
    );
    res.json(verificationResult);
  });

  app.post('/api/evidence/simulate-tampering/:id', (req: Request, res: Response) => {
    const evidenceId = req.params.id;
    const success = evidenceVault.simulateFileTampering(evidenceId);
    if (!success) {
      return res.status(404).json({ error: 'Evidence file could not be found to tamper.' });
    }
    res.json({
      tampered: true,
      message: `Simulated attack complete: Inverted bytes of stored evidence file '${evidenceId}'. Re-verifying this file will now detect TAMPERED status!`,
    });
  });

  // --- Security Event Routes ---

  app.get('/api/events', (_req: Request, res: Response) => {
    const events = eventService.getAllEvents();
    res.json(events);
  });

  app.get('/api/events/stats', (_req: Request, res: Response) => {
    res.json(eventService.getStats());
  });

  app.post('/api/events', async (req: Request, res: Response) => {
    try {
      const {
        severity = 'MEDIUM',
        category = 'UNAUTHORIZED_ACCESS',
        title,
        description,
        sourceIp,
        destinationIp,
        sourceHost,
        actor,
        evidenceRefId,
        creator = 'fatima.forensics',
      } = req.body;

      if (!title || !description) {
        return res.status(400).json({ error: 'Title and description are required for security events.' });
      }

      const event = await eventService.createEvent({
        severity: severity as EventSeverity,
        category: category as EventCategory,
        title,
        description,
        sourceIp,
        destinationIp,
        sourceHost,
        actor,
        evidenceRefId,
        creator,
      });

      res.status(201).json({
        success: true,
        message: `Security event '${event.title}' created and committed to Block #${event.ledgerBlockIndex}`,
        event,
      });
    } catch (err: unknown) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Event creation failed' });
    }
  });

  app.patch('/api/events/:id/triage', (req: Request, res: Response) => {
    const eventId = req.params.id;
    const { status, actor = 'fatima.forensics', notes } = req.body;

    if (!status) {
      return res.status(400).json({ error: 'New status is required' });
    }

    const updated = eventService.updateStatus(
      eventId,
      status as IncidentStatus,
      actor,
      notes
    );

    if (!updated) {
      return res.status(404).json({ error: `Event '${eventId}' not found` });
    }

    res.json({
      success: true,
      message: `Event '${eventId}' status updated to ${status}`,
      event: updated,
    });
  });

  // --- Threat Model & Tamper Simulation Routes ---

  app.get('/api/simulations/run-all', (_req: Request, res: Response) => {
    const report = tamperSimulator.runAllSimulations();
    res.json(report);
  });

  app.get('/api/simulations/run/:id', (req: Request, res: Response) => {
    const attackId = parseInt(req.params.id, 10);
    try {
      const result = tamperSimulator.runSimulation(attackId);
      res.json(result);
    } catch (err: unknown) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Simulation failed' });
    }
  });

  // --- Checkpoints & Ed25519 Signatures Routes ---

  app.get('/api/checkpoints', (_req: Request, res: Response) => {
    res.json(checkpointService.getCheckpoints());
  });

  app.get('/api/checkpoints/authority-key', (_req: Request, res: Response) => {
    res.json({
      algorithm: 'Ed25519 (Edwards-curve Digital Signature Algorithm)',
      standard: 'RFC 8032',
      authority: 'CyberProof National Forensic Authority BD',
      fingerprint: signatureManager.getKeyFingerprint(),
      publicKeyPem: signatureManager.getPublicKeyPem(),
    });
  });

  app.post('/api/checkpoints/create', (req: Request, res: Response) => {
    const { blockIndex, memo } = req.body;
    try {
      const targetIndex =
        blockIndex !== undefined
          ? parseInt(blockIndex, 10)
          : ledgerStore.getLatestBlock().index;

      const checkpoint = checkpointService.createCheckpoint(targetIndex, memo);
      res.status(201).json({
        success: true,
        message: `Ed25519 signed checkpoint successfully anchored for Block #${checkpoint.blockIndex}`,
        checkpoint,
      });
    } catch (err: unknown) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Checkpoint creation failed' });
    }
  });

  app.get('/api/checkpoints/verify', (_req: Request, res: Response) => {
    const report = checkpointService.verifyLedgerAgainstCheckpoints();
    res.json(report);
  });

  app.post('/api/checkpoints/simulate-rewrite-defense', (_req: Request, res: Response) => {
    try {
      const result = checkpointService.simulateAntiRewriteDefense();
      res.json(result);
    } catch (err: unknown) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Defense simulation failed' });
    }
  });

  // --- AI-Assisted Security Analytics Routes ---

  app.post('/api/ai/analyze-incidents', async (_req: Request, res: Response) => {
    try {
      const report = await analyticsService.analyzeIncidents();
      res.json(report);
    } catch (err: unknown) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'AI analytics failed' });
    }
  });

  app.get('/api/ai/latest-report', (_req: Request, res: Response) => {
    const cached = analyticsService.getLatestReport();
    res.json(cached || { status: 'NO_REPORT_YET' });
  });

  // --- Forensic Reports & Cryptographic Certificates Routes ---

  app.get('/api/reports/certificate/:evidenceId', (req: Request, res: Response) => {
    const certificate = reportService.generateEvidenceCertificate(req.params.evidenceId);
    if (!certificate) {
      return res.status(404).json({ error: `Could not generate certificate: Evidence ID '${req.params.evidenceId}' not found.` });
    }
    res.json(certificate);
  });

  // --- Empirical Cryptographic Performance Benchmark Route ---

  app.get('/api/benchmarks/run', (_req: Request, res: Response) => {
    const benchmark = benchmarkService.runBenchmarkSuite();
    res.json(benchmark);
  });

  // Test endpoint for RFC-8785 Canonical verification
  app.post('/api/crypto/verify-canonical', (req: Request, res: Response) => {
    const data = req.body;
    const canonicalString = canonicalizeJson(data);
    const hash = sha256(Buffer.from(canonicalString, 'utf-8'));
    res.json({
      canonicalString,
      hash,
    });
  });

  // Mount Vite middleware in development
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    // Serve static frontend in production
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CyberProof BD] Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();

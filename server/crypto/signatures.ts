/**
 * @file server/crypto/signatures.ts
 * @description Ed25519 Digital Signatures and Asymmetric Key Management.
 * Uses Node.js crypto module for high-speed, elliptic-curve digital signatures (RFC 8032).
 * Secures forensic checkpoints and eliminates the single-admin chain rewrite threat.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { canonicalizeJson } from '../crypto.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const KEYS_DIR = path.resolve(__dirname, '../../data/keys');
const PRIVATE_KEY_FILE = path.join(KEYS_DIR, 'authority_ed25519.pem');
const PUBLIC_KEY_FILE = path.join(KEYS_DIR, 'authority_ed25519_pub.pem');

export interface AuthorityKeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
  fingerprint: string;
}

export class SignatureManager {
  private keyPair: AuthorityKeyPair;

  constructor() {
    this.ensureKeyDirectory();
    this.keyPair = this.loadOrGenerateKeyPair();
  }

  private ensureKeyDirectory() {
    if (!fs.existsSync(KEYS_DIR)) {
      fs.mkdirSync(KEYS_DIR, { recursive: true });
    }
  }

  /**
   * Loads existing Ed25519 keys or generates a new pair on first run
   */
  private loadOrGenerateKeyPair(): AuthorityKeyPair {
    if (fs.existsSync(PRIVATE_KEY_FILE) && fs.existsSync(PUBLIC_KEY_FILE)) {
      const privateKeyPem = fs.readFileSync(PRIVATE_KEY_FILE, 'utf-8');
      const publicKeyPem = fs.readFileSync(PUBLIC_KEY_FILE, 'utf-8');
      const fingerprint = crypto
        .createHash('sha256')
        .update(publicKeyPem)
        .digest('hex');

      return { privateKeyPem, publicKeyPem, fingerprint };
    }

    // Generate new Ed25519 keypair
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });

    fs.writeFileSync(PRIVATE_KEY_FILE, privateKey, { mode: 0o600 });
    fs.writeFileSync(PUBLIC_KEY_FILE, publicKey, { mode: 0o644 });

    const fingerprint = crypto
      .createHash('sha256')
      .update(publicKey)
      .digest('hex');

    console.log(`[SignatureManager] Generated new Ed25519 Authority Keypair. Fingerprint: ${fingerprint.slice(0, 16)}...`);
    return { privateKeyPem: privateKey, publicKeyPem: publicKey, fingerprint };
  }

  public getPublicKeyPem(): string {
    return this.keyPair.publicKeyPem;
  }

  public getKeyFingerprint(): string {
    return this.keyPair.fingerprint;
  }

  /**
   * Signs arbitrary canonical data using the Ed25519 private key.
   * Returns base64-encoded signature.
   */
  public signCanonicalData(data: unknown): string {
    const canonicalString = canonicalizeJson(data);
    const buffer = Buffer.from(canonicalString, 'utf-8');
    const signature = crypto.sign(null, buffer, this.keyPair.privateKeyPem);
    return signature.toString('base64');
  }

  /**
   * Verifies an Ed25519 signature against canonical data using the public key.
   */
  public verifySignature(
    data: unknown,
    signatureBase64: string,
    publicKeyPem?: string
  ): boolean {
    try {
      const canonicalString = canonicalizeJson(data);
      const buffer = Buffer.from(canonicalString, 'utf-8');
      const sigBuffer = Buffer.from(signatureBase64, 'base64');
      const keyToUse = publicKeyPem || this.keyPair.publicKeyPem;

      return crypto.verify(null, buffer, keyToUse, sigBuffer);
    } catch (err) {
      console.error('[SignatureManager] Verification error:', err);
      return false;
    }
  }
}

export const signatureManager = new SignatureManager();

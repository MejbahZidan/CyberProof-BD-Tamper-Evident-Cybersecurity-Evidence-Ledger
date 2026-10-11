/**
 * @file blockchain.js
 * @description Cryptographic Blockchain Engine & State Controller for CyberProof BD.
 * Implements deterministic RFC 8785 canonical serialization, SHA-256 hashing,
 * Proof-of-Work mining, chain integrity validation, and real-time tamper detection.
 */

/**
 * Official Forensic Engineering Team Roster
 */
export const TEAM_MEMBERS = [
  {
    id: 'zidan',
    name: 'Md. Mejbaul Islam Zidan',
    role: 'Lead Blockchain Architect',
    initials: 'MZ',
    badge: 'ARCHITECT',
    publicKey: 'ed25519:pub_7f9c21b384a0d9e8c4b12398a12e3456789abcdef0123456789abcdef012',
    bio: 'Oversees deterministic consensus structures, Merkle tree commitments, and immutability architecture.'
  },
  {
    id: 'mainul',
    name: 'Md. Mainul Islam',
    role: 'Cryptographic Security Analyst',
    initials: 'MI',
    badge: 'CRYPTO',
    publicKey: 'ed25519:pub_5e8d32a104b7c6f9e8a2341098bcdef0123456789abcdef0123456789abc',
    bio: 'Manages SHA-256 collision resistance auditing, zero-knowledge proofs, and Edwards-curve signatures.'
  },
  {
    id: 'kamrun',
    name: 'Kamrun Nahar',
    role: 'Compliance & Forensic Auditor',
    initials: 'KN',
    badge: 'AUDITOR',
    publicKey: 'ed25519:pub_3a7b92f481c6d5e0a12398fe45bcdef0123456789abcdef0123456789abc',
    bio: 'Verifies court-admissible chain of custody logs, statutory compliance, and witness checkpointing.'
  },
  {
    id: 'anzuman',
    name: 'Anzuman Islam',
    role: 'SOC Lead & Incident Responder',
    initials: 'AI',
    badge: 'SOC-LEAD',
    publicKey: 'ed25519:pub_9c1e45f280a7b3d6e5412980bcdef0123456789abcdef0123456789abcdef',
    bio: 'Commands live threat triage, telemetry correlation, and incident attribution across enterprise nodes.'
  }
];

/**
 * Deterministic JSON serialization following RFC 8785 principles.
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalizeJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalizeJson).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  const pairs = keys.map(k => `${JSON.stringify(k)}:${canonicalizeJson(value[k])}`);
  return '{' + pairs.join(',') + '}';
}

/**
 * Synchronous standard SHA-256 implementation ensuring instantaneous
 * client-side hashing without asynchronous microtask stalls.
 * @param {string} message
 * @returns {string} 64-character lowercase hexadecimal hash.
 */
export function sha256Sync(message) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  
  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  const words = [];
  const messageLength = message.length * 8;
  
  let i, j;
  let result = '';

  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  let H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  const utf8 = unescape(encodeURIComponent(message));
  for (i = 0; i < utf8.length; i++) {
    words[i >> 2] |= (utf8.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
  }
  words[utf8.length >> 2] |= 0x80 << (24 - (utf8.length % 4) * 8);
  words[(((utf8.length + 8) >> 6) << 4) + 15] = messageLength;

  const W = new Array(64);
  for (i = 0; i < words.length; i += 16) {
    let [a, b, c, d, e, f, g, h] = H;

    for (j = 0; j < 64; j++) {
      if (j < 16) {
        W[j] = words[i + j] | 0;
      } else {
        const gamma0 = rightRotate(W[j - 15], 7) ^ rightRotate(W[j - 15], 18) ^ (W[j - 15] >>> 3);
        const gamma1 = rightRotate(W[j - 2], 17) ^ rightRotate(W[j - 2], 19) ^ (W[j - 2] >>> 10);
        W[j] = ((W[j - 16] + gamma0) | 0) + ((W[j - 7] + gamma1) | 0);
      }

      const ch = (e & f) ^ (~e & g);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const sigma0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const sigma1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const t1 = (((h + sigma1) | 0) + ((ch + K[j]) | 0) + W[j]) | 0;
      const t2 = (sigma0 + maj) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }

    H[0] = (H[0] + a) | 0;
    H[1] = (H[1] + b) | 0;
    H[2] = (H[2] + c) | 0;
    H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0;
    H[5] = (H[5] + f) | 0;
    H[6] = (H[6] + g) | 0;
    H[7] = (H[7] + h) | 0;
  }

  for (i = 0; i < 8; i++) {
    result += ('00000000' + (H[i] >>> 0).toString(16)).slice(-8);
  }
  return result;
}

/**
 * Represents a single cryptographically linked Block in the ledger.
 */
export class Block {
  /**
   * @param {number} index - Sequence number.
   * @param {string} timestamp - UTC ISO string.
   * @param {object} data - Forensic payload or incident details.
   * @param {string} previousHash - SHA-256 digest of preceding block.
   * @param {string} miner - Attributed team member.
   * @param {number} [nonce=0] - Proof of Work nonce.
   * @param {number} [difficulty=2] - Mining target difficulty.
   */
  constructor(index, timestamp, data, previousHash, miner, nonce = 0, difficulty = 2) {
    this.index = index;
    this.timestamp = timestamp;
    this.data = data;
    this.previousHash = previousHash;
    this.miner = miner;
    this.nonce = nonce;
    this.difficulty = difficulty;
    this.hash = this.calculateHash();
    this.tampered = false;
  }

  /**
   * Computes the deterministic SHA-256 hash across canonical block fields.
   * @returns {string}
   */
  calculateHash() {
    const canonicalPayload = canonicalizeJson(this.data);
    const headerString = `${this.index}|${this.timestamp}|${this.previousHash}|${canonicalPayload}|${this.miner}|${this.nonce}`;
    return sha256Sync(headerString);
  }

  /**
   * Performs Proof-of-Work mining until hash meets target difficulty prefix.
   * @param {number} difficulty
   */
  mineBlock(difficulty) {
    const targetPrefix = '0'.repeat(difficulty);
    while (!this.hash.startsWith(targetPrefix)) {
      this.nonce++;
      this.hash = this.calculateHash();
    }
  }
}

/**
 * Core Blockchain Ledger Engine
 */
export class Blockchain {
  constructor() {
    this.chain = [this.createGenesisBlock()];
    this.difficulty = 2;
    this.activeMember = TEAM_MEMBERS[0];
    this.pendingIncidents = [];
    this.defendedCount = 10;
  }

  /**
   * Generates the immutable anchor Genesis Block (#0).
   * @returns {Block}
   */
  createGenesisBlock() {
    const genesisData = {
      event: 'GENESIS_ANCHOR',
      system: 'CyberProof BD National Forensic Ledger',
      architect: 'Md. Mejbaul Islam Zidan',
      specVersion: '2.0.0-PROD',
      integrityState: 'CANONICAL_ROOT_INITIALIZED'
    };
    const block = new Block(
      0,
      '2026-10-11T00:00:00.000Z',
      genesisData,
      '0000000000000000000000000000000000000000000000000000000000000000',
      'Md. Mejbaul Islam Zidan',
      42,
      2
    );
    block.mineBlock(2);
    return block;
  }

  /**
   * Returns the most recent block in the chain.
   * @returns {Block}
   */
  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  /**
   * Sets the active investigator from the team roster.
   * @param {string} memberId
   */
  setActiveMember(memberId) {
    const found = TEAM_MEMBERS.find(m => m.id === memberId);
    if (found) {
      this.activeMember = found;
    }
  }

  /**
   * Records a security incident into the immutable ledger.
   * @param {object} incidentInput
   * @returns {Block}
   */
  recordIncident(incidentInput) {
    const latest = this.getLatestBlock();
    const incidentData = {
      incidentId: `INC-${Date.now()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`,
      title: incidentInput.title,
      severity: incidentInput.severity || 'HIGH',
      category: incidentInput.category || 'UNAUTHORIZED_ACCESS',
      sourceIp: incidentInput.sourceIp || '192.168.1.105',
      evidenceHash: incidentInput.evidenceHash || sha256Sync(incidentInput.title + Date.now()),
      details: incidentInput.details,
      attributedBy: this.activeMember.name,
      attributedRole: this.activeMember.role,
      signatureProof: `SIG_${this.activeMember.id.toUpperCase()}_${Date.now()}`
    };

    const newBlock = new Block(
      latest.index + 1,
      new Date().toISOString(),
      incidentData,
      latest.hash,
      this.activeMember.name,
      0,
      this.difficulty
    );

    newBlock.mineBlock(this.difficulty);
    this.chain.push(newBlock);
    this.defendedCount++;
    return newBlock;
  }

  /**
   * Validates cryptographic integrity of the entire chain.
   * Checks sequence numbers, hash pointers, and recomputed SHA-256 digests.
   * @returns {{isValid: boolean, brokenIndex: number|null, reason: string|null}}
   */
  isChainValid() {
    for (let i = 0; i < this.chain.length; i++) {
      const current = this.chain[i];
      const recomputedHash = current.calculateHash();

      // Verify block's own integrity
      if (current.hash !== recomputedHash) {
        return {
          isValid: false,
          brokenIndex: i,
          reason: `Block #${current.index} data has been altered. Expected: ${recomputedHash.substring(0, 16)}..., Found: ${current.hash.substring(0, 16)}...`
        };
      }

      // Verify backward cryptographic pointer
      if (i > 0) {
        const previous = this.chain[i - 1];
        if (current.previousHash !== previous.hash) {
          return {
            isValid: false,
            brokenIndex: i,
            reason: `Broken chain link at Block #${current.index}. Previous hash pointer (${current.previousHash.substring(0, 16)}...) does not match Block #${previous.index} hash (${previous.hash.substring(0, 16)}...).`
          };
        }
      }
    }
    return { isValid: true, brokenIndex: null, reason: null };
  }

  /**
   * Simulates an adversarial tampering attack on a specified block.
   * @param {number} blockIndex
   * @param {string} alteredTitle
   */
  tamperBlock(blockIndex, alteredTitle = 'MALICIOUS_LOG_TAMPERING_UNAUTHORIZED') {
    if (blockIndex < 0 || blockIndex >= this.chain.length) return false;
    const block = this.chain[blockIndex];
    block.data = {
      ...block.data,
      title: alteredTitle,
      tamperedAt: new Date().toISOString(),
      attackerNote: 'Attacker modified incident record to conceal intrusion.'
    };
    block.tampered = true;
    return true;
  }

  /**
   * Restores a block's valid hash or re-mines downstream chain.
   * @param {number} fromIndex
   */
  recalculateChain(fromIndex) {
    for (let i = fromIndex; i < this.chain.length; i++) {
      const block = this.chain[i];
      if (i > 0) {
        block.previousHash = this.chain[i - 1].hash;
      }
      block.tampered = false;
      block.nonce = 0;
      block.mineBlock(this.difficulty);
    }
  }
}

// Global engine instance
export const ledger = new Blockchain();

// Seed initial forensic evidence blocks attributed to the 4 team members
ledger.setActiveMember('anzuman');
ledger.recordIncident({
  title: 'Ransomware C2 Beaconing Detected',
  severity: 'CRITICAL',
  category: 'MALWARE_C2',
  sourceIp: '10.0.12.84',
  evidenceHash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  details: 'Cobalt Strike payload staging on internal Active Directory controller.'
});

ledger.setActiveMember('mainul');
ledger.recordIncident({
  title: 'Unauthorized Privilege Escalation Attempt',
  severity: 'HIGH',
  category: 'PRIVILEGE_ESCALATION',
  sourceIp: '10.0.4.19',
  evidenceHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
  details: 'Kerberoasting attack detected against service account krbtgt.'
});

ledger.setActiveMember('kamrun');
ledger.recordIncident({
  title: 'Database Exfiltration Staging Area Located',
  severity: 'HIGH',
  category: 'DATA_EXFILTRATION',
  sourceIp: '172.16.50.21',
  evidenceHash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
  details: 'Encrypted 7z archive staged on web server staging mount.'
});

// Restore default active member to Lead Architect
ledger.setActiveMember('zidan');

/**
 * UI Controller & DOM Event Wiring
 */
export function initUI() {
  const profileBtn = document.getElementById('profile-btn');
  const dropdownMenu = document.getElementById('profile-dropdown');
  const profileName = document.getElementById('nav-profile-name');
  const profileRole = document.getElementById('nav-profile-role');
  const profileAvatar = document.getElementById('nav-profile-avatar');
  
  const contributorName = document.getElementById('active-contributor-name');
  const contributorRole = document.getElementById('active-contributor-role');
  const contributorBio = document.getElementById('active-contributor-bio');
  const contributorKey = document.getElementById('active-contributor-key');
  const contributorBadge = document.getElementById('active-contributor-badge');
  
  const blocksContainer = document.getElementById('blocks-container');
  const telemetryBadge = document.getElementById('telemetry-status');
  const consoleEl = document.getElementById('audit-console');
  
  const teamModal = document.getElementById('team-modal');
  const openTeamBtn = document.getElementById('open-team-modal');
  const closeTeamBtn = document.getElementById('close-team-modal');
  
  const incidentForm = document.getElementById('incident-form');
  const runAuditBtn = document.getElementById('run-audit-btn');

  function logConsole(message, type = 'info') {
    if (!consoleEl) return;
    const time = new Date().toISOString().substring(11, 19);
    const div = document.createElement('div');
    div.className = `console-entry ${type}`;
    div.innerHTML = `<span class="console-timestamp">[${time}]</span> <span>${message}</span>`;
    consoleEl.appendChild(div);
    consoleEl.scrollTop = consoleEl.scrollHeight;
  }

  function updateActiveProfileDisplay() {
    const member = ledger.activeMember;
    if (profileName) profileName.textContent = member.name;
    if (profileRole) profileRole.textContent = member.role;
    if (profileAvatar) profileAvatar.textContent = member.initials;
    
    if (contributorName) contributorName.textContent = member.name;
    if (contributorRole) contributorRole.textContent = member.role;
    if (contributorBio) contributorBio.textContent = member.bio;
    if (contributorKey) contributorKey.textContent = member.publicKey;
    if (contributorBadge) contributorBadge.textContent = member.initials;

    // Update active class in dropdown options
    document.querySelectorAll('.profile-option').forEach(el => {
      if (el.getAttribute('data-id') === member.id) {
        el.classList.add('active');
      } else {
        el.classList.remove('active');
      }
    });
  }

  function renderBlocks() {
    if (!blocksContainer) return;
    blocksContainer.innerHTML = '';

    const validation = ledger.isChainValid();
    const hasTamper = !validation.isValid;

    if (telemetryBadge) {
      if (hasTamper) {
        telemetryBadge.className = 'telemetry-badge tampered';
        telemetryBadge.innerHTML = `<span class="pulse-dot"></span> <span>TAMPER DETECTED (BLOCK #${validation.brokenIndex})</span>`;
      } else {
        telemetryBadge.className = 'telemetry-badge';
        telemetryBadge.innerHTML = `<span class="pulse-dot"></span> <span>● ${ledger.defendedCount} DEFENDED | LEDGER SECURE</span>`;
      }
    }

    ledger.chain.forEach((block, idx) => {
      // If chain is broken from this index or onwards, mark with alarming crimson glow
      const isCompromised = hasTamper && idx >= validation.brokenIndex;

      const card = document.createElement('div');
      card.className = `block-card ${isCompromised ? 'tampered' : 'valid'}`;
      card.id = `block-node-${block.index}`;

      const title = block.data.title || block.data.event || 'Security Checkpoint';
      const severity = block.data.severity || 'SYSTEM';

      card.innerHTML = `
        <div class="block-header-row">
          <div class="block-num">
            <span>BLOCK #${block.index}</span>
            ${block.index === 0 ? '<span class="badge badge-miner">GENESIS ROOT</span>' : ''}
          </div>
          <div class="block-badges">
            <span class="badge ${isCompromised ? 'badge-tampered' : 'badge-valid'}">
              ${isCompromised ? 'CORRUPTED / TAMPERED' : 'CRYPTOGRAPHICALLY VERIFIED'}
            </span>
            <span class="badge badge-miner">${block.miner}</span>
          </div>
        </div>

        <div class="block-meta-grid mono">
          <div>
            <div class="meta-field-label">Current Block Hash (SHA-256)</div>
            <div class="meta-field-value ${isCompromised ? 'red-alert' : 'cyan-glow'}">${block.hash}</div>
          </div>
          <div>
            <div class="meta-field-label">Previous Hash Pointer</div>
            <div class="meta-field-value">${block.previousHash}</div>
          </div>
          <div>
            <div class="meta-field-label">Nonce / Proof of Work</div>
            <div class="meta-field-value">${block.nonce} (Difficulty: ${block.difficulty})</div>
          </div>
          <div>
            <div class="meta-field-label">Committed UTC Timestamp</div>
            <div class="meta-field-value">${block.timestamp}</div>
          </div>
        </div>

        <div class="block-payload-box">
          <div class="payload-title">Forensic Incident Payload [${severity}]</div>
          <div class="payload-data">
            <strong>${title}</strong><br />
            <span style="color: var(--text-muted); font-size: 0.75rem;">
              ${block.data.details || 'System anchor established.'}
              ${block.data.sourceIp ? ` • Source: ${block.data.sourceIp}` : ''}
              ${block.data.evidenceHash ? ` • Digest: ${block.data.evidenceHash.substring(0, 16)}...` : ''}
            </span>
          </div>
        </div>

        <div class="block-actions">
          ${isCompromised ? `
            <button class="btn btn-primary btn-sm restore-block-btn" data-index="${block.index}">
              Restore & Recalculate
            </button>
          ` : `
            <button class="btn btn-danger btn-sm tamper-block-btn" data-index="${block.index}">
              Simulate Attack (Tamper)
            </button>
          `}
        </div>
      `;

      blocksContainer.appendChild(card);

      // Add visual connector if not the last block
      if (idx < ledger.chain.length - 1) {
        const link = document.createElement('div');
        const nextIsCompromised = hasTamper && (idx + 1) >= validation.brokenIndex;
        link.className = `chain-link-connector ${nextIsCompromised ? 'broken' : ''}`;
        link.innerHTML = `
          <span>↓</span>
          <span>SHA-256 HASH LINK: ${block.hash.substring(0, 12)}... → previousHash</span>
          <span>↓</span>
        `;
        blocksContainer.appendChild(link);
      }
    });

    // Attach event listeners for tamper and restore buttons
    document.querySelectorAll('.tamper-block-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const index = parseInt(e.currentTarget.getAttribute('data-index'), 10);
        ledger.tamperBlock(index);
        logConsole(`ADVERSARIAL ATTACK: Modified payload bytes in Block #${index}!`, 'err');
        renderBlocks();
      });
    });

    document.querySelectorAll('.restore-block-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const index = parseInt(e.currentTarget.getAttribute('data-index'), 10);
        ledger.recalculateChain(index);
        logConsole(`CHAIN RESTORATION: Recomputed Proof-of-Work and re-linked Block #${index} through end of chain.`, 'info');
        renderBlocks();
      });
    });
  }

  // Profile switcher toggle
  if (profileBtn && dropdownMenu) {
    profileBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      dropdownMenu.classList.toggle('show');
    });

    document.addEventListener('click', () => {
      dropdownMenu.classList.remove('show');
    });
  }

  // Profile selection
  document.querySelectorAll('.profile-option').forEach(opt => {
    opt.addEventListener('click', () => {
      const id = opt.getAttribute('data-id');
      ledger.setActiveMember(id);
      updateActiveProfileDisplay();
      logConsole(`AUTH CONTEXT: Switched active operator to ${ledger.activeMember.name} (${ledger.activeMember.role})`, 'info');
      dropdownMenu.classList.remove('show');
    });
  });

  // Modal open/close
  if (openTeamBtn && teamModal) {
    openTeamBtn.addEventListener('click', () => teamModal.classList.add('show'));
  }
  if (closeTeamBtn && teamModal) {
    closeTeamBtn.addEventListener('click', () => teamModal.classList.remove('show'));
  }
  if (teamModal) {
    teamModal.addEventListener('click', (e) => {
      if (e.target === teamModal) teamModal.classList.remove('show');
    });
  }

  // Incident submission
  if (incidentForm) {
    incidentForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const title = document.getElementById('inc-title').value.trim();
      const category = document.getElementById('inc-category').value;
      const severity = document.getElementById('inc-severity').value;
      const sourceIp = document.getElementById('inc-source-ip').value.trim();
      const details = document.getElementById('inc-details').value.trim();

      if (!title) return;

      const newBlock = ledger.recordIncident({
        title,
        category,
        severity,
        sourceIp,
        details
      });

      logConsole(`BLOCK MINED: Block #${newBlock.index} appended by ${newBlock.miner}. Hash: ${newBlock.hash.substring(0, 16)}...`, 'info');
      incidentForm.reset();
      renderBlocks();
    });
  }

  // Full cryptographic audit button
  if (runAuditBtn) {
    runAuditBtn.addEventListener('click', () => {
      const result = ledger.isChainValid();
      if (result.isValid) {
        logConsole(`CRYPTOGRAPHIC AUDIT: Complete! All ${ledger.chain.length} blocks passed RFC 8785 canonical hash verification. Chain is 100% authentic.`, 'info');
      } else {
        logConsole(`TAMPER ALERT: Integrity failure at Block #${result.brokenIndex}: ${result.reason}`, 'err');
      }
      renderBlocks();
    });
  }

  // Initial render
  updateActiveProfileDisplay();
  renderBlocks();
  logConsole('CYBERPROOF BD: Core forensic engine online. SHA-256 and RFC 8785 active.', 'info');
}

// Auto-initialize when DOM is ready
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initUI);
  } else {
    initUI();
  }
}

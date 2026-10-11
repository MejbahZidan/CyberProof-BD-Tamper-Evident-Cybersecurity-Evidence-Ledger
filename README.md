# CyberProof BD

<div align="center">

<img src="./public/logo.svg" alt="CyberProof BD Logo" width="120" height="120" />

### Tamper-Evident Digital Forensics & Cybersecurity Evidence Ledger

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg?style=flat-square)](#)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue.svg?style=flat-square)](#)
[![React](https://img.shields.io/badge/React-19.0-61dafb.svg?style=flat-square)](#)
[![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-4.0-38b2ac.svg?style=flat-square)](#)
[![RFC 8785](https://img.shields.io/badge/RFC_8785-JSON_Canonicalization-purple.svg?style=flat-square)](#)
[![Ed25519](https://img.shields.io/badge/Ed25519-RFC_8032_Signatures-orange.svg?style=flat-square)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

*A military-grade, court-admissible digital evidence preservation engine and Security Operations Center (SOC) incident response ledger.*

[Features](#key-architectural-features) • [Architecture](#forensic-architecture) • [Team Roster](#official-engineering-team) • [Attack Suite](#10-canonical-attack-vectors) • [API Guide](#api-endpoints) • [Quickstart](#getting-started)

</div>

---

## Executive Summary

**CyberProof BD** resolves the fundamental trust problem in digital forensics and SOC incident handling: *how do you guarantee that security logs, telemetry captures, and digital evidence have not been altered, rewritten, or backdated by adversaries or malicious system administrators?*

Instead of incurring the multi-second latency, volatility, and high transaction costs of public blockchain networks, CyberProof BD engineers an **in-memory, high-throughput append-only hash chain anchored by external Edwards-curve (Ed25519) digital signatures**. This achieves **sub-millisecond write latency (< 1 ms)**, deterministic byte-level tamper detection, and zero gas fees.

---

## Key Architectural Features

- **RFC 8785 Canonical JSON Serialization:** Eliminates whitespace, key-ordering, and unicode normalization ambiguities before SHA-256 fingerprinting.
- **Continuous SHA-256 Hash Chaining:** Every block cryptographically seals the previous block's hash. Inverting a single bit fractures all downstream links instantly.
- **Asymmetric External Checkpoints (Ed25519 / RFC 8032):** Mitigates the "Single-Admin Rewrite" vulnerability. Independent authority signatures make internal chain recalculation mathematically detectable.
- **Court-Admissible Evidence Vault:** Byte-level SHA-256 hashing for network captures, forensic disk dumps, and incident logs with automated Chain of Custody (CoC) verification certificates.
- **Forensically Isolated AI Triage:** LLM-assisted anomaly correlation adhering to strict immutability boundaries—AI analysis cannot modify ledger blocks.
- **Dynamic Light & Dark Modes:** Tactile, soft-touch UI with customizable themes, smooth spring transitions, and persistent storage.
- **Left-Side Navigation Architecture:** Intuitive, streamlined sidebar with real-time incident counters, node sync badges, and contributor profile switches.

---

## Forensic Architecture

```
+-----------------------------------------------------------------------------------+
|                            CYBERPROOF BD ARCHITECTURE                             |
+-----------------------------------------------------------------------------------+
                                                                                     
  [ SOC Incidents & Telemetry ]     [ Digital Evidence Vault (PCAP, Syslog, Raw) ]   
                 │                                        │                         
                 ▼                                        ▼                         
     ┌──────────────────────┐                 ┌──────────────────────┐              
     │  RFC 8785 Canonical  │                 │   SHA-256 Byte Digest│              
     │    JSON Serializer   │                 │   Fingerprinting     │              
     └──────────┬───────────┘                 └──────────┬───────────┘              
                │                                        │                          
                └───────────────────┬────────────────────┘                          
                                    ▼                                               
                       ┌─────────────────────────┐                                  
                       │  Deterministic Payload  │                                  
                       │       Commitment        │                                  
                       └────────────┬────────────┘                                  
                                    ▼                                               
    ┌───────────────────────────────────────────────────────────────┐               
    │                  IMMUTABLE HASH CHAIN LEDGER                  │               
    │                                                               │               
    │   ┌─────────────┐        ┌─────────────┐        ┌─────────────┐│              
    │   │   Block 0   │◄───────┤   Block 1   │◄───────┤   Block 2   ││              
    │   │  (Genesis)  │  prev  │ (Incident)  │  prev  │ (Evidence)  ││              
    │   │   Hash: A   │  Hash  │   Hash: B   │  Hash  │   Hash: C   ││              
    │   └──────▲──────┘        └──────▲──────┘        └──────▲──────┘│              
    └──────────┼──────────────────────┼──────────────────────┼───────┘              
               │                      │                      │                      
               └──────────────────────┼──────────────────────┘                      
                                      ▼                                             
                       ┌─────────────────────────────┐                              
                       │   Ed25519 Signed Witness    │                              
                       │     Periodic Checkpoints    │                              
                       │  (Anti-Admin Rewrite Guard) │                              
                       └─────────────────────────────┘                              
```

---

## Official Engineering Team

The platform was architected and built by the **Forensic Systems Division**:

| Contributor | Title & Forensic Role | Primary Responsibilities |
| :--- | :--- | :--- |
| **Md. Mejbaul Islam Zidan** | **Lead Blockchain Architect** | Deterministic RFC 8785 JSON canonicalization, block header invariants, hash linkage, and Proof-of-Work difficulty routines. |
| **Md. Mainul Islam** | **Cryptographic Security Analyst** | SHA-256 byte digest pipelines, collision-resistance auditing, Edwards-curve Ed25519 keys, and zero-knowledge commitments. |
| **Kamrun Nahar** | **Compliance & Forensic Auditor** | Court-admissible chain-of-custody protocols, statutory audit logs, ISO/IEC 27037 digital evidence standards, and witness checkpoints. |
| **Anzuman Islam** | **SOC Lead & Incident Responder** | Threat event taxonomy (C2, Exfiltration, Privilege Escalation), telemetry correlation, and real-time adversarial detection rules. |

---

## 10 Canonical Attack Vectors & Mathematical Defenses

CyberProof BD includes an automated adversarial simulation lab verifying defenses against:

1. **Adversarial In-Place Data Mutation:** Immediate detection via SHA-256 payload mismatch ($H(P') \ne \text{payloadHash}$).
2. **Intermediate Block Deletion:** Fractures forward reference pointers ($B_{k+1}.\text{previousHash} \ne B_{k-1}.\text{blockHash}$).
3. **Adversarial Block Insertion:** Invalidates all downstream hash chains instantaneously.
4. **JSON Serialization Permutation:** Normalized deterministically via RFC 8785 lexicographical key sorting.
5. **Single-Admin Chain Rewrite:** Block hashes recomputed locally are rejected by external Ed25519 signed checkpoints.
6. **Timestamp Backdating:** Monotonic timestamp invariant enforced ($T_{i} \ge T_{i-1}$).
7. **Identity Spoofing:** Strict role-based access control and Ed25519 cryptographic custodian attribution.
8. **Hash Collision Attempt:** SHA-256 provides $2^{128}$ preimage collision resistance.
9. **Disk Bit Rot / File Corruption:** Real-time byte verification against ledger commitments.
10. **Evidence Tampering via Elevated Privileges:** Isolated digital vault cross-checks disk bytes against immutable blocks.

---

## API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Cryptographic health and ledger metrics |
| `GET` | `/api/ledger/blocks` | Retrieve full immutable block chain |
| `GET` | `/api/ledger/verify` | Perform full deep recalculation of all hash links |
| `GET` | `/api/events` | List all operational security incidents |
| `POST` | `/api/events` | Commit new security incident to the ledger |
| `GET` | `/api/evidence` | List registered evidence objects in vault |
| `POST` | `/api/evidence/register` | Register file bytes, calculate SHA-256, commit block |
| `POST` | `/api/evidence/verify-stored/:id` | Compare current disk bytes with recorded block hash |
| `POST` | `/api/evidence/simulate-tampering/:id` | Invert bytes to simulate adversarial disk alteration |
| `GET` | `/api/reports/certificate/:id` | Generate court-admissible forensic certificate |
| `GET` | `/api/checkpoints` | List Ed25519 signed milestone checkpoints |
| `POST` | `/api/checkpoints/create` | Sign and anchor new checkpoint for latest block |
| `POST` | `/api/checkpoints/simulate-rewrite-defense` | Simulate admin rewrite caught by checkpoint |
| `GET` | `/api/benchmarks/run` | Execute real-time cryptographic latency & throughput test |
| `POST` | `/api/ai/analyze-incidents` | Run forensic threat anomaly correlation |

---

## Getting Started

### Prerequisites
- Node.js (v18.x or v20.x+)
- npm or bun

### Installation

1. **Clone Repository:**
   ```bash
   git clone https://github.com/your-username/cyberproof-bd.git
   cd cyberproof-bd
   ```

2. **Install Dependencies:**
   ```bash
   npm install
   ```

3. **Configure Environment:**
   ```bash
   cp .env.example .env
   ```

4. **Launch Development Server:**
   ```bash
   npm run dev
   ```
   Access the dashboard at `http://localhost:3000`.

5. **Build for Production:**
   ```bash
   npm run build
   npm run start
   ```

---

## License

Distributed under the **MIT License**. See `LICENSE` for details.

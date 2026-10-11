/**
 * @file src/App.tsx
 * @description CyberProof BD Command Center.
 * Comprehensive SOC operations dashboard with Left-Side Navigation,
 * Light/Dark Mode toggle, Soft-Touch Glassmorphic UI, and Multi-Role Forensic Attribution.
 */

import React, { useEffect, useState, useRef } from 'react';
import {
  ShieldCheck,
  Server,
  Layers,
  Key,
  Terminal,
  Activity,
  CheckCircle2,
  RefreshCw,
  Cpu,
  UserCheck,
  Database,
  FileCode2,
  PlusCircle,
  AlertTriangle,
  Link as LinkIcon,
  Search,
  FileCheck,
  Upload,
  HardDrive,
  FileX,
  Bug,
  AlertOctagon,
  Clock,
  Filter,
  Check,
  ChevronRight,
  ShieldAlert,
  Flame,
  Zap,
  Award,
  Sparkles,
  Bot,
  FileText,
  Download,
  Gauge,
  BarChart3,
  Menu,
  Sun,
  Moon,
  ExternalLink,
  Lock,
} from 'lucide-react';
import type {
  LedgerBlock,
  UserSession,
  UserRole,
  LedgerAuditReport,
  EvidenceRecord,
  VerificationResult,
  EventSeverity,
  EventCategory,
} from './types/ledger';
import { SidebarNav, TabKey } from './components/SidebarNav';
import { TeamModal } from './components/TeamModal';
import { CertificateModal } from './components/CertificateModal';
import { NewEventModal } from './components/NewEventModal';
import { ThemeToggle } from './components/ThemeToggle';
import { CyberProofLogo } from './components/CyberProofLogo';

interface OperationalEvent {
  eventId: string;
  timestamp: string;
  severity: EventSeverity;
  category: EventCategory;
  sourceIp?: string;
  destinationIp?: string;
  sourceHost?: string;
  actor?: string;
  title: string;
  description: string;
  evidenceRefId?: string;
  status: 'NEW' | 'TRIAGED' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED';
  ledgerBlockIndex: number;
  auditTrail: {
    action: string;
    actor: string;
    timestamp: string;
    notes?: string;
  }[];
}

interface IncidentCluster {
  clusterId: string;
  clusterName: string;
  threatActorHypothesis: string;
  mitreTactic: string;
  eventIds: string[];
  aggregateRiskScore: number;
  recommendedAction: string;
}

interface SecurityAnalyticsReport {
  generatedAt: string;
  modelVersion: string;
  analyzedEventsCount: number;
  engineUsed: 'GEMINI_3_8_FLASH' | 'TRANSPARENT_HEURISTIC_BASELINE';
  baselineRiskSummary: {
    criticalCount: number;
    highCount: number;
    highestRiskHost: string;
    velocityScore: number;
  };
  campaignAssessment: string;
  identifiedClusters: IncidentCluster[];
  analystExecutiveSummary: string;
  safetyDisclaimer: string;
}

interface AttackSimulationResult {
  attackId: number;
  name: string;
  threatDescription: string;
  targetComponent: string;
  detectedByLocalLedger: boolean;
  requiresExternalCheckpoint: boolean;
  simulatedAction: string;
  verificationOutcome: 'CAUGHT' | 'BYPASSED_LOCALLY_CAUGHT_BY_CHECKPOINT' | 'BLOCKED_BY_VALIDATION';
  technicalExplanation: string;
}

interface SignedCheckpoint {
  checkpointId: string;
  blockIndex: number;
  blockHash: string;
  authorityId: string;
  authorityPublicKeyFingerprint: string;
  timestamp: string;
  signature: string;
}

interface ForensicEvidenceCertificate {
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

interface BenchmarkMetrics {
  timestamp: string;
  hardwareRuntime: string;
  hashingBenchmark: {
    iterations: number;
    totalTimeMs: number;
    averageLatencyMs: number;
    throughputOpsPerSec: number;
  };
  chainVerificationBenchmark: {
    blocksEvaluated: number;
    totalTimeMs: number;
    recomputedHashesCount: number;
    averageVerificationPerBlockMs: number;
  };
  signatureBenchmark: {
    iterations: number;
    averageSignTimeMs: number;
    averageVerifyTimeMs: number;
    signaturesPerSec: number;
  };
  evidenceThroughputBenchmark: {
    sampleSizeBytes: number;
    hashingDurationMs: number;
    throughputMBPerSec: number;
  };
  architecturalVerdict: string;
}

interface HealthData {
  status: string;
  system: string;
  timestamp: string;
  cryptography: {
    hashAlgorithm: string;
    asymmetricSignature: string;
    serialization: string;
    aiAnalytics: string;
    certificates: string;
    benchmarks: string;
    status: string;
  };
  ledger: {
    totalBlocks: number;
    totalEvidence: number;
    totalEvents: number;
    totalCheckpoints: number;
    genesisHash: string;
    latestHash: string;
    integrity: string;
    violationsCount: number;
  };
}

export default function App() {
  const [activeTab, setActiveTab] = useState<TabKey>('events');
  const [isMobileNavOpen, setIsMobileNavOpen] = useState<boolean>(false);

  // Theme State: defaults to dark, persists in localStorage
  const [isDark, setIsDark] = useState<boolean>(() => {
    const saved = localStorage.getItem('cyberproof-theme');
    if (saved !== null) return saved === 'dark';
    return true;
  });

  useEffect(() => {
    localStorage.setItem('cyberproof-theme', isDark ? 'dark' : 'light');
    if (isDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDark]);

  const toggleTheme = () => setIsDark((prev) => !prev);

  // Core Data States
  const [health, setHealth] = useState<HealthData | null>(null);
  const [blocks, setBlocks] = useState<LedgerBlock[]>([]);
  const [evidenceList, setEvidenceList] = useState<EvidenceRecord[]>([]);
  const [eventsList, setEventsList] = useState<OperationalEvent[]>([]);
  const [checkpoints, setCheckpoints] = useState<SignedCheckpoint[]>([]);
  const [authorityKey, setAuthorityKey] = useState<{ fingerprint: string; publicKeyPem: string } | null>(null);
  const [selectedBlock, setSelectedBlock] = useState<LedgerBlock | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<OperationalEvent | null>(null);
  const [seedUsers, setSeedUsers] = useState<UserSession[]>([]);
  const [currentUser, setCurrentUser] = useState<UserSession | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [auditReport, setAuditReport] = useState<LedgerAuditReport | null>(null);
  const [verificationResult, setVerificationResult] = useState<VerificationResult | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Modals
  const [activeCertificate, setActiveCertificate] = useState<ForensicEvidenceCertificate | null>(null);
  const [showTeamModal, setShowTeamModal] = useState<boolean>(false);
  const [showEventModal, setShowEventModal] = useState<boolean>(false);

  // Benchmark State
  const [benchmarkMetrics, setBenchmarkMetrics] = useState<BenchmarkMetrics | null>(null);
  const [isRunningBenchmark, setIsRunningBenchmark] = useState<boolean>(false);

  // AI Analytics State
  const [aiReport, setAiReport] = useState<SecurityAnalyticsReport | null>(null);
  const [isAnalyzingAi, setIsAnalyzingAi] = useState<boolean>(false);

  // Attack Simulation Lab State
  const [simulationResults, setSimulationResults] = useState<AttackSimulationResult[]>([]);
  const [isRunningSimulations, setIsRunningSimulations] = useState<boolean>(false);

  // Rewrite defense simulation result state
  const [rewriteDefenseResult, setRewriteDefenseResult] = useState<{
    attackScenario: string;
    localChainInternalPointersValid: boolean;
    caughtBySignedCheckpoint: boolean;
    checkpointId: string;
    authoritySignedHash: string;
    attackerRewrittenHash: string;
    conclusion: string;
  } | null>(null);

  // Filter state for Security Events
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // New Event Form State
  const [newEventTitle, setNewEventTitle] = useState<string>('Ransomware Pre-Execution Activity');
  const [newEventSeverity, setNewEventSeverity] = useState<EventSeverity>('CRITICAL');
  const [newEventCategory, setNewEventCategory] = useState<EventCategory>('MALWARE_DETECTION');
  const [newEventSourceHost, setNewEventSourceHost] = useState<string>('ENDPOINT-FIN-08');
  const [newEventSourceIp, setNewEventSourceIp] = useState<string>('192.168.1.104');
  const [newEventDesc, setNewEventDesc] = useState<string>('Mass vssadmin shadow copy deletion attempted by PowerShell process.');
  const [newEventEvidenceRef, setNewEventEvidenceRef] = useState<string>('');
  const [isSubmittingEvent, setIsSubmittingEvent] = useState<boolean>(false);

  // Evidence Registration Form State
  const [regFilename, setRegFilename] = useState<string>('auth_bypass_attempt.log');
  const [regCaseId, setRegCaseId] = useState<string>('CASE-2026-BD-02');
  const [regDescription, setRegDescription] = useState<string>('Extracted syslog showing brute-force SSH credentials.');
  const [regTextPayload, setRegTextPayload] = useState<string>(
    'AUTH_FAIL_LOG::SRC_IP:203.0.113.195::ATTEMPT_USER:root::METHOD:password::TIME:2026-10-11T03:40:12Z'
  );
  const [regTags, setRegTags] = useState<string>('SYSLOG, SSH_BRUTE, AUTH');
  const [isRegistering, setIsRegistering] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Sandbox state
  const [sandboxInput, setSandboxInput] = useState<string>(
    JSON.stringify(
      {
        filename: 'firewall_syslog_2026.pcap',
        caseId: 'CASE-2026-BD-01',
        evidenceType: 'NETWORK_CAPTURE',
        custodian: 'fatima.forensics',
        severity: 'CRITICAL',
      },
      null,
      2
    )
  );
  const [canonicalResult, setCanonicalResult] = useState<{ canonicalString: string; hash: string } | null>(null);
  const [isHashing, setIsHashing] = useState<boolean>(false);

  // Fetch initial system state
  const fetchSystemData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [healthRes, blocksRes, evidenceRes, eventsRes, chkptRes, keyRes, usersRes] = await Promise.all([
        fetch('/api/health'),
        fetch('/api/ledger/blocks'),
        fetch('/api/evidence'),
        fetch('/api/events'),
        fetch('/api/checkpoints'),
        fetch('/api/checkpoints/authority-key'),
        fetch('/api/seed-users'),
      ]);

      if (!healthRes.ok) throw new Error(`Health check failed (${healthRes.status})`);
      if (!blocksRes.ok) throw new Error(`Ledger query failed (${blocksRes.status})`);
      if (!evidenceRes.ok) throw new Error(`Evidence query failed (${evidenceRes.status})`);
      if (!eventsRes.ok) throw new Error(`Events query failed (${eventsRes.status})`);
      if (!chkptRes.ok) throw new Error(`Checkpoints query failed (${chkptRes.status})`);
      if (!keyRes.ok) throw new Error(`Key query failed (${keyRes.status})`);
      if (!usersRes.ok) throw new Error(`User query failed (${usersRes.status})`);

      const healthData: HealthData = await healthRes.json();
      const blocksData = await blocksRes.json();
      const evidenceData: EvidenceRecord[] = await evidenceRes.json();
      const eventsData: OperationalEvent[] = await eventsRes.json();
      const chkptData: SignedCheckpoint[] = await chkptRes.json();
      const keyData = await keyRes.json();
      const usersData: UserSession[] = await usersRes.json();

      setHealth(healthData);
      const fetchedBlocks: LedgerBlock[] = blocksData.blocks || [];
      setBlocks(fetchedBlocks);
      if (fetchedBlocks.length > 0 && !selectedBlock) {
        setSelectedBlock(fetchedBlocks[fetchedBlocks.length - 1]);
      }
      setEvidenceList(evidenceData);
      setEventsList(eventsData);
      setCheckpoints(chkptData);
      setAuthorityKey(keyData);
      if (eventsData.length > 0 && !selectedEvent) {
        setSelectedEvent(eventsData[0]);
      }
      setSeedUsers(usersData);
      if (!currentUser && usersData.length > 0) {
        setCurrentUser(usersData[0]);
      }
    } catch (err: unknown) {
      console.error('Failed to load system data:', err);
      setError(err instanceof Error ? err.message : 'Unknown network error');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchSystemData();
  }, []);

  // Run Empirical Cryptographic Benchmark
  const handleRunBenchmark = async () => {
    setIsRunningBenchmark(true);
    try {
      const res = await fetch('/api/benchmarks/run');
      if (!res.ok) throw new Error('Benchmark execution failed');
      const data: BenchmarkMetrics = await res.json();
      setBenchmarkMetrics(data);
    } catch (err) {
      alert('Benchmark failed to execute');
    } finally {
      setIsRunningBenchmark(false);
    }
  };

  // Fetch certificate
  const handleViewCertificate = async (evidenceId: string) => {
    try {
      const res = await fetch(`/api/reports/certificate/${evidenceId}`);
      if (!res.ok) throw new Error('Certificate generation failed');
      const data: ForensicEvidenceCertificate = await res.json();
      setActiveCertificate(data);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Error fetching certificate');
    }
  };

  // Download certificate as JSON
  const handleDownloadCertificate = () => {
    if (!activeCertificate) return;
    const jsonStr = JSON.stringify(activeCertificate, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeCertificate.certificateId}_Proof.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Trigger AI Security Incident Correlation
  const handleRunAiAnalysis = async () => {
    setIsAnalyzingAi(true);
    try {
      const res = await fetch('/api/ai/analyze-incidents', { method: 'POST' });
      if (!res.ok) throw new Error('AI analysis failed');
      const data: SecurityAnalyticsReport = await res.json();
      setAiReport(data);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'AI analysis failed');
    } finally {
      setIsAnalyzingAi(false);
    }
  };

  // Create new signed checkpoint
  const handleCreateCheckpoint = async () => {
    try {
      const res = await fetch('/api/checkpoints/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          memo: `Forensic audit milestone anchored by ${currentUser?.username || 'admin'}`,
        }),
      });
      if (!res.ok) throw new Error('Checkpoint anchoring failed');
      const data = await res.json();
      alert(data.message);
      await fetchSystemData();
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Checkpoint creation failed');
    }
  };

  // Run live anti-rewrite defense simulation
  const handleSimulateRewriteDefense = async () => {
    try {
      const res = await fetch('/api/checkpoints/simulate-rewrite-defense', { method: 'POST' });
      const data = await res.json();
      setRewriteDefenseResult(data);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Simulation failed');
    }
  };

  // Run all 10 Attack Vector Simulations
  const handleRunAllAttacks = async () => {
    setIsRunningSimulations(true);
    try {
      const res = await fetch('/api/simulations/run-all');
      const data: AttackSimulationResult[] = await res.json();
      setSimulationResults(data);
    } catch (err) {
      alert('Failed to execute simulation suite');
    } finally {
      setIsRunningSimulations(false);
    }
  };

  // Handle Event Creation
  const handleCreateEvent = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmittingEvent(true);
    try {
      const res = await fetch('/api/events', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newEventTitle,
          severity: newEventSeverity,
          category: newEventCategory,
          sourceHost: newEventSourceHost,
          sourceIp: newEventSourceIp,
          description: newEventDesc,
          evidenceRefId: newEventEvidenceRef || undefined,
          creator: currentUser?.username || 'Md. Mejbaul Islam Zidan',
        }),
      });

      if (!res.ok) throw new Error('Failed to create event');
      setShowEventModal(false);
      await fetchSystemData();
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Event recording failed');
    } finally {
      setIsSubmittingEvent(false);
    }
  };

  // Handle Evidence File Upload
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setRegFilename(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        setRegTextPayload(reader.result);
      }
    };
    reader.readAsText(file);
  };

  // Submit Evidence Registration
  const handleRegisterEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!regFilename || !regTextPayload) {
      alert('Please provide a filename and content.');
      return;
    }

    setIsRegistering(true);
    try {
      const res = await fetch('/api/evidence/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          caseId: regCaseId,
          filename: regFilename,
          rawText: regTextPayload,
          mimeType: 'text/plain',
          custodianId: currentUser?.userId || 'usr-zidan-01',
          custodianName: currentUser?.username || 'Md. Mejbaul Islam Zidan',
          acquiredAt: new Date().toISOString(),
          description: regDescription,
          tags: regTags.split(',').map((t) => t.trim()).filter(Boolean),
        }),
      });

      if (!res.ok) throw new Error('Registration failed');
      const data = await res.json();
      alert(`Success! Evidence fingerprinted with SHA-256 and committed to Block #${data.ledgerBlockIndex}`);
      await fetchSystemData();
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setIsRegistering(false);
    }
  };

  // Verify Stored Evidence directly from Vault against Ledger
  const handleVerifyEvidence = async (evidenceId: string) => {
    setIsVerifying(true);
    setVerificationResult(null);
    try {
      const res = await fetch(`/api/evidence/verify-stored/${evidenceId}`, { method: 'POST' });
      const data: VerificationResult = await res.json();
      setVerificationResult(data);
      await fetchSystemData();
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setIsVerifying(false);
    }
  };

  // Tamper Simulation Attack
  const handleSimulateTampering = async (evidenceId: string) => {
    if (!confirm('This will simulate a disk attack by inverting bits in the evidence file. Proceed?')) return;
    try {
      const res = await fetch(`/api/evidence/simulate-tampering/${evidenceId}`, { method: 'POST' });
      const data = await res.json();
      alert(data.message);
      await handleVerifyEvidence(evidenceId);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Simulation failed');
    }
  };

  // Run full cryptographic chain audit
  const handleRunAudit = async () => {
    setIsAuditing(true);
    try {
      const res = await fetch('/api/ledger/verify');
      const data: LedgerAuditReport = await res.json();
      setAuditReport(data);
    } catch (err) {
      console.error('Audit failed:', err);
    } finally {
      setIsAuditing(false);
    }
  };

  // Compute canonical hash in sandbox
  const handleComputeCanonical = async () => {
    setIsHashing(true);
    try {
      const parsed = JSON.parse(sandboxInput);
      const res = await fetch('/api/crypto/verify-canonical', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsed),
      });
      const data = await res.json();
      setCanonicalResult(data);
    } catch (err) {
      alert(err instanceof Error ? `Invalid JSON syntax: ${err.message}` : 'Error parsing JSON');
    } finally {
      setIsHashing(false);
    }
  };

  const getSeverityBadge = (severity: EventSeverity) => {
    switch (severity) {
      case 'CRITICAL':
        return isDark
          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
          : 'bg-rose-50 text-rose-700 border-rose-300';
      case 'HIGH':
        return isDark
          ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
          : 'bg-amber-50 text-amber-700 border-amber-300';
      case 'MEDIUM':
        return isDark
          ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
          : 'bg-cyan-50 text-cyan-700 border-cyan-300';
      case 'LOW':
        return isDark
          ? 'bg-blue-500/20 text-blue-300 border-blue-500/40'
          : 'bg-blue-50 text-blue-700 border-blue-300';
      case 'INFORMATIONAL':
        return isDark
          ? 'bg-slate-500/20 text-slate-300 border-slate-500/40'
          : 'bg-slate-100 text-slate-700 border-slate-300';
    }
  };

  const filteredEvents = eventsList.filter((e) => {
    if (severityFilter !== 'ALL' && e.severity !== severityFilter) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      e.title.toLowerCase().includes(q) ||
      e.description.toLowerCase().includes(q) ||
      (e.sourceIp && e.sourceIp.includes(q)) ||
      (e.sourceHost && e.sourceHost.toLowerCase().includes(q))
    );
  });

  const getSectionTitle = (tab: TabKey) => {
    switch (tab) {
      case 'events':
        return { title: 'Security Incidents & Telemetry', desc: 'Real-time threat triage and forensic immutable event logging' };
      case 'evidence':
        return { title: 'Digital Evidence Vault', desc: 'SHA-256 byte-level fingerprinting, custody tracking, and tamper verification' };
      case 'ledger':
        return { title: 'Cryptographic Ledger Explorer', desc: 'RFC 8785 canonical hash chain inspection and tamper cascade visualization' };
      case 'benchmarks':
        return { title: 'Performance Benchmarks & Proofs', desc: 'Empirical throughput metrics and architectural comparison proofs' };
      case 'ai':
        return { title: 'AI Anomaly & Campaign Radar', desc: 'Forensically isolated threat correlation and MITRE ATT&CK clustering' };
      case 'checkpoints':
        return { title: 'Asymmetric Checkpoints', desc: 'Ed25519 external witness commitments protecting against admin rewrites' };
      case 'attacks':
        return { title: 'The 10 Canonical Attack Vectors', desc: 'Empirical mathematical validation against real-world adversarial attacks' };
      case 'sandbox':
        return { title: 'RFC 8785 Canonical Sandbox', desc: 'Deterministic JSON serialization and SHA-256 digest playground' };
    }
  };

  const sectionMeta = getSectionTitle(activeTab);

  return (
    <div className={`min-h-screen flex font-sans transition-colors duration-300 ${
      isDark ? 'bg-[#090d16] text-slate-100' : 'bg-slate-50 text-slate-900'
    }`}>
      {/* Left-Side Navigation Sidebar */}
      <SidebarNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        isDark={isDark}
        onToggleTheme={toggleTheme}
        currentUser={currentUser}
        seedUsers={seedUsers}
        onSelectUser={setCurrentUser}
        onOpenTeamModal={() => setShowTeamModal(true)}
        counts={{
          events: eventsList.length,
          evidence: evidenceList.length,
          blocks: blocks.length,
          checkpoints: checkpoints.length,
        }}
        isLoading={isLoading}
        onRefresh={fetchSystemData}
        isOpenMobile={isMobileNavOpen}
        onCloseMobile={() => setIsMobileNavOpen(false)}
      />

      {/* Main Content Stage */}
      <div className="flex-1 flex flex-col min-w-0 lg:pl-72 transition-all duration-300">
        {/* Top Header Bar */}
        <header
          className={`sticky top-0 z-30 px-6 py-3.5 border-b backdrop-blur-md flex items-center justify-between transition-colors ${
            isDark
              ? 'bg-[#0b1120]/80 border-slate-800/80 text-slate-200'
              : 'bg-white/80 border-slate-200 text-slate-800 shadow-sm'
          }`}
        >
          <div className="flex items-center gap-3">
            {/* Mobile Sidebar Toggle Button */}
            <button
              onClick={() => setIsMobileNavOpen(true)}
              className="lg:hidden p-2 rounded-xl border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
              aria-label="Open navigation menu"
            >
              <Menu className="w-5 h-5" />
            </button>

            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-bold text-base tracking-tight leading-tight">{sectionMeta.title}</h1>
                <span className="hidden sm:inline-flex text-[10px] font-mono px-2 py-0.5 rounded-full font-bold bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
                  ONLINE
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 hidden sm:block leading-tight">
                {sectionMeta.desc}
              </p>
            </div>
          </div>

          {/* Quick Header Actions */}
          <div className="flex items-center gap-2.5">
            {/* Defense badge */}
            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-xl border text-xs font-mono font-semibold transition-all shadow-sm bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>10 ATTACKS DEFENDED</span>
            </div>

            {/* Quick action: Audit Chain */}
            <button
              onClick={handleRunAudit}
              disabled={isAuditing}
              title="Audit cryptographic integrity across all blocks"
              className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 border transition cursor-pointer shadow-sm ${
                isDark
                  ? 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
                  : 'bg-slate-100 hover:bg-slate-200 text-slate-700 border-slate-300'
              }`}
            >
              <ShieldCheck className={`w-3.5 h-3.5 text-cyan-500 ${isAuditing ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">{isAuditing ? 'Auditing...' : 'Audit Chain'}</span>
            </button>

            {/* Quick action: Log Incident */}
            <button
              onClick={() => setShowEventModal(true)}
              className="px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 text-white bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 transition cursor-pointer shadow-sm shadow-cyan-950/40"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Log Incident</span>
            </button>

            {/* Light/Dark Toggle in header for convenience */}
            <div className="pl-1">
              <ThemeToggle isDark={isDark} onToggle={toggleTheme} showLabel={false} />
            </div>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
          {/* Error Banner */}
          {error && (
            <div className="p-4 rounded-2xl bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-300 text-xs flex items-center justify-between">
              <div>
                <strong>Backend Connection Notice:</strong> {error}
              </div>
              <button onClick={fetchSystemData} className="underline font-mono cursor-pointer">
                Retry
              </button>
            </div>
          )}

          {/* Audit Result Banner */}
          {auditReport && (
            <div
              className={`p-4 rounded-2xl border flex items-center justify-between transition-all shadow-sm ${
                auditReport.isValid
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-700 dark:text-emerald-300'
                  : 'bg-rose-500/10 border-rose-500/30 text-rose-700 dark:text-rose-300'
              }`}
            >
              <div className="flex items-center gap-3">
                <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
                <div>
                  <div className="font-bold text-xs">
                    Cryptographic Ledger Audit: {auditReport.isValid ? '100% VALID & INTACT' : 'COMPROMISED'}
                  </div>
                  <div className="text-[11px] font-mono opacity-90">
                    Checked {auditReport.totalBlocks} blocks • Violations: {auditReport.violations.length} • Verified at: {new Date(auditReport.checkedAt).toLocaleTimeString()}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setAuditReport(null)}
                className="text-xs font-mono underline cursor-pointer opacity-80 hover:opacity-100"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* TAB: SECURITY EVENTS */}
          {activeTab === 'events' && (
            <div className="space-y-6">
              {/* Event Filter & Stats Bar */}
              <div
                className={`p-4 rounded-2xl border flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all shadow-sm ${
                  isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                }`}
              >
                <div className="flex items-center gap-2 flex-1 max-w-md">
                  <div className="relative w-full">
                    <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
                    <input
                      type="text"
                      placeholder="Search incidents by IP, host, title..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className={`w-full pl-9 pr-4 py-2 rounded-xl text-xs border focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition ${
                        isDark
                          ? 'bg-slate-950 border-slate-800 text-slate-200 placeholder-slate-500'
                          : 'bg-slate-50 border-slate-200 text-slate-800 placeholder-slate-400'
                      }`}
                    />
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">Severity:</span>
                  {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
                    <button
                      key={lvl}
                      onClick={() => setSeverityFilter(lvl)}
                      className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-semibold transition cursor-pointer border ${
                        severityFilter === lvl
                          ? isDark
                            ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-sm'
                            : 'bg-cyan-50 text-cyan-800 border-cyan-300 shadow-sm'
                          : isDark
                          ? 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                          : 'bg-slate-50 text-slate-600 border-slate-200 hover:text-slate-900'
                      }`}
                    >
                      {lvl}
                    </button>
                  ))}
                </div>
              </div>

              {/* Incidents Master-Detail Layout */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Master: Incident List */}
                <div
                  className={`lg:col-span-1 rounded-2xl border overflow-hidden flex flex-col max-h-[650px] shadow-sm ${
                    isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                  }`}
                >
                  <div
                    className={`p-4 border-b flex items-center justify-between text-xs font-bold ${
                      isDark ? 'bg-slate-950/60 border-slate-800' : 'bg-slate-50 border-slate-200'
                    }`}
                  >
                    <span>Incidents Stream ({filteredEvents.length})</span>
                    <span className="text-[10px] font-mono text-cyan-500">Append-Only Feed</span>
                  </div>

                  <div className="divide-y divide-slate-200 dark:divide-slate-800/80 overflow-y-auto flex-1">
                    {filteredEvents.map((evt) => {
                      const isSelected = selectedEvent?.eventId === evt.eventId;
                      return (
                        <button
                          key={evt.eventId}
                          onClick={() => setSelectedEvent(evt)}
                          className={`w-full text-left p-3.5 transition cursor-pointer ${
                            isSelected
                              ? isDark
                                ? 'bg-cyan-950/40 border-l-4 border-cyan-500'
                                : 'bg-cyan-50/70 border-l-4 border-cyan-500'
                              : isDark
                              ? 'hover:bg-slate-800/40'
                              : 'hover:bg-slate-50'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-1.5">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getSeverityBadge(evt.severity)}`}>
                              {evt.severity}
                            </span>
                            <span className="text-[10px] font-mono text-cyan-600 dark:text-cyan-400 font-semibold">
                              Block #{evt.ledgerBlockIndex}
                            </span>
                          </div>
                          <div className="font-semibold text-xs truncate mb-1">{evt.title}</div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400 line-clamp-2">
                            {evt.description}
                          </div>
                          <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-slate-400">
                            <span>{evt.sourceHost || evt.sourceIp || 'NETWORK-NODE'}</span>
                            <span>{new Date(evt.timestamp).toLocaleTimeString()}</span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Detail: Selected Incident Inspection */}
                <div
                  className={`lg:col-span-2 rounded-2xl border p-6 space-y-5 shadow-sm ${
                    isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                  }`}
                >
                  {selectedEvent ? (
                    <>
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-200 dark:border-slate-800">
                        <div>
                          <div className="flex items-center gap-2 mb-1.5">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getSeverityBadge(selectedEvent.severity)}`}>
                              {selectedEvent.severity}
                            </span>
                            <span className="text-[11px] font-mono font-semibold text-slate-500 dark:text-slate-400">
                              {selectedEvent.category}
                            </span>
                          </div>
                          <h2 className="text-lg font-bold leading-tight">{selectedEvent.title}</h2>
                          <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                            Logged by: <strong className="text-cyan-600 dark:text-cyan-400">{selectedEvent.actor || 'System'}</strong> •{' '}
                            {new Date(selectedEvent.timestamp).toLocaleString()}
                          </div>
                        </div>

                        <div className="text-left sm:text-right p-3 rounded-xl border bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800">
                          <span className="text-[10px] font-mono text-slate-500 block">Ledger Block Commitment</span>
                          <span className="text-base font-bold font-mono text-cyan-600 dark:text-cyan-400">
                            Block #{selectedEvent.ledgerBlockIndex}
                          </span>
                        </div>
                      </div>

                      {/* Technical Incident Metadata */}
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <div className="p-3 rounded-xl border bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-xs">
                          <span className="text-[10px] text-slate-500 block">Source Host</span>
                          <strong className="font-mono">{selectedEvent.sourceHost || 'N/A'}</strong>
                        </div>
                        <div className="p-3 rounded-xl border bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-xs">
                          <span className="text-[10px] text-slate-500 block">Source IP</span>
                          <strong className="font-mono">{selectedEvent.sourceIp || 'N/A'}</strong>
                        </div>
                        <div className="p-3 rounded-xl border bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-xs">
                          <span className="text-[10px] text-slate-500 block">Status</span>
                          <strong className="font-mono text-emerald-600 dark:text-emerald-400">{selectedEvent.status}</strong>
                        </div>
                        <div className="p-3 rounded-xl border bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-xs">
                          <span className="text-[10px] text-slate-500 block">Evidence Ref</span>
                          <strong className="font-mono truncate block">{selectedEvent.evidenceRefId || 'None'}</strong>
                        </div>
                      </div>

                      {/* Description Narrative */}
                      <div className="p-4 rounded-xl border bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 space-y-1.5 text-xs">
                        <span className="text-[11px] font-bold text-slate-600 dark:text-slate-300 block">Forensic Narrative:</span>
                        <p className="leading-relaxed text-slate-700 dark:text-slate-300">{selectedEvent.description}</p>
                      </div>

                      {/* Audit Trail Sequence */}
                      <div className="space-y-2">
                        <span className="text-xs font-bold text-slate-600 dark:text-slate-300">
                          Chain of Custody & Audit Trail ({selectedEvent.auditTrail.length})
                        </span>
                        <div className="space-y-1.5">
                          {selectedEvent.auditTrail.map((trail, idx) => (
                            <div
                              key={idx}
                              className="p-3 rounded-xl border text-xs flex items-center justify-between bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800"
                            >
                              <div className="flex items-center gap-2">
                                <span className="w-1.5 h-1.5 rounded-full bg-cyan-500"></span>
                                <span className="font-semibold">{trail.action}</span>
                                <span className="text-slate-500">by {trail.actor}</span>
                              </div>
                              <span className="font-mono text-[10px] text-slate-400">
                                {new Date(trail.timestamp).toLocaleTimeString()}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="p-12 text-center text-slate-400 text-sm">
                      Select an incident from the stream to inspect forensic details.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB: EVIDENCE VAULT */}
          {activeTab === 'evidence' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Register Form */}
                <div
                  className={`lg:col-span-1 p-5 rounded-2xl border space-y-4 shadow-sm ${
                    isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
                    <h3 className="font-bold text-sm">Register Evidence Subject</h3>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-500 font-semibold">
                      SHA-256 VAULT
                    </span>
                  </div>

                  <form onSubmit={handleRegisterEvidence} className="space-y-3 text-xs">
                    <div>
                      <label className="block text-slate-500 dark:text-slate-400 mb-1 font-semibold">Case ID</label>
                      <input
                        type="text"
                        value={regCaseId}
                        onChange={(e) => setRegCaseId(e.target.value)}
                        className={`w-full rounded-xl border p-2 text-xs ${
                          isDark ? 'bg-slate-950 border-slate-800 text-slate-200' : 'bg-slate-50 border-slate-200'
                        }`}
                        required
                      />
                    </div>

                    <div>
                      <label className="block text-slate-500 dark:text-slate-400 mb-1 font-semibold">Filename</label>
                      <input
                        type="text"
                        value={regFilename}
                        onChange={(e) => setRegFilename(e.target.value)}
                        className={`w-full rounded-xl border p-2 text-xs ${
                          isDark ? 'bg-slate-950 border-slate-800 text-slate-200' : 'bg-slate-50 border-slate-200'
                        }`}
                        required
                      />
                    </div>

                    <div>
                      <label className="block text-slate-500 dark:text-slate-400 mb-1 font-semibold">
                        Payload / Extracted Log
                      </label>
                      <textarea
                        rows={4}
                        value={regTextPayload}
                        onChange={(e) => setRegTextPayload(e.target.value)}
                        className={`w-full rounded-xl border p-2 text-xs font-mono resize-none ${
                          isDark ? 'bg-slate-950 border-slate-800 text-slate-200' : 'bg-slate-50 border-slate-200'
                        }`}
                        required
                      />
                    </div>

                    <button
                      type="submit"
                      disabled={isRegistering}
                      className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white font-semibold text-xs cursor-pointer shadow-sm transition"
                    >
                      {isRegistering ? 'Hashing Bytes...' : 'Register & Commit to Ledger'}
                    </button>
                  </form>
                </div>

                {/* Evidence List */}
                <div
                  className={`lg:col-span-2 rounded-2xl border divide-y overflow-y-auto max-h-[650px] shadow-sm ${
                    isDark
                      ? 'bg-slate-900/80 border-slate-800/80 divide-slate-800'
                      : 'bg-white border-slate-200 divide-slate-200'
                  }`}
                >
                  <div
                    className={`p-4 flex items-center justify-between text-xs font-bold ${
                      isDark ? 'bg-slate-950/60' : 'bg-slate-50'
                    }`}
                  >
                    <span>Registered Evidence Objects ({evidenceList.length})</span>
                    <span className="text-[10px] font-mono text-emerald-500">Byte-Level Immutable</span>
                  </div>

                  {evidenceList.map((item) => (
                    <div key={item.evidenceId} className="p-4 space-y-3 text-xs">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-sm">{item.filename}</span>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800">
                              {item.caseId}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                            Custodian: <strong>{item.custodianName}</strong> • {item.fileSizeBytes} bytes
                          </div>
                        </div>

                        {/* Action buttons */}
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleViewCertificate(item.evidenceId)}
                            className="px-2.5 py-1.5 rounded-lg border text-[11px] font-semibold text-indigo-600 dark:text-indigo-400 border-indigo-300 dark:border-indigo-800/80 bg-indigo-50 dark:bg-indigo-950/50 hover:bg-indigo-100 dark:hover:bg-indigo-900/50 transition cursor-pointer"
                          >
                            Certificate
                          </button>
                          <button
                            onClick={() => handleVerifyEvidence(item.evidenceId)}
                            className="px-2.5 py-1.5 rounded-lg border text-[11px] font-semibold text-emerald-600 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800/80 bg-emerald-50 dark:bg-emerald-950/50 hover:bg-emerald-100 dark:hover:bg-emerald-900/50 transition cursor-pointer"
                          >
                            Verify
                          </button>
                          <button
                            onClick={() => handleSimulateTampering(item.evidenceId)}
                            className="px-2.5 py-1.5 rounded-lg border text-[11px] font-semibold text-rose-600 dark:text-rose-400 border-rose-300 dark:border-rose-800/80 bg-rose-50 dark:bg-rose-950/50 hover:bg-rose-100 dark:hover:bg-rose-900/50 transition cursor-pointer"
                          >
                            Tamper Disk
                          </button>
                        </div>
                      </div>

                      <div className="p-2.5 rounded-xl border font-mono text-[11px] break-all bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-cyan-600 dark:text-cyan-400">
                        SHA-256: {item.sha256Fingerprint}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB: BENCHMARKS */}
          {activeTab === 'benchmarks' && (
            <div className="space-y-6">
              <div
                className={`p-5 rounded-2xl border flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm ${
                  isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                }`}
              >
                <div>
                  <h2 className="text-base font-bold">Empirical Cryptographic Benchmarks</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400 max-w-xl">
                    Measured micro-benchmarks demonstrating why an append-only hash chain with Ed25519 external checkpoints outperforms public blockchains and standard RDBMS for digital evidence forensics.
                  </p>
                </div>
                <button
                  onClick={handleRunBenchmark}
                  disabled={isRunningBenchmark}
                  className="px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-600 to-cyan-600 text-white font-semibold text-xs flex items-center gap-2 cursor-pointer shadow-sm transition"
                >
                  <Gauge className="w-4 h-4" />
                  {isRunningBenchmark ? 'Running Measurements...' : 'Run Benchmark Suite'}
                </button>
              </div>

              {benchmarkMetrics && (
                <div className="space-y-6">
                  {/* Metric Cards */}
                  <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
                    <div
                      className={`p-4 rounded-2xl border shadow-sm ${
                        isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                      }`}
                    >
                      <span className="text-[10px] font-mono uppercase text-slate-500">SHA-256 Latency</span>
                      <div className="text-2xl font-bold font-mono text-cyan-600 dark:text-cyan-400">
                        {benchmarkMetrics.hashingBenchmark.averageLatencyMs} ms
                      </div>
                      <span className="text-[10px] text-slate-400 font-mono">
                        {benchmarkMetrics.hashingBenchmark.throughputOpsPerSec.toLocaleString()} ops/sec
                      </span>
                    </div>

                    <div
                      className={`p-4 rounded-2xl border shadow-sm ${
                        isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                      }`}
                    >
                      <span className="text-[10px] font-mono uppercase text-slate-500">Full Chain Verification</span>
                      <div className="text-2xl font-bold font-mono text-emerald-600 dark:text-emerald-400">
                        {benchmarkMetrics.chainVerificationBenchmark.totalTimeMs} ms
                      </div>
                      <span className="text-[10px] text-slate-400 font-mono">100% deep recalculation</span>
                    </div>

                    <div
                      className={`p-4 rounded-2xl border shadow-sm ${
                        isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                      }`}
                    >
                      <span className="text-[10px] font-mono uppercase text-slate-500">Ed25519 Sign Speed</span>
                      <div className="text-2xl font-bold font-mono text-amber-600 dark:text-amber-400">
                        {benchmarkMetrics.signatureBenchmark.averageSignTimeMs} ms
                      </div>
                      <span className="text-[10px] text-slate-400 font-mono">
                        {benchmarkMetrics.signatureBenchmark.signaturesPerSec.toLocaleString()} sigs/sec
                      </span>
                    </div>

                    <div
                      className={`p-4 rounded-2xl border shadow-sm ${
                        isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                      }`}
                    >
                      <span className="text-[10px] font-mono uppercase text-slate-500">Evidence Throughput</span>
                      <div className="text-2xl font-bold font-mono text-indigo-600 dark:text-indigo-400">
                        {benchmarkMetrics.evidenceThroughputBenchmark.throughputMBPerSec} MB/s
                      </div>
                      <span className="text-[10px] text-slate-400 font-mono">Direct streaming</span>
                    </div>
                  </div>

                  {/* Architecture Table */}
                  <div
                    className={`p-5 rounded-2xl border shadow-sm overflow-x-auto ${
                      isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                    }`}
                  >
                    <h3 className="font-bold text-sm mb-3">Architectural Comparison Matrix</h3>
                    <table className="w-full text-left text-xs font-mono">
                      <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400">
                          <th className="py-2 pr-4">Architecture</th>
                          <th className="py-2 px-3">Write Latency</th>
                          <th className="py-2 px-3">Tamper Detection</th>
                          <th className="py-2 px-3">Admin Resistance</th>
                          <th className="py-2 px-3">Cost / Gas</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800 text-slate-600 dark:text-slate-300">
                        <tr>
                          <td className="py-2.5 pr-4 font-semibold text-slate-500">Conventional RDBMS (PostgreSQL)</td>
                          <td className="py-2.5 px-3 text-emerald-600 dark:text-emerald-400">&lt; 5 ms</td>
                          <td className="py-2.5 px-3 text-rose-500">Weak (Silent UPDATE)</td>
                          <td className="py-2.5 px-3 text-rose-500">Zero (DBA root access)</td>
                          <td className="py-2.5 px-3 text-emerald-600 dark:text-emerald-400">Minimal</td>
                        </tr>
                        <tr className="bg-cyan-500/10 font-bold text-cyan-700 dark:text-cyan-300">
                          <td className="py-2.5 pr-4 text-cyan-600 dark:text-cyan-400">
                            CyberProof BD (Hash Chain + Ed25519)
                          </td>
                          <td className="py-2.5 px-3 text-emerald-600 dark:text-emerald-400">&lt; 1 ms</td>
                          <td className="py-2.5 px-3 text-emerald-600 dark:text-emerald-400">Absolute (SHA-256 cascade)</td>
                          <td className="py-2.5 px-3 text-emerald-600 dark:text-emerald-400">High (Signed Checkpoints)</td>
                          <td className="py-2.5 px-3 text-emerald-600 dark:text-emerald-400">Zero gas fees</td>
                        </tr>
                        <tr>
                          <td className="py-2.5 pr-4 font-semibold text-slate-500">Public Blockchain (Ethereum)</td>
                          <td className="py-2.5 px-3 text-rose-500">2,000 – 15,000 ms</td>
                          <td className="py-2.5 px-3 text-emerald-600 dark:text-emerald-400">Absolute</td>
                          <td className="py-2.5 px-3 text-emerald-600 dark:text-emerald-400">Consensus-based</td>
                          <td className="py-2.5 px-3 text-rose-500">High gas fees per TX</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB: AI ANALYTICS */}
          {activeTab === 'ai' && (
            <div className="space-y-6">
              <div
                className={`p-5 rounded-2xl border flex justify-between items-center shadow-sm ${
                  isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                }`}
              >
                <div>
                  <h2 className="text-base font-bold">AI Threat Correlation Radar</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Forensically isolated threat reasoning correlating incidents across MITRE ATT&CK tactics.
                  </p>
                </div>
                <button
                  onClick={handleRunAiAnalysis}
                  disabled={isAnalyzingAi}
                  className="px-4 py-2 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold text-xs flex items-center gap-2 cursor-pointer shadow-sm transition"
                >
                  <Sparkles className="w-4 h-4" />
                  {isAnalyzingAi ? 'Analyzing Incidents...' : 'Run Forensic Correlation'}
                </button>
              </div>

              {aiReport && (
                <div
                  className={`p-5 rounded-2xl border space-y-3 text-xs shadow-sm ${
                    isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                  }`}
                >
                  <h3 className="font-bold text-sm text-indigo-600 dark:text-indigo-400">Campaign Assessment:</h3>
                  <p className="leading-relaxed text-slate-700 dark:text-slate-300">{aiReport.campaignAssessment}</p>

                  <div className="pt-2">
                    <h4 className="font-bold mb-2">Identified Threat Clusters:</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {aiReport.identifiedClusters.map((cluster) => (
                        <div
                          key={cluster.clusterId}
                          className="p-3.5 rounded-xl border bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 space-y-1"
                        >
                          <div className="font-bold text-indigo-500">{cluster.clusterName}</div>
                          <div className="text-[11px] text-slate-500">Tactic: {cluster.mitreTactic}</div>
                          <div className="text-[11px] text-slate-600 dark:text-slate-300">
                            {cluster.threatActorHypothesis}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB: CHECKPOINTS */}
          {activeTab === 'checkpoints' && (
            <div className="space-y-6">
              <div
                className={`p-5 rounded-2xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm ${
                  isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                }`}
              >
                <div>
                  <h2 className="text-base font-bold">Asymmetric Signed Checkpoints (Ed25519)</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    External cryptographic anchors that detect and neutralize single-admin ledger rewrites.
                  </p>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={handleCreateCheckpoint}
                    className="px-3.5 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold cursor-pointer shadow-sm transition"
                  >
                    Anchor Milestone Checkpoint
                  </button>
                  <button
                    onClick={handleSimulateRewriteDefense}
                    className="px-3.5 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold cursor-pointer shadow-sm transition"
                  >
                    Test Anti-Rewrite Proof
                  </button>
                </div>
              </div>

              {rewriteDefenseResult && (
                <div
                  className={`p-4 rounded-2xl border text-xs space-y-2 shadow-sm ${
                    rewriteDefenseResult.caughtBySignedCheckpoint
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-800 dark:text-emerald-300'
                      : 'bg-rose-500/10 border-rose-500/30 text-rose-800 dark:text-rose-300'
                  }`}
                >
                  <strong className="block font-bold">Adversarial Rewrite Defense Outcome:</strong>
                  <p>{rewriteDefenseResult.conclusion}</p>
                </div>
              )}

              <div
                className={`rounded-2xl border divide-y overflow-hidden shadow-sm ${
                  isDark
                    ? 'bg-slate-900/80 border-slate-800/80 divide-slate-800'
                    : 'bg-white border-slate-200 divide-slate-200'
                }`}
              >
                {checkpoints.map((c) => (
                  <div key={c.checkpointId} className="p-4 text-xs font-mono space-y-1">
                    <div className="flex justify-between items-center">
                      <span className="text-amber-600 dark:text-amber-400 font-bold">
                        Checkpoint for Block #{c.blockIndex} ({c.checkpointId})
                      </span>
                      <span className="text-[10px] text-slate-400 font-sans">
                        {new Date(c.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <div className="break-all text-[11px] text-emerald-600 dark:text-emerald-400">
                      Block Hash: {c.blockHash}
                    </div>
                    <div className="break-all text-[10px] text-slate-500">Signature: {c.signature}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB: 10 ATTACK LAB */}
          {activeTab === 'attacks' && (
            <div className="space-y-6">
              <div
                className={`p-5 rounded-2xl border flex justify-between items-center shadow-sm ${
                  isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                }`}
              >
                <div>
                  <h2 className="text-base font-bold">The 10 Canonical Threat Vectors & Attack Suite</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Simulates MITRE attack scenarios verifying hash-cascade breakages and checkpoint alarms.
                  </p>
                </div>
                <button
                  onClick={handleRunAllAttacks}
                  disabled={isRunningSimulations}
                  className="px-4 py-2 rounded-xl bg-gradient-to-r from-rose-600 to-amber-600 text-white font-semibold text-xs flex items-center gap-2 cursor-pointer shadow-sm transition"
                >
                  <Flame className="w-4 h-4" />
                  {isRunningSimulations ? 'Simulating Attacks...' : 'Run All 10 Simulations'}
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {simulationResults.map((atk) => (
                  <div
                    key={atk.attackId}
                    className={`p-4 rounded-2xl border text-xs space-y-2 shadow-sm ${
                      isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-sm">
                        #{atk.attackId} {atk.name}
                      </span>
                      <span className="px-2 py-0.5 rounded-full font-mono text-[10px] font-bold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
                        DEFENDED
                      </span>
                    </div>
                    <p className="text-slate-600 dark:text-slate-400 leading-relaxed text-[11px]">
                      {atk.technicalExplanation}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB: LEDGER EXPLORER */}
          {activeTab === 'ledger' && (
            <div className="space-y-6">
              <div
                className={`p-5 rounded-2xl border flex justify-between items-center shadow-sm ${
                  isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                }`}
              >
                <div>
                  <h2 className="text-base font-bold">Immutable Block Explorer</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Live inspection of chained block headers, RFC 8785 canonical payloads, and SHA-256 digests.
                  </p>
                </div>
                <button
                  onClick={handleRunAudit}
                  className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-emerald-600 text-white font-semibold text-xs flex items-center gap-2 cursor-pointer shadow-sm transition"
                >
                  <ShieldCheck className="w-4 h-4" />
                  Validate Ledger
                </button>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div
                  className={`lg:col-span-1 rounded-2xl border p-4 space-y-2 max-h-[600px] overflow-y-auto shadow-sm ${
                    isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                  }`}
                >
                  <span className="text-xs font-bold block mb-2 text-slate-500 dark:text-slate-400">
                    Blocks In Chain ({blocks.length})
                  </span>
                  {blocks.map((b) => (
                    <button
                      key={b.index}
                      onClick={() => setSelectedBlock(b)}
                      className={`w-full text-left p-3 rounded-xl border text-xs font-mono transition cursor-pointer ${
                        selectedBlock?.index === b.index
                          ? isDark
                            ? 'bg-cyan-950/60 border-cyan-500/50 text-cyan-200'
                            : 'bg-cyan-50 border-cyan-300 text-cyan-900'
                          : isDark
                          ? 'bg-slate-950/80 border-slate-800 text-slate-300 hover:border-slate-700'
                          : 'bg-slate-50 border-slate-200 text-slate-700 hover:border-slate-300'
                      }`}
                    >
                      <div className="flex items-center justify-between font-bold">
                        <span>Block #{b.index}</span>
                        <span className="text-[10px] font-sans px-1.5 py-0.2 rounded bg-slate-200 dark:bg-slate-800">
                          {b.entryType}
                        </span>
                      </div>
                      <div className="truncate text-[10px] text-slate-500 mt-1">{b.blockHash}</div>
                    </button>
                  ))}
                </div>

                <div
                  className={`lg:col-span-2 rounded-2xl border p-5 font-mono text-xs space-y-3 shadow-sm ${
                    isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
                  }`}
                >
                  {selectedBlock ? (
                    <>
                      <div className="flex justify-between items-center pb-3 border-b border-slate-200 dark:border-slate-800">
                        <span className="font-bold text-base text-cyan-600 dark:text-cyan-400">
                          Block #{selectedBlock.index} Inspector
                        </span>
                        <span className="text-[11px] text-slate-400">
                          {new Date(selectedBlock.timestamp).toLocaleString()}
                        </span>
                      </div>

                      <div className="space-y-1.5">
                        <div className="text-slate-500">
                          Previous Hash:{' '}
                          <span className="text-slate-700 dark:text-slate-300 break-all">{selectedBlock.previousHash}</span>
                        </div>
                        <div className="text-slate-500">
                          Block Hash:{' '}
                          <span className="text-emerald-600 dark:text-emerald-400 font-bold break-all">
                            {selectedBlock.blockHash}
                          </span>
                        </div>
                        <div className="text-slate-500">
                          Payload Hash:{' '}
                          <span className="text-cyan-600 dark:text-cyan-300 break-all">{selectedBlock.payloadHash}</span>
                        </div>
                      </div>

                      <div className="pt-2">
                        <span className="text-[11px] font-sans font-bold block mb-1 text-slate-500">
                          RFC 8785 Canonical Payload:
                        </span>
                        <pre
                          className={`p-3 rounded-xl border max-h-72 overflow-x-auto text-[11px] ${
                            isDark ? 'bg-slate-950 border-slate-800 text-slate-300' : 'bg-slate-50 border-slate-200 text-slate-800'
                          }`}
                        >
                          {JSON.stringify(selectedBlock.payload, null, 2)}
                        </pre>
                      </div>
                    </>
                  ) : (
                    <div className="p-8 text-center text-slate-400 font-sans">Select a block to inspect.</div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB: RFC 8785 SANDBOX */}
          {activeTab === 'sandbox' && (
            <div
              className={`p-6 rounded-2xl border space-y-4 shadow-sm ${
                isDark ? 'bg-slate-900/80 border-slate-800/80' : 'bg-white border-slate-200'
              }`}
            >
              <div className="flex justify-between items-center border-b pb-3 border-slate-200 dark:border-slate-800">
                <div>
                  <h3 className="font-bold text-sm">RFC 8785 Canonical Serialization Engine</h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Verify deterministic key ordering and compute invariant SHA-256 digests.
                  </p>
                </div>
                <button
                  onClick={handleComputeCanonical}
                  disabled={isHashing}
                  className="px-4 py-2 rounded-xl bg-gradient-to-r from-purple-600 to-cyan-600 text-white font-semibold text-xs flex items-center gap-2 cursor-pointer shadow-sm transition"
                >
                  <FileCode2 className="w-4 h-4" />
                  {isHashing ? 'Hashing...' : 'Compute Canonical SHA-256'}
                </button>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-500 mb-1">Raw JSON Input</label>
                  <textarea
                    value={sandboxInput}
                    onChange={(e) => setSandboxInput(e.target.value)}
                    rows={8}
                    className={`w-full rounded-xl border p-3 font-mono text-xs resize-none ${
                      isDark ? 'bg-slate-950 border-slate-800 text-slate-200' : 'bg-slate-50 border-slate-200'
                    }`}
                  />
                </div>

                <div className="space-y-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-500 mb-1">
                      Deterministic Canonical Output
                    </label>
                    <div
                      className={`p-3 rounded-xl border font-mono text-xs break-all min-h-[60px] text-amber-600 dark:text-amber-300 ${
                        isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'
                      }`}
                    >
                      {canonicalResult?.canonicalString || 'Run calculation to preview canonical output...'}
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-500 mb-1">
                      Computed SHA-256 Fingerprint
                    </label>
                    <div
                      className={`p-3 rounded-xl border font-mono text-xs break-all font-bold text-cyan-600 dark:text-cyan-400 ${
                        isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-50 border-slate-200'
                      }`}
                    >
                      {canonicalResult?.hash || 'Waiting for computation...'}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Modals */}
      <TeamModal
        isOpen={showTeamModal}
        onClose={() => setShowTeamModal(false)}
        isDark={isDark}
      />

      <CertificateModal
        certificate={activeCertificate}
        onClose={() => setActiveCertificate(null)}
        onDownload={handleDownloadCertificate}
        isDark={isDark}
      />

      <NewEventModal
        isOpen={showEventModal}
        onClose={() => setShowEventModal(false)}
        onSubmit={handleCreateEvent}
        isDark={isDark}
        isSubmitting={isSubmittingEvent}
        title={newEventTitle}
        setTitle={setNewEventTitle}
        severity={newEventSeverity}
        setSeverity={setNewEventSeverity}
        category={newEventCategory}
        setCategory={setNewEventCategory}
        sourceHost={newEventSourceHost}
        setSourceHost={setNewEventSourceHost}
        sourceIp={newEventSourceIp}
        setSourceIp={setNewEventSourceIp}
        description={newEventDesc}
        setDescription={setNewEventDesc}
        evidenceRef={newEventEvidenceRef}
        setEvidenceRef={setNewEventEvidenceRef}
      />
    </div>
  );
}

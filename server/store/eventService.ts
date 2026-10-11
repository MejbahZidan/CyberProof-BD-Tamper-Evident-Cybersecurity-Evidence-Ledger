/**
 * @file server/store/eventService.ts
 * @description Security Event Management and Operational Audit Trail Service.
 * Manages mutable operational incident states (triage, status changes, assignments)
 * while committing immutable cryptographic event records into the ledger.
 */

import fs from 'node:fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { ledgerStore } from './ledgerStore.ts';
import type {
  SecurityEventRecord,
  EventSeverity,
  EventCategory,
} from '../../src/types/ledger.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../../data');
const EVENTS_FILE = path.join(DATA_DIR, 'events.json');

export type IncidentStatus = 'NEW' | 'TRIAGED' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED';

export interface OperationalSecurityEvent extends SecurityEventRecord {
  status: IncidentStatus;
  assignee?: string;
  ledgerBlockIndex: number;
  auditTrail: {
    action: string;
    actor: string;
    timestamp: string;
    notes?: string;
  }[];
}

export class EventService {
  private events: Map<string, OperationalSecurityEvent> = new Map();

  constructor() {
    this.loadEvents();
    this.seedDefaultEventsIfEmpty();
  }

  private loadEvents() {
    if (fs.existsSync(EVENTS_FILE)) {
      try {
        const raw = fs.readFileSync(EVENTS_FILE, 'utf-8');
        const list: OperationalSecurityEvent[] = JSON.parse(raw);
        list.forEach((e) => this.events.set(e.eventId, e));
      } catch (err) {
        console.error('[EventService] Failed to parse events file:', err);
      }
    }
  }

  private saveEvents() {
    const list = Array.from(this.events.values());
    fs.writeFileSync(EVENTS_FILE, JSON.stringify(list, null, 2), 'utf-8');
  }

  private async seedDefaultEventsIfEmpty() {
    if (this.events.size > 0) return;

    // Seed realistic synthetic incidents
    await this.createEvent({
      severity: 'CRITICAL',
      category: 'UNAUTHORIZED_ACCESS',
      sourceIp: '198.51.100.12',
      destinationIp: '10.0.1.15',
      sourceHost: 'AUTH-GATEWAY-BD-01',
      actor: 'unknown_external_agent',
      title: 'High-Volume SSH Credential Stuffing Attack',
      description: 'More than 2,400 authentication attempts within 60 seconds targeting root and service accounts.',
      metadata: { attemptsPerSec: 40, attackSignature: 'BRUTE_FORCE_SSH_V2' },
      creator: 'fatima.forensics',
    });

    await this.createEvent({
      severity: 'HIGH',
      category: 'DATA_EXFILTRATION',
      sourceIp: '10.0.2.88',
      destinationIp: '203.0.113.89',
      sourceHost: 'DATABASE-SRV-CORE',
      actor: 'svc_database',
      title: 'Suspicious Encrypted Egress Flow',
      description: 'Unusual 4.2 MB outbound payload routed to unclassified foreign IP on non-standard port 8443.',
      metadata: { egressBytes: 4404019, protocol: 'TLSv1.3' },
      creator: 'fatima.forensics',
    });

    await this.createEvent({
      severity: 'HIGH',
      category: 'MALWARE_DETECTION',
      sourceHost: 'WS-FINANCE-14',
      actor: 'local_workstation_user',
      title: 'Endpoint Memory Injection Detected',
      description: 'Heuristic sensor detected Cobalt Strike beacon reflective DLL injection in host explorer.exe process.',
      metadata: { malwareFamily: 'Beacon.Stager', pid: 4102 },
      creator: 'fatima.forensics',
    });

    await this.createEvent({
      severity: 'MEDIUM',
      category: 'INTEGRITY_VIOLATION',
      sourceHost: 'WEB-PROXY-01',
      actor: 'cron_integrity_daemon',
      title: 'Configuration File Modification Alert',
      description: 'Unauthorized checksum change detected in /etc/nginx/conf.d/reverse-proxy.conf.',
      metadata: { path: '/etc/nginx/conf.d/reverse-proxy.conf' },
      creator: 'kamal.zaman',
    });
  }

  /**
   * Creates a security event, validates inputs, and commits an immutable block to the ledger.
   */
  public async createEvent(params: {
    severity: EventSeverity;
    category: EventCategory;
    sourceIp?: string;
    destinationIp?: string;
    sourceHost?: string;
    actor?: string;
    title: string;
    description: string;
    evidenceRefId?: string;
    metadata?: Record<string, unknown>;
    creator: string;
  }): Promise<OperationalSecurityEvent> {
    const eventId = `sec-evt-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const timestamp = new Date().toISOString();

    // 1. Immutable Ledger Commitment
    const blockPayload = {
      action: 'SECURITY_EVENT_RECORDED',
      eventId,
      timestamp,
      severity: params.severity,
      category: params.category,
      title: params.title.trim(),
      description: params.description.trim(),
      sourceIp: params.sourceIp?.trim() || null,
      destinationIp: params.destinationIp?.trim() || null,
      sourceHost: params.sourceHost?.trim() || null,
      actor: params.actor?.trim() || null,
      evidenceRefId: params.evidenceRefId || null,
      creator: params.creator,
    };

    const block = await ledgerStore.appendBlock(
      'SECURITY_EVENT',
      eventId,
      blockPayload
    );

    // 2. Mutable Operational Record (with initial audit trail)
    const operationalEvent: OperationalSecurityEvent = {
      eventId,
      timestamp,
      severity: params.severity,
      category: params.category,
      sourceIp: params.sourceIp,
      destinationIp: params.destinationIp,
      sourceHost: params.sourceHost,
      actor: params.actor,
      title: params.title.trim(),
      description: params.description.trim(),
      evidenceRefId: params.evidenceRefId,
      metadata: params.metadata || {},
      status: 'NEW',
      ledgerBlockIndex: block.index,
      auditTrail: [
        {
          action: 'EVENT_RECORDED_AND_COMMITTED',
          actor: params.creator,
          timestamp,
          notes: `Event committed to immutable ledger Block #${block.index}`,
        },
      ],
    };

    this.events.set(eventId, operationalEvent);
    this.saveEvents();
    return operationalEvent;
  }

  /**
   * Updates the mutable operational status of an incident and logs audit provenance.
   */
  public updateStatus(
    eventId: string,
    newStatus: IncidentStatus,
    actor: string,
    notes?: string
  ): OperationalSecurityEvent | null {
    const event = this.events.get(eventId);
    if (!event) return null;

    event.status = newStatus;
    event.auditTrail.unshift({
      action: `STATUS_CHANGED_TO_${newStatus}`,
      actor,
      timestamp: new Date().toISOString(),
      notes,
    });

    this.saveEvents();
    return event;
  }

  public getAllEvents(): OperationalSecurityEvent[] {
    return Array.from(this.events.values()).sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  public getEventById(id: string): OperationalSecurityEvent | undefined {
    return this.events.get(id);
  }

  public getStats() {
    const list = Array.from(this.events.values());
    const severityCount: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFORMATIONAL: 0,
    };
    const categoryCount: Record<string, number> = {};
    const statusCount: Record<string, number> = {};

    list.forEach((e) => {
      severityCount[e.severity] = (severityCount[e.severity] || 0) + 1;
      categoryCount[e.category] = (categoryCount[e.category] || 0) + 1;
      statusCount[e.status] = (statusCount[e.status] || 0) + 1;
    });

    return {
      total: list.length,
      severityCount,
      categoryCount,
      statusCount,
    };
  }
}

export const eventService = new EventService();

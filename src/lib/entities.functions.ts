import { entities, type EntityKey } from "./threat-entities";

type JsonPrimitive = string | number | boolean | null;
type Json = JsonPrimitive | Json[] | { [k: string]: Json };
type EntityRow = { [k: string]: Json };

const JAVA_BASE = import.meta.env.VITE_JAVA_BASE_URL || "http://localhost:8081";

const LOCAL_STORAGE_KEY_PREFIX = "threat_intel_entity_";

// Pre-populated realistic initial mock data for static SPA demo
const INITIAL_MOCK_ENTITIES: Record<EntityKey, EntityRow[]> = {
  threats: [
    { id: 1, name: "LockBit Ransomware Campaign", threat_type: "Ransomware", severity: "critical", description: "Active ransomware deployment targeting network storage shares.", detected_at: new Date(Date.now() - 3600000).toISOString() },
    { id: 2, name: "Credential Stuffing Botnet", threat_type: "Botnet", severity: "high", description: "Automated authentication attempts using leaked database lists.", detected_at: new Date(Date.now() - 7200000).toISOString() },
    { id: 3, name: "SQL Injection Probe", threat_type: "Exploit", severity: "medium", description: "Scanning web endpoints for unescaped parameter inputs.", detected_at: new Date(Date.now() - 14400000).toISOString() },
  ],
  phishing_urls: [
    { id: 1, url: "https://paypal-secure-login.ru/update", domain: "paypal-secure-login.ru", severity: "critical", threat_level: "Critical", detected_at: new Date(Date.now() - 1800000).toISOString() },
    { id: 2, url: "http://verify-bank-access-code.xyz", domain: "verify-bank-access-code.xyz", severity: "high", threat_level: "High", detected_at: new Date(Date.now() - 5400000).toISOString() },
    { id: 3, url: "https://account-security-alert-center.info", domain: "account-security-alert-center.info", severity: "medium", threat_level: "Medium", detected_at: new Date(Date.now() - 10800000).toISOString() },
  ],
  suspicious_calls: [
    { id: 1, phone_number: "+91 98765 43210", country: "India", severity: "critical", pattern: "Banking Fraud · Mobile · Airtel · trust 15%", reported_at: new Date(Date.now() - 900000).toISOString() },
    { id: 2, phone_number: "+1 (800) 555-0199", country: "United States", severity: "high", pattern: "IRS Impersonation · Toll Free · AT&T · trust 25%", reported_at: new Date(Date.now() - 2700000).toISOString() },
    { id: 3, phone_number: "+44 7700 900077", country: "United Kingdom", severity: "medium", pattern: "Lottery Scam · Mobile · EE · trust 48%", reported_at: new Date(Date.now() - 8100000).toISOString() },
  ],
  email_scams: [
    { id: 1, sender: "claims@lottery-winner-payout.com", subject: "Urgent: Unclaimed Funds Notification", severity: "critical", content: "You have been chosen as the recipient of 1,500,000 USD...", detected_at: new Date(Date.now() - 1200000).toISOString() },
    { id: 2, sender: "alert@security-bank-verify.org", subject: "Account Suspension Notice", severity: "high", content: "Your account will be suspended within 24 hours unless verified...", detected_at: new Date(Date.now() - 4800000).toISOString() },
  ],
  malicious_ips: [
    { id: 1, ip_address: "185.220.101.5", country: "Germany", severity: "critical", threat_type: "C2 Server", last_seen: new Date(Date.now() - 600000).toISOString() },
    { id: 2, ip_address: "45.142.212.100", country: "Russia", severity: "high", threat_type: "Port Scanner", last_seen: new Date(Date.now() - 3000000).toISOString() },
  ],
  scam_messages: [
    { id: 1, channel: "SMS", sender: "INFO-ALERT", content: "Your package is waiting. Pay $2.99 fee to release shipment: bit.ly/fake-delivery", severity: "critical", detected_at: new Date(Date.now() - 1500000).toISOString() },
    { id: 2, channel: "WhatsApp", sender: "+91 9988776655", content: "Work from home part time. Earn 5000 Rs daily by liking videos.", severity: "high", detected_at: new Date(Date.now() - 6000000).toISOString() },
  ],
};

function getLocalEntityStore(entity: EntityKey): EntityRow[] {
  if (typeof window === "undefined") return INITIAL_MOCK_ENTITIES[entity] || [];
  try {
    const raw = localStorage.getItem(LOCAL_STORAGE_KEY_PREFIX + entity);
    if (!raw) {
      const initial = INITIAL_MOCK_ENTITIES[entity] || [];
      localStorage.setItem(LOCAL_STORAGE_KEY_PREFIX + entity, JSON.stringify(initial));
      return initial;
    }
    return JSON.parse(raw);
  } catch {
    return INITIAL_MOCK_ENTITIES[entity] || [];
  }
}

function setLocalEntityStore(entity: EntityKey, rows: EntityRow[]) {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(LOCAL_STORAGE_KEY_PREFIX + entity, JSON.stringify(rows));
  } catch {
    /* ignore storage errors */
  }
}

export async function listEntity(params: { data: { entity: EntityKey; limit?: number; offset?: number } }) {
  const { entity, limit = 200, offset = 0 } = params.data;
  try {
    const res = await fetch(
      `${JAVA_BASE}/api/v1/entity/${entity}?limit=${limit}&offset=${offset}`,
      { signal: AbortSignal.timeout(3000) }
    );
    if (res.ok) {
      const json = await res.json();
      return {
        rows: (json.rows ?? []) as EntityRow[],
        total: (json.total ?? 0) as number,
        limit,
        offset,
      };
    }
  } catch {
    /* fallback to local store */
  }

  const localRows = getLocalEntityStore(entity);
  const pagedRows = localRows.slice(offset, offset + limit);
  return {
    rows: pagedRows,
    total: localRows.length,
    limit,
    offset,
  };
}

export async function createEntity(params: { data: { entity: EntityKey; values: Record<string, unknown> } }) {
  const { entity, values } = params.data;
  const def = entities[entity];
  const parsed = def ? def.schema.parse(values) : values;

  try {
    const res = await fetch(`${JAVA_BASE}/api/v1/entity/${entity}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsed),
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) {
      const json = await res.json();
      return { row: json.row as EntityRow };
    }
  } catch {
    /* fallback to local store */
  }

  const dateCol = def?.dateColumn || "created_at";
  const newRow: EntityRow = {
    id: Date.now(),
    ...parsed,
    [dateCol]: new Date().toISOString(),
  };
  const current = getLocalEntityStore(entity);
  const updated = [newRow, ...current];
  setLocalEntityStore(entity, updated);
  return { row: newRow };
}

export async function deleteEntity(params: { data: { entity: EntityKey; id: string | number } }) {
  const { entity, id } = params.data;

  try {
    const res = await fetch(`${JAVA_BASE}/api/v1/entity/${entity}/${id}`, {
      method: "DELETE",
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) return { ok: true };
  } catch {
    /* fallback to local store */
  }

  const current = getLocalEntityStore(entity);
  const updated = current.filter((r) => String(r.id) !== String(id));
  setLocalEntityStore(entity, updated);
  return { ok: true };
}
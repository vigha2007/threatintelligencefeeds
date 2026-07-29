export type MatchSource = "exact" | "normalized" | "fuzzy";

export interface DbPhoneRecord {
  found: true;
  source: MatchSource;
  matchScore: number;
  id: number;
  phone_number: string;
  country: string | null;
  severity: "critical" | "high" | "medium" | "low";
  pattern: string | null;
  reported_at: string | null;
  detected_at: string | null;
}

export interface DbSmsRecord {
  found: true;
  source: MatchSource;
  matchScore: number;
  id: number;
  channel: string;
  sender: string | null;
  content: string;
  severity: "critical" | "high" | "medium" | "low";
  detected_at: string | null;
}

export type PhoneLookupResult = DbPhoneRecord | { found: false };
export type SmsLookupResult   = DbSmsRecord   | { found: false };

const JAVA_BASE = import.meta.env.VITE_JAVA_BASE_URL || "http://localhost:8081";

export async function logSearch(params: {
  data: { module: "Phone" | "SMS"; input: string; dbMatch: boolean; aiUsed: boolean; result: string };
}) {
  const { module, input, dbMatch, aiUsed, result } = params.data;
  console.log(`📊 SEARCH LOG: [Module: ${module}] [Input: "${input}"] [DB Match: ${dbMatch}] [AI Used: ${aiUsed}] [Result: ${result}]`);
  return { ok: true };
}

export async function lookupPhoneInDb(params: { data: { phone: string } }): Promise<PhoneLookupResult> {
  const { phone } = params.data;
  try {
    const url = `${JAVA_BASE}/api/v1/search/phone?q=${encodeURIComponent(phone)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return { found: false };
    const json = (await res.json()) as Record<string, unknown>;
    if (!json.found) return { found: false };

    const row = (json.row ?? {}) as Record<string, unknown>;
    return {
      found:       true,
      source:      (json.source as MatchSource) ?? "exact",
      matchScore:  Number(json.matchScore ?? 1),
      id:          Number(row.id ?? 0),
      phone_number: String(row.phone_number ?? phone),
      country:     row.country != null ? String(row.country) : null,
      severity:    (row.severity as DbPhoneRecord["severity"]) ?? "low",
      pattern:     row.pattern != null ? String(row.pattern) : null,
      reported_at: row.reported_at != null ? String(row.reported_at) : null,
      detected_at: row.detected_at != null ? String(row.detected_at) : null,
    };
  } catch {
    return { found: false };
  }
}

export async function lookupSmsInDb(params: { data: { text: string } }): Promise<SmsLookupResult> {
  const { text } = params.data;
  try {
    const url = `${JAVA_BASE}/api/v1/search/sms?q=${encodeURIComponent(text)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return { found: false };
    const json = (await res.json()) as Record<string, unknown>;
    if (!json.found) return { found: false };

    const row = (json.row ?? {}) as Record<string, unknown>;
    return {
      found:       true,
      source:      (json.source as MatchSource) ?? "exact",
      matchScore:  Number(json.matchScore ?? 1),
      id:          Number(row.id ?? 0),
      channel:     String(row.channel ?? "sms"),
      sender:      row.sender != null ? String(row.sender) : null,
      content:     String(row.content ?? ""),
      severity:    (row.severity as DbSmsRecord["severity"]) ?? "low",
      detected_at: row.detected_at != null ? String(row.detected_at) : null,
    };
  } catch {
    return { found: false };
  }
}

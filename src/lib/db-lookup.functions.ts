/**
 * db-lookup.functions.ts
 *
 * Server functions that hit the Java /api/v1/search/* endpoints to check
 * whether a phone number or SMS message already exists in the database.
 *
 * Priority chain:
 *   1. DB exact match  → return DB record immediately, skip AI
 *   2. DB normalized   → return DB record immediately, skip AI
 *   3. DB fuzzy (SMS)  → return DB record immediately, skip AI
 *   4. No match        → caller should fall back to AI analysis
 */

import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const JAVA_BASE = process.env.JAVA_BASE_URL || "http://localhost:8081";

export async function logSearchActivity(
  module: "Phone" | "SMS",
  input: string,
  dbMatch: boolean,
  aiUsed: boolean,
  result: string
) {
  if (typeof window !== "undefined") return;
  const fs = await import("fs");
  const path = await import("path");

  const timestamp = new Date().toISOString();
  const logDir = path.join(process.cwd(), "logs");
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }
  const logPath = path.join(logDir, "search_activity.log");
  const logLine = `[${timestamp}] [Module: ${module}] [Input: "${input.replace(/\n/g, "\\n")}"] [DB Match: ${dbMatch ? "Yes" : "No"}] [AI Used: ${aiUsed ? "Yes" : "No"}] [Final Result: ${result}]\n`;

  console.log(`📊 SEARCH LOG: ${logLine.trim()}`);

  try {
    fs.appendFileSync(logPath, logLine, "utf8");
  } catch (err) {
    console.error("Failed to write to search activity log file:", err);
  }
}

export const logSearch = createServerFn({ method: "POST" })
  .validator((d: { module: "Phone" | "SMS"; input: string; dbMatch: boolean; aiUsed: boolean; result: string }) =>
    z.object({
      module: z.enum(["Phone", "SMS"]),
      input: z.string(),
      dbMatch: z.boolean(),
      aiUsed: z.boolean(),
      result: z.string(),
    }).parse(d)
  )
  .handler(async ({ data }) => {
    await logSearchActivity(data.module, data.input, data.dbMatch, data.aiUsed, data.result);
    return { ok: true };
  });


// ---------------------------------------------------------------------------
// Types for DB results
// ---------------------------------------------------------------------------

export type MatchSource = "exact" | "normalized" | "fuzzy";

export interface DbPhoneRecord {
  found: true;
  source: MatchSource;
  matchScore: number;
  // Raw DB row fields from suspicious_calls
  id: number;
  phone_number: string;
  country: string | null;
  severity: "critical" | "high" | "medium" | "low";
  pattern: string | null;        // "Category · Type · Carrier · trust X%"
  reported_at: string | null;
  detected_at: string | null;
}

export interface DbSmsRecord {
  found: true;
  source: MatchSource;
  matchScore: number;
  // Raw DB row fields from scam_messages
  id: number;
  channel: string;
  sender: string | null;
  content: string;
  severity: "critical" | "high" | "medium" | "low";
  detected_at: string | null;
}

export type PhoneLookupResult = DbPhoneRecord | { found: false };
export type SmsLookupResult   = DbSmsRecord   | { found: false };

// ---------------------------------------------------------------------------
// Server functions
// ---------------------------------------------------------------------------

export const lookupPhoneInDb = createServerFn({ method: "GET" })
  .validator((d: { phone: string }) => z.object({ phone: z.string().min(1).max(64) }).parse(d))
  .handler(async ({ data }): Promise<PhoneLookupResult> => {
    try {
      const url = `${JAVA_BASE}/api/v1/search/phone?q=${encodeURIComponent(data.phone)}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (!res.ok) return { found: false };
      const json = await res.json() as Record<string, unknown>;
      if (!json.found) return { found: false };

      const row = (json.row ?? {}) as Record<string, unknown>;
      return {
        found:       true,
        source:      (json.source as MatchSource) ?? "exact",
        matchScore:  Number(json.matchScore ?? 1),
        id:          Number(row.id ?? 0),
        phone_number: String(row.phone_number ?? data.phone),
        country:     row.country != null ? String(row.country) : null,
        severity:    (row.severity as DbPhoneRecord["severity"]) ?? "low",
        pattern:     row.pattern != null ? String(row.pattern) : null,
        reported_at: row.reported_at != null ? String(row.reported_at) : null,
        detected_at: row.detected_at != null ? String(row.detected_at) : null,
      };
    } catch {
      // DB unavailable — let caller fall back to AI
      return { found: false };
    }
  });

export const lookupSmsInDb = createServerFn({ method: "GET" })
  .validator((d: { text: string }) => z.object({ text: z.string().min(1).max(4000) }).parse(d))
  .handler(async ({ data }): Promise<SmsLookupResult> => {
    try {
      const url = `${JAVA_BASE}/api/v1/search/sms?q=${encodeURIComponent(data.text)}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (!res.ok) return { found: false };
      const json = await res.json() as Record<string, unknown>;
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
      // DB unavailable — let caller fall back to AI
      return { found: false };
    }
  });

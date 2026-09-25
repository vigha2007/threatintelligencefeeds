import { z } from "zod";
import { severityEnum } from "./threat-entities";

const JAVA_BASE = import.meta.env.VITE_JAVA_BASE_URL || import.meta.env.VITE_API_BASE_URL || "http://localhost:8081";

const inputSchema = z.object({
  input_text: z.string().min(1).max(8000),
  classification: z.string().min(1).max(128),
  confidence: z.number().min(0).max(1).optional(),
  severity: severityEnum,
  raw_response: z.record(z.string(), z.unknown()).optional(),
});

type ScamResultRow = Record<string, string | number | boolean | null>;

const LOCAL_STORAGE_KEY = "threat_intel_scam_results";

function getLocalScamResults(): ScamResultRow[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(LOCAL_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export async function saveScamDetectorResult(params: { data: z.infer<typeof inputSchema> }) {
  const data = inputSchema.parse(params.data);
  try {
    const res = await fetch(`${JAVA_BASE}/api/v1/entity/scam_detector_results`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) {
      const json = await res.json();
      return { row: json.row as ScamResultRow };
    }
  } catch {
    /* fallback to local store */
  }

  const newRow: ScamResultRow = { ...data, id: Date.now() } as unknown as ScamResultRow;
  const current = getLocalScamResults();
  if (typeof window !== "undefined") {
    try {
      localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify([newRow, ...current]));
    } catch { /* ignore */ }
  }
  return { row: newRow };
}

export async function listScamDetectorResults() {
  try {
    const res = await fetch(`${JAVA_BASE}/api/v1/entity/scam_detector_results`, {
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) {
      const json = await res.json();
      return { rows: json.rows ?? [] };
    }
  } catch {
    /* fallback to local store */
  }

  return { rows: getLocalScamResults() };
}
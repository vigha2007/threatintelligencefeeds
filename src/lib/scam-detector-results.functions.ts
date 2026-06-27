import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { severityEnum } from "./threat-entities";

const inputSchema = z.object({
  input_text: z.string().min(1).max(8000),
  classification: z.string().min(1).max(128),
  confidence: z.number().min(0).max(1).optional(),
  severity: severityEnum,
  raw_response: z.record(z.string(), z.unknown()).optional(),
});

export const saveScamDetectorResult = createServerFn({ method: "POST" })
  .inputValidator((d) => inputSchema.parse(d))
  .handler(async ({ data }) => {
    // Save to Java backend
    try {
      const res = await fetch(`http://localhost:8080/api/v1/entity/scam_detector_results`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      if (!res.ok) throw new Error("Failed to insert result in Java backend");
      const json = await res.json();
      return { row: json.row as Record<string, string | number | boolean | null> };
    } catch {
      // Mock if table doesn't exist — cast through unknown to satisfy the index signature
      // since raw_response (Record<string, unknown>) isn't directly assignable to the return type
      return { row: ({ ...data, id: Date.now() } as unknown) as Record<string, string | number | boolean | null> };
    }
  });

export const listScamDetectorResults = createServerFn({ method: "GET" })
  .handler(async () => {
    try {
      const res = await fetch(`http://localhost:8080/api/v1/entity/scam_detector_results`);
      if (!res.ok) return { rows: [] };
      const json = await res.json();
      return { rows: json.rows ?? [] };
    } catch {
      return { rows: [] };
    }
  });
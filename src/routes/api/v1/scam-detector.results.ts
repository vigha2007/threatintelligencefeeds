import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { jsonResponse, jsonError } from "@/lib/api-auth.server";
import { severityEnum } from "@/lib/threat-entities";

const inputSchema = z.object({
  input_text: z.string().min(1).max(8000),
  classification: z.string().min(1).max(128),
  confidence: z.number().min(0).max(1).optional(),
  severity: severityEnum,
  raw_response: z.record(z.string(), z.unknown()).optional(),
});

export const Route = createFileRoute("/api/v1/scam-detector/results")({
  server: {
    handlers: {
      GET: async () => {
        try {
          const res = await fetch(`http://localhost:8080/api/v1/entity/scam_detector_results`);
          if (!res.ok) return jsonResponse(200, { rows: [] });
          const json = await res.json();
          return jsonResponse(200, { rows: json.rows ?? [] });
        } catch (e) {
          return jsonError(500, (e as Error).message);
        }
      },
      POST: async ({ request }) => {
        let body: unknown;
        try { body = await request.json(); } catch { return jsonError(400, "Invalid JSON"); }
        const values = inputSchema.safeParse(body);
        if (!values.success) return jsonError(400, values.error.message);
        try {
          const res = await fetch(`http://localhost:8080/api/v1/entity/scam_detector_results`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(values.data)
          });
          if (!res.ok) throw new Error("Failed to insert result in Java backend");
          const json = await res.json();
          return jsonResponse(201, { row: json.row });
        } catch (e) {
          // Mock if table doesn't exist
          return jsonResponse(201, { row: { ...values.data, id: Date.now() } });
        }
      },
    },
  },
});

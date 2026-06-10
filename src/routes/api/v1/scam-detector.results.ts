import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { authenticateRequest, jsonResponse, jsonError } from "@/lib/api-auth.server";
import { severityEnum } from "@/lib/threat-entities";

const schema = z.object({
  input_text: z.string().min(1).max(8000),
  classification: z.string().min(1).max(128),
  confidence: z.number().min(0).max(1).optional(),
  severity: severityEnum,
  raw_response: z.record(z.string(), z.unknown()).optional(),
});

export const Route = createFileRoute("/api/v1/scam-detector/results")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const auth = await authenticateRequest(request);
        if (auth instanceof Response) return auth;
        let body: unknown;
        try { body = await request.json(); } catch { return jsonError(400, "Invalid JSON"); }
        const parsed = schema.safeParse(body);
        if (!parsed.success) return jsonError(400, parsed.error.message);
        const { data, error } = await auth.supabase
          .from("scam_detector_results")
          .insert({ ...parsed.data, user_id: auth.userId })
          .select()
          .single();
        if (error) return jsonError(500, error.message);
        return jsonResponse(201, { row: data });
      },
      GET: async ({ request }) => {
        const auth = await authenticateRequest(request);
        if (auth instanceof Response) return auth;
        const { data, error } = await auth.supabase
          .from("scam_detector_results")
          .select("*")
          .order("created_at", { ascending: false })
          .limit(200);
        if (error) return jsonError(500, error.message);
        return jsonResponse(200, { rows: data ?? [] });
      },
    },
  },
});

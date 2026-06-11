import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { createClient } from "@supabase/supabase-js";
import { severityEnum } from "./threat-entities";

const inputSchema = z.object({
  input_text: z.string().min(1).max(8000),
  classification: z.string().min(1).max(128),
  confidence: z.number().min(0).max(1).optional(),
  severity: severityEnum,
  raw_response: z.record(z.string(), z.unknown()).optional(),
});

function getSupabase() {
  return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_PUBLISHABLE_KEY!);
}

export const saveScamDetectorResult = createServerFn({ method: "POST" })
  .inputValidator((d) => inputSchema.parse(d))
  .handler(async ({ data }) => {
    const supabase = getSupabase();
    const sb = supabase as unknown as {
      from: (t: string) => { insert: (v: Record<string, unknown>) => { select: () => { single: () => Promise<{ data: unknown; error: { message: string } | null }> } } };
    };
    const { data: row, error } = await sb
      .from("scam_detector_results")
      .insert(data)
      .select()
      .single();
    if (error) throw new Error(error.message);
    return { row: row as Record<string, string | number | boolean | null> };
  });

export const listScamDetectorResults = createServerFn({ method: "GET" })
  .handler(async () => {
    const supabase = getSupabase();
    const { data, error } = await supabase
      .from("scam_detector_results")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(100);
    if (error) throw new Error(error.message);
    return { rows: data ?? [] };
  });

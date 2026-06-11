import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { createClient } from "@supabase/supabase-js";
import { jsonResponse, jsonError } from "@/lib/api-auth.server";
import { entities, allEntityKeys, type EntityKey } from "@/lib/threat-entities";

const entityParam = z.enum(allEntityKeys as [EntityKey, ...EntityKey[]]);

function getSupabase() {
  return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_PUBLISHABLE_KEY!);
}

export const Route = createFileRoute("/api/v1/$entity")({
  server: {
    handlers: {
      GET: async ({ params }) => {
        const parsed = entityParam.safeParse(params.entity);
        if (!parsed.success) return jsonError(404, "Unknown entity");
        const supabase = getSupabase();
        const def = entities[parsed.data];
        const { data, error } = await supabase
          .from(def.key)
          .select("*")
          .order(def.dateColumn, { ascending: false })
          .limit(500);
        if (error) return jsonError(500, error.message);
        return jsonResponse(200, { rows: data ?? [] });
      },
      POST: async ({ request, params }) => {
        const parsed = entityParam.safeParse(params.entity);
        if (!parsed.success) return jsonError(404, "Unknown entity");
        const supabase = getSupabase();
        const def = entities[parsed.data];
        let body: unknown;
        try { body = await request.json(); } catch { return jsonError(400, "Invalid JSON"); }
        const values = def.schema.safeParse(body);
        if (!values.success) return jsonError(400, values.error.message);
        const { data, error } = await supabase
          .from(def.key)
          .insert(values.data)
          .select()
          .single();
        if (error) return jsonError(500, error.message);
        return jsonResponse(201, { row: data });
      },
    },
  },
});

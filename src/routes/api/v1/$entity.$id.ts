import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { createClient } from "@supabase/supabase-js";
import { jsonResponse, jsonError } from "@/lib/api-auth.server";
import { entities, allEntityKeys, type EntityKey } from "@/lib/threat-entities";

const entityParam = z.enum(allEntityKeys as [EntityKey, ...EntityKey[]]);
const idParam = z.string().uuid();

function getSupabase() {
  return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_PUBLISHABLE_KEY!);
}

export const Route = createFileRoute("/api/v1/$entity/$id")({
  server: {
    handlers: {
      GET: async ({ params }) => {
        const e = entityParam.safeParse(params.entity);
        const id = idParam.safeParse(params.id);
        if (!e.success || !id.success) return jsonError(400, "Bad parameters");
        const supabase = getSupabase();
        const def = entities[e.data];
        const { data, error } = await supabase.from(def.key).select("*").eq("id", id.data).maybeSingle();
        if (error) return jsonError(500, error.message);
        if (!data) return jsonError(404, "Not found");
        return jsonResponse(200, { row: data });
      },
      DELETE: async ({ params }) => {
        const e = entityParam.safeParse(params.entity);
        const id = idParam.safeParse(params.id);
        if (!e.success || !id.success) return jsonError(400, "Bad parameters");
        const supabase = getSupabase();
        const def = entities[e.data];
        const { error } = await supabase.from(def.key).delete().eq("id", id.data);
        if (error) return jsonError(500, error.message);
        return jsonResponse(200, { ok: true });
      },
      PATCH: async ({ request, params }) => {
        const e = entityParam.safeParse(params.entity);
        const id = idParam.safeParse(params.id);
        if (!e.success || !id.success) return jsonError(400, "Bad parameters");
        const supabase = getSupabase();
        const def = entities[e.data];
        let body: unknown;
        try { body = await request.json(); } catch { return jsonError(400, "Invalid JSON"); }
        const values = def.schema.partial().safeParse(body);
        if (!values.success) return jsonError(400, values.error.message);
        const { data, error } = await supabase.from(def.key).update(values.data).eq("id", id.data).select().single();
        if (error) return jsonError(500, error.message);
        return jsonResponse(200, { row: data });
      },
    },
  },
});

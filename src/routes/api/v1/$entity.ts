import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { authenticateRequest, jsonResponse, jsonError } from "@/lib/api-auth.server";
import { entities, allEntityKeys, type EntityKey } from "@/lib/threat-entities";

const entityParam = z.enum(allEntityKeys as [EntityKey, ...EntityKey[]]);

export const Route = createFileRoute("/api/v1/$entity")({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        const parsed = entityParam.safeParse(params.entity);
        if (!parsed.success) return jsonError(404, "Unknown entity");
        const auth = await authenticateRequest(request);
        if (auth instanceof Response) return auth;
        const def = entities[parsed.data];
        const { data, error } = await auth.supabase
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
        const auth = await authenticateRequest(request);
        if (auth instanceof Response) return auth;
        const def = entities[parsed.data];
        let body: unknown;
        try { body = await request.json(); } catch { return jsonError(400, "Invalid JSON"); }
        const values = def.schema.safeParse(body);
        if (!values.success) return jsonError(400, values.error.message);
        const { data, error } = await auth.supabase
          .from(def.key)
          .insert({ ...values.data, user_id: auth.userId })
          .select()
          .single();
        if (error) return jsonError(500, error.message);
        return jsonResponse(201, { row: data });
      },
    },
  },
});

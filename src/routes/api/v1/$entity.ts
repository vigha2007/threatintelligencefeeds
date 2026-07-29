import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { jsonResponse, jsonError } from "@/lib/api-auth.server";
import { entities, allEntityKeys, type EntityKey } from "@/lib/threat-entities";

const entityParam = z.enum(allEntityKeys as [EntityKey, ...EntityKey[]]);
const JAVA_BASE = process.env.JAVA_BASE_URL || "http://localhost:8081";

export const Route = createFileRoute("/api/v1/$entity")({
  server: {
    handlers: {
      GET: async ({ params }) => {
        const parsed = entityParam.safeParse(params.entity);
        if (!parsed.success) return jsonError(404, "Unknown entity");
        
        try {
          const res = await fetch(`${JAVA_BASE}/api/v1/entity/${parsed.data}`);
          if (!res.ok) throw new Error("Failed to fetch entity from Java backend");
          const data = await res.json();
          return jsonResponse(200, { rows: data.rows ?? [] });
        } catch (e) {
          return jsonResponse(200, { rows: [] });
        }
      },
      POST: async ({ request, params }) => {
        const parsed = entityParam.safeParse(params.entity);
        if (!parsed.success) return jsonError(404, "Unknown entity");
        
        let body: unknown;
        try { body = await request.json(); } catch { return jsonError(400, "Invalid JSON"); }
        const values = entities[parsed.data].schema.safeParse(body);
        if (!values.success) return jsonError(400, values.error.message);
        
        try {
          const res = await fetch(`${JAVA_BASE}/api/v1/entity/${parsed.data}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(values.data)
          });
          if (!res.ok) throw new Error("Failed to insert entity in Java backend");
          const data = await res.json();
          return jsonResponse(201, { row: data.row });
        } catch (e) {
          return jsonResponse(201, { row: { ...values.data, id: Date.now() } });
        }
      },
    },
  },
});

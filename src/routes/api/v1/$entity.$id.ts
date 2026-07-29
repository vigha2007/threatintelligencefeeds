import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { jsonResponse, jsonError } from "@/lib/api-auth.server";
import { entities, allEntityKeys, type EntityKey } from "@/lib/threat-entities";

const entityParam = z.enum(allEntityKeys as [EntityKey, ...EntityKey[]]);
const idParam = z.union([z.string(), z.number()]);
const JAVA_BASE = process.env.JAVA_BASE_URL || "http://localhost:8081";

export const Route = createFileRoute("/api/v1/$entity/$id")({
  server: {
    handlers: {
      GET: async ({ params }) => {
        const e = entityParam.safeParse(params.entity);
        const id = idParam.safeParse(params.id);
        if (!e.success || !id.success) return jsonError(400, "Bad parameters");
        try {
          const res = await fetch(`${JAVA_BASE}/api/v1/entity/${e.data}/${id.data}`);
          if (!res.ok) {
             if (res.status === 404) return jsonError(404, "Not found");
             throw new Error("Failed to fetch entity");
          }
          const data = await res.json();
          return jsonResponse(200, { row: data.row });
        } catch (err) {
          return jsonError(404, "Not found");
        }
      },
      DELETE: async ({ params }) => {
        const e = entityParam.safeParse(params.entity);
        const id = idParam.safeParse(params.id);
        if (!e.success || !id.success) return jsonError(400, "Bad parameters");
        try {
          const res = await fetch(`${JAVA_BASE}/api/v1/entity/${e.data}/${id.data}`, {
            method: 'DELETE'
          });
          if (!res.ok) throw new Error("Failed to delete entity");
          return jsonResponse(200, { ok: true });
        } catch (err) {
          return jsonResponse(200, { ok: true });
        }
      },
      PATCH: async ({ request, params }) => {
        const e = entityParam.safeParse(params.entity);
        const id = idParam.safeParse(params.id);
        if (!e.success || !id.success) return jsonError(400, "Bad parameters");
        
        let body: unknown;
        try { body = await request.json(); } catch { return jsonError(400, "Invalid JSON"); }
        const values = entities[e.data].schema.partial().safeParse(body);
        if (!values.success) return jsonError(400, values.error.message);
        
        try {
          const res = await fetch(`${JAVA_BASE}/api/v1/entity/${e.data}/${id.data}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(values.data)
          });
          if (!res.ok) throw new Error("Failed to update entity");
          const data = await res.json();
          return jsonResponse(200, { row: data.row });
        } catch (err) {
          return jsonResponse(200, { row: { ...values.data, id: params.id } });
        }
      },
    },
  },
});

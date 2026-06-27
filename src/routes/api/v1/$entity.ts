import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { jsonResponse, jsonError } from "@/lib/api-auth.server";
import { entities, allEntityKeys, type EntityKey } from "@/lib/threat-entities";

const entityParam = z.enum(allEntityKeys as [EntityKey, ...EntityKey[]]);

export const Route = createFileRoute("/api/v1/$entity")({
  server: {
    handlers: {
      GET: async ({ params }) => {
        const parsed = entityParam.safeParse(params.entity);
        if (!parsed.success) return jsonError(404, "Unknown entity");
        
        try {
          const res = await fetch(`http://localhost:8080/api/v1/entity/${parsed.data}`);
          if (!res.ok) throw new Error("Failed to fetch entity from Java backend");
          const data = await res.json();
          return jsonResponse(200, { rows: data.rows ?? [] });
        } catch (e) {
          return jsonError(500, (e as Error).message);
        }
      },
      POST: async ({ request, params }) => {
        const parsed = entityParam.safeParse(params.entity);
        if (!parsed.success) return jsonError(404, "Unknown entity");
        
        let body: unknown;
        try { body = await request.json(); } catch { return jsonError(400, "Invalid JSON"); }
        const values = entities[parsed.data].schema.safeParse(body);
        if (!values.success) return jsonError(400, values.error.message);
        
        // POST to Java backend is not implemented in our basic handler, but we can add it later if needed
        // For now, since user wants CRUD, let's just return a mock success or pass to Java backend
        // We will pass it to Java backend
        try {
          const res = await fetch(`http://localhost:8080/api/v1/entity/${parsed.data}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(values.data)
          });
          if (!res.ok) throw new Error("Failed to insert entity in Java backend");
          const data = await res.json();
          return jsonResponse(201, { row: data.row });
        } catch (e) {
          return jsonError(500, (e as Error).message);
        }
      },
    },
  },
});

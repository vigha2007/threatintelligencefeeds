import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { entities, allEntityKeys, type EntityKey } from "./threat-entities";

type JsonPrimitive = string | number | boolean | null;
type Json = JsonPrimitive | Json[] | { [k: string]: Json };
type EntityRow = { [k: string]: Json };

const JAVA_BASE = process.env.JAVA_BASE_URL || "http://localhost:8081";
const entityKeySchema = z.enum(allEntityKeys as [EntityKey, ...EntityKey[]]);

export const listEntity = createServerFn({ method: "GET" })
  .validator((d: { entity: EntityKey; limit?: number; offset?: number }) =>
    z.object({
      entity: entityKeySchema,
      limit:  z.number().int().positive().optional(),
      offset: z.number().int().min(0).optional(),
    }).parse(d)
  )
  .handler(async ({ data }) => {
    const limit  = data.limit  ?? 200;
    const offset = data.offset ?? 0;
    const res = await fetch(
      `${JAVA_BASE}/api/v1/entity/${data.entity}?limit=${limit}&offset=${offset}`
    );
    if (!res.ok) throw new Error("Failed to fetch from Java backend");
    const json = await res.json();
    return {
      rows:   (json.rows  ?? []) as EntityRow[],
      total:  (json.total ?? 0)  as number,
      limit,
      offset,
    };
  });

export const createEntity = createServerFn({ method: "POST" })
  .validator((d: { entity: EntityKey; values: Record<string, unknown> }) =>
    z.object({ entity: entityKeySchema, values: z.record(z.string(), z.unknown()) }).parse(d)
  )
  .handler(async ({ data }) => {
    const def = entities[data.entity];
    const parsed = def.schema.parse(data.values);

    const res = await fetch(`${JAVA_BASE}/api/v1/entity/${data.entity}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(parsed)
    });
    if (!res.ok) throw new Error("Failed to insert entity in Java backend");
    const json = await res.json();
    return { row: json.row as EntityRow };
  });

export const deleteEntity = createServerFn({ method: "POST" })
  .validator((d: { entity: EntityKey; id: string }) =>
    z.object({ entity: entityKeySchema, id: z.union([z.string(), z.number()]).transform(String) }).parse(d)
  )
  .handler(async ({ data }) => {
    const res = await fetch(`${JAVA_BASE}/api/v1/entity/${data.entity}/${data.id}`, {
      method: 'DELETE'
    });
    if (!res.ok) throw new Error("Failed to delete entity");
    return { ok: true };
  });
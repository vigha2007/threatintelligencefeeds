import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { entities, allEntityKeys, type EntityKey } from "./threat-entities";

const entityKeySchema = z.enum(allEntityKeys as [EntityKey, ...EntityKey[]]);

export const listEntity = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: { entity: EntityKey }) => z.object({ entity: entityKeySchema }).parse(d))
  .handler(async ({ data, context }) => {
    const def = entities[data.entity];
    const { data: rows, error } = await context.supabase
      .from(def.key)
      .select("*")
      .order(def.dateColumn, { ascending: false })
      .limit(500);
    if (error) throw new Error(error.message);
    return { rows: rows ?? [] };
  });

export const createEntity = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: { entity: EntityKey; values: Record<string, unknown> }) =>
    z.object({ entity: entityKeySchema, values: z.record(z.string(), z.unknown()) }).parse(d)
  )
  .handler(async ({ data, context }) => {
    const def = entities[data.entity];
    const parsed = def.schema.parse(data.values);
    const { data: row, error } = await context.supabase
      .from(def.key)
      .insert({ ...parsed, user_id: context.userId })
      .select()
      .single();
    if (error) throw new Error(error.message);
    return { row };
  });

export const deleteEntity = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: { entity: EntityKey; id: string }) =>
    z.object({ entity: entityKeySchema, id: z.string().uuid() }).parse(d)
  )
  .handler(async ({ data, context }) => {
    const def = entities[data.entity];
    const { error } = await context.supabase.from(def.key).delete().eq("id", data.id);
    if (error) throw new Error(error.message);
    return { ok: true };
  });

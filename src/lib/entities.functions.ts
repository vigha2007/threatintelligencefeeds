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
    const sb = context.supabase as unknown as {
      from: (t: string) => {
        select: (s: string) => { order: (c: string, o: { ascending: boolean }) => { limit: (n: number) => Promise<{ data: unknown[] | null; error: { message: string } | null }> } };
      };
    };
    const { data: rows, error } = await sb
      .from(def.key)
      .select("*")
      .order(def.dateColumn, { ascending: false })
      .limit(500);
    if (error) throw new Error(error.message);
    return { rows: (rows ?? []) as Array<Record<string, unknown>> };
  });

export const createEntity = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: { entity: EntityKey; values: Record<string, unknown> }) =>
    z.object({ entity: entityKeySchema, values: z.record(z.string(), z.unknown()) }).parse(d)
  )
  .handler(async ({ data, context }) => {
    const def = entities[data.entity];
    const parsed = def.schema.parse(data.values);
    const sb = context.supabase as unknown as {
      from: (t: string) => {
        insert: (v: Record<string, unknown>) => { select: () => { single: () => Promise<{ data: unknown; error: { message: string } | null }> } };
      };
    };
    const { data: row, error } = await sb
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
    const sb = context.supabase as unknown as {
      from: (t: string) => { delete: () => { eq: (c: string, v: string) => Promise<{ error: { message: string } | null }> } };
    };
    const def = entities[data.entity];
    const { error } = await sb.from(def.key).delete().eq("id", data.id);
    if (error) throw new Error(error.message);
    return { ok: true };
  });

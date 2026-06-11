import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { createClient } from "@supabase/supabase-js";
import { entities, allEntityKeys, type EntityKey } from "./threat-entities";

type JsonPrimitive = string | number | boolean | null;
type Json = JsonPrimitive | Json[] | { [k: string]: Json };
type EntityRow = { [k: string]: Json };

const entityKeySchema = z.enum(allEntityKeys as [EntityKey, ...EntityKey[]]);

function getSupabase() {
  return createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_PUBLISHABLE_KEY!);
}

export const listEntity = createServerFn({ method: "GET" })
  .inputValidator((d: { entity: EntityKey }) => z.object({ entity: entityKeySchema }).parse(d))
  .handler(async ({ data }) => {
    const supabase = getSupabase();
    const def = entities[data.entity];
    const sb = supabase as unknown as {
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
    return { rows: (rows ?? []) as EntityRow[] };
  });

export const createEntity = createServerFn({ method: "POST" })
  .inputValidator((d: { entity: EntityKey; values: Record<string, unknown> }) =>
    z.object({ entity: entityKeySchema, values: z.record(z.string(), z.unknown()) }).parse(d)
  )
  .handler(async ({ data }) => {
    const supabase = getSupabase();
    const def = entities[data.entity];
    const parsed = def.schema.parse(data.values);
    const sb = supabase as unknown as {
      from: (t: string) => {
        insert: (v: Record<string, unknown>) => { select: () => { single: () => Promise<{ data: unknown; error: { message: string } | null }> } };
      };
    };
    const { data: row, error } = await sb
      .from(def.key)
      .insert(parsed)
      .select()
      .single();
    if (error) throw new Error(error.message);
    return { row: row as EntityRow };
  });

export const deleteEntity = createServerFn({ method: "POST" })
  .inputValidator((d: { entity: EntityKey; id: string }) =>
    z.object({ entity: entityKeySchema, id: z.string().uuid() }).parse(d)
  )
  .handler(async ({ data }) => {
    const supabase = getSupabase();
    const sb = supabase as unknown as {
      from: (t: string) => { delete: () => { eq: (c: string, v: string) => Promise<{ error: { message: string } | null }> } };
    };
    const def = entities[data.entity];
    const { error } = await sb.from(def.key).delete().eq("id", data.id);
    if (error) throw new Error(error.message);
    return { ok: true };
  });

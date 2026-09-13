import { entities, type EntityKey } from "./threat-entities";
import { API_BASE_URL, DEFAULT_TIMEOUT_MS } from "./api-config";

type JsonPrimitive = string | number | boolean | null;
type Json = JsonPrimitive | Json[] | { [k: string]: Json };
type EntityRow = { [k: string]: Json };

export const toSafeString = (value: unknown): string => {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch {
    return "";
  }
};

export interface EntityListResult {
  rows: EntityRow[];
  total: number;
  totalElements: number;
  totalPages: number;
  page: number;
  limit: number;
  offset: number;
}

/**
 * Fetch a paginated list of entity rows from the Java backend.
 * Throws an Error with a descriptive message when the backend is unreachable
 * or returns an error — no mock/static fallback.
 */
export async function listEntity(params: {
  data: { entity: EntityKey; limit?: number; offset?: number; page?: number };
}): Promise<EntityListResult> {
  const { entity, limit = 50, offset = 0, page = 0 } = params.data;

  const resolvedOffset = page > 0 ? page * limit : offset;
  const resolvedPage   = page > 0 ? page : Math.floor(offset / limit);

  const url = `${API_BASE_URL}/api/v1/entity/${entity}?limit=${limit}&offset=${resolvedOffset}`;

  let res: Response;
  try {
    res = await fetch(url, {
      signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
    });
  } catch (err: unknown) {
    const isTimeout =
      err instanceof Error &&
      (err.name === "TimeoutError" || err.name === "AbortError");
    throw new Error(
      isTimeout
        ? "Backend server unavailable — request timed out. Is the Java backend running?"
        : "Backend server unavailable — cannot connect to http://localhost:8081."
    );
  }

  if (!res.ok) {
    let errMsg = `Backend returned ${res.status}`;
    try {
      const j = await res.json();
      if (j?.error) errMsg = j.error;
    } catch { /* ignore */ }
    if (res.status === 503 || res.status === 500) {
      throw new Error("Database connection failed — " + errMsg);
    }
    throw new Error("Backend error: " + errMsg);
  }

  const json = await res.json();

  // Support both Spring-style (content/totalElements) and legacy (rows/total) keys
  const rows         = (json.content ?? json.rows ?? []) as EntityRow[];
  const total        = Number(json.totalElements ?? json.total ?? rows.length);
  const totalPages   = Number(json.totalPages ?? Math.ceil(total / limit));

  return {
    rows,
    total,
    totalElements: total,
    totalPages,
    page: resolvedPage,
    limit,
    offset: resolvedOffset,
  };
}

/**
 * Create a new entity row in the backend database.
 * Throws on any failure — no local store fallback.
 */
export async function createEntity(params: {
  data: { entity: EntityKey; values: Record<string, unknown> };
}): Promise<{ row: EntityRow }> {
  const { entity, values } = params.data;
  const def = entities[entity];
  const parsed = def ? def.schema.parse(values) : values;

  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}/api/v1/entity/${entity}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsed),
      signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
    });
  } catch {
    throw new Error("Backend server unavailable — could not create record.");
  }

  if (!res.ok) {
    let msg = `Create failed (${res.status})`;
    try {
      const j = await res.json();
      if (j?.error) msg = j.error;
    } catch { /* ignore */ }
    throw new Error(msg);
  }

  const json = await res.json();
  return { row: json.row as EntityRow };
}

/**
 * Delete an entity row by ID from the backend database.
 * Throws on any failure — no local store fallback.
 */
export async function deleteEntity(params: {
  data: { entity: EntityKey; id: string | number };
}): Promise<{ ok: boolean }> {
  const { entity, id } = params.data;

  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}/api/v1/entity/${entity}/${id}`, {
      method: "DELETE",
      signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
    });
  } catch {
    throw new Error("Backend server unavailable — could not delete record.");
  }

  if (!res.ok) {
    throw new Error(`Delete failed (${res.status})`);
  }

  return { ok: true };
}
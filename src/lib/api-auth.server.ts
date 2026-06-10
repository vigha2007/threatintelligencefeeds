// Shared bearer-token authentication for REST API routes.
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

export interface AuthResult {
  userId: string;
  supabase: SupabaseClient;
}

export async function authenticateRequest(request: Request): Promise<AuthResult | Response> {
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_PUBLISHABLE_KEY = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!SUPABASE_URL || !SUPABASE_PUBLISHABLE_KEY) {
    return jsonError(500, "Server misconfigured");
  }
  const auth = request.headers.get("authorization") ?? "";
  if (!auth.startsWith("Bearer ")) return jsonError(401, "Missing Bearer token");
  const token = auth.slice("Bearer ".length);
  const supabase = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { storage: undefined, persistSession: false, autoRefreshToken: false },
  });
  const { data, error } = await supabase.auth.getClaims(token);
  if (error || !data?.claims?.sub) return jsonError(401, "Invalid token");
  return { userId: data.claims.sub as string, supabase };
}

export function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export function jsonError(status: number, message: string) {
  return jsonResponse(status, { error: message });
}

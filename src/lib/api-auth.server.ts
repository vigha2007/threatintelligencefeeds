// Shared bearer-token authentication for REST API routes.
// Supabase removed — uses a simple static API key check via environment variable.

export interface AuthResult {
  userId: string;
}

export async function authenticateRequest(request: Request): Promise<AuthResult | Response> {
  const API_SECRET = process.env.API_SECRET;
  if (!API_SECRET) {
    return jsonError(500, "Server misconfigured: missing API_SECRET");
  }

  const auth = request.headers.get("authorization") ?? "";
  if (!auth.startsWith("Bearer ")) return jsonError(401, "Missing Bearer token");

  const token = auth.slice("Bearer ".length);
  if (token !== API_SECRET) return jsonError(401, "Invalid token");

  return { userId: "authenticated-user" };
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

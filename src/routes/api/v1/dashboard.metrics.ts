import { createFileRoute } from "@tanstack/react-router";
import { getDashboardMetrics } from "@/lib/dashboard.functions";
import { authenticateRequest, jsonResponse, jsonError } from "@/lib/api-auth.server";

export const Route = createFileRoute("/api/v1/dashboard/metrics")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const auth = await authenticateRequest(request);
        if (auth instanceof Response) return auth;
        try {
          // Reuse server fn via direct call won't have request context — re-implement minimally
          // by calling Supabase via the authenticated client.
          const tables = [
            { name: "threats", date: "detected_at" },
            { name: "phishing_urls", date: "blocked_at" },
            { name: "spam_calls", date: "reported_at" },
            { name: "email_scams", date: "detected_at" },
            { name: "malicious_ips", date: "last_seen" },
            { name: "scam_messages", date: "detected_at" },
          ];
          const since = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString();
          const results = await Promise.all(
            tables.map(async (t) => {
              const { data, error } = await auth.supabase.from(t.name).select(`${t.date}, severity`).gte(t.date, since);
              if (error) throw new Error(`${t.name}: ${error.message}`);
              return { table: t.name, rows: data ?? [] };
            })
          );
          const counts = Object.fromEntries(results.map((r) => [r.table, r.rows.length]));
          const severity = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
          for (const r of results) for (const row of (r.rows as unknown as Array<{ severity: string }>)) {
            if (row.severity in severity) severity[row.severity]++;
          }
          return jsonResponse(200, { counts, severity, total: Object.values(counts).reduce((a, b) => a + b, 0) });
        } catch (e) {
          return jsonError(500, (e as Error).message);
        }
      },
    },
  },
});

// Suppress unused-import warning for getDashboardMetrics (kept for future expansion):
void getDashboardMetrics;

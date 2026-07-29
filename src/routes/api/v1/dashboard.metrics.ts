import { createFileRoute } from "@tanstack/react-router";
import { jsonResponse, jsonError } from "@/lib/api-auth.server";

const JAVA_BASE = process.env.JAVA_BASE_URL || "http://localhost:8081";

export const Route = createFileRoute("/api/v1/dashboard/metrics")({
  server: {
    handlers: {
      GET: async () => {
        try {
          const res = await fetch(`${JAVA_BASE}/api/v1/dashboard/metrics`);
          if (!res.ok) throw new Error("Failed to fetch metrics from Java backend");
          const data = await res.json();
          return jsonResponse(200, data);
        } catch (e) {
          return jsonError(500, (e as Error).message);
        }
      },
    },
  },
});

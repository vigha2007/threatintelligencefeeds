import { createFileRoute } from "@tanstack/react-router";
import { jsonResponse, jsonError } from "@/lib/api-auth.server";

export const Route = createFileRoute("/api/v1/dashboard/metrics")({
  server: {
    handlers: {
      GET: async () => {
        try {
          const res = await fetch("http://localhost:8080/api/v1/dashboard/metrics");
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

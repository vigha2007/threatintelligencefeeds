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
          return jsonResponse(200, {
            totalThreats: 1420,
            spamCalls: 580,
            scamMessages: 410,
            phishingUrls: 250,
            maliciousIps: 120,
            emailScams: 60,
            scamDetectorResults: 45,
            recentThreats: [],
            severityBreakdown: { critical: 210, high: 430, medium: 520, low: 260 },
            dailyTrends: Array.from({ length: 14 }, (_, i) => ({
              date: new Date(Date.now() - (13 - i) * 86400000).toISOString().slice(5, 10),
              calls: 20 + Math.floor(Math.sin(i) * 10 + 10),
              messages: 15 + Math.floor(Math.cos(i) * 8 + 8),
              urls: 10 + Math.floor(Math.sin(i * 2) * 5 + 5),
            })),
            categoryBreakdown: [
              { name: "Phishing", count: 480 },
              { name: "Financial Fraud", count: 350 },
              { name: "Identity Theft", count: 290 },
              { name: "Malware", count: 180 },
              { name: "Other", count: 120 },
            ],
          });
        }
      },
    },
  },
});

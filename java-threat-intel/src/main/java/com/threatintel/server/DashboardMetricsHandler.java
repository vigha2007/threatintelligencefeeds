package com.threatintel.server;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.threatintel.dao.DashboardDao;
import com.threatintel.DashboardService;
import com.threatintel.ThreatPrediction;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class DashboardMetricsHandler implements HttpHandler {

    private final DashboardDao dao;
    private final Gson gson = new Gson();

    public DashboardMetricsHandler(DashboardDao dao) {
        this.dao = dao;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {

        // ── CORS Headers ───────────────────────────────────────────────────
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin",  "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
        exchange.getResponseHeaders().add("Content-Type", "application/json");

        // ── Preflight ──────────────────────────────────────────────────────
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        String path   = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        try {
            if (path.equals("/api/analyze") && "POST".equalsIgnoreCase(method)) {
                handleAnalyze(exchange);
            } else if ("GET".equalsIgnoreCase(method)) {
                handleMetrics(exchange);
            } else {
                sendJson(exchange, 405, Map.of("error", "Method not allowed"));
            }
        } catch (Exception e) {
            sendJson(exchange, 500, Map.of("error", e.getMessage() != null
                ? e.getMessage() : "Internal server error"));
        }
    }

    // ── Handler: GET /api/metrics ─────────────────────────────────────────────

    private void handleMetrics(HttpExchange exchange) throws IOException {
        try {
            // Get existing dashboard metrics from DashboardDao
            Map<String, Object> metrics = dao.getMetrics();

            // Attach live ML stats from DashboardService
            DashboardService.DashboardStats stats = DashboardService.getDashboardStats();
            metrics.put("total_threats_detected",  stats.totalThreats);
            metrics.put("phishing_urls_blocked",    stats.phishingUrls);
            metrics.put("suspicious_calls_flagged", stats.suspiciousCalls);
            metrics.put("email_scams_detected",     stats.emailScams);
            metrics.put("malicious_ips_tracked",    stats.maliciousIps);
            metrics.put("scam_messages_analyzed",   stats.scamMessages);

            sendJson(exchange, 200, metrics);

        } catch (Exception e) {
            sendJson(exchange, 500, Map.of("error", "Failed to fetch metrics: "
                + e.getMessage()));
        }
    }

    // ── Handler: POST /api/analyze ────────────────────────────────────────────

    private void handleAnalyze(HttpExchange exchange) throws IOException {
        // Read request body
        String body;
        try (InputStream is = exchange.getRequestBody()) {
            body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }

        // Parse JSON using Gson
        @SuppressWarnings("unchecked")
        Map<String, String> request = gson.fromJson(body, Map.class);

        String type    = request.getOrDefault("type",    "").trim();
        String content = request.getOrDefault("content", "").trim();

        // Validate input
        if (type.isEmpty() || content.isEmpty()) {
            sendJson(exchange, 400, Map.of(
                "error",       "Both 'type' and 'content' fields are required.",
                "valid_types", "url | email | sms | call | ip"
            ));
            return;
        }

        // Call Flask ML API + save to DB
        ThreatPrediction result = DashboardService.analyzeAndStore(type, content);

        if (result != null) {
            Map<String, Object> response = new HashMap<>();
            response.put("status",         "success");
            response.put("prediction",     result.getPrediction());
            response.put("confidence",     result.getConfidence());
            response.put("threat_level",   result.getThreatLevel());
            response.put("data_type",      result.getDataType());
            response.put("is_malicious",   result.isMalicious());
            response.put("confidence_pct",
                String.format("%.1f%%", result.getConfidence() * 100));

            sendJson(exchange, 200, response);
        } else {
            sendJson(exchange, 503, Map.of(
                "status",  "error",
                "message", "ML analysis failed. Make sure Flask API is running on port 5000."
            ));
        }
    }

    // ── Utility: write JSON response ──────────────────────────────────────────

    private void sendJson(HttpExchange exchange, int statusCode, Object data) throws IOException {
        byte[] bytes = gson.toJson(data).getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
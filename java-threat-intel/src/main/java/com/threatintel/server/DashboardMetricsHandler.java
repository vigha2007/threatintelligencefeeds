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
import java.util.LinkedHashMap;
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
            if ((path.equals("/api/analyze") || path.equals("/api/call-detect")) && "POST".equalsIgnoreCase(method)) {
                handleAnalyze(exchange, path.equals("/api/call-detect"));
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

    // ── Handler: POST /api/analyze and /api/call-detect ───────────────────────

    private void handleAnalyze(HttpExchange exchange, boolean isCallDetect) throws IOException {
        // Read request body
        String body;
        try (InputStream is = exchange.getRequestBody()) {
            body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }

        // Parse JSON using Gson
        @SuppressWarnings("unchecked")
        Map<String, String> request = gson.fromJson(body, Map.class);

        // Support both { type, content } and { phone, content } payloads
        String type    = request.getOrDefault("type",    isCallDetect ? "call" : "").trim();
        String content = request.getOrDefault("content",
                            request.getOrDefault("phone", "")).trim();

        if (type.isEmpty()) type = isCallDetect ? "call" : "unknown";

        // Validate input
        if (content.isEmpty()) {
            sendJson(exchange, 400, Map.of(
                "error",       "A 'content' or 'phone' field is required.",
                "valid_types", "url | email | sms | call | ip"
            ));
            return;
        }

        // Call Flask ML API + save to DB
        ThreatPrediction result = DashboardService.analyzeAndStore(type, content);

        if (result != null) {
            boolean malicious  = result.isMalicious();
            double  rawConf    = result.getConfidence(); // 0.0 – 1.0
            double  confPct    = Math.round(rawConf * 1000.0) / 10.0; // e.g. 96.8

            String prediction  = malicious ? "SCAM" : "GOOD";
            int    label       = malicious ? 1 : 0;
            String threatType  = malicious ? "Fraud" : "Benign";
            String phone       = request.getOrDefault("phone", content);
            String country     = request.getOrDefault("country", "Unknown");
            String timestamp   = java.time.Instant.now().toString();

            if (isCallDetect) {
                // Clean structured response for frontend Call Detection
                Map<String, Object> resp = new LinkedHashMap<>();
                resp.put("prediction",  prediction);
                resp.put("label",       label);
                resp.put("confidence",  confPct);
                resp.put("threatType",  threatType);
                resp.put("phone",       phone);
                resp.put("country",     country);
                resp.put("timestamp",   timestamp);
                resp.put("threat_level", result.getThreatLevel());
                resp.put("is_malicious", malicious);
                sendJson(exchange, 200, resp);
            } else {
                // Legacy analyze response
                Map<String, Object> resp = new HashMap<>();
                resp.put("status",      "success");
                resp.put("prediction",  prediction);
                resp.put("confidence",  rawConf);
                resp.put("threat_level", result.getThreatLevel());
                resp.put("data_type",   result.getDataType());
                resp.put("is_malicious", malicious);
                resp.put("confidence_pct", String.format("%.1f%%", confPct));
                sendJson(exchange, 200, resp);
            }
        } else {
            sendJson(exchange, 503, Map.of(
                "status",  "error",
                "message", "ML analysis failed. Make sure FastAPI ML server is running on port 8000."
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
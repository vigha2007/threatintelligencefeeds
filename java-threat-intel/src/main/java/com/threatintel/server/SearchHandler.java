package com.threatintel.server;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.threatintel.db.DatabaseConfig;

import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;
import java.util.regex.Pattern;

/**
 * SearchHandler — Database-first lookup for Phone Number Intelligence & SMS Scam Detection.
 *
 * Routes (all GET):
 *   /api/v1/search/phone?q=<number>   — search suspicious_calls by phone_number
 *   /api/v1/search/sms?q=<text>       — search scam_messages by content (exact → normalized → fuzzy)
 *
 * Returns:
 *   { "found": true,  "source": "exact|normalized|fuzzy", "matchScore": 1.0, "row": { ... } }
 *   { "found": false }
 */
public class SearchHandler implements HttpHandler {

    private static final Gson GSON = new Gson();
    /** Fuzzy similarity threshold — 0.85 = 85 % match required. */
    private static final double FUZZY_THRESHOLD = 0.85;
    /** Maximum rows to pull for fuzzy SMS matching. */
    private static final int    FUZZY_FETCH_LIMIT = 300;

    // ── Non-digit stripper for phone normalisation ──────────────────────────
    private static final Pattern NON_DIGIT = Pattern.compile("[^0-9]");
    // ── Non-alphanum stripper for SMS normalisation ─────────────────────────
    private static final Pattern NON_ALNUM = Pattern.compile("[^a-z0-9]");

    @Override
    public void handle(HttpExchange ex) throws IOException {
        // CORS headers
        ex.getResponseHeaders().add("Access-Control-Allow-Origin",  "*");
        ex.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, OPTIONS");
        ex.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
        ex.getResponseHeaders().add("Content-Type",                 "application/json");

        if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
            ex.sendResponseHeaders(204, -1);
            return;
        }

        String path = ex.getRequestURI().getPath(); // e.g. /api/v1/search/phone
        String query = ex.getRequestURI().getRawQuery(); // e.g. q=+91...
        String q = extractParam(query, "q");

        if (q == null || q.isBlank()) {
            sendJson(ex, 400, Map.of("error", "Missing query parameter 'q'"));
            return;
        }

        try {
            if (path.endsWith("/phone")) {
                handlePhoneSearch(ex, q);
            } else if (path.endsWith("/sms")) {
                handleSmsSearch(ex, q);
            } else {
                sendJson(ex, 404, Map.of("error", "Unknown search type"));
            }
        } catch (SQLException e) {
            System.err.println("[SearchHandler] DB error: " + e.getMessage());
            sendJson(ex, 503, Map.of("found", false, "error", "Database unavailable: " + e.getMessage()));
        }
    }

    // ========================================================================
    //  PHONE SEARCH
    // ========================================================================

    private void handlePhoneSearch(HttpExchange ex, String rawInput) throws IOException, SQLException {
        // Normalize: keep digits only — covers +91, spaces, dashes etc.
        String normalized = NON_DIGIT.matcher(rawInput).replaceAll("");

        try (Connection conn = DatabaseConfig.getConnection()) {
            // 1. Exact match (as stored)
            Map<String, Object> row = phoneQuery(conn,
                "SELECT *, detected_at AS reported_at FROM suspicious_calls WHERE phone_number = ?",
                rawInput);
            if (row != null) { sendFound(ex, "exact", 1.0, enrichPhone(row)); return; }

            // 2. Normalized match — check if stripped DB value equals normalized query
            //    or if stripped DB value contains normalized query as a substring
            row = phoneQuery(conn,
                "SELECT *, detected_at AS reported_at FROM suspicious_calls " +
                "WHERE REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(" +
                "REPLACE(REPLACE(REPLACE(phone_number,' ',''),'-',''),'(',''),')','')," +
                "'+',''),'.',''),'\\t',''),'\\n','') LIKE ?",
                "%" + normalized + "%");
            if (row != null) { sendFound(ex, "normalized", 1.0, enrichPhone(row)); return; }

            // 3. Suffix match — check last 10 digits
            if (normalized.length() >= 10) {
                String suffix = normalized.substring(normalized.length() - 10);
                row = phoneQuery(conn,
                    "SELECT *, detected_at AS reported_at FROM suspicious_calls " +
                    "WHERE REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(" +
                    "REPLACE(REPLACE(REPLACE(phone_number,' ',''),'-',''),'(',''),')','')," +
                    "'+',''),'.',''),'\\t',''),'\\n','') LIKE ?",
                    "%" + suffix + "%");
                if (row != null) { sendFound(ex, "normalized", 0.95, enrichPhone(row)); return; }
            }
        }

        sendJson(ex, 200, Map.of("found", false));
    }

    private Map<String, Object> phoneQuery(Connection conn, String sql, String param)
            throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, param);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rowToMap(rs);
            }
        }
        return null;
    }

    /** Add computed convenience fields to a suspicious_calls row. */
    private Map<String, Object> enrichPhone(Map<String, Object> row) {
        // Make sure reported_at alias is set
        if (!row.containsKey("reported_at") && row.containsKey("detected_at")) {
            row.put("reported_at", row.get("detected_at"));
        }
        return row;
    }

    // ========================================================================
    //  SMS SEARCH
    // ========================================================================

    private void handleSmsSearch(HttpExchange ex, String rawInput) throws IOException, SQLException {
        String normalizedInput = normalizeSms(rawInput);

        try (Connection conn = DatabaseConfig.getConnection()) {
            // 1. Exact match
            Map<String, Object> row = smsQuery(conn,
                "SELECT * FROM scam_messages WHERE content = ?", rawInput);
            if (row != null) { sendFound(ex, "exact", 1.0, row); return; }

            // 2. Normalized match (lowercase + strip punctuation on DB side)
            row = smsQuery(conn,
                "SELECT * FROM scam_messages " +
                "WHERE LOWER(REGEXP_REPLACE(content, '[^a-z0-9]', '')) = ?",
                normalizedInput);
            if (row != null) { sendFound(ex, "normalized", 1.0, row); return; }

            // 3. Fuzzy match — pull candidate rows that share keywords, or recent rows as fallback
            List<String> keywords = new ArrayList<>();
            for (String token : rawInput.split("[^a-zA-Z0-9]+")) {
                if (token.length() >= 4) {
                    keywords.add(token.toLowerCase());
                }
            }

            List<Map<String, Object>> candidates;
            if (!keywords.isEmpty()) {
                StringBuilder sql = new StringBuilder("SELECT * FROM scam_messages WHERE ");
                for (int i = 0; i < keywords.size(); i++) {
                    if (i > 0) sql.append(" OR ");
                    sql.append("content LIKE ?");
                }
                sql.append(" LIMIT ?");
                
                try (PreparedStatement ps = conn.prepareStatement(sql.toString())) {
                    for (int i = 0; i < keywords.size(); i++) {
                        ps.setString(i + 1, "%" + keywords.get(i) + "%");
                    }
                    ps.setInt(keywords.size() + 1, FUZZY_FETCH_LIMIT);
                    try (ResultSet rs = ps.executeQuery()) {
                        candidates = new ArrayList<>();
                        while (rs.next()) candidates.add(rowToMap(rs));
                    }
                }
            } else {
                candidates = smsQueryMany(conn,
                    "SELECT * FROM scam_messages ORDER BY id DESC LIMIT ?",
                    FUZZY_FETCH_LIMIT);
            }

            double bestScore = 0;
            Map<String, Object> bestRow = null;

            for (Map<String, Object> candidate : candidates) {
                String content = String.valueOf(candidate.getOrDefault("content", ""));
                double score = similarity(normalizedInput, normalizeSms(content));
                if (score > bestScore) {
                    bestScore = score;
                    bestRow   = candidate;
                }
            }

            if (bestScore >= FUZZY_THRESHOLD && bestRow != null) {
                sendFound(ex, "fuzzy", bestScore, bestRow);
                return;
            }
        }

        sendJson(ex, 200, Map.of("found", false));
    }

    private Map<String, Object> smsQuery(Connection conn, String sql, String param)
            throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, param);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rowToMap(rs);
            }
        }
        return null;
    }

    private List<Map<String, Object>> smsQueryMany(Connection conn, String sql, int limit)
            throws SQLException {
        List<Map<String, Object>> rows = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) rows.add(rowToMap(rs));
            }
        }
        return rows;
    }

    // ========================================================================
    //  HELPERS
    // ========================================================================

    /** Lowercase + strip all non-alphanumeric characters (used for normalized SMS comparison). */
    private static String normalizeSms(String text) {
        return NON_ALNUM.matcher(text.toLowerCase()).replaceAll("");
    }

    /**
     * Jaro-Winkler similarity — returns a value in [0,1].
     * Pure Java, no external dependency.
     */
    private static double similarity(String a, String b) {
        if (a.equals(b)) return 1.0;
        if (a.isEmpty() || b.isEmpty()) return 0.0;
        int matchWindow = Math.max(0, Math.max(a.length(), b.length()) / 2 - 1);
        boolean[] aMatched = new boolean[a.length()];
        boolean[] bMatched = new boolean[b.length()];
        int matches = 0, transpositions = 0;

        for (int i = 0; i < a.length(); i++) {
            int start = Math.max(0, i - matchWindow);
            int end   = Math.min(i + matchWindow + 1, b.length());
            for (int j = start; j < end; j++) {
                if (!bMatched[j] && a.charAt(i) == b.charAt(j)) {
                    aMatched[i] = bMatched[j] = true;
                    matches++;
                    break;
                }
            }
        }
        if (matches == 0) return 0.0;
        int k = 0;
        for (int i = 0; i < a.length(); i++) {
            if (aMatched[i]) {
                while (!bMatched[k]) k++;
                if (a.charAt(i) != b.charAt(k++)) transpositions++;
            }
        }
        double jaro = (matches / (double) a.length()
                     + matches / (double) b.length()
                     + (matches - transpositions / 2.0) / matches) / 3.0;
        // Winkler prefix boost
        int prefix = 0;
        for (int i = 0; i < Math.min(4, Math.min(a.length(), b.length())); i++) {
            if (a.charAt(i) == b.charAt(i)) prefix++; else break;
        }
        return jaro + prefix * 0.1 * (1 - jaro);
    }

    private static Map<String, Object> rowToMap(ResultSet rs) throws SQLException {
        ResultSetMetaData meta = rs.getMetaData();
        Map<String, Object> row = new LinkedHashMap<>();
        for (int i = 1; i <= meta.getColumnCount(); i++) {
            row.put(meta.getColumnName(i), rs.getObject(i));
        }
        return row;
    }

    private static String extractParam(String query, String name) {
        if (query == null) return null;
        for (String kv : query.split("&")) {
            String[] parts = kv.split("=", 2);
            if (parts.length == 2 && name.equals(parts[0])) {
                try { return URLDecoder.decode(parts[1], StandardCharsets.UTF_8); }
                catch (Exception e) { return parts[1]; }
            }
        }
        return null;
    }

    private void sendFound(HttpExchange ex, String source, double score, Map<String, Object> row)
            throws IOException {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("found",       true);
        resp.put("source",      source);
        resp.put("matchScore",  Math.round(score * 1000.0) / 1000.0);
        resp.put("row",         row);
        sendJson(ex, 200, resp);
    }

    private void sendJson(HttpExchange ex, int status, Object body) throws IOException {
        byte[] bytes = GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }
}

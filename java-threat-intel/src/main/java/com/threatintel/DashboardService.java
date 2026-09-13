package com.threatintel;

import java.sql.*;

public class DashboardService {

    // ── MySQL connection details ───────────────────────────────────────────────
    private static final String DB_URL  = "jdbc:mysql://localhost:3306/threat_intelligence_db";
    private static final String DB_USER = "root";
    private static final String DB_PASS = "yourpassword";

    // ── Save Prediction ───────────────────────────────────────────────────────

    /**
     * Saves a prediction result to existing scam_detector_results table.
     *
     * @param content    Original user input
     * @param prediction Populated ThreatPrediction from Flask API
     */
    public static void savePrediction(String content, ThreatPrediction prediction) {
        String sql = """
            INSERT INTO scam_detector_results
              (input_text, classification, confidence, severity, created_at)
            VALUES (?, ?, ?, ?, NOW())
            """;

        try (Connection conn = com.threatintel.db.DatabaseConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, content);
            ps.setString(2, prediction.getPrediction());   // "Safe" or "Malicious"
            ps.setDouble(3, prediction.getConfidence());   // 0.0 – 1.0
            ps.setString(4, prediction.getThreatLevel());  // "LOW", "MEDIUM", "HIGH"
            ps.executeUpdate();

            System.out.println("✅ Prediction saved to scam_detector_results.");

            // ── If malicious, also save to the specific threat table ───────
            if (prediction.isMalicious()) {
                insertIntoThreatTable(conn, content, prediction);
            }

        } catch (SQLException e) {
            System.err.println("❌ DB error in savePrediction: " + e.getMessage());
        }
    }

    // ── Insert Into Specific Threat Table ─────────────────────────────────────

    /**
     * Inserts malicious results into the relevant existing threat table.
     * phishing_urls | suspicious_calls | email_scams |
     * malicious_ips | scam_messages    | threats (fallback)
     */
    private static void insertIntoThreatTable(Connection conn,
                                               String content,
                                               ThreatPrediction p) throws SQLException {
        String type     = p.getDataType().toLowerCase();
        String severity = p.getThreatLevel().toLowerCase(); // "low", "medium", "high"
        String sql;

        switch (type) {

            case "url" -> {
                // ── phishing_urls ──────────────────────────────────────────
                sql = """
                    INSERT INTO phishing_urls (url, domain, severity, notes, detected_at)
                    VALUES (?, ?, ?, ?, NOW())
                    """;
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setString(1, content);
                    ps.setString(2, extractDomain(content));
                    ps.setString(3, severity);
                    ps.setString(4, "Detected by ML model. Confidence: "
                                    + String.format("%.1f%%", p.getConfidence() * 100));
                    ps.executeUpdate();
                    System.out.println("🔗 Saved to phishing_urls.");
                }
            }

            case "call" -> {
                // ── suspicious_calls ───────────────────────────────────────
                sql = """
                    INSERT INTO suspicious_calls (phone_number, severity, pattern, detected_at)
                    VALUES (?, ?, ?, NOW())
                    """;
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setString(1, content);
                    ps.setString(2, severity);
                    ps.setString(3, "Flagged by ML model. Confidence: "
                                    + String.format("%.1f%%", p.getConfidence() * 100));
                    ps.executeUpdate();
                    System.out.println("📞 Saved to suspicious_calls.");
                }
            }

            case "email" -> {
                // ── email_scams ────────────────────────────────────────────
                sql = """
                    INSERT INTO email_scams (sender, subject, category, severity, detected_at)
                    VALUES (?, ?, ?, ?, NOW())
                    """;
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setString(1, extractEmailSender(content));
                    ps.setString(2, extractEmailSubject(content));
                    ps.setString(3, "scam");
                    ps.setString(4, severity);
                    ps.executeUpdate();
                    System.out.println("📧 Saved to email_scams.");
                }
            }

            case "ip" -> {
                // ── malicious_ips ──────────────────────────────────────────
                sql = """
                    INSERT INTO malicious_ips (ip_address, threat_type, severity, detected_at)
                    VALUES (?, ?, ?, NOW())
                    """;
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setString(1, content);
                    ps.setString(2, "malicious");
                    ps.setString(3, severity);
                    ps.executeUpdate();
                    System.out.println("🌐 Saved to malicious_ips.");
                }
            }

            case "sms" -> {
                // ── scam_messages ──────────────────────────────────────────
                sql = """
                    INSERT INTO scam_messages (channel, content, severity, detected_at)
                    VALUES (?, ?, ?, NOW())
                    """;
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setString(1, "sms");
                    ps.setString(2, content);
                    ps.setString(3, severity);
                    ps.executeUpdate();
                    System.out.println("💬 Saved to scam_messages.");
                }
            }

            default -> {
                // ── threats (fallback for unknown types) ───────────────────
                sql = """
                    INSERT INTO threats (title, type, severity, description, detected_at)
                    VALUES (?, ?, ?, ?, NOW())
                    """;
                try (PreparedStatement ps = conn.prepareStatement(sql)) {
                    ps.setString(1, "ML Detected Threat");
                    ps.setString(2, type);
                    ps.setString(3, severity);
                    ps.setString(4, "Content: "
                                    + content.substring(0, Math.min(content.length(), 200)));
                    ps.executeUpdate();
                    System.out.println("⚠️ Saved to threats.");
                }
            }
        }
    }

    // ── Dashboard Stats ───────────────────────────────────────────────────────

    /**
     * Returns live dashboard counts from your existing tables.
     * Called by DashboardMetricsHandler to refresh dashboard numbers.
     */
    public static DashboardStats getDashboardStats() {
        String sql = """
            SELECT
              ((SELECT COUNT(*) FROM phishing_urls) +
               (SELECT COUNT(*) FROM suspicious_calls) +
               (SELECT COUNT(*) FROM email_scams) +
               (SELECT COUNT(*) FROM malicious_ips) +
               (SELECT COUNT(*) FROM scam_messages))   AS total_threats,
              (SELECT COUNT(*) FROM phishing_urls)    AS phishing_urls,
              (SELECT COUNT(*) FROM suspicious_calls) AS suspicious_calls,
              (SELECT COUNT(*) FROM email_scams)      AS email_scams,
              (SELECT COUNT(*) FROM malicious_ips)    AS malicious_ips,
              (SELECT COUNT(*) FROM scam_messages)    AS scam_messages
            """;

        try (Connection conn = com.threatintel.db.DatabaseConfig.getConnection();
             Statement st   = conn.createStatement();
             ResultSet rs   = st.executeQuery(sql)) {

            if (rs.next()) {
                return new DashboardStats(
                    rs.getInt("total_threats"),
                    rs.getInt("phishing_urls"),
                    rs.getInt("suspicious_calls"),
                    rs.getInt("email_scams"),
                    rs.getInt("malicious_ips"),
                    rs.getInt("scam_messages")
                );
            }

        } catch (SQLException e) {
            System.err.println("❌ Stats fetch error: " + e.getMessage());
        }

        // Return zeros if DB fails
        return new DashboardStats(0, 0, 0, 0, 0, 0);
    }

    // ── Analyze and Store (Main Entry Point) ──────────────────────────────────

    /**
     * Called from DashboardMetricsHandler when POST /api/analyze is received.
     * Sends input to Flask ML API, saves result to DB, returns prediction.
     *
     * @param type    "url" | "email" | "sms" | "call" | "ip"
     * @param content Raw user input string
     * @return ThreatPrediction object, or null if Flask API is unreachable
     */
    public static ThreatPrediction analyzeAndStore(String type, String content) {
        try {
            ThreatPrediction result = ThreatApiClient.predict(type, content);
            savePrediction(content, result);
            return result;
        } catch (Exception e) {
            System.err.println("❌ analyzeAndStore failed: " + e.getMessage());
            return null;
        }
    }

    // ── Helper Methods ────────────────────────────────────────────────────────

    private static String extractDomain(String url) {
        try {
            if (url.contains("://")) url = url.split("://")[1];
            return url.split("/")[0];
        } catch (Exception e) {
            return url;
        }
    }

    private static String extractEmailSender(String content) {
        if (content.toLowerCase().contains("from:")) {
            for (String line : content.split("\\n")) {
                if (line.toLowerCase().startsWith("from:")) {
                    return line.substring(5).trim();
                }
            }
        }
        return content.substring(0, Math.min(content.length(), 100));
    }

    private static String extractEmailSubject(String content) {
        if (content.toLowerCase().contains("subject:")) {
            for (String line : content.split("\\n")) {
                if (line.toLowerCase().startsWith("subject:")) {
                    return line.substring(8).trim();
                }
            }
        }
        return "Unknown Subject";
    }

    // ── DashboardStats Inner Class ────────────────────────────────────────────

    public static class DashboardStats {
        public final int totalThreats;
        public final int phishingUrls;
        public final int suspiciousCalls;
        public final int emailScams;
        public final int maliciousIps;
        public final int scamMessages;

        public DashboardStats(int totalThreats,
                               int phishingUrls,
                               int suspiciousCalls,
                               int emailScams,
                               int maliciousIps,
                               int scamMessages) {
            this.totalThreats    = totalThreats;
            this.phishingUrls    = phishingUrls;
            this.suspiciousCalls = suspiciousCalls;
            this.emailScams      = emailScams;
            this.maliciousIps    = maliciousIps;
            this.scamMessages    = scamMessages;
        }
    }
}
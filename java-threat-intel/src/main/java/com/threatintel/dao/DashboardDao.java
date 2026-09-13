package com.threatintel.dao;

import com.threatintel.db.DatabaseConfig;
import java.sql.*;
import java.util.*;

public class DashboardDao {

    public Map<String, Object> getMetrics() throws SQLException {
        Map<String, Object> metrics = new LinkedHashMap<>();

        try (Connection conn = DatabaseConfig.getConnection();
             Statement stmt = conn.createStatement()) {

            int phishingUrls    = queryCount(stmt, "SELECT COUNT(*) FROM phishing_urls");
            int suspiciousCalls = queryCount(stmt, "SELECT COUNT(*) FROM suspicious_calls");
            int emailScams      = queryCount(stmt, "SELECT COUNT(*) FROM email_scams");
            int maliciousIps    = queryCount(stmt, "SELECT COUNT(*) FROM malicious_ips");
            int scamMessages    = queryCount(stmt, "SELECT COUNT(*) FROM scam_messages");
            int totalDomainThreats = phishingUrls + suspiciousCalls + emailScams + maliciousIps + scamMessages;

            // Total threats is the sum of domain-specific threat records to avoid double-counting
            metrics.put("threats", totalDomainThreats);
            metrics.put("phishing_urls", phishingUrls);
            metrics.put("suspicious_calls", suspiciousCalls);
            metrics.put("email_scams", emailScams);
            metrics.put("malicious_ips", maliciousIps);
            metrics.put("scam_messages", scamMessages);
            metrics.put("scam_detector_results", queryCount(stmt, "SELECT COUNT(*) FROM scam_detector_results"));

            // Severity breakdown aggregated across all 5 domain threat tables
            Map<String, Integer> sevMap = querySeverityCounts(stmt);
            metrics.put("critical_count", sevMap.getOrDefault("critical", 0));
            metrics.put("high_count",     sevMap.getOrDefault("high", 0));
            metrics.put("medium_count",   sevMap.getOrDefault("medium", 0));
            metrics.put("low_count",      sevMap.getOrDefault("low", 0));
        }

        return metrics;
    }

    private int queryCount(Statement stmt, String sql) {
        try (ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) return rs.getInt(1);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0;
    }

    private Map<String, Integer> querySeverityCounts(Statement stmt) {
        Map<String, Integer> counts = new HashMap<>();
        String[] tables = {"phishing_urls", "suspicious_calls", "email_scams", "malicious_ips", "scam_messages"};
        for (String t : tables) {
            String sql = "SELECT severity, COUNT(*) FROM " + t + " GROUP BY severity";
            try (ResultSet rs = stmt.executeQuery(sql)) {
                while (rs.next()) {
                    String sev = rs.getString(1);
                    int cnt = rs.getInt(2);
                    if (sev != null) {
                        String s = sev.toLowerCase().trim();
                        counts.put(s, counts.getOrDefault(s, 0) + cnt);
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        return counts;
    }
}
package com.threatintel.dao;

import com.threatintel.db.DatabaseConfig;
import java.sql.*;
import java.util.*;

public class DashboardDao {

    public Map<String, Object> getMetrics() throws SQLException {
        Map<String, Object> metrics = new LinkedHashMap<>();

        try (Connection conn = DatabaseConfig.getConnection();
             Statement stmt = conn.createStatement()) {

            metrics.put("threats", queryCount(stmt, "SELECT COUNT(*) FROM threats"));
            metrics.put("phishing_urls", queryCount(stmt, "SELECT COUNT(*) FROM phishing_urls"));
            metrics.put("suspicious_calls", queryCount(stmt, "SELECT COUNT(*) FROM suspicious_calls"));
            metrics.put("email_scams", queryCount(stmt, "SELECT COUNT(*) FROM email_scams"));
            metrics.put("malicious_ips", queryCount(stmt, "SELECT COUNT(*) FROM malicious_ips"));
            metrics.put("scam_messages", queryCount(stmt, "SELECT COUNT(*) FROM scam_messages"));
            metrics.put("scam_detector_results", queryCount(stmt, "SELECT COUNT(*) FROM scam_detector_results"));
            metrics.put("critical_count", queryCount(stmt, "SELECT COUNT(*) FROM threats WHERE severity = 'critical'"));
            metrics.put("high_count", queryCount(stmt, "SELECT COUNT(*) FROM threats WHERE severity = 'high'"));
            metrics.put("medium_count", queryCount(stmt, "SELECT COUNT(*) FROM threats WHERE severity = 'medium'"));
            metrics.put("low_count", queryCount(stmt, "SELECT COUNT(*) FROM threats WHERE severity = 'low'"));
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
}
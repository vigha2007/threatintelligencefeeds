package com.threatintel.dao;

import com.threatintel.db.DatabaseConfig;
import java.sql.*;
import java.util.*;

public class EntityDao {

    private static final Map<String, String> TABLE_MAP = new HashMap<>();

    static {
        TABLE_MAP.put("threats", "threats");
        TABLE_MAP.put("phishing_urls", "phishing_urls");
        TABLE_MAP.put("spam_calls", "suspicious_calls");
        TABLE_MAP.put("email_scams", "email_scams");
        TABLE_MAP.put("malicious_ips", "malicious_ips");
        TABLE_MAP.put("scam_messages", "scam_messages");
        TABLE_MAP.put("scam_detector_results", "scam_detector_results");
        TABLE_MAP.put("users", "users");
    }

    public boolean isValidEntity(String entity) {
        return TABLE_MAP.containsKey(entity);
    }

    public List<Map<String, Object>> list(String entity) throws SQLException {
        String table = TABLE_MAP.get(entity);
        List<Map<String, Object>> rows = new ArrayList<>();
        String sql = entity.equals("users")
                ? "SELECT * FROM users ORDER BY user_id DESC LIMIT 15000"
                : "SELECT * FROM " + table + " ORDER BY id DESC LIMIT 15000";

        try (Connection conn = DatabaseConfig.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            ResultSetMetaData meta = rs.getMetaData();
            int cols = meta.getColumnCount();
            while (rs.next()) {
                Map<String, Object> row = new LinkedHashMap<>();
                for (int i = 1; i <= cols; i++) {
                    row.put(meta.getColumnName(i), rs.getObject(i));
                }
                rows.add(row);
            }
        }
        return rows;
    }

    public Map<String, Object> getById(String entity, String id) throws SQLException {
        String table = TABLE_MAP.get(entity);
        String idCol = entity.equals("users") ? "user_id" : "id";
        String sql = "SELECT * FROM " + table + " WHERE " + idCol + " = ?";

        try (Connection conn = DatabaseConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    ResultSetMetaData meta = rs.getMetaData();
                    int cols = meta.getColumnCount();
                    Map<String, Object> row = new LinkedHashMap<>();
                    for (int i = 1; i <= cols; i++) {
                        row.put(meta.getColumnName(i), rs.getObject(i));
                    }
                    return row;
                }
            }
        }
        return null;
    }

    public Map<String, Object> insert(String entity, Map<String, Object> values) throws SQLException {
        String table = TABLE_MAP.get(entity);
        if (values.isEmpty()) throw new SQLException("No values provided");

        StringBuilder cols = new StringBuilder();
        StringBuilder placeholders = new StringBuilder();
        List<Object> params = new ArrayList<>();

        for (Map.Entry<String, Object> entry : values.entrySet()) {
            if (cols.length() > 0) {
                cols.append(", ");
                placeholders.append(", ");
            }
            cols.append(entry.getKey());
            placeholders.append("?");
            params.add(entry.getValue());
        }

        String sql = "INSERT INTO " + table + " (" + cols + ") VALUES (" + placeholders + ")";

        try (Connection conn = DatabaseConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            for (int i = 0; i < params.size(); i++) {
                ps.setObject(i + 1, params.get(i));
            }
            ps.executeUpdate();
            try (ResultSet keys = ps.getGeneratedKeys()) {
                if (keys.next()) {
                    return getById(entity, String.valueOf(keys.getLong(1)));
                }
            }
        }
        return null;
    }

    public Map<String, Object> update(String entity, String id, Map<String, Object> values) throws SQLException {
        String table = TABLE_MAP.get(entity);
        String idCol = entity.equals("users") ? "user_id" : "id";
        if (values.isEmpty()) throw new SQLException("No values provided");

        StringBuilder sets = new StringBuilder();
        List<Object> params = new ArrayList<>();

        for (Map.Entry<String, Object> entry : values.entrySet()) {
            if (sets.length() > 0) sets.append(", ");
            sets.append(entry.getKey()).append(" = ?");
            params.add(entry.getValue());
        }
        params.add(id);

        String sql = "UPDATE " + table + " SET " + sets + " WHERE " + idCol + " = ?";

        try (Connection conn = DatabaseConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            for (int i = 0; i < params.size(); i++) {
                ps.setObject(i + 1, params.get(i));
            }
            ps.executeUpdate();
        }
        return getById(entity, id);
    }

    public boolean delete(String entity, String id) throws SQLException {
        String table = TABLE_MAP.get(entity);
        String idCol = entity.equals("users") ? "user_id" : "id";
        String sql = "DELETE FROM " + table + " WHERE " + idCol + " = ?";

        try (Connection conn = DatabaseConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            return ps.executeUpdate() > 0;
        }
    }
}
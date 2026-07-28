package com.threatintel.dao;

import com.threatintel.db.DatabaseConfig;
import java.sql.*;
import java.util.*;

public class EntityDao {

    /** Default page size when the caller does not specify a limit. */
    public static final int DEFAULT_PAGE_SIZE = 1000;

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

    /**
     * Returns a paginated list of rows for the given entity.
     * No artificial row ceiling — pages are controlled by limit/offset.
     *
     * @param entity logical entity name (key in TABLE_MAP)
     * @param limit  maximum rows to return (≤ 0 means use DEFAULT_PAGE_SIZE)
     * @param offset number of rows to skip (0-based)
     */
    public List<Map<String, Object>> list(String entity, int limit, int offset) throws SQLException {
        String table  = TABLE_MAP.get(entity);
        String idCol  = entity.equals("users") ? "user_id" : "id";
        int    pageSize = (limit > 0) ? limit : DEFAULT_PAGE_SIZE;

        String colsStr = "*";
        if (entity.equals("phishing_urls")) {
            colsStr = "*, detected_at AS blocked_at";
        } else if (entity.equals("spam_calls")) {
            colsStr = "*, detected_at AS reported_at";
        } else if (entity.equals("malicious_ips")) {
            colsStr = "*, detected_at AS last_seen";
        }

        String sql = "SELECT " + colsStr + " FROM " + table
                   + " ORDER BY " + idCol + " DESC"
                   + " LIMIT ? OFFSET ?";

        List<Map<String, Object>> rows = new ArrayList<>();
        try (Connection conn = DatabaseConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, pageSize);
            ps.setInt(2, offset);

            try (ResultSet rs = ps.executeQuery()) {
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
        }
        return rows;
    }

    /**
     * Convenience overload — returns the first page with the default page size.
     * Replaces the old LIMIT 15000 call sites that did not need pagination.
     */
    public List<Map<String, Object>> list(String entity) throws SQLException {
        return list(entity, DEFAULT_PAGE_SIZE, 0);
    }

    /**
     * Returns the total row count for the given entity table.
     * Callers can use this to compute total pages for pagination.
     */
    public long count(String entity) throws SQLException {
        String table = TABLE_MAP.get(entity);
        String sql   = "SELECT COUNT(*) FROM " + table;
        try (Connection conn = DatabaseConfig.getConnection();
             Statement  stmt = conn.createStatement();
             ResultSet  rs   = stmt.executeQuery(sql)) {
            return rs.next() ? rs.getLong(1) : 0L;
        }
    }

    public Map<String, Object> getById(String entity, String id) throws SQLException {
        String table = TABLE_MAP.get(entity);
        String idCol = entity.equals("users") ? "user_id" : "id";

        String colsStr = "*";
        if (entity.equals("phishing_urls")) {
            colsStr = "*, detected_at AS blocked_at";
        } else if (entity.equals("spam_calls")) {
            colsStr = "*, detected_at AS reported_at";
        } else if (entity.equals("malicious_ips")) {
            colsStr = "*, detected_at AS last_seen";
        }

        String sql = "SELECT " + colsStr + " FROM " + table + " WHERE " + idCol + " = ?";

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
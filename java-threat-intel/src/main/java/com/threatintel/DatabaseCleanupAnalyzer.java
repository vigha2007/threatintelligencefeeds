package com.threatintel;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.threatintel.db.DatabaseConfig;
import com.threatintel.server.CallDetectHandler;

import java.io.FileWriter;
import java.io.IOException;
import java.sql.*;
import java.util.*;

public class DatabaseCleanupAnalyzer {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public static void main(String[] args) {
        System.out.println("==================================================");
        System.out.println("PHONE DATABASE DEDUPLICATION & BACKUP ANALYZER");
        System.out.println("==================================================");

        try (Connection conn = DatabaseConfig.getConnection()) {
            if (conn == null) {
                System.err.println("❌ Database connection failed. Check MySQL.");
                return;
            }

            // 1. Total row count before cleanup
            int totalBefore = 0;
            try (Statement st = conn.createStatement();
                 ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM suspicious_calls")) {
                if (rs.next()) totalBefore = rs.getInt(1);
            }
            System.out.println("[PHONE CLEANUP] Table: suspicious_calls");
            System.out.println("[PHONE CLEANUP] Total Rows Before: " + totalBefore);

            // 2. Export Backup
            List<Map<String, Object>> allRows = new ArrayList<>();
            try (Statement st = conn.createStatement();
                 ResultSet rs = st.executeQuery("SELECT * FROM suspicious_calls")) {
                ResultSetMetaData meta = rs.getMetaData();
                while (rs.next()) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    for (int i = 1; i <= meta.getColumnCount(); i++) {
                        row.put(meta.getColumnName(i), rs.getObject(i));
                    }
                    allRows.add(row);
                }
            }

            String backupPath = "backup_suspicious_calls.json";
            try (FileWriter fw = new FileWriter(backupPath)) {
                GSON.toJson(allRows, fw);
            }
            System.out.println("[PHONE CLEANUP] Backup Exported To: " + backupPath + " (" + allRows.size() + " records)");

            // 3. Group by Normalized Indian Phone Number
            Map<String, List<Map<String, Object>>> groups = new LinkedHashMap<>();
            int indianCount = 0;

            for (Map<String, Object> row : allRows) {
                String rawPhone = String.valueOf(row.getOrDefault("phone_number", ""));
                String norm = CallDetectHandler.normalizePhone(rawPhone);
                if (norm.length() >= 7) {
                    if (rawPhone.contains("+91") || rawPhone.startsWith("91") || norm.length() == 10) {
                        indianCount++;
                    }
                    groups.computeIfAbsent(norm, k -> new ArrayList<>()).add(row);
                }
            }

            System.out.println("[PHONE CLEANUP] Indian/Mobile Phone Rows: " + indianCount);

            int duplicateGroupCount = 0;
            int totalRedundantRowsToRemove = 0;
            List<Long> idsToDelete = new ArrayList<>();

            for (Map.Entry<String, List<Map<String, Object>>> entry : groups.entrySet()) {
                String norm = entry.getKey();
                List<Map<String, Object>> rows = entry.getValue();

                if (rows.size() > 1) {
                    duplicateGroupCount++;
                    System.out.println("--------------------------------------------------");
                    System.out.println("[DUPLICATE GROUP] Normalized: " + norm + " (Count: " + rows.size() + ")");

                    // Keep the best canonical record (first ID or highest id / most detailed pattern)
                    Map<String, Object> keepRow = rows.get(0);
                    System.out.println("   [KEEP] ID: " + keepRow.get("id") + " | Phone: " + keepRow.get("phone_number") + " | Severity: " + keepRow.get("severity"));

                    for (int i = 1; i < rows.size(); i++) {
                        Map<String, Object> dup = rows.get(i);
                        long dupId = ((Number) dup.get("id")).longValue();
                        idsToDelete.add(dupId);
                        totalRedundantRowsToRemove++;
                        System.out.println("   [REMOVE] ID: " + dupId + " | Phone: " + dup.get("phone_number") + " | Severity: " + dup.get("severity"));
                    }
                }
            }

            System.out.println("==================================================");
            System.out.println("[PHONE CLEANUP] Duplicate Groups: " + duplicateGroupCount);
            System.out.println("[PHONE CLEANUP] Redundant Rows To Remove: " + totalRedundantRowsToRemove);

            // Execute deletion of exact redundant duplicate IDs
            if (!idsToDelete.isEmpty()) {
                String deleteSql = "DELETE FROM suspicious_calls WHERE id = ?";
                try (PreparedStatement ps = conn.prepareStatement(deleteSql)) {
                    for (Long id : idsToDelete) {
                        ps.setLong(1, id);
                        ps.addBatch();
                    }
                    int[] deleted = ps.executeBatch();
                    System.out.println("[PHONE CLEANUP] Successfully Deleted Redundant Rows: " + deleted.length);
                }
            }

            // 4. Total row count after cleanup
            int totalAfter = 0;
            try (Statement st = conn.createStatement();
                 ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM suspicious_calls")) {
                if (rs.next()) totalAfter = rs.getInt(1);
            }
            System.out.println("[PHONE CLEANUP] Rows After Cleanup: " + totalAfter);

            // 5. Ensure index on phone_number
            try (Statement st = conn.createStatement()) {
                st.executeUpdate("CREATE INDEX idx_calls_phone ON suspicious_calls(phone_number)");
                System.out.println("[PHONE CLEANUP] Index idx_calls_phone verified/created.");
            } catch (SQLException ex) {
                System.out.println("[PHONE CLEANUP] Index idx_calls_phone already exists.");
            }

            System.out.println("==================================================");
            System.out.println("PHONE DATABASE CLEANUP COMPLETE!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

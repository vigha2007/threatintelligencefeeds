package com.threatintel.db;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.Statement;

public class SchemaInitializer {
    public static void initialize() {
        System.out.println("Initializing database schema...");
        try (Connection conn = DatabaseConfig.getConnection();
             Statement stmt = conn.createStatement()) {

            String schemaContent = new String(Files.readAllBytes(Paths.get("schema.sql")));

            // Split on semicolons but skip blank segments
            String[] statements = schemaContent.split(";");
            int executed = 0;
            for (String sql : statements) {
                String trimmed = sql.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("--")) continue;
                try {
                    stmt.execute(trimmed);
                    executed++;
                } catch (Exception e) {
                    // Warn but continue — some statements like duplicate indexes are acceptable
                    System.err.println("Warning executing statement: " + e.getMessage());
                    System.err.println("  SQL: " + trimmed.substring(0, Math.min(trimmed.length(), 80)) + "...");
                }
            }
            System.out.println("Schema initialized successfully (" + executed + " statements executed).");

        } catch (Exception e) {
            System.err.println("Failed to initialize schema:");
            e.printStackTrace();
        }
    }
}

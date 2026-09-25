package com.threatintel.db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.SQLException;

/**
 * HikariCP connection pool configured for large-dataset workloads.
 *
 * Key tuning applied for 1.2 M+ row bulk inserts:
 *   - rewriteBatchedStatements=true  → rewrites addBatch()/executeBatch() into
 *     multi-row INSERT packets, dramatically cutting round-trips.
 *   - max_allowed_packet=128M        → avoids "Packet too large" errors when
 *     a single INSERT statement becomes very long.
 *   - net_read_timeout / net_write_timeout = 600 s → prevents the server
 *     from closing the connection mid-batch.
 *   - connectionTimeout / socketTimeout adjusted for bulk-insert workloads.
 */
public class DatabaseConfig {

    /**
     * JDBC URL shared by both the primary and fallback connection attempts.
     * Parameters:
     *   createDatabaseIfNotExist  – creates the DB if missing (handy first run)
     *   useSSL=false              – local dev; enable + add certs for production
     *   allowPublicKeyRetrieval   – required for MySQL 8 caching_sha2_password
     *   serverTimezone            – avoids timezone-negotiation overhead
     *   rewriteBatchedStatements  – essential for efficient executeBatch()
     *   max_allowed_packet        – 128 MB; avoids "Packet too large" on bulk
     *   net_read_timeout          – keep connection alive during long reads
     *   net_write_timeout         – keep connection alive during long writes
     *   connectTimeout            – 30 s to establish initial connection
     *   socketTimeout             – 600 s (10 min) for long-running statements
     */
    private static String getJdbcUrl() {
        String customUrl = System.getenv("DB_URL");
        if (customUrl != null && !customUrl.trim().isEmpty()) {
            return customUrl.trim();
        }

        String host = System.getenv().getOrDefault("DB_HOST", "localhost");
        String port = System.getenv().getOrDefault("DB_PORT", "3306");
        String dbName = System.getenv().getOrDefault("DB_NAME", "threat_intelligence_db");
        String sslMode = System.getenv().getOrDefault("DB_SSL_MODE", "false");
        boolean useSsl = "true".equalsIgnoreCase(sslMode)
                || "REQUIRED".equalsIgnoreCase(sslMode)
                || "VERIFY_IDENTITY".equalsIgnoreCase(sslMode)
                || "VERIFY_CA".equalsIgnoreCase(sslMode);

        StringBuilder sb = new StringBuilder();
        sb.append("jdbc:mysql://").append(host).append(":").append(port).append("/").append(dbName)
          .append("?createDatabaseIfNotExist=true")
          .append("&useSSL=").append(useSsl ? "true" : "false");

        if (useSsl && (sslMode.equalsIgnoreCase("VERIFY_IDENTITY") || sslMode.equalsIgnoreCase("VERIFY_CA") || sslMode.equalsIgnoreCase("REQUIRED"))) {
            sb.append("&sslMode=").append(sslMode);
        }

        sb.append("&allowPublicKeyRetrieval=true")
          .append("&serverTimezone=UTC")
          .append("&rewriteBatchedStatements=true")
          .append("&max_allowed_packet=134217728")
          .append("&net_read_timeout=600")
          .append("&net_write_timeout=600")
          .append("&connectTimeout=30000")
          .append("&socketTimeout=600000");

        return sb.toString();
    }

    private static HikariDataSource dataSource;

    static {
        // Prefer DB_PASSWORD environment variable; fall back to local-dev default.
        String envPassword = System.getenv("DB_PASSWORD");
        String primaryPassword = (envPassword != null && !envPassword.isEmpty()) ? envPassword : "vigha@2007";
        dataSource = tryConnect(primaryPassword);
        if (dataSource == null) {
            System.err.println("Primary password failed — retrying with empty password.");
            dataSource = tryConnect("");
        }
        if (dataSource == null) {
            System.err.println("Database connection failed entirely. Please check credentials.");
        }
    }

    /**
     * Builds a HikariCP pool for the given password; returns null on failure.
     */
    private static HikariDataSource tryConnect(String password) {
        try {
            String user = System.getenv().getOrDefault("DB_USER", "root");
            String jdbcUrl = getJdbcUrl();

            HikariConfig config = new HikariConfig();
            config.setDriverClassName("com.mysql.cj.jdbc.Driver");
            config.setJdbcUrl(jdbcUrl);
            config.setUsername(user);
            config.setPassword(password);

            // PreparedStatement cache — reduces parse overhead for repeated inserts
            config.addDataSourceProperty("cachePrepStmts",        "true");
            config.addDataSourceProperty("prepStmtCacheSize",     "500");
            config.addDataSourceProperty("prepStmtCacheSqlLimit", "4096");
            config.addDataSourceProperty("useServerPrepStmts",    "true");

            // Pool sizing — 30 connections for parallel bulk-insert workloads
            config.setMaximumPoolSize(30);
            config.setMinimumIdle(5);

            // Timeout / keep-alive settings
            config.setConnectionTimeout(30_000);        // 30 s to get a connection from pool
            config.setIdleTimeout(300_000);             // 5 min before idle conn is evicted
            config.setMaxLifetime(1_200_000);           // 20 min max lifetime per connection
            config.setKeepaliveTime(60_000);            // ping every 60 s to keep alive

            return new HikariDataSource(config);
        } catch (Exception e) {
            System.err.println("HikariCP init failed (password='"
                    + (password.isEmpty() ? "<empty>" : "****") + "'): " + e.getMessage());
            return null;
        }
    }

    public static Connection getConnection() throws SQLException {
        if (dataSource == null) {
            throw new SQLException("DataSource is null — check DB credentials and MySQL status.");
        }
        return dataSource.getConnection();
    }
}

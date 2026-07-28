package com.threatintel;

import com.threatintel.db.DatabaseConfig;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Random;

/**
 * Generates large-scale synthetic threat data for all database tables.
 *
 * Target: 200,000 rows per threat table → ≥ 1,200,000 rows total.
 * Inserts are committed in batches of BATCH_COMMIT_SIZE (5,000 rows) to avoid
 * holding one enormous transaction in memory and to prevent max_allowed_packet
 * errors with MySQL.
 */
public class DataGenerator {

    private static final Random random = new Random();

    /** Rows inserted per table. Change this to scale up/down. */
    public static final int ROWS_PER_TABLE = 200_000;

    /**
     * How many rows to accumulate in a PreparedStatement batch before
     * calling executeBatch() + conn.commit(). Keep ≤ 10,000 for MySQL safety.
     */
    private static final int BATCH_COMMIT_SIZE = 5_000;

    /** How often (in rows) to print a progress message. */
    private static final int PROGRESS_INTERVAL = 10_000;

    public static void generateData() {
        System.out.println("=================================================");
        System.out.println(" Starting data generation (" + ROWS_PER_TABLE
                + " rows × 6 tables = " + (ROWS_PER_TABLE * 6L) + " rows total)");
        System.out.println("=================================================");
        long startTime = System.currentTimeMillis();

        try (Connection conn = DatabaseConfig.getConnection()) {

            // ── Truncate existing data ────────────────────────────────────
            System.out.println("[1/8] Truncating existing data...");
            try (java.sql.Statement st = conn.createStatement()) {
                st.execute("SET FOREIGN_KEY_CHECKS = 0");
                st.execute("TRUNCATE TABLE scam_detector_results");
                st.execute("TRUNCATE TABLE email_scams");
                st.execute("TRUNCATE TABLE malicious_ips");
                st.execute("TRUNCATE TABLE phishing_urls");
                st.execute("TRUNCATE TABLE suspicious_calls");
                st.execute("TRUNCATE TABLE scam_messages");
                st.execute("TRUNCATE TABLE threats");
                st.execute("SET FOREIGN_KEY_CHECKS = 1");
            }
            System.out.println("       Tables truncated.");

            // ── Session-level MySQL bulk-insert optimisations ─────────────
            try (java.sql.Statement st = conn.createStatement()) {
                st.execute("SET SESSION bulk_insert_buffer_size = 268435456"); // 256 MB
                st.execute("SET SESSION net_write_timeout       = 600");
                st.execute("SET SESSION net_read_timeout        = 600");
                st.execute("SET SESSION wait_timeout            = 600");
                st.execute("SET SESSION interactive_timeout     = 600");
            }

            // ── Insert seed users (no AUTOCOMMIT change needed here) ──────
            System.out.println("[2/8] Inserting users...");
            generateUsers(conn);

            // ── Insert large datasets with per-batch commits ──────────────
            System.out.println("[3/8] Inserting " + ROWS_PER_TABLE + " threats...");
            generateThreats(conn, ROWS_PER_TABLE);

            System.out.println("[4/8] Inserting " + ROWS_PER_TABLE + " scam messages...");
            generateScamMessages(conn, ROWS_PER_TABLE);

            System.out.println("[5/8] Inserting " + ROWS_PER_TABLE + " suspicious calls...");
            generateSuspiciousCalls(conn, ROWS_PER_TABLE);

            System.out.println("[6/8] Inserting " + ROWS_PER_TABLE + " phishing URLs...");
            generatePhishingUrls(conn, ROWS_PER_TABLE);

            System.out.println("[7/8] Inserting " + ROWS_PER_TABLE + " malicious IPs...");
            generateMaliciousIps(conn, ROWS_PER_TABLE);

            System.out.println("[8/8] Inserting " + ROWS_PER_TABLE + " email scams...");
            generateEmailScams(conn, ROWS_PER_TABLE);

            long elapsed = System.currentTimeMillis() - startTime;
            System.out.println("=================================================");
            System.out.printf(" Data generation completed in %d min %d sec.%n",
                    elapsed / 60000, (elapsed % 60000) / 1000);
            System.out.printf(" Total rows inserted: %,d%n", ROWS_PER_TABLE * 6L);
            System.out.println("=================================================");

        } catch (Exception e) {
            System.err.println("Data generation failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ── Helpers for batched insert logic ────────────────────────────────────

    /**
     * Flushes the current PreparedStatement batch and commits the connection.
     * Resets autoCommit to false afterwards so the caller can keep batching.
     */
    private static void flushBatch(PreparedStatement pstmt, Connection conn,
                                   String table, int rowsFlushed) throws Exception {
        pstmt.executeBatch();
        conn.commit();
        System.out.printf("    ... %,d rows committed to %s%n", rowsFlushed, table);
    }

    // ── Table generators ────────────────────────────────────────────────────

    private static void generateUsers(Connection conn) throws Exception {
        String sql = "INSERT IGNORE INTO users (username, email, password, role) VALUES (?, ?, ?, ?)";
        conn.setAutoCommit(false);
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, "admin");
            pstmt.setString(2, "admin@threatintel.com");
            pstmt.setString(3, "admin123");
            pstmt.setString(4, "admin");
            pstmt.addBatch();

            pstmt.setString(1, "analyst");
            pstmt.setString(2, "analyst@threatintel.com");
            pstmt.setString(3, "analyst123");
            pstmt.setString(4, "user");
            pstmt.addBatch();

            pstmt.executeBatch();
            conn.commit();
            System.out.println("       Inserted seed users.");
        }
        conn.setAutoCommit(true);
    }

    private static void generateThreats(Connection conn, int count) throws Exception {
        String sql = "INSERT INTO threats (title, type, severity, description, source) VALUES (?, ?, ?, ?, ?)";
        String[] types      = {"phishing_url", "spam_call", "email_scam", "malicious_ip", "scam_message", "other"};
        String[] severities = {"low", "medium", "high", "critical"};
        int[]    sevWeights = {3, 4, 2, 1};

        conn.setAutoCommit(false);
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < count; i++) {
                String type = types[random.nextInt(types.length)];
                String sev  = weightedPick(severities, sevWeights);
                pstmt.setString(1, "Threat-" + (i + 1) + "-" + type.replace("_", ""));
                pstmt.setString(2, type);
                pstmt.setString(3, sev);
                pstmt.setString(4, "Automated threat detection record for security analysis.");
                pstmt.setString(5, randomIp());
                pstmt.addBatch();

                if ((i + 1) % BATCH_COMMIT_SIZE == 0) {
                    flushBatch(pstmt, conn, "threats", i + 1);
                }
                if ((i + 1) % PROGRESS_INTERVAL == 0) {
                    System.out.printf("    threats: %,d / %,d rows%n", i + 1, count);
                }
            }
            // Final partial batch
            pstmt.executeBatch();
            conn.commit();
        }
        conn.setAutoCommit(true);
        System.out.printf("    threats: %,d rows inserted.%n", count);
    }

    private static void generateScamMessages(Connection conn, int count) throws Exception {
        String sql = "INSERT INTO scam_messages (channel, sender, content, severity) VALUES (?, ?, ?, ?)";
        String[] channels   = {"sms", "whatsapp", "telegram", "other"};
        String[] severities = {"low", "medium", "high", "critical"};
        int[]    sevWeights = {2, 4, 3, 1};
        String[] templates  = {
            "Congratulations! You have won a prize. Click here to claim: http://scam.link",
            "Your bank account has been suspended. Verify immediately: http://fake-bank.com",
            "URGENT: Your package could not be delivered. Pay Rs. 50 fee: http://phish.site",
            "Hello, I am a Nigerian prince and need your help to transfer funds.",
            "You have been selected for a government grant. Reply with your Aadhaar number.",
            "Investment opportunity: guaranteed 50% returns monthly. Contact us now!",
            "Your OTP is 837462. Do NOT share this with anyone.",
            "Free Netflix subscription! Claim yours: http://free-netflix-scam.com"
        };

        conn.setAutoCommit(false);
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < count; i++) {
                pstmt.setString(1, channels[random.nextInt(channels.length)]);
                pstmt.setString(2, randomPhone());
                pstmt.setString(3, templates[random.nextInt(templates.length)]);
                pstmt.setString(4, weightedPick(severities, sevWeights));
                pstmt.addBatch();

                if ((i + 1) % BATCH_COMMIT_SIZE == 0) {
                    flushBatch(pstmt, conn, "scam_messages", i + 1);
                }
                if ((i + 1) % PROGRESS_INTERVAL == 0) {
                    System.out.printf("    scam_messages: %,d / %,d rows%n", i + 1, count);
                }
            }
            pstmt.executeBatch();
            conn.commit();
        }
        conn.setAutoCommit(true);
        System.out.printf("    scam_messages: %,d rows inserted.%n", count);
    }

    private static void generateSuspiciousCalls(Connection conn, int count) throws Exception {
        String sql = "INSERT INTO suspicious_calls (phone_number, country, severity, pattern) VALUES (?, ?, ?, ?)";
        String[] countries  = {"IN", "US", "GB", "AU", "CA", "NG", "PK", "BD", "PH", "GH"};
        String[] severities = {"low", "medium", "high", "critical"};
        int[]    sevWeights = {2, 4, 3, 1};
        String[] patterns   = {
            "IRS Scam · mobile · spoofed · trust 12%",
            "Tech Support Scam · mobile · voip · trust 8%",
            "Bank Fraud · landline · local · trust 20%",
            "Grandparent Scam · mobile · roaming · trust 5%",
            "Debt Collector · landline · local · trust 65%",
            "Prize Winner · mobile · international · trust 10%",
            "Loan Scam · mobile · mobile · trust 15%"
        };

        conn.setAutoCommit(false);
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < count; i++) {
                pstmt.setString(1, randomPhone());
                pstmt.setString(2, countries[random.nextInt(countries.length)]);
                pstmt.setString(3, weightedPick(severities, sevWeights));
                pstmt.setString(4, patterns[random.nextInt(patterns.length)]);
                pstmt.addBatch();

                if ((i + 1) % BATCH_COMMIT_SIZE == 0) {
                    flushBatch(pstmt, conn, "suspicious_calls", i + 1);
                }
                if ((i + 1) % PROGRESS_INTERVAL == 0) {
                    System.out.printf("    suspicious_calls: %,d / %,d rows%n", i + 1, count);
                }
            }
            pstmt.executeBatch();
            conn.commit();
        }
        conn.setAutoCommit(true);
        System.out.printf("    suspicious_calls: %,d rows inserted.%n", count);
    }

    private static void generatePhishingUrls(Connection conn, int count) throws Exception {
        String sql = "INSERT INTO phishing_urls (url, domain, severity, notes) VALUES (?, ?, ?, ?)";
        String[] fakeDomains = {
            "secure-login-paypal", "apple-verify-account", "amazon-security-alert",
            "netflix-billing-update", "microsoft-support-login", "sbi-netbanking-verify",
            "hdfc-account-update", "google-account-recover", "irs-refund-portal", "dmv-renewal-fee"
        };
        String[] tlds        = {".com", ".net", ".org", ".info", ".co", ".xyz"};
        String[] severities  = {"low", "medium", "high", "critical"};
        int[]    sevWeights  = {1, 3, 4, 2};

        conn.setAutoCommit(false);
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < count; i++) {
                String base   = fakeDomains[random.nextInt(fakeDomains.length)] + "-" + random.nextInt(9999999);
                String domain = base + tlds[random.nextInt(tlds.length)];
                String url    = "https://" + domain + "/login?session=" + random.nextInt(9999999);
                pstmt.setString(1, url);
                pstmt.setString(2, domain);
                pstmt.setString(3, weightedPick(severities, sevWeights));
                pstmt.setString(4, "Detected by automated URL scanner. Suspected credential harvesting.");
                pstmt.addBatch();

                if ((i + 1) % BATCH_COMMIT_SIZE == 0) {
                    flushBatch(pstmt, conn, "phishing_urls", i + 1);
                }
                if ((i + 1) % PROGRESS_INTERVAL == 0) {
                    System.out.printf("    phishing_urls: %,d / %,d rows%n", i + 1, count);
                }
            }
            pstmt.executeBatch();
            conn.commit();
        }
        conn.setAutoCommit(true);
        System.out.printf("    phishing_urls: %,d rows inserted.%n", count);
    }

    private static void generateMaliciousIps(Connection conn, int count) throws Exception {
        String sql = "INSERT INTO malicious_ips (ip_address, country, threat_type, severity) VALUES (?, ?, ?, ?)";
        String[] countries   = {"RU", "CN", "KP", "IR", "BR", "VN", "NG", "UA", "RO", "IN"};
        String[] threatTypes = {"Botnet C2", "DDoS Source", "Port Scanner", "Proxy/VPN Exit",
                                "Malware Host", "Spam Relay", "Brute Force"};
        String[] severities  = {"medium", "high", "critical"};
        int[]    sevWeights  = {3, 4, 3};

        conn.setAutoCommit(false);
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < count; i++) {
                pstmt.setString(1, randomIp());
                pstmt.setString(2, countries[random.nextInt(countries.length)]);
                pstmt.setString(3, threatTypes[random.nextInt(threatTypes.length)]);
                pstmt.setString(4, weightedPick(severities, sevWeights));
                pstmt.addBatch();

                if ((i + 1) % BATCH_COMMIT_SIZE == 0) {
                    flushBatch(pstmt, conn, "malicious_ips", i + 1);
                }
                if ((i + 1) % PROGRESS_INTERVAL == 0) {
                    System.out.printf("    malicious_ips: %,d / %,d rows%n", i + 1, count);
                }
            }
            pstmt.executeBatch();
            conn.commit();
        }
        conn.setAutoCommit(true);
        System.out.printf("    malicious_ips: %,d rows inserted.%n", count);
    }

    private static void generateEmailScams(Connection conn, int count) throws Exception {
        String sql = "INSERT INTO email_scams (sender, subject, category, severity, recipients_count) VALUES (?, ?, ?, ?, ?)";
        String[] subjects   = {
            "URGENT: Your account has been compromised",
            "Invoice #49202 attached — immediate action required",
            "You have won $1,000,000 — claim now",
            "Business Proposal — confidential",
            "Please update your password immediately",
            "Your parcel is waiting — pay customs fee",
            "Exclusive investment opportunity — 200% returns",
            "Security alert: unusual sign-in to your account"
        };
        String[] categories = {"BEC", "Phishing", "Extortion", "Spam", "Malware Delivery", "Lottery", "Advance Fee"};
        String[] severities = {"low", "medium", "high", "critical"};
        int[]    sevWeights = {2, 4, 3, 1};

        conn.setAutoCommit(false);
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < count; i++) {
                pstmt.setString(1, "scammer" + random.nextInt(10_000_000) + "@" + randomFakeDomain());
                pstmt.setString(2, subjects[random.nextInt(subjects.length)]);
                pstmt.setString(3, categories[random.nextInt(categories.length)]);
                pstmt.setString(4, weightedPick(severities, sevWeights));
                pstmt.setInt(5, 1 + random.nextInt(5000));
                pstmt.addBatch();

                if ((i + 1) % BATCH_COMMIT_SIZE == 0) {
                    flushBatch(pstmt, conn, "email_scams", i + 1);
                }
                if ((i + 1) % PROGRESS_INTERVAL == 0) {
                    System.out.printf("    email_scams: %,d / %,d rows%n", i + 1, count);
                }
            }
            pstmt.executeBatch();
            conn.commit();
        }
        conn.setAutoCommit(true);
        System.out.printf("    email_scams: %,d rows inserted.%n", count);
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static String randomIp() {
        return random.nextInt(256) + "."
             + random.nextInt(256) + "."
             + random.nextInt(256) + "."
             + random.nextInt(256);
    }

    private static String randomPhone() {
        String[] prefixes = {"+91", "+1", "+44", "+61", "+234", "+92"};
        String prefix = prefixes[random.nextInt(prefixes.length)];
        long number = 1000000000L + (long)(random.nextDouble() * 9000000000L);
        return prefix + number;
    }

    private static String randomFakeDomain() {
        String[] domains = {"bad-domain.com", "scam-mail.net", "phish.org",
                            "fraud-alert.info", "noreply-secure.com"};
        return domains[random.nextInt(domains.length)];
    }

    /**
     * Weighted random pick. weights[i] is the relative weight for items[i].
     */
    private static String weightedPick(String[] items, int[] weights) {
        int total = 0;
        for (int w : weights) total += w;
        int r = random.nextInt(total);
        int cumulative = 0;
        for (int i = 0; i < items.length; i++) {
            cumulative += weights[i];
            if (r < cumulative) return items[i];
        }
        return items[items.length - 1];
    }
}

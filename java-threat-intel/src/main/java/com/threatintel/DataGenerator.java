package com.threatintel;

import com.threatintel.db.DatabaseConfig;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Random;

public class DataGenerator {

    private static final Random random = new Random();

    public static void generateData() {
        System.out.println("Starting data generation...");
        long startTime = System.currentTimeMillis();

        try (Connection conn = DatabaseConfig.getConnection()) {
            conn.setAutoCommit(false);

            generateUsers(conn);
            generateThreats(conn, 40000);
            generateScamMessages(conn, 25000);
            generateSuspiciousCalls(conn, 20000);
            generatePhishingUrls(conn, 25000);
            generateMaliciousIps(conn, 20000);
            generateEmailScams(conn, 20000);

            conn.commit();
            conn.setAutoCommit(true);
            System.out.println("Data generation completed in " + (System.currentTimeMillis() - startTime) + "ms.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void generateUsers(Connection conn) throws Exception {
        String sql = "INSERT IGNORE INTO users (username, email, password, role) VALUES (?, ?, ?, ?)";
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
            System.out.println("Inserted users.");
        }
    }

    // threats: title, type, severity, description, source
    private static void generateThreats(Connection conn, int count) throws Exception {
        String sql = "INSERT INTO threats (title, type, severity, description, source) VALUES (?, ?, ?, ?, ?)";
        String[] types = {"phishing_url", "spam_call", "email_scam", "malicious_ip", "scam_message", "other"};
        String[] severities = {"low", "medium", "high", "critical"};
        // Weighted: more medium/high than critical
        int[] sevWeights = {3, 4, 2, 1}; // low, medium, high, critical

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < count; i++) {
                String type = types[random.nextInt(types.length)];
                String sev = weightedPick(severities, sevWeights);
                pstmt.setString(1, "Threat-" + (i + 1) + "-" + type.replace("_", ""));
                pstmt.setString(2, type);
                pstmt.setString(3, sev);
                pstmt.setString(4, "Automated threat detection record for security analysis.");
                pstmt.setString(5, randomIp());
                pstmt.addBatch();

                if (i % 5000 == 4999) {
                    pstmt.executeBatch();
                }
            }
            pstmt.executeBatch();
            System.out.println("Inserted " + count + " threats.");
        }
    }

    // scam_messages: channel, sender, content, severity
    private static void generateScamMessages(Connection conn, int count) throws Exception {
        String sql = "INSERT INTO scam_messages (channel, sender, content, severity) VALUES (?, ?, ?, ?)";
        String[] channels = {"sms", "whatsapp", "telegram", "other"};
        String[] severities = {"low", "medium", "high", "critical"};
        int[] sevWeights = {2, 4, 3, 1};
        String[] templates = {
            "Congratulations! You have won a prize. Click here to claim: http://scam.link",
            "Your bank account has been suspended. Verify immediately: http://fake-bank.com",
            "URGENT: Your package could not be delivered. Pay Rs. 50 fee: http://phish.site",
            "Hello, I am a Nigerian prince and need your help to transfer funds.",
            "You have been selected for a government grant. Reply with your Aadhaar number.",
            "Investment opportunity: guaranteed 50% returns monthly. Contact us now!",
            "Your OTP is 837462. Do NOT share this with anyone.",
            "Free Netflix subscription! Claim yours: http://free-netflix-scam.com"
        };

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < count; i++) {
                pstmt.setString(1, channels[random.nextInt(channels.length)]);
                pstmt.setString(2, randomPhone());
                pstmt.setString(3, templates[random.nextInt(templates.length)]);
                pstmt.setString(4, weightedPick(severities, sevWeights));
                pstmt.addBatch();

                if (i % 5000 == 4999) {
                    pstmt.executeBatch();
                }
            }
            pstmt.executeBatch();
            System.out.println("Inserted " + count + " scam messages.");
        }
    }

    // suspicious_calls: phone_number, country, severity, pattern
    private static void generateSuspiciousCalls(Connection conn, int count) throws Exception {
        String sql = "INSERT INTO suspicious_calls (phone_number, country, severity, pattern) VALUES (?, ?, ?, ?)";
        String[] countries = {"IN", "US", "GB", "AU", "CA", "NG", "PK", "BD", "PH", "GH"};
        String[] severities = {"low", "medium", "high", "critical"};
        int[] sevWeights = {2, 4, 3, 1};
        String[] patterns = {
            "IRS Scam · mobile · spoofed · trust 12%",
            "Tech Support Scam · mobile · voip · trust 8%",
            "Bank Fraud · landline · local · trust 20%",
            "Grandparent Scam · mobile · roaming · trust 5%",
            "Debt Collector · landline · local · trust 65%",
            "Prize Winner · mobile · international · trust 10%",
            "Loan Scam · mobile · mobile · trust 15%"
        };

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < count; i++) {
                pstmt.setString(1, randomPhone());
                pstmt.setString(2, countries[random.nextInt(countries.length)]);
                pstmt.setString(3, weightedPick(severities, sevWeights));
                pstmt.setString(4, patterns[random.nextInt(patterns.length)]);
                pstmt.addBatch();

                if (i % 5000 == 4999) {
                    pstmt.executeBatch();
                }
            }
            pstmt.executeBatch();
            System.out.println("Inserted " + count + " suspicious calls.");
        }
    }

    // phishing_urls: url, domain, severity, notes
    private static void generatePhishingUrls(Connection conn, int count) throws Exception {
        String sql = "INSERT INTO phishing_urls (url, domain, severity, notes) VALUES (?, ?, ?, ?)";
        String[] fakeDomains = {
            "secure-login-paypal", "apple-verify-account", "amazon-security-alert",
            "netflix-billing-update", "microsoft-support-login", "sbi-netbanking-verify",
            "hdfc-account-update", "google-account-recover", "irs-refund-portal", "dmv-renewal-fee"
        };
        String[] tlds = {".com", ".net", ".org", ".info", ".co", ".xyz"};
        String[] severities = {"low", "medium", "high", "critical"};
        int[] sevWeights = {1, 3, 4, 2};

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < count; i++) {
                String base = fakeDomains[random.nextInt(fakeDomains.length)] + "-" + random.nextInt(99999);
                String domain = base + tlds[random.nextInt(tlds.length)];
                String url = "https://" + domain + "/login?session=" + random.nextInt(999999);
                pstmt.setString(1, url);
                pstmt.setString(2, domain);
                pstmt.setString(3, weightedPick(severities, sevWeights));
                pstmt.setString(4, "Detected by automated URL scanner. Suspected credential harvesting.");
                pstmt.addBatch();

                if (i % 5000 == 4999) {
                    pstmt.executeBatch();
                }
            }
            pstmt.executeBatch();
            System.out.println("Inserted " + count + " phishing URLs.");
        }
    }

    // malicious_ips: ip_address, country, threat_type, severity
    private static void generateMaliciousIps(Connection conn, int count) throws Exception {
        String sql = "INSERT INTO malicious_ips (ip_address, country, threat_type, severity) VALUES (?, ?, ?, ?)";
        String[] countries = {"RU", "CN", "KP", "IR", "BR", "VN", "NG", "UA", "RO", "IN"};
        String[] threatTypes = {"Botnet C2", "DDoS Source", "Port Scanner", "Proxy/VPN Exit", "Malware Host", "Spam Relay", "Brute Force"};
        String[] severities = {"medium", "high", "critical"};
        int[] sevWeights = {3, 4, 3};

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < count; i++) {
                pstmt.setString(1, randomIp());
                pstmt.setString(2, countries[random.nextInt(countries.length)]);
                pstmt.setString(3, threatTypes[random.nextInt(threatTypes.length)]);
                pstmt.setString(4, weightedPick(severities, sevWeights));
                pstmt.addBatch();

                if (i % 5000 == 4999) {
                    pstmt.executeBatch();
                }
            }
            pstmt.executeBatch();
            System.out.println("Inserted " + count + " malicious IPs.");
        }
    }

    // email_scams: sender, subject, category, severity, recipients_count
    private static void generateEmailScams(Connection conn, int count) throws Exception {
        String sql = "INSERT INTO email_scams (sender, subject, category, severity, recipients_count) VALUES (?, ?, ?, ?, ?)";
        String[] subjects = {
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
        int[] sevWeights = {2, 4, 3, 1};

        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            for (int i = 0; i < count; i++) {
                pstmt.setString(1, "scammer" + random.nextInt(10000) + "@" + randomFakeDomain());
                pstmt.setString(2, subjects[random.nextInt(subjects.length)]);
                pstmt.setString(3, categories[random.nextInt(categories.length)]);
                pstmt.setString(4, weightedPick(severities, sevWeights));
                pstmt.setInt(5, 1 + random.nextInt(5000));
                pstmt.addBatch();

                if (i % 5000 == 4999) {
                    pstmt.executeBatch();
                }
            }
            pstmt.executeBatch();
            System.out.println("Inserted " + count + " email scams.");
        }
    }

    // --- Helpers ---

    private static String randomIp() {
        return random.nextInt(256) + "." + random.nextInt(256) + "." + random.nextInt(256) + "." + random.nextInt(256);
    }

    private static String randomPhone() {
        String[] prefixes = {"+91", "+1", "+44", "+61", "+234", "+92"};
        String prefix = prefixes[random.nextInt(prefixes.length)];
        long number = 1000000000L + (long)(random.nextDouble() * 9000000000L);
        return prefix + number;
    }

    private static String randomFakeDomain() {
        String[] domains = {"bad-domain.com", "scam-mail.net", "phish.org", "fraud-alert.info", "noreply-secure.com"};
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

package com.threatintel;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class ThreatDataGenerator {
    private static final Random RANDOM = new Random();
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final String[] THREAT_TYPES = {"phishing_url", "spam_call", "email_scam", "malicious_ip", "scam_message", "other"};
    private static final String[] SEVERITIES = {"critical", "high", "medium", "low"};
    private static final String[] COUNTRIES = {"US", "CN", "RU", "GB", "DE", "IN", "BR", "FR", "KR", "JP", "UNKNOWN"};
    private static final String[] DEVICE_TYPES = {"Desktop", "Mobile", "Tablet", "IoT", "Server"};
    
    public static class ThreatRecord {
        String sourceIp;
        String destinationIp;
        String domain;
        String url;
        String email;
        String phoneNumber;
        String threatType;
        String severity;
        double detectionScore;
        String country;
        String deviceType;
        String timestamp;
        boolean isMalicious;
    }

    public static List<ThreatRecord> generateRecords(int count) {
        List<ThreatRecord> records = new ArrayList<>(count);
        LocalDateTime now = LocalDateTime.now();

        for (int i = 0; i < count; i++) {
            ThreatRecord record = new ThreatRecord();
            record.sourceIp = randomIp();
            record.destinationIp = randomIp();
            record.domain = randomDomain();
            record.url = "http://" + record.domain + "/" + randomString(8);
            record.email = randomString(5) + "@" + randomDomain();
            record.phoneNumber = randomPhone();
            record.threatType = THREAT_TYPES[RANDOM.nextInt(THREAT_TYPES.length)];
            record.severity = SEVERITIES[RANDOM.nextInt(SEVERITIES.length)];
            record.detectionScore = Math.round(RANDOM.nextDouble() * 100.0) / 100.0;
            record.country = COUNTRIES[RANDOM.nextInt(COUNTRIES.length)];
            record.deviceType = DEVICE_TYPES[RANDOM.nextInt(DEVICE_TYPES.length)];
            
            // Random timestamp within the last 30 days
            record.timestamp = now.minusMinutes(RANDOM.nextInt(43200)).format(FORMATTER);

            // Rules: is_malicious = true when severity is high/critical or detection_score > 0.7
            if (record.severity.equals("high") || record.severity.equals("critical") || record.detectionScore > 0.7) {
                record.isMalicious = true;
            } else {
                record.isMalicious = false;
            }

            records.add(record);
        }
        return records;
    }

    private static String randomIp() {
        return RANDOM.nextInt(256) + "." + RANDOM.nextInt(256) + "." + RANDOM.nextInt(256) + "." + RANDOM.nextInt(256);
    }

    private static String randomDomain() {
        String[] tlds = {".com", ".org", ".net", ".info", ".biz", ".xyz", ".ru", ".cn"};
        String[] bases = {"secure-login", "account-update", "free-money", "bank-verify", "support-tech", "example", "my-site"};
        return bases[RANDOM.nextInt(bases.length)] + "-" + RANDOM.nextInt(999) + tlds[RANDOM.nextInt(tlds.length)];
    }

    private static String randomString(int length) {
        String chars = "abcdefghijklmnopqrstuvwxyz1234567890";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(RANDOM.nextInt(chars.length())));
        }
        return sb.toString();
    }
    
    private static String randomPhone() {
        return "+1-" + (200 + RANDOM.nextInt(800)) + "-" + (200 + RANDOM.nextInt(800)) + "-" + (1000 + RANDOM.nextInt(9000));
    }
}

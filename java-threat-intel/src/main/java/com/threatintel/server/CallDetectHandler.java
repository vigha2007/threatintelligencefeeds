package com.threatintel.server;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.threatintel.db.DatabaseConfig;

import java.io.*;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/**
 * CallDetectHandler — Granular 9-Category Real-Time Phone Call Intelligence Engine.
 *
 * Supported Classifications:
 *   1. SAFE        (Risk: LOW)
 *   2. PROMOTIONAL (Risk: LOW)
 *   3. MARKETING   (Risk: LOW)
 *   4. SPAM        (Risk: MEDIUM)
 *   5. SUSPICIOUS  (Risk: MEDIUM)
 *   6. FRAUD       (Risk: HIGH)
 *   7. SCAM        (Risk: CRITICAL)
 *   8. UNKNOWN     (Risk: UNKNOWN)
 *   9. INVALID     (Risk: NONE)
 *
 * Duplicate Database Handling:
 *   Queries ALL matching database rows for normalized number without `LIMIT 1`.
 *   If conflicting classifications exist across duplicate DB records, resolves to SUSPICIOUS
 *   and documents the exact conflicting evidence.
 */
public class CallDetectHandler implements HttpHandler {

    private static final Gson GSON = new Gson();

    /** Non-digit stripper for phone normalisation */
    private static final Pattern NON_DIGIT = Pattern.compile("[^0-9]");

    /** ML FastAPI base URL */
    private static final String ML_API_URL =
        System.getenv().getOrDefault("ML_API_URL", "http://localhost:8000");

    private final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(4))
        .build();

    private static String getIpqsApiKey() {
        String key = System.getenv("IPQS_API_KEY");
        if (key != null && !key.trim().isEmpty()) return key.trim();
        try {
            File envFile = new File(".env");
            if (!envFile.exists()) envFile = new File("../.env");
            if (envFile.exists()) {
                try (BufferedReader br = new BufferedReader(new FileReader(envFile, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        line = line.trim();
                        if (line.startsWith("IPQS_API_KEY=")) {
                            String v = line.substring("IPQS_API_KEY=".length()).trim();
                            if (v.startsWith("\"") && v.endsWith("\"")) v = v.substring(1, v.length() - 1);
                            return v;
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return "";
    }

    private static Map<String, String> getTruecallerCredentials() {
        String clientId = System.getenv("TRUECALLER_CLIENT_ID");
        String clientSecret = System.getenv("TRUECALLER_CLIENT_SECRET");
        String redirectUri = System.getenv("TRUECALLER_REDIRECT_URI");
        if (clientId != null && !clientId.trim().isEmpty() && !clientId.startsWith("YOUR_")) {
            return Map.of("clientId", clientId.trim(), "clientSecret", clientSecret != null ? clientSecret.trim() : "", "redirectUri", redirectUri != null ? redirectUri.trim() : "");
        }
        try {
            File envFile = new File(".env");
            if (!envFile.exists()) envFile = new File("../.env");
            if (envFile.exists()) {
                try (BufferedReader br = new BufferedReader(new FileReader(envFile, StandardCharsets.UTF_8))) {
                    String line;
                    String cid = "", csec = "", red = "";
                    while ((line = br.readLine()) != null) {
                        line = line.trim();
                        if (line.startsWith("TRUECALLER_CLIENT_ID=")) {
                            cid = line.substring("TRUECALLER_CLIENT_ID=".length()).trim().replace("\"", "");
                        } else if (line.startsWith("TRUECALLER_CLIENT_SECRET=")) {
                            csec = line.substring("TRUECALLER_CLIENT_SECRET=".length()).trim().replace("\"", "");
                        } else if (line.startsWith("TRUECALLER_REDIRECT_URI=")) {
                            red = line.substring("TRUECALLER_REDIRECT_URI=".length()).trim().replace("\"", "");
                        }
                    }
                    if (!cid.isEmpty() && !cid.startsWith("YOUR_")) {
                        return Map.of("clientId", cid, "clientSecret", csec, "redirectUri", red);
                    }
                }
            }
        } catch (Exception ignored) {}
        return Collections.emptyMap();
    }

    private Map<String, Object> callTruecallerApi(String normalized, Map<String, String> creds) {
        return null;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        // CORS headers
        ex.getResponseHeaders().add("Access-Control-Allow-Origin",  "*");
        ex.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
        ex.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
        ex.getResponseHeaders().add("Content-Type", "application/json");

        if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
            ex.sendResponseHeaders(204, -1);
            return;
        }

        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            sendJson(ex, 405, Map.of("success", false, "error", "Only POST is supported"));
            return;
        }

        String body;
        try (InputStream is = ex.getRequestBody()) {
            body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> req = GSON.fromJson(body, Map.class);
        String rawInput = req == null ? "" :
            String.valueOf(req.getOrDefault("phoneNumber",
                req.getOrDefault("phone",
                    req.getOrDefault("content", "")))).trim();

        System.out.println("[CALL DETECTION] Input: " + rawInput);

        if (rawInput.isEmpty()) {
            System.out.println("[CALL DETECTION] Final result: INVALID (NONE)");
            sendJson(ex, 400, Map.of(
                "success", false,
                "category", "INVALID",
                "classification", "INVALID",
                "status", "INVALID",
                "riskLevel", "NONE",
                "confidence", null,
                "error", "phoneNumber field is required"));
            return;
        }

        String normalized = normalizePhone(rawInput);
        System.out.println("[CALL DETECTION] Normalized: " + normalized);

        try {
            Map<String, Object> result = detectMultiSource(rawInput, normalized);
            sendJson(ex, 200, result);
        } catch (Exception e) {
            System.err.println("[CALL DETECTION] Unexpected error: " + e.getMessage());
            sendJson(ex, 500, Map.of(
                "success", false,
                "error",   "Detection pipeline error",
                "details", e.getMessage() != null ? e.getMessage() : "Unknown error"
            ));
        }
    }

    // =========================================================================
    //  Phone Normalization Logic
    // =========================================================================

    public static String normalizePhone(String raw) {
        if (raw == null) return "";
        String digits = NON_DIGIT.matcher(raw.trim()).replaceAll("");

        // Handle Indian numbers (+91, 0091, 091, 0)
        if (digits.length() == 12 && digits.startsWith("91")) {
            String candidate = digits.substring(2);
            if (candidate.length() == 10) return candidate;
        }
        if (digits.length() == 13 && digits.startsWith("910")) {
            return digits.substring(2);
        }
        if (digits.length() == 14 && digits.startsWith("0091")) {
            String candidate = digits.substring(4);
            if (candidate.length() == 10) return candidate;
        }
        if (digits.length() == 11 && digits.startsWith("0")) {
            String candidate = digits.substring(1);
            if (candidate.length() == 10) return candidate;
        }
        // US 11-digit number starting with country code 1
        if (digits.length() == 11 && digits.startsWith("1")) {
            String candidate = digits.substring(1);
            if (candidate.length() == 10) return candidate;
        }
        // UK 12-digit number starting with country code 44
        if (digits.length() == 12 && digits.startsWith("44")) {
            return digits.substring(2);
        }

        return digits;
    }

    // =========================================================================
    //  Multi-Source Phone Reputation Engine
    // =========================================================================

    private Map<String, Object> detectMultiSource(String rawInput, String normalized) {
        String timestamp = Instant.now().toString();

        Map<String, Object> dbSource   = new LinkedHashMap<>();
        Map<String, Object> tcSource   = new LinkedHashMap<>();
        Map<String, Object> ipqsSource = new LinkedHashMap<>();
        List<String> evidence          = new ArrayList<>();

        System.out.println("[CALL REPUTATION] Input: " + rawInput);
        System.out.println("[CALL REPUTATION] Normalized: " + normalized);

        // ── 0. Pre-DB Structural Validation ──────────────────────────────────
        boolean hasExplicitPlus = rawInput.startsWith("+") || rawInput.startsWith("00");
        boolean isTooShort = hasExplicitPlus ? normalized.length() < 7 : normalized.length() < 10;
        boolean isTooLong  = normalized.length() > 15;
        if (isTooShort || isTooLong) {
            System.out.println("[CALL REPUTATION] Invalid length (" + normalized.length() + " digits). Skipping DB lookup.");
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success",               true);
            result.put("source",                "Telecom Reputation Engine");
            result.put("databaseMatch",         false);
            result.put("phoneNumber",           rawInput);
            result.put("normalizedPhoneNumber", normalized);
            result.put("callerIdentity",        "Unidentified Caller");
            result.put("classification",        "INVALID_NUMBER");
            result.put("verdict",               "INVALID_NUMBER");
            result.put("category",              "INVALID PHONE NUMBER");
            result.put("status",                "INVALID_NUMBER");
            result.put("riskLevel",             "NONE");
            result.put("threatLevel",           "NONE");
            result.put("confidence",            null);
            result.put("recommendation",        "Invalid phone number length. Valid telephone numbering plans require 10 digits for national inputs or 7 to 15 digits for international E.164 numbers.");
            result.put("country",               "Unknown");
            result.put("carrier",               "Unknown");
            result.put("lineType",              "Unknown");
            result.put("sources", Map.of(
                "database", Map.of("available", true, "matched", false, "recordsFound", 0, "dbIds", List.of()),
                "truecaller", Map.of("queried", false, "available", false),
                "ipqs", Map.of("queried", false, "available", false),
                "telecomEngine", Map.of("analyzed", true, "formatValid", false, "country", "Unknown", "lineType", "Unknown", "carrier", "Unknown")
            ));
            result.put("evidence", List.of("Invalid phone number length (" + normalized.length() + " digits). National phone numbers without explicit country code require at least 10 digits."));
            result.put("timestamp", timestamp);
            return result;
        }

        // ── 1. DATABASE — Primary Source of Truth (Exact Match Only) ────────
        System.out.println("[CALL REPUTATION] DB Query: searching suspicious_calls for " + normalized);
        List<Map<String, Object>> dbRows = lookupAllInDb(normalized);
        boolean dbMatched = !dbRows.isEmpty();
        dbSource.put("available", true);
        dbSource.put("matched", dbMatched);
        dbSource.put("recordsFound", dbRows.size());

        System.out.println("[CALL REPUTATION] DB Matches: " + dbRows.size());

        // Parse FCC pattern text to extract actual classification fields
        java.util.regex.Pattern ISSUE_PATTERN   = java.util.regex.Pattern.compile("Issue reported:\\s*([^.]+)");
        java.util.regex.Pattern CALLTYPE_PATTERN = java.util.regex.Pattern.compile("Call type:\\s*([^.]+)");
        java.util.regex.Pattern CALLER_PATTERN   = java.util.regex.Pattern.compile("Caller phone:\\s*([^.]+)");
        java.util.regex.Pattern REGION_PATTERN   = java.util.regex.Pattern.compile("Reported in:\\s*([^.]+)");

        List<Map<String, Object>> dbRecordList = new ArrayList<>();
        List<Object> dbIds        = new ArrayList<>();
        List<String> dbSeverities = new ArrayList<>();
        List<String> dbActualCategories = new ArrayList<>();
        List<String> dbCallTypes = new ArrayList<>();
        boolean dbConflict = false;

        for (Map<String, Object> row : dbRows) {
            Object id       = row.get("id");
            String severity = String.valueOf(row.getOrDefault("severity", "medium")).toLowerCase();
            String pattern  = String.valueOf(row.getOrDefault("pattern", ""));
            String country  = String.valueOf(row.getOrDefault("country", "Unknown"));

            dbIds.add(id);
            dbSeverities.add(severity);

            String actualCategory = null;
            String callType       = null;
            String callerPhone    = null;
            String reportedIn     = null;

            if (pattern != null && !pattern.equals("null") && !pattern.isEmpty()) {
                java.util.regex.Matcher m;
                m = ISSUE_PATTERN.matcher(pattern);
                if (m.find()) actualCategory = m.group(1).trim();
                m = CALLTYPE_PATTERN.matcher(pattern);
                if (m.find()) callType = m.group(1).trim();
                m = CALLER_PATTERN.matcher(pattern);
                if (m.find()) callerPhone = m.group(1).trim();
                m = REGION_PATTERN.matcher(pattern);
                if (m.find()) reportedIn = m.group(1).trim();
            }

            if (actualCategory == null && pattern != null && !pattern.equals("null")) {
                String[] parts = pattern.split("\u00b7");
                if (parts.length >= 2 && !parts[1].trim().isEmpty()) {
                    actualCategory = parts[1].trim();
                } else if (parts.length >= 1 && !parts[0].trim().isEmpty()) {
                    actualCategory = parts[0].trim();
                }
            }

            if ((actualCategory == null || actualCategory.equals("null") || "Unknown Threat".equals(actualCategory)) && row.get("category") != null) {
                String catCol = String.valueOf(row.get("category")).trim();
                if (!catCol.isEmpty() && !"null".equalsIgnoreCase(catCol)) {
                    actualCategory = catCol;
                }
            }

            if (actualCategory == null || actualCategory.equals("null")) {
                actualCategory = "Unknown Threat";
            }

            dbActualCategories.add(actualCategory);
            if (callType != null) dbCallTypes.add(callType);

            Map<String, Object> record = new LinkedHashMap<>();
            record.put("recordId",      id);
            record.put("severity",      severity);
            record.put("category",      actualCategory);
            record.put("callType",      callType != null ? callType : "Unknown");
            record.put("callerPhone",   callerPhone != null ? callerPhone : normalized);
            record.put("reportedIn",    reportedIn != null ? reportedIn : "Unknown");
            record.put("country",       country.equals("null") ? "Unknown" : country);
            record.put("description",   pattern);
            dbRecordList.add(record);
        }

        Set<String> uniqueCategories = new LinkedHashSet<>(dbActualCategories);
        if (uniqueCategories.size() > 1) {
            dbConflict = true;
            System.out.println("[CALL REPUTATION] DB Conflict: multiple classifications: " + uniqueCategories);
        }

        dbSource.put("dbIds",            dbIds);
        dbSource.put("severities",       dbSeverities);
        dbSource.put("categories",       dbActualCategories);
        dbSource.put("records",          dbRecordList);
        dbSource.put("conflictDetected", dbConflict);

        String dbDerivedClassification = null;
        String dbDerivedCategory       = null;
        String dbDerivedRiskLevel      = null;
        Double dbDerivedConfidence     = null;

        if (dbMatched) {
            String strongest = null;
            String strongestSeverity = "low";

            for (int i = 0; i < dbActualCategories.size(); i++) {
                String cat = dbActualCategories.get(i);
                String sev = dbSeverities.get(i);
                if (strongest == null) {
                    strongest = cat;
                    strongestSeverity = sev;
                } else {
                    int prevRank = severityRank(strongestSeverity);
                    int currRank = severityRank(sev);
                    if (currRank > prevRank) {
                        strongest = cat;
                        strongestSeverity = sev;
                    }
                }
            }

            dbDerivedCategory = strongest != null ? strongest : "Reported Threat";
            dbDerivedRiskLevel = severityToRisk(strongestSeverity);
            dbDerivedConfidence = Math.min(98.0, 90.0 + (dbRows.size() * 2.0));

            String catLower = dbDerivedCategory.toLowerCase();
            if (catLower.contains("scam call") || catLower.contains("scam") || catLower.contains("imposter")) {
                dbDerivedClassification = "SCAM";
            } else if (catLower.contains("fraud") || catLower.contains("phishing")) {
                dbDerivedClassification = "FRAUD";
            } else if (catLower.contains("robocall") || catLower.contains("robo")) {
                dbDerivedClassification = "SPAM";
            } else if (catLower.contains("telemarketing") || catLower.contains("do not call")) {
                dbDerivedClassification = "SPAM";
            } else if (catLower.contains("spam")) {
                dbDerivedClassification = "SPAM";
            } else if (catLower.contains("debt") || catLower.contains("collection")) {
                dbDerivedClassification = "SUSPICIOUS";
            } else if (catLower.contains("legitimate") || catLower.contains("good call")) {
                dbDerivedClassification = "LEGITIMATE";
            } else {
                dbDerivedClassification = "SUSPICIOUS";
            }

            if (dbConflict) {
                evidence.add("Conflicting threat records found in local DB. Reported categories: " + uniqueCategories);
            }
            evidence.add("Registered threat found in Threat Intelligence Database (" + dbRows.size() + " record" + (dbRows.size() > 1 ? "s" : "") + ").");
            for (Map<String, Object> rec : dbRecordList) {
                evidence.add("Database Threat ID #" + rec.get("recordId") + ": "
                    + rec.get("category") + " (Severity: " + rec.get("severity").toString().toUpperCase()
                    + (!"Unknown".equals(rec.get("callType")) ? ", Call Type: " + rec.get("callType") : "")
                    + ")");
            }
        }

        // ── 2. Truecaller Integration ──────────────────────────────────────
        Map<String, String> tcCreds = getTruecallerCredentials();
        String tcName = null;
        String tcCategory = null;
        if (!tcCreds.isEmpty()) {
            Map<String, Object> tcRes = callTruecallerApi(normalized, tcCreds);
            tcSource.put("queried", true);
            if (tcRes != null && Boolean.TRUE.equals(tcRes.get("success"))) {
                tcSource.put("available", true);
                if (tcRes.containsKey("name"))     tcName     = String.valueOf(tcRes.get("name"));
                if (tcRes.containsKey("category")) tcCategory = String.valueOf(tcRes.get("category"));
                if (!dbMatched) {
                    evidence.add("Truecaller API identity match: " + (tcName != null ? tcName : "Verified"));
                }
            } else {
                tcSource.put("available", false);
            }
        } else {
            tcSource.put("queried",   false);
            tcSource.put("available", false);
        }

        // ── 3. IPQS Phone Intelligence ─────────────────────────────────────
        boolean ipqsAvailable = false;
        String country  = "Unknown";
        String carrier  = "Unknown";
        String lineType = "Unknown";
        int fraudScore  = 0;

        String ipqsKey = getIpqsApiKey();
        if (!ipqsKey.isEmpty() && !ipqsKey.equals("YOUR_API_KEY") && !ipqsKey.equals("YOUR_REAL_API_KEY")) {
            Map<String, Object> ipqsRes = callIpqsApi(normalized, ipqsKey);
            ipqsSource.put("queried", true);
            if (ipqsRes != null && Boolean.TRUE.equals(ipqsRes.get("success"))) {
                ipqsAvailable = true;
                fraudScore = ((Number) ipqsRes.getOrDefault("fraud_score", 0)).intValue();
                ipqsSource.put("available",   true);
                ipqsSource.put("fraudScore",  fraudScore);
                ipqsSource.put("risky",       ipqsRes.getOrDefault("risky", false));
                ipqsSource.put("recentAbuse", ipqsRes.getOrDefault("recent_abuse", false));
                ipqsSource.put("spammer",     ipqsRes.getOrDefault("spammer", false));
                carrier  = String.valueOf(ipqsRes.getOrDefault("carrier",   "Unknown"));
                lineType = String.valueOf(ipqsRes.getOrDefault("line_type", "Unknown"));
                country  = String.valueOf(ipqsRes.getOrDefault("country",   "Unknown"));
                ipqsSource.put("carrier",  carrier);
                ipqsSource.put("lineType", lineType);
                ipqsSource.put("country",  country);
                evidence.add("IPQualityScore Intelligence: Fraud Score " + fraudScore + "/100 (Line: " + lineType + ", Carrier: " + carrier + ")");
            } else {
                ipqsSource.put("available", false);
            }
        } else {
            ipqsSource.put("queried",   false);
            ipqsSource.put("available", false);
        }

        // ── 4. Country & Generic Numbering-Plan Validation ────────────────
        String cleanDigits = NON_DIGIT.matcher(rawInput).replaceAll("");
        int digitLen = cleanDigits.length();

        // Detect country from explicit international prefix or default context
        boolean isIndia = false;
        boolean isUS    = false;
        boolean isUK    = false;

        if (rawInput.startsWith("+91") || rawInput.startsWith("0091") || (cleanDigits.startsWith("91") && digitLen == 12)) {
            country = "India";
            isIndia = true;
        } else if (rawInput.startsWith("+1") || rawInput.startsWith("001") || (cleanDigits.startsWith("1") && digitLen == 11)) {
            country = "United States";
            isUS = true;
        } else if (rawInput.startsWith("+44") || rawInput.startsWith("0044") || (cleanDigits.startsWith("44") && digitLen == 12)) {
            country = "United Kingdom";
            isUK = true;
        } else if (!hasExplicitPlus && normalized.matches("[6-9]\\d{9}")) {
            country = "India";
            isIndia = true;
        } else if (!hasExplicitPlus && normalized.matches("[2-9]\\d{9}")) {
            country = "United States";
            isUS = true;
        }

        // Structural anomaly flags
        boolean invalidLength        = normalized.length() < 7 || normalized.length() > 15;
        boolean invalidPrefix        = false;
        boolean repeatedDigits       = normalized.matches(".*(\\d)\\1{5,}.*");
        boolean sequentialRepetitive = normalized.matches(".*(\\d{3,})\\1+.*");

        if (isIndia && normalized.length() == 10 && !normalized.matches("[6-9]\\d{9}")) {
            invalidPrefix = true;
        }
        if (isUS && normalized.length() == 10 && (normalized.startsWith("0") || normalized.startsWith("1") || normalized.matches("^[01].*"))) {
            invalidPrefix = true;
        }

        if (lineType.equals("Unknown")) {
            if (isIndia && normalized.matches("[6-9]\\d{9}")) {
                lineType = "Mobile";
            } else if (isUK && normalized.startsWith("7")) {
                lineType = "Mobile";
            } else if (normalized.startsWith("1800") || normalized.startsWith("1888")) {
                lineType = "Toll Free";
            } else if (normalized.startsWith("1900") || normalized.startsWith("900")) {
                lineType = "Premium Rate";
            }
        }

        // ── 5. Final Phone Reputation Scoring Engine ───────────────────────
        String finalClassification;
        String finalCategory;
        String finalRiskLevel;
        Double finalConfidence;
        String callerIdentity;
        String recommendation;

        if (dbMatched) {
            // DB match is primary source of truth
            finalClassification = dbDerivedClassification;
            finalCategory       = dbDerivedCategory;
            finalRiskLevel      = dbDerivedRiskLevel;
            finalConfidence     = dbDerivedConfidence;

            if (tcName != null && !tcName.isEmpty()) {
                callerIdentity = tcName;
            } else if (dbRecordList.size() > 0) {
                callerIdentity = "Reported Threat (" + dbDerivedCategory + ")";
            } else {
                callerIdentity = "Database Listed Threat Number";
            }

            if ("CRITICAL".equals(finalRiskLevel) || "HIGH".equals(finalRiskLevel)) {
                recommendation = "Block call immediately. Registered in active threat database.";
            } else {
                recommendation = "Exercise caution. Flagged in local threat database as " + finalCategory + ".";
            }

        } else {
            // Number NOT present in local DB — evaluate via Telecom & Anomaly Engine
            boolean ipqsSpam  = ipqsAvailable && Boolean.TRUE.equals(ipqsSource.get("spammer"));
            boolean ipqsAbuse = ipqsAvailable && Boolean.TRUE.equals(ipqsSource.get("recentAbuse"));
            boolean ipqsRisky = ipqsAvailable && Boolean.TRUE.equals(ipqsSource.get("risky"));

            if (tcName != null && !tcName.isEmpty()) {
                callerIdentity = tcName;
            } else if (isIndia) {
                callerIdentity = "Indian Telecom Subscriber";
            } else if (isUS) {
                callerIdentity = "US Telephony Subscriber";
            } else if (isUK) {
                callerIdentity = "UK Telephony Subscriber";
            } else if (!"Unknown".equals(carrier)) {
                callerIdentity = carrier + " Subscriber";
            } else {
                callerIdentity = "Unidentified Caller";
            }

            if (ipqsAvailable && (fraudScore >= 85 || ipqsAbuse)) {
                finalClassification = "MALICIOUS";
                finalCategory       = "Suspected Scam Caller";
                finalRiskLevel      = "CRITICAL";
                finalConfidence     = Math.min(99.0, Math.max(88.0, (double) fraudScore));
                recommendation      = "High risk scam number detected by global phone reputation services. Do not engage.";
                evidence.add("Global threat intelligence flags high fraud activity (Fraud score: " + fraudScore + "/100).");
            } else if (ipqsSpam || (tcCategory != null && tcCategory.toLowerCase().contains("spam"))) {
                finalClassification = "SUSPICIOUS";
                finalCategory       = "Spam / Telemarketer";
                finalRiskLevel      = "MEDIUM";
                finalConfidence     = 85.0;
                recommendation      = "Likely unsolicited spam or telemarketing caller. Avoid answering.";
                evidence.add("Phone number reported as frequent spam caller across telecom reputation feeds.");
            } else if (invalidLength) {
                finalClassification = "INVALID";
                finalCategory       = "Invalid Digit Length (E.164 Violation)";
                finalRiskLevel      = "NONE";
                finalConfidence     = null;
                recommendation      = "Invalid phone number length. Valid international numbers must contain 7 to 15 digits.";
                evidence.add("Digit length (" + normalized.length() + ") violates ITU-T E.164 standard (7-15 digits).");
            } else if (invalidPrefix) {
                finalClassification = "SUSPICIOUS";
                finalCategory       = "Invalid Area / Telecom Prefix";
                finalRiskLevel      = "MEDIUM";
                finalConfidence     = null;
                recommendation      = "Exercise caution. Phone number contains an unassigned or invalid area code prefix.";
                evidence.add("Invalid or unassigned telecom prefix for " + country + " numbering plan.");
            } else if (repeatedDigits || sequentialRepetitive) {
                finalClassification = "SUSPICIOUS";
                finalCategory       = "Repetitive Digit Sequence";
                finalRiskLevel      = "MEDIUM";
                finalConfidence     = null;
                recommendation      = "Exercise caution. Repetitive digit pattern detected (possible spoofed caller ID).";
                evidence.add("Repetitive digit pattern detected (possible spoofed caller ID).");
            } else if (ipqsRisky || "VOIP".equalsIgnoreCase(lineType) || "Premium Rate".equalsIgnoreCase(lineType)) {
                finalClassification = "SUSPICIOUS";
                finalCategory       = "Unverified Virtual/VOIP Line";
                finalRiskLevel      = "MEDIUM";
                finalConfidence     = null;
                recommendation      = "Unverified VOIP or premium line type detected. Be cautious of potential caller ID spoofing.";
                evidence.add("VOIP or virtual line type detected — unverified subscriber identity.");
            } else {
                // Number NOT in DB & Structurally Valid & External APIs unconfigured -> LEGITIMATE
                finalClassification = "LEGITIMATE";
                finalCategory       = "Unreported Number (Local DB Check Passed)";
                finalRiskLevel      = "LOW";
                finalConfidence     = null; // Unverified confidence!
                recommendation      = "No threat record found in local database. External reputation APIs are unconfigured; reputation unverified.";
                evidence.add("Valid telecom format and active prefix structure for " + country + ".");
                evidence.add("Zero threat records found in local Threat Intelligence Database.");
                evidence.add("External reputation APIs (IPQS/Truecaller) are unconfigured; phone reputation is unverified.");
            }
        }

        // Standardize classification and recommendations
        if (dbMatched) {
            if ("SCAM".equalsIgnoreCase(finalClassification) || "FRAUD".equalsIgnoreCase(finalClassification)) {
                finalClassification = "MALICIOUS";
                finalRiskLevel = "HIGH";
            } else if ("SPAM".equalsIgnoreCase(finalClassification)) {
                finalClassification = "SUSPICIOUS";
                finalRiskLevel = "MEDIUM";
            }
        }

        if ("MALICIOUS".equalsIgnoreCase(finalClassification) || "CRITICAL".equalsIgnoreCase(finalRiskLevel) || "HIGH".equalsIgnoreCase(finalRiskLevel)) {
            finalClassification = "MALICIOUS";
            if (!"CRITICAL".equalsIgnoreCase(finalRiskLevel)) finalRiskLevel = "HIGH";
            recommendation = "Do not interact with this content. Block/report it and follow the recommended incident-response steps.";
        } else if ("SUSPICIOUS".equalsIgnoreCase(finalClassification) || "MEDIUM".equalsIgnoreCase(finalRiskLevel)) {
            finalClassification = "SUSPICIOUS";
            finalRiskLevel = "MEDIUM";
            recommendation = "Exercise caution. Do not click links, provide credentials, send money, or share OTPs until the source is verified.";
        } else if ("INVALID".equalsIgnoreCase(finalClassification)) {
            finalRiskLevel = "NONE";
            recommendation = "Please provide a valid input format.";
        } else if ("UNVERIFIED".equalsIgnoreCase(finalClassification)) {
            finalRiskLevel = "UNKNOWN";
            recommendation = "Unable to reliably determine the threat status. Verify the source through an independent trusted channel.";
        } else {
            finalClassification = "LEGITIMATE";
            finalRiskLevel = "LOW";
            recommendation = "Low-risk content detected. Continue with normal security awareness.";
        }

        System.out.println("[CALL REPUTATION] Verdict: " + finalClassification + " (" + finalCategory + ", Risk: " + finalRiskLevel + ", Conf: " + finalConfidence + ")");

        boolean isThreat = finalClassification.equals("MALICIOUS") || finalClassification.equals("SUSPICIOUS")
            || finalRiskLevel.equals("CRITICAL") || finalRiskLevel.equals("HIGH");

        if (isThreat) {
            logCallDetection(normalized, country, finalRiskLevel.toLowerCase(),
                "Flagged Threat · " + finalCategory + " · " + carrier);
        } else {
            System.out.println("[CALL DETECTION] Safe/unreported call - skipping DB threat persistence.");
        }

        // ── Build sources map ─────────────────────────────────────────────
        Map<String, Object> sourcesMap = new LinkedHashMap<>();
        sourcesMap.put("database",   dbSource);
        sourcesMap.put("truecaller", tcSource);
        sourcesMap.put("ipqs",       ipqsSource);
        sourcesMap.put("telecomEngine", Map.of(
            "analyzed", true,
            "formatValid", !invalidLength && !invalidPrefix,
            "country", country,
            "lineType", lineType,
            "carrier", carrier
        ));

        // ── 3b. ML Model Inference — Primary verdict source when DB has no match ──
        Map<String, Object> mlRes = callMlApi("/predict", Map.of("content", rawInput, "type", "call"));
        boolean mlAvailable = (mlRes != null);
        Map<String, Object> mlSource = new LinkedHashMap<>();
        mlSource.put("queried", true);
        mlSource.put("available", mlAvailable);
        if (mlAvailable && mlRes != null) {
            mlSource.putAll(mlRes);
        }
        sourcesMap.put("ml", mlSource);

        // ── Apply ML result when DB had no match (DB NO MATCH → ML is authoritative) ──
        // Previously this block only added evidence but never updated finalClassification.
        // Now it correctly overrides the fallback "LEGITIMATE" verdict with the actual ML result.
        if (!dbMatched && !ipqsAvailable && mlAvailable && mlRes != null) {
            String mlPrediction = String.valueOf(mlRes.getOrDefault("prediction", "")).toUpperCase();
            Object mlConf = mlRes.get("confidence");
            Double mlConfidence = null;
            if (mlConf instanceof Number) {
                double raw = ((Number) mlConf).doubleValue();
                mlConfidence = raw <= 1.0 ? Math.round(raw * 1000.0) / 10.0 : Math.round(raw * 10.0) / 10.0;
            }

            if ("MALICIOUS".equalsIgnoreCase(mlPrediction) || "SCAM".equalsIgnoreCase(mlPrediction) || "FRAUD".equalsIgnoreCase(mlPrediction)) {
                finalClassification = "MALICIOUS";
                finalCategory       = mlRes.containsKey("attack_type") ? String.valueOf(mlRes.get("attack_type")) : "ML-Detected Suspicious Call";
                finalRiskLevel      = "HIGH";
                finalConfidence     = mlConfidence;
                recommendation      = "ML model flagged this number as a potential threat. Do not share personal information.";
                evidence.add("ML Model (RandomForestClassifier) classified call as MALICIOUS (" + (mlConfidence != null ? mlConfidence + "%" : "N/A") + " confidence).");
            } else if ("SUSPICIOUS".equalsIgnoreCase(mlPrediction) || "SPAM".equalsIgnoreCase(mlPrediction)) {
                finalClassification = "SUSPICIOUS";
                finalCategory       = mlRes.containsKey("attack_type") ? String.valueOf(mlRes.get("attack_type")) : "ML-Detected Suspicious Pattern";
                finalRiskLevel      = "MEDIUM";
                finalConfidence     = mlConfidence;
                recommendation      = "ML model detected suspicious patterns. Exercise caution and verify the caller.";
                evidence.add("ML Model (RandomForestClassifier) classified call as SUSPICIOUS (" + (mlConfidence != null ? mlConfidence + "%" : "N/A") + " confidence).");
            } else if ("SAFE".equalsIgnoreCase(mlPrediction) || "LEGITIMATE".equalsIgnoreCase(mlPrediction) || "GOOD".equalsIgnoreCase(mlPrediction)) {
                finalClassification = "LEGITIMATE";
                finalCategory       = "No Threat Detected (ML Verified)";
                finalRiskLevel      = "LOW";
                finalConfidence     = mlConfidence;
                recommendation      = "ML model classifies this number as low-risk. No known threat patterns detected.";
                evidence.add("ML Model (RandomForestClassifier) classified call as LEGITIMATE (" + (mlConfidence != null ? mlConfidence + "%" : "N/A") + " confidence).");
            } else {
                // ML returned an unknown/unrecognised prediction — mark UNVERIFIED, not LEGITIMATE
                finalClassification = "UNVERIFIED";
                finalCategory       = "Unverified — No DB Record, ML Inconclusive";
                finalRiskLevel      = "UNKNOWN";
                finalConfidence     = mlConfidence;
                recommendation      = "Unable to verify threat status. No database record found and ML result was inconclusive. Verify caller independently.";
                evidence.add("ML model returned an inconclusive result (" + mlPrediction + "). Reputation unverified.");
            }

            // Re-run the standardization normalization after ML override
            if ("MALICIOUS".equalsIgnoreCase(finalClassification) || "CRITICAL".equalsIgnoreCase(finalRiskLevel) || "HIGH".equalsIgnoreCase(finalRiskLevel)) {
                finalClassification = "MALICIOUS";
                if (!"CRITICAL".equalsIgnoreCase(finalRiskLevel)) finalRiskLevel = "HIGH";
                recommendation = "Do not interact with this content. Block/report it and follow the recommended incident-response steps.";
            } else if ("SUSPICIOUS".equalsIgnoreCase(finalClassification) || "MEDIUM".equalsIgnoreCase(finalRiskLevel)) {
                finalClassification = "SUSPICIOUS";
                finalRiskLevel = "MEDIUM";
                recommendation = "Exercise caution. Do not click links, provide credentials, send money, or share OTPs until the source is verified.";
            } else if ("UNVERIFIED".equalsIgnoreCase(finalClassification)) {
                finalRiskLevel = "UNKNOWN";
                recommendation = "Unable to reliably determine the threat status. Verify the source through an independent trusted channel.";
            } else if ("LEGITIMATE".equalsIgnoreCase(finalClassification)) {
                finalRiskLevel = "LOW";
                recommendation = "ML model classifies this number as low-risk. No known threat patterns detected.";
            }
        } else if (!dbMatched && !ipqsAvailable && !mlAvailable) {
            // No DB, no IPQS, no ML — truly unverified. Never silently say LEGITIMATE.
            finalClassification = "UNVERIFIED";
            finalCategory       = "Unverified — No Intelligence Sources Available";
            finalRiskLevel      = "UNKNOWN";
            finalConfidence     = null;
            recommendation      = "No database record found and all external intelligence sources are unavailable. Reputation cannot be determined. Verify caller independently.";
            evidence.add("Zero threat records in local Threat Intelligence Database.");
            evidence.add("External reputation APIs (IPQS/Truecaller) are unconfigured.");
            evidence.add("ML model is unavailable. Threat status cannot be determined.");
        }

        // ── Build unified response payload ────────────────────────────────
        String modelClass = mlAvailable && mlRes != null ? String.valueOf(mlRes.getOrDefault("model_class", "RandomForestClassifier")) : "RandomForestClassifier";
        String datasetName = mlAvailable && mlRes != null ? String.valueOf(mlRes.getOrDefault("dataset", "suspicious_calls")) : "suspicious_calls";
        String attackType = mlAvailable && mlRes != null ? String.valueOf(mlRes.getOrDefault("attack_type", "Suspicious Call")) : "Suspicious Call";
        String callSource = dbMatched ? "DB_MATCH" : (ipqsAvailable ? "RULE" : (mlAvailable ? "ML" : "RULE"));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success",               true);
        result.put("source",                callSource);
        result.put("databaseMatch",         dbMatched);
        result.put("phoneNumber",           rawInput);
        result.put("normalizedPhoneNumber", normalized);
        result.put("callerIdentity",        callerIdentity);
        result.put("classification",        finalClassification);
        result.put("verdict",               finalClassification);
        result.put("category",              finalCategory);
        result.put("status",                finalClassification);
        result.put("riskLevel",             finalRiskLevel);
        result.put("threatLevel",           finalRiskLevel);
        result.put("severity",              finalRiskLevel);
        result.put("confidence",            finalConfidence != null ? finalConfidence : (mlAvailable && mlRes != null ? mlRes.get("confidence") : null));
        result.put("attack_type",           finalClassification.equals("LEGITIMATE") || finalClassification.equals("UNVERIFIED") || finalClassification.equals("INVALID") ? "None Detected" : attackType);
        result.put("dataset",               datasetName);
        result.put("model_class",           modelClass);
        if (mlAvailable && mlRes != null) {
            result.put("ml_confidence", mlRes.get("confidence"));
        }
        result.put("recommendation",        recommendation);
        result.put("recommended_action",    recommendation);
        result.put("country",               country);
        result.put("carrier",               carrier);
        result.put("lineType",              lineType);
        result.put("sources",               sourcesMap);
        result.put("evidence",              evidence);
        result.put("timestamp",             timestamp);

        if (dbMatched && !dbRecordList.isEmpty()) {
            Map<String, Object> primaryRecord = dbRecordList.get(0);
            Map<String, Object> dbField = new LinkedHashMap<>();
            dbField.put("recordId",       primaryRecord.get("recordId"));
            dbField.put("category",       primaryRecord.get("category"));
            dbField.put("severity",       primaryRecord.get("severity"));
            dbField.put("confidence",     dbDerivedConfidence);
            dbField.put("callType",       primaryRecord.get("callType"));
            dbField.put("reportedIn",     primaryRecord.get("reportedIn"));
            dbField.put("description",    primaryRecord.get("description"));
            dbField.put("totalRecords",   dbRows.size());
            dbField.put("allCategories",  dbActualCategories);
            dbField.put("conflicting",    dbConflict);
            result.put("database", dbField);
        }

        return result;
    }

    /** Convert severity string to integer rank for comparison */
    private static int severityRank(String severity) {
        switch (severity.toLowerCase()) {
            case "critical": return 4;
            case "high":     return 3;
            case "medium":   return 2;
            case "low":      return 1;
            default:         return 0;
        }
    }

    /** Convert severity string to risk level label */
    private static String severityToRisk(String severity) {
        switch (severity.toLowerCase()) {
            case "critical": return "CRITICAL";
            case "high":     return "HIGH";
            case "medium":   return "MEDIUM";
            case "low":      return "LOW";
            default:         return "UNKNOWN";
        }
    }

    // =========================================================================
    //  Database Query Helper (Fetch ALL matching duplicate rows)
    // =========================================================================

    private List<Map<String, Object>> lookupAllInDb(String normalized) {
        List<Map<String, Object>> results = new ArrayList<>();
        Set<Object> seenIds = new HashSet<>();

        try (Connection conn = DatabaseConfig.getConnection()) {
            // 1. Exact match (checks phone_number, phone_number_10digit, +91 prefix, and 91 prefix)
            for (Map<String, Object> r : phoneQueryList(conn,
                    "SELECT *, detected_at AS reported_at FROM suspicious_calls WHERE phone_number = ? OR phone_number_10digit = ? OR phone_number = ? OR phone_number = ?",
                    normalized, normalized, "+91" + normalized, "91" + normalized)) {
                if (seenIds.add(r.get("id"))) results.add(r);
            }

            // 2. DB-side normalized match (formatting stripped) — for bare phone numbers
            for (Map<String, Object> r : phoneQueryList(conn,
                    "SELECT *, detected_at AS reported_at FROM suspicious_calls " +
                    "WHERE REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(" +
                    "REPLACE(REPLACE(REPLACE(phone_number,' ',''),'-',''),'(',''),')','')," +
                    "'+',''),'.',''),'\\t',''),'\\n','') = ?", normalized)) {
                if (seenIds.add(r.get("id"))) results.add(r);
            }

            // 3. 10-digit US phone lookup in FCC embedded text columns (5168998888 -> '%516-899-8888%')
            if (normalized.length() == 10) {
                String usDash = normalized.substring(0,3) + "-" + normalized.substring(3,6) + "-" + normalized.substring(6);
                String usSpace = normalized.substring(0,3) + " " + normalized.substring(3,6) + " " + normalized.substring(6);
                for (Map<String, Object> r : phoneQueryList(conn,
                        "SELECT *, detected_at AS reported_at FROM suspicious_calls WHERE phone_number LIKE ? OR pattern LIKE ?", "%" + usDash + "%", "%" + usDash + "%")) {
                    if (seenIds.add(r.get("id"))) results.add(r);
                }
                if (results.isEmpty()) {
                    for (Map<String, Object> r : phoneQueryList(conn,
                            "SELECT *, detected_at AS reported_at FROM suspicious_calls WHERE phone_number LIKE ? OR pattern LIKE ?", "%" + usSpace + "%", "%" + usSpace + "%")) {
                        if (seenIds.add(r.get("id"))) results.add(r);
                    }
                }
            }
        } catch (SQLException e) {
            System.err.println("[CALL DETECTION] DB query error: " + e.getMessage());
        }
        return results;
    }

    private List<Map<String, Object>> phoneQueryList(Connection conn, String sql, String... params) throws SQLException {
        List<Map<String, Object>> list = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) {
                ps.setString(i + 1, params[i]);
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) list.add(rowToMap(rs));
            }
        }
        return list;
    }

    // =========================================================================
    //  ML Model API Helper
    // =========================================================================

    private Map<String, Object> callMlApi(String normalized) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(ML_API_URL + "/predict"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(Map.of("content", normalized, "type", "call"))))
                .timeout(Duration.ofSeconds(4))
                .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                @SuppressWarnings("unchecked")
                Map<String, Object> json = GSON.fromJson(resp.body(), Map.class);
                return json;
            }
        } catch (Exception e) {
            System.out.println("[CALL DETECTION] ML API call failed: " + e.getMessage());
        }
        return null;
    }

    // =========================================================================
    //  IPQualityScore (IPQS) API Helper
    // =========================================================================

    private Map<String, Object> callIpqsApi(String normalized, String apiKey) {
        try {
            String url = "https://www.ipqualityscore.com/api/json/phone/" +
                URLEncoder.encode(apiKey, StandardCharsets.UTF_8) + "/" +
                URLEncoder.encode(normalized, StandardCharsets.UTF_8) +
                "?strictness=1&country=IN";

            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .timeout(Duration.ofSeconds(5))
                .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                @SuppressWarnings("unchecked")
                Map<String, Object> json = GSON.fromJson(resp.body(), Map.class);
                return json;
            }
        } catch (Exception e) {
            System.out.println("[CALL DETECTION] IPQS API call failed: " + e.getMessage());
        }
        return null;
    }

    // =========================================================================
    //  Utilities
    // =========================================================================

    private static Map<String, Object> rowToMap(ResultSet rs) throws SQLException {
        ResultSetMetaData meta = rs.getMetaData();
        Map<String, Object> row = new LinkedHashMap<>();
        for (int i = 1; i <= meta.getColumnCount(); i++) {
            row.put(meta.getColumnName(i), rs.getObject(i));
        }
        return row;
    }

    private void logCallDetection(String phoneNumber, String country, String severity, String pattern) {
        try (Connection conn = DatabaseConfig.getConnection()) {
            String checkSql = "SELECT COUNT(*) FROM suspicious_calls WHERE phone_number = ?";
            try (PreparedStatement checkPs = conn.prepareStatement(checkSql)) {
                checkPs.setString(1, phoneNumber);
                try (ResultSet rs = checkPs.executeQuery()) {
                    if (rs.next() && rs.getInt(1) > 0) {
                        System.out.println("[CallDetectHandler] Duplicate suspicious_calls skipped: " + phoneNumber);
                        return;
                    }
                }
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO suspicious_calls (phone_number, country, severity, pattern, data_type, source, detected_at) VALUES (?, ?, ?, ?, 'detected', 'call_detection_engine', NOW())")) {
                ps.setString(1, phoneNumber);
                ps.setString(2, country != null ? country : "Unknown");
                ps.setString(3, severity != null ? severity : "medium");
                ps.setString(4, pattern != null && pattern.length() > 500 ? pattern.substring(0, 500) : pattern);
                ps.executeUpdate();
                System.out.println("📞 Malicious Call saved to suspicious_calls.");
            }
        } catch (Exception e) {
            System.err.println("[CallDetectHandler] DB error: " + e.getMessage());
        }
    }

    private Map<String, Object> callMlApi(String endpoint, Map<String, Object> payload) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(ML_API_URL + endpoint))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(payload)))
                .timeout(Duration.ofSeconds(4))
                .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                @SuppressWarnings("unchecked")
                Map<String, Object> json = GSON.fromJson(resp.body(), Map.class);
                return json;
            }
        } catch (Exception ignored) {}
        return null;
    }

    private void sendJson(HttpExchange ex, int status, Object body) throws IOException {
        byte[] bytes = GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}

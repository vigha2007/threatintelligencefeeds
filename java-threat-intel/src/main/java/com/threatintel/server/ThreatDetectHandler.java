package com.threatintel.server;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.threatintel.db.DatabaseConfig;

import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * ThreatDetectHandler — Backend Threat Detection Engine for Email, URL, IP, and Message/SMS.
 *
 * Supported Endpoints (POST):
 *   /api/v1/detect/email   or  /api/detect/email
 *   /api/v1/detect/url     or  /api/detect/url
 *   /api/v1/detect/ip      or  /api/detect/ip
 *   /api/v1/detect/sms     or  /api/detect/sms
 *   /api/v1/detect/message or  /api/detect/message
 */
public class ThreatDetectHandler implements HttpHandler {

    private static final Gson GSON = new Gson();
    private static final String ML_API_URL =
        System.getenv().getOrDefault("ML_API_URL", "http://localhost:8000");

    private final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(4))
        .build();

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
            sendJson(ex, 405, buildMap("success", false, "error", "Only POST is supported"));
            return;
        }

        String path = ex.getRequestURI().getPath().toLowerCase();
        String body;
        try (InputStream is = ex.getRequestBody()) {
            body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> req = GSON.fromJson(body, Map.class);
        if (req == null) req = Collections.emptyMap();

        if (path.contains("/email")) {
            handleEmail(ex, req);
        } else if (path.contains("/url")) {
            handleUrl(ex, req);
        } else if (path.contains("/ip")) {
            handleIp(ex, req);
        } else if (path.contains("/sms") || path.contains("/message")) {
            handleMessage(ex, req);
        } else {
            sendJson(ex, 404, buildMap("success", false, "error", "Unknown detection endpoint"));
        }
    }

    // =========================================================================
    //  1. EMAIL DETECTION
    // =========================================================================
    private void handleEmail(HttpExchange ex, Map<String, Object> req) throws IOException {
        String input = String.valueOf(req.getOrDefault("email", req.getOrDefault("content", ""))).trim();

        System.out.println("[EMAIL DETECTION] Input received (length=" + input.length() + ")");

        if (input.isEmpty()) {
            Map<String, Object> errResp = new LinkedHashMap<>();
            errResp.put("success", true);
            errResp.put("email", input);
            errResp.put("category", "INVALID_EMAIL");
            errResp.put("status", "INVALID");
            errResp.put("riskLevel", "NONE");
            errResp.put("confidence", null);
            errResp.put("attack_type", "None Detected");
            errResp.put("recommended_action", "Please provide a valid input.");
            errResp.put("evidence", List.of("Email input content cannot be empty."));
            sendJson(ex, 200, errResp);
            return;
        }

        // Extract sender domain if an email address exists in the text
        String domain = "Unknown";
        String fullSender = null;
        java.util.regex.Pattern emailPattern = java.util.regex.Pattern.compile("([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}))");
        java.util.regex.Matcher emailMatcher = emailPattern.matcher(input);
        if (emailMatcher.find()) {
            fullSender = emailMatcher.group(1).toLowerCase();
            domain = emailMatcher.group(2).toLowerCase();
        }
        System.out.println("[EMAIL DETECTION] Extracted sender: " + fullSender + " (domain=" + domain + ")");

        // DB Lookup
        boolean dbMatch = false;
        List<Map<String, Object>> dbRows = Collections.emptyList();
        if (fullSender != null) {
            System.out.println("[EMAIL DETECTION] Database: searching email_scams for sender=" + fullSender);
            dbRows = queryDb(
                "SELECT * FROM email_scams WHERE sender LIKE ? LIMIT 10",
                "%" + fullSender + "%");
            dbMatch = !dbRows.isEmpty();
            System.out.println("[EMAIL DETECTION] Database: " + (dbMatch ? dbRows.size() + " matches found" : "0 matches"));
        }

        // ML Lookup — send complete email content to FastAPI CatBoost model
        System.out.println("[EMAIL DETECTION] ML: querying " + ML_API_URL + "/predict for email_scams model");
        Map<String, Object> mlRes = callMlApi("/predict", buildMap("content", input, "type", "email"));
        boolean mlAvailable = (mlRes != null);
        String mlPred = mlAvailable ? String.valueOf(mlRes.getOrDefault("prediction", "")).toUpperCase() : "";

        double mlConfidenceVal = 0.0;
        if (mlAvailable && mlRes.containsKey("confidence") && mlRes.get("confidence") != null) {
            try {
                mlConfidenceVal = Double.parseDouble(String.valueOf(mlRes.get("confidence")));
            } catch (Exception e) {
                mlConfidenceVal = 0.0;
            }
        }
        System.out.println("[EMAIL DETECTION] ML: " + (mlAvailable ? mlPred + " (Confidence: " + mlConfidenceVal + ")" : "UNAVAILABLE"));

        // =====================================================================
        //  CONTEXT-AWARE, NEGATION-SAFE INDICATOR DETECTION
        //
        //  hasActiveIndicator(text, positives, negations) returns true ONLY when
        //  a positive phrase exists AND is NOT preceded/followed by a negation
        //  phrase within the same or adjacent sentence.
        // =====================================================================
        String lower = input.toLowerCase();

        // --- Domain / reputation checks (not negatable) ---
        List<String> evidence = new ArrayList<>();
        int riskScore = 0;
        boolean domainKnown = !domain.equals("Unknown");

        if (domainKnown) {
            evidence.add("Sender domain extracted: " + domain);
            String tld = domain.contains(".") ? domain.substring(domain.lastIndexOf(".") + 1) : "";
            List<String> highRiskTlds = List.of("tk", "ml", "cf", "gq", "xyz", "top", "click", "zip", "mov", "ru");
            if (highRiskTlds.contains(tld)) {
                riskScore += 35;
                evidence.add("Domain uses high-risk TLD (." + tld + ") frequently associated with phishing.");
            }
            List<String> spoofBrands = List.of("paypal", "netflix", "amazon", "apple", "microsoft", "google", "facebook");
            for (String b : spoofBrands) {
                if (domain.contains(b) && !domain.endsWith(b + ".com") && !domain.endsWith(b + ".co.in")) {
                    riskScore += 45;
                    evidence.add("Domain appears to spoof brand name: \"" + b + "\".");
                    break;
                }
            }
        } else {
            evidence.add("Sender identity could not be verified (no sender header/address found in input).");
        }

        // --- 1. PAYMENT / FINANCIAL indicator ---
        List<String> paymentPositives = List.of(
            "pay the fee", "make a payment", "send payment", "wire transfer", "send money",
            "pay now", "pay immediately", "pay online", "processing fee", "registration fee",
            "invoice due", "amount due", "pay via", "pay using", "pay through",
            "bitcoin", "crypto", "pay in", "transfer the amount", "remit payment",
            "pay us", "pay me", "pay them"
        );
        List<String> paymentNegations = List.of(
            "no payment", "no fee", "no charge", "not required", "not a payment",
            "free of charge", "free to attend", "no cost", "no registration fee",
            "you do not need to pay", "there is no fee", "you are not required to pay",
            "no financial", "does not require payment", "payment is not", "no payment required",
            "this is not a payment", "without any payment", "without payment", "no money"
        );
        boolean paymentThreat = hasActiveIndicator(lower, paymentPositives, paymentNegations);
        if (paymentThreat) {
            riskScore += 25;
            evidence.add("Active payment or fee demand detected in email content.");
        } else {
            evidence.add("No financial or payment request detected.");
        }

        // --- 2. CREDENTIAL / OTP indicator ---
        List<String> credPositives = List.of(
            "send your otp", "enter your otp", "provide your otp", "share your otp", "submit your otp",
            "enter your password", "provide your password", "share your password", "send your password",
            "enter your username", "enter your pin", "provide your credentials",
            "enter your bank", "provide your account number", "submit your details",
            "verify your password", "confirm your password", "reset your password by clicking"
        );
        List<String> credNegations = List.of(
            "do not share", "never share", "do not provide", "never provide",
            "we will never ask", "we never ask", "do not enter", "never enter",
            "we do not ask for your password", "we will not ask", "never ask for your otp",
            "not required to provide", "you are not required", "protect your otp",
            "keep your password", "never disclose", "do not disclose"
        );
        boolean credThreat = hasActiveIndicator(lower, credPositives, credNegations);
        if (credThreat) {
            riskScore += 40;
            evidence.add("Credential or OTP submission demand detected in email content.");
        } else {
            evidence.add("No credential or OTP request detected.");
        }

        // --- 3. SUSPICIOUS URL indicator ---
        boolean hasRealUrl = lower.contains("http://") || lower.contains("https://");
        List<String> urlPositives = List.of(
            "click here to claim", "click here to verify", "click here to reset",
            "click the link to", "click below to", "follow this link",
            "click this link", "click here to confirm", "click to redeem",
            "click here to update", "verify your account here", "log in here",
            "login here", "access here", "open the link"
        );
        List<String> urlNegations = List.of(
            "no suspicious link", "no link", "does not contain a link",
            "this email contains no link", "no malicious link", "no external link",
            "without any link"
        );
        boolean urlThreat = false;
        if (hasRealUrl) {
            boolean urlNegated = false;
            for (String neg : urlNegations) {
                if (lower.contains(neg)) { urlNegated = true; break; }
            }
            urlThreat = !urlNegated;
        } else {
            urlThreat = hasActiveIndicator(lower, urlPositives, urlNegations);
        }
        if (urlThreat) {
            riskScore += 15;
            evidence.add("External URL or suspicious link detected in email content.");
        } else {
            evidence.add("No suspicious URL or external link detected.");
        }

        // --- 4. URGENCY indicator ---
        List<String> urgencyPositives = List.of(
            "account will be suspended", "account suspended", "act within 24 hours",
            "respond immediately", "urgent action required", "your account has been locked",
            "immediate action", "action required within", "respond within"
        );
        List<String> urgencyNegations = List.of(
            "not urgent", "no action required", "this is not urgent",
            "no immediate action", "you do not need to act", "no urgency"
        );
        boolean urgencyThreat = hasActiveIndicator(lower, urgencyPositives, urgencyNegations);
        if (urgencyThreat) {
            riskScore += 20;
            evidence.add("Urgency or account-suspension threat language detected.");
        }

        // --- 5. KYC / ACCOUNT VERIFICATION lure ---
        List<String> kycPositives = List.of(
            "verify your account", "account verification required", "kyc update required",
            "complete your kyc", "submit your kyc", "kyc verification", "re-verify your account",
            "confirm your identity to", "identity verification required"
        );
        List<String> kycNegations = List.of(
            "no verification required", "you do not need to verify", "no kyc required",
            "verification is not required", "not required to verify"
        );
        boolean kycThreat = hasActiveIndicator(lower, kycPositives, kycNegations);
        if (kycThreat) {
            riskScore += 30;
            evidence.add("Account KYC/verification lure detected in email content.");
        }

        // --- 6. PRIZE / REWARD / LOTTERY lure ---
        List<String> rewardPositives = List.of(
            "reward", "special reward", "received a reward", "claim your reward",
            "selected for a special", "selected for a special reward", "prize",
            "won a prize", "lottery winner", "gift card", "congratulations you won"
        );
        List<String> rewardNegations = List.of(
            "no reward", "not a reward", "no prize", "not won"
        );
        boolean rewardThreat = hasActiveIndicator(lower, rewardPositives, rewardNegations);
        if (rewardThreat) {
            riskScore += 25;
            evidence.add("Prize, reward, or lottery lure language detected in email content.");
        }

        // --- Legitimate transactional email detection ---
        // Recognized as LEGITIMATE when: no threats, no URLs, no urgency, no credentials,
        // no rewards, sender from a known-safe domain OR email contains "no action required".
        List<String> trustedSenderDomains = List.of(
            "github.com", "gitlab.com", "bitbucket.org",
            "google.com", "gmail.com", "googlemail.com",
            "microsoft.com", "outlook.com", "hotmail.com", "live.com",
            "amazon.com", "amazon.in", "amazonaws.com",
            "apple.com", "icloud.com",
            "linkedin.com", "twitter.com", "x.com",
            "stackoverflow.com", "stackexchange.com",
            "paypal.com", "stripe.com",
            "slack.com", "notion.so", "atlassian.com", "jira.com",
            "zoom.us", "teams.microsoft.com"
        );
        final String domainFinal = domain;
        boolean isTrustedSender = domainKnown && trustedSenderDomains.stream().anyMatch(d -> domainFinal.equalsIgnoreCase(d));
        boolean hasNoActionRequired = lower.contains("no action required") || lower.contains("no further action") || lower.contains("no action is needed");
        boolean hasNoThreats = !paymentThreat && !credThreat && !urlThreat && !urgencyThreat && !kycThreat && !rewardThreat && !dbMatch;

        List<String> transactionalPhrases = List.of(
            "has been shipped", "order has been", "order status", "expected delivery",
            "delivered to", "tracking number", "track your order", "track your package",
            "thank you for shopping", "thank you for your order", "purchase confirmation",
            "order confirmation", "order #", "order number", "shipping confirmation"
        );
        boolean hasTransactionalMarker = transactionalPhrases.stream().anyMatch(p -> lower.contains(p));
        boolean isLegitimateTransactional = hasNoThreats && riskScore == 0 && (isTrustedSender || hasNoActionRequired || hasTransactionalMarker);

        if (isLegitimateTransactional) {
            evidence.add("Legitimate transactional email: zero threat indicators detected" +
                (isTrustedSender ? " and sender domain is a verified trusted service (" + domain + ")." :
                 hasNoActionRequired ? " and message explicitly states no action is required." :
                 " and content matches verified transactional shipping/order notification."));
        }

        // --- DB / ML evidence lines ---
        if (dbMatch) {
            riskScore += 50;
            evidence.add("Matched " + dbRows.size() + " historical phishing record(s) in email_scams threat database.");
        } else {
            evidence.add("No known malicious indicator found in threat database.");
        }

        if (mlAvailable) {
            double confPct = mlConfidenceVal <= 1.0 ? mlConfidenceVal * 100 : mlConfidenceVal;
            evidence.add("ML Model (CatBoostClassifier) prediction: " + mlPred + " (" + String.format("%.2f", confPct) + "% confidence).");
        } else {
            evidence.add("ML inference model currently unavailable for automated classification.");
        }

        // =====================================================================
        //  5-STATE STANDARDIZED VERDICT
        //
        //  LOW risk    -> LEGITIMATE (Severity: LOW or NONE)
        //  MEDIUM risk -> SUSPICIOUS (Severity: MEDIUM)
        //  HIGH risk   -> MALICIOUS  (Severity: HIGH or CRITICAL)
        //  UNKNOWN risk-> UNVERIFIED (Severity: UNKNOWN)
        //  INVALID     -> INVALID    (Severity: NONE)
        // =====================================================================
        boolean mlSaysScam = mlAvailable && (mlPred.equals("MALICIOUS") || mlPred.equals("SCAM") || mlPred.equals("PHISHING"));
        boolean mlSaysSafe = mlAvailable && (mlPred.equals("SAFE") || mlPred.equals("BENIGN") || mlPred.equals("LEGITIMATE"));
        boolean mlSaysSuspicious = mlAvailable && (mlPred.equals("SUSPICIOUS") || "SUSPICIOUS".equalsIgnoreCase(String.valueOf(mlRes.getOrDefault("classification", ""))));
        boolean heuristicHigh = riskScore >= 45;
        boolean heuristicMed  = riskScore >= 15 && riskScore < 45;

        String category;
        String status;
        String riskLevel;
        String attackType;
        String recommendedAction;
        String source;
        Object confidence;

        if (isLegitimateTransactional) {
            // Highest-priority safe rule: no threats detected + trusted sender, explicit "no action required", or verified transactional format.
            // This prevents false-positive alerts on clean transactional emails.
            status = "LEGITIMATE";
            category = "LEGITIMATE_TRANSACTIONAL_EMAIL";
            riskLevel = "LOW";
            source = mlAvailable ? "ML" : "RULE";
            attackType = "None Detected";
            recommendedAction = "Low-risk content detected. Continue with normal security awareness.";
            confidence = mlAvailable ? mlRes.get("confidence") : null;

        } else if (dbMatch) {
            status = "MALICIOUS";
            category = "PHISHING_EMAIL";
            riskLevel = "HIGH";
            source = "DB_MATCH";
            attackType = "Phishing Email";
            recommendedAction = "Do not interact with this content. Block/report it and follow the recommended incident-response steps.";
            confidence = null; // No fake ML confidence for DB matches

        } else if ((mlSaysScam && mlConfidenceVal >= 0.65) || (mlSaysScam && riskScore >= 15) || heuristicHigh) {
            status = "MALICIOUS";
            category = "PHISHING_EMAIL";
            riskLevel = "HIGH";
            source = (mlSaysScam && mlConfidenceVal >= 0.65) ? "ML" : "RULE";
            attackType = mlAvailable ? String.valueOf(mlRes.getOrDefault("attack_type", "Phishing Email")) : "Phishing Email";
            recommendedAction = "Do not interact with this content. Block/report it and follow the recommended incident-response steps.";
            confidence = mlAvailable ? mlRes.get("confidence") : null;

        } else if (heuristicMed || mlSaysSuspicious || (mlSaysScam && mlConfidenceVal < 0.65)) {
            status = "SUSPICIOUS";
            category = "SUSPICIOUS_EMAIL";
            riskLevel = "MEDIUM";
            source = (mlSaysSuspicious || mlSaysScam) ? "ML" : "RULE";
            attackType = "Suspicious Email";
            recommendedAction = "Exercise caution. Do not click links, provide credentials, send money, or share OTPs until the source is verified.";
            confidence = mlAvailable ? mlRes.get("confidence") : null;

        } else if (mlAvailable && mlSaysSafe && riskScore < 15) {
            status = "LEGITIMATE";
            category = "LEGITIMATE_EMAIL";
            riskLevel = "LOW";
            source = "ML";
            attackType = "None Detected";
            recommendedAction = "Low-risk content detected. Continue with normal security awareness.";
            confidence = mlRes.get("confidence");

        } else if (!mlAvailable) {
            status = "UNVERIFIED";
            category = "UNVERIFIED_EMAIL";
            riskLevel = "UNKNOWN";
            source = "UNVERIFIED";
            attackType = "None Detected";
            recommendedAction = "Unable to reliably determine the threat status. Verify the source through an independent trusted channel.";
            confidence = null;

        } else {
            status = mlSaysSafe ? "LEGITIMATE" : "UNVERIFIED";
            category = mlSaysSafe ? "LEGITIMATE_EMAIL" : "UNVERIFIED_EMAIL";
            riskLevel = mlSaysSafe ? "LOW" : "UNKNOWN";
            source = "ML";
            attackType = "None Detected";
            recommendedAction = mlSaysSafe
                ? "Low-risk content detected. Continue with normal security awareness."
                : "Unable to reliably determine the threat status. Verify the source through an independent trusted channel.";
            confidence = mlRes.get("confidence");
        }

        System.out.println("[EMAIL DETECTION] Final result: " + status + " (" + category + ") riskScore=" + riskScore);

        if (status.equals("MALICIOUS")) {
            logDetection("email_scams", input.substring(0, Math.min(input.length(), 200)), domain,
                riskLevel.toLowerCase(), "Email detection: " + category);
        } else {
            System.out.println("[EMAIL DETECTION] Non-malicious verdict - skipping DB threat persistence.");
        }

        Map<String, Object> sourcesMap = new LinkedHashMap<>();
        Map<String, Object> dbSourceMap = new LinkedHashMap<>();
        dbSourceMap.put("queried", true);
        dbSourceMap.put("matched", dbMatch);
        dbSourceMap.put("matchedCount", dbRows.size());
        Map<String, Object> mlSourceMap = new LinkedHashMap<>();
        mlSourceMap.put("queried", true);
        mlSourceMap.put("available", mlAvailable);
        if (mlAvailable && mlRes != null) {
            mlSourceMap.putAll(mlRes);
        } else {
            mlSourceMap.put("prediction", mlPred);
        }
        sourcesMap.put("database", dbSourceMap);
        sourcesMap.put("ml", mlSourceMap);

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("success", true);
        resp.put("email", input);
        resp.put("domain", domain);
        resp.put("source", source);
        resp.put("classification", status);
        resp.put("category", category);
        resp.put("prediction", mlAvailable && mlRes != null ? mlRes.getOrDefault("prediction", status) : status);
        resp.put("status", status);
        resp.put("riskLevel", riskLevel);
        resp.put("threatLevel", riskLevel);
        resp.put("confidence", confidence != null ? confidence : (mlAvailable && mlRes != null ? mlRes.get("confidence") : null));
        String resolvedAttackType = attackType;
        if (mlAvailable && mlRes != null) {
            String mlAtk = String.valueOf(mlRes.getOrDefault("attack_type", ""));
            if (!mlAtk.isEmpty() && !"None Detected".equalsIgnoreCase(mlAtk)) {
                resolvedAttackType = mlAtk;
            }
        }
        if (resolvedAttackType.isEmpty() || "None Detected".equalsIgnoreCase(resolvedAttackType)) {
            resolvedAttackType = "Phishing Email";
        }
        resp.put("attack_type", status.equals("LEGITIMATE") || status.equals("UNVERIFIED") || status.equals("INVALID") ? "None Detected" : resolvedAttackType);
        resp.put("recommended_action", recommendedAction);
        resp.put("dataset", mlAvailable && mlRes != null ? mlRes.getOrDefault("dataset", "email_scams") : "email_scams");
        resp.put("model_class", mlAvailable && mlRes != null ? mlRes.getOrDefault("model_class", "CatBoostClassifier") : "CatBoostClassifier");
        if (mlAvailable && mlRes != null) {
            resp.put("ml_confidence", mlRes.get("confidence"));
        }
        resp.put("databaseMatch", dbMatch);
        resp.put("sources", sourcesMap);
        resp.put("evidence", evidence);
        resp.put("timestamp", Instant.now().toString());
        sendJson(ex, 200, resp);
    }

    /**
     * Context-aware, negation-safe indicator detection.
     *
     * Returns true ONLY when at least one positivePhrase is present in the text
     * AND no negationPhrase appears within the same sentence or the full text.
     *
     * Strategy: we check each sentence independently. If a sentence contains
     * a negation phrase AND a positive phrase, the indicator is suppressed for
     * that sentence. An indicator is only raised when a positive phrase exists
     * in a sentence that has NO negation phrase.
     */
    private boolean hasActiveIndicator(String lower,
                                       List<String> positivePhrases,
                                       List<String> negationPhrases) {
        // Split on sentence boundaries
        String[] sentences = lower.split("[.!?\\n]");
        for (String sentence : sentences) {
            String s = sentence.trim();
            boolean hasPositive = false;
            for (String pos : positivePhrases) {
                if (s.contains(pos)) { hasPositive = true; break; }
            }
            if (!hasPositive) continue;

            // Positive phrase found in this sentence — check if negated within same sentence
            boolean negated = false;
            for (String neg : negationPhrases) {
                if (s.contains(neg)) { negated = true; break; }
            }
            if (!negated) return true;  // un-negated positive → real threat indicator
        }

        // Full-text fallback: if positive phrase exists but ALL occurrences are
        // covered by a global negation in the full text, suppress it.
        boolean anyPositiveInFullText = false;
        for (String pos : positivePhrases) {
            if (lower.contains(pos)) { anyPositiveInFullText = true; break; }
        }
        if (!anyPositiveInFullText) return false;

        for (String neg : negationPhrases) {
            if (lower.contains(neg)) return false;  // global negation wins
        }
        return true;
    }

    // =========================================================================
    //  2. URL DETECTION
    // =========================================================================

    private void handleUrl(HttpExchange ex, Map<String, Object> req) throws IOException {
        String input = String.valueOf(req.getOrDefault("url", req.getOrDefault("content", ""))).trim();

        System.out.println("[URL DETECTION] Input: " + input);

        if (input.isEmpty()) {
            Map<String, Object> errResp = new LinkedHashMap<>();
            errResp.put("success", true);
            errResp.put("url", input);
            errResp.put("category", "INVALID_URL");
            errResp.put("classification", "INVALID");
            errResp.put("status", "INVALID");
            errResp.put("source", "RULE");
            errResp.put("riskLevel", "NONE");
            errResp.put("threatLevel", "NONE");
            errResp.put("severity", "NONE");
            errResp.put("confidence", null);
            errResp.put("attack_type", "None Detected");
            errResp.put("recommended_action", "Please provide a valid input format.");
            errResp.put("evidence", List.of("URL input content cannot be empty."));
            sendJson(ex, 200, errResp);
            return;
        }

        String lower = input.toLowerCase();

        // ── Localhost Check ─────────────────────────────────────────────────
        if (lower.contains("localhost") || lower.contains("127.0.0.1") || lower.contains("0.0.0.0") || lower.contains("[::1]")) {
            System.out.println("[URL DETECTION] Host: localhost (LOCAL DEV)");

            Map<String, Object> localResp = new LinkedHashMap<>();
            localResp.put("success", true);
            localResp.put("url", input);
            localResp.put("hostname", "localhost");
            localResp.put("category", "LOCAL_DEVELOPMENT_URL");
            localResp.put("classification", "LEGITIMATE");
            localResp.put("status", "LEGITIMATE");
            localResp.put("source", "RULE");
            localResp.put("riskLevel", "LOW");
            localResp.put("threatLevel", "LOW");
            localResp.put("severity", "LOW");
            localResp.put("confidence", null);
            localResp.put("attack_type", "None Detected");
            Map<String, Object> localSources = new LinkedHashMap<>();
            localSources.put("database", buildMap("matched", false));
            localSources.put("ml", buildMap("available", false));
            localResp.put("sources", localSources);
            localResp.put("evidence", List.of(
                "Local development URL detected (localhost / 127.0.0.1).",
                "Private local development addresses are not malicious threat targets."
            ));
            localResp.put("recommended_action", "Low-risk content detected. Continue with normal security awareness.");
            localResp.put("timestamp", Instant.now().toString());
            sendJson(ex, 200, localResp);
            return;
        }

        String hostname = input;
        try {
            URI uri = URI.create(input.contains("://") ? input : "https://" + input);
            if (uri.getHost() != null) hostname = uri.getHost();
        } catch (Exception ignored) {}

        System.out.println("[URL DETECTION] Host: " + hostname);

        // DB Lookup — exact hostname match
        System.out.println("[URL DETECTION] Database: searching phishing_urls for " + hostname);
        List<Map<String, Object>> dbRows = queryDb(
            "SELECT * FROM phishing_urls WHERE url LIKE ? OR domain = ? OR domain LIKE ? LIMIT 10",
            "%" + hostname + "%", hostname, hostname + ".%");
        boolean dbMatch = false;
        if (!dbRows.isEmpty()) {
            for (Map<String, Object> row : dbRows) {
                String storedUrl = String.valueOf(row.getOrDefault("url", ""));
                String storedDomain = String.valueOf(row.getOrDefault("domain", ""));
                if (storedDomain.equalsIgnoreCase(hostname) ||
                    storedDomain.toLowerCase().endsWith("." + hostname.toLowerCase()) ||
                    storedUrl.toLowerCase().contains("://" + hostname.toLowerCase() + "/") ||
                    storedUrl.toLowerCase().contains("://" + hostname.toLowerCase() + "?") ||
                    storedUrl.toLowerCase().endsWith("://" + hostname.toLowerCase())) {
                    dbMatch = true;
                    break;
                }
            }
            if (!dbMatch) dbRows = Collections.emptyList();
        }
        System.out.println("[URL DETECTION] Database: " + (dbMatch ? "match found (hostname-verified)" : "0 exact matches"));

        // ML Lookup — always run for every URL
        System.out.println("[URL DETECTION] ML: querying " + ML_API_URL + "/predict");
        Map<String, Object> mlRes = callMlApi("/predict", buildMap("content", input, "type", "url"));
        boolean mlAvailable = (mlRes != null);
        String mlPred = mlAvailable ? String.valueOf(mlRes.getOrDefault("prediction", "")).toUpperCase() : "";
        System.out.println("[URL DETECTION] ML: " + (mlAvailable ? mlPred + " (conf=" + mlRes.get("confidence") + ")" : "UNAVAILABLE"));

        // Evidence + heuristic risk score
        List<String> evidence = new ArrayList<>();
        int riskScore = 0;

        String tld = hostname.contains(".") ? hostname.substring(hostname.lastIndexOf(".") + 1).toLowerCase() : "";
        List<String> highRiskTlds = List.of("tk", "ml", "cf", "gq", "xyz", "top", "click", "zip", "mov", "ru");
        if (highRiskTlds.contains(tld)) {
            riskScore += 35;
            evidence.add("High-risk TLD (." + tld + ") frequently used in phishing.");
        }

        if (hostname.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
            riskScore += 30;
            evidence.add("URL uses a raw IPv4 address instead of a domain name.");
        }

        List<String> shorteners = List.of("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "shorturl.at");
        for (String s : shorteners) {
            if (hostname.contains(s)) {
                riskScore += 25;
                evidence.add("URL shortener service detected — destination domain is hidden.");
                break;
            }
        }

        boolean hasPhishKw = lower.contains("login") || lower.contains("verify") || lower.contains("account")
                          || lower.contains("kyc") || lower.contains("secure") || lower.contains("banking") || lower.contains("update")
                          || lower.contains("free") || lower.contains("gift") || lower.contains("claim") || lower.contains("winner")
                          || lower.contains("prize") || lower.contains("reward");
        if (hasPhishKw && (highRiskTlds.contains(tld) || lower.contains("-") || lower.contains("claim") || lower.contains("winner") || lower.contains("gift") || lower.contains("free"))) {
            riskScore += 35;
            evidence.add("Contains sensitive account, prize, or lure keywords on a suspicious domain structure.");
        }

        boolean hasMalwareKw = lower.contains("malware") || lower.contains("payload") || lower.contains("exploit")
                            || lower.contains("trojan") || lower.contains("ransomware") || (lower.contains("download") && (lower.contains("virus") || lower.contains("malware") || lower.contains("site")));
        if (hasMalwareKw) {
            riskScore += 45;
            evidence.add("Contains malware / exploit / hostile download indicators in URL structure.");
        }

        if (input.startsWith("http://") && !input.startsWith("https://")) {
            riskScore += 10;
            evidence.add("Uses unencrypted HTTP protocol.");
        }

        if (dbMatch) {
            riskScore += 45;
            evidence.add("Matched " + dbRows.size() + " phishing URL record(s) in local threat database.");
        }

        if (evidence.isEmpty()) {
            evidence.add("Domain evaluated: " + hostname);
            evidence.add("No threat indicators matched.");
        }

        // Classification
        String category;
        String status;
        String riskLevel;
        String source;
        Object confidence;
        String attackType;
        String recommendedAction;

        boolean mlSaysScam = mlAvailable && (mlPred.equals("MALICIOUS") || mlPred.equals("PHISHING") || mlPred.equals("SCAM"));
        boolean heuristicScam = riskScore >= 45;

        if (dbMatch) {
            category = hasMalwareKw ? "MALICIOUS_URL" : "PHISHING_URL";
            status = "MALICIOUS";
            riskLevel = "HIGH";
            source = "DB_MATCH";
            confidence = null;
            attackType = hasMalwareKw ? "Malicious URL" : "Phishing URL";
            recommendedAction = "Do not interact with this content. Block/report it and follow the recommended incident-response steps.";
        } else if (mlSaysScam || heuristicScam) {
            category = hasMalwareKw ? "MALICIOUS_URL" : "PHISHING_URL";
            status = "MALICIOUS";
            riskLevel = "HIGH";
            source = mlSaysScam ? "ML" : "RULE";
            confidence = mlAvailable ? mlRes.get("confidence") : null;
            attackType = hasMalwareKw ? "Malicious URL" : "Phishing URL";
            recommendedAction = "Do not interact with this content. Block/report it and follow the recommended incident-response steps.";
        } else if (riskScore >= 15 || (mlAvailable && "SUSPICIOUS".equalsIgnoreCase(String.valueOf(mlRes.getOrDefault("classification", "")))) || (mlAvailable && "MEDIUM".equalsIgnoreCase(String.valueOf(mlRes.getOrDefault("severity", ""))))) {
            category = "SUSPICIOUS_URL";
            status = "SUSPICIOUS";
            riskLevel = "MEDIUM";
            source = (riskScore >= 15) ? "RULE" : "ML";
            confidence = mlAvailable ? mlRes.get("confidence") : null;
            attackType = "Suspicious URL";
            recommendedAction = "Exercise caution. Do not click links, provide credentials, send money, or share OTPs until the source is verified.";
        } else if (mlAvailable && (mlPred.equals("SAFE") || mlPred.equals("BENIGN") || mlPred.equals("LEGITIMATE")) && riskScore < 15) {
            category = "LEGITIMATE_URL";
            status = "LEGITIMATE";
            riskLevel = "LOW";
            source = "ML";
            confidence = mlRes.get("confidence");
            attackType = "None Detected";
            recommendedAction = "Low-risk content detected. Continue with normal security awareness.";
        } else {
            category = "UNVERIFIED_URL";
            status = "UNVERIFIED";
            riskLevel = "UNKNOWN";
            source = "UNVERIFIED";
            confidence = null;
            attackType = "None Detected";
            recommendedAction = "Unable to reliably determine the threat status. Verify the source through an independent trusted channel.";
        }

        System.out.println("[URL DETECTION] Final result: " + status + " (" + category + ")");

        if (status.equals("MALICIOUS") || status.equals("PHISHING") || status.equals("SCAM")) {
            logDetection("phishing_urls", input, hostname,
                riskLevel.toLowerCase(), "URL detection: " + category);
        } else {
            System.out.println("[URL DETECTION] Safe/unverified URL - skipping DB threat persistence.");
        }

        Map<String, Object> sourcesMap = new LinkedHashMap<>();
        Map<String, Object> dbSourceMap = new LinkedHashMap<>();
        dbSourceMap.put("queried", true);
        dbSourceMap.put("matched", dbMatch);
        dbSourceMap.put("matchedCount", dbRows.size());
        Map<String, Object> mlSourceMap = new LinkedHashMap<>();
        mlSourceMap.put("queried", true);
        mlSourceMap.put("available", mlAvailable);
        if (mlAvailable && mlRes != null) {
            mlSourceMap.putAll(mlRes);
        } else {
            mlSourceMap.put("prediction", mlPred);
        }
        sourcesMap.put("database", dbSourceMap);
        sourcesMap.put("ml", mlSourceMap);

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("success", true);
        resp.put("url", input);
        resp.put("hostname", hostname);
        resp.put("source", source);
        resp.put("classification", status);
        resp.put("category", category);
        resp.put("prediction", mlAvailable && mlRes != null ? mlRes.getOrDefault("prediction", status) : status);
        resp.put("status", status);
        resp.put("riskLevel", riskLevel);
        resp.put("threatLevel", riskLevel);
        resp.put("severity", riskLevel);
        resp.put("confidence", confidence != null ? confidence : (mlAvailable && mlRes != null ? mlRes.get("confidence") : null));
        resp.put("attack_type", status.equals("LEGITIMATE") || status.equals("UNVERIFIED") || status.equals("INVALID") ? "None Detected" : (attackType != null ? attackType : "Phishing URL"));
        resp.put("recommended_action", recommendedAction);
        resp.put("dataset", mlAvailable && mlRes != null ? mlRes.getOrDefault("dataset", "phishing_urls") : "phishing_urls");
        resp.put("model_class", mlAvailable && mlRes != null ? mlRes.getOrDefault("model_class", "XGBClassifier") : "XGBClassifier");
        if (mlAvailable && mlRes != null) {
            resp.put("ml_confidence", mlRes.get("confidence"));
        }
        resp.put("databaseMatch", dbMatch);
        resp.put("sources", sourcesMap);
        resp.put("evidence", evidence);
        resp.put("timestamp", Instant.now().toString());
        sendJson(ex, 200, resp);
    }

    // =========================================================================
    //  3. IP DETECTION
    // =========================================================================

    private void handleIp(HttpExchange ex, Map<String, Object> req) throws IOException {
        String input = String.valueOf(req.getOrDefault("ip", req.getOrDefault("content", ""))).trim();

        System.out.println("[IP DETECTION] Input: " + input);

        // Validation check (must be 4 numeric octets 0-255)
        String[] octets = input.split("\\.");
        boolean validFormat = (octets.length == 4);
        if (validFormat) {
            for (String o : octets) {
                try {
                    int val = Integer.parseInt(o);
                    if (val < 0 || val > 255) { validFormat = false; break; }
                } catch (NumberFormatException e) {
                    validFormat = false; break;
                }
            }
        }

        System.out.println("[IP DETECTION] Validation: " + (validFormat ? "VALID IPv4" : "INVALID IPv4 FORMAT"));

        if (!validFormat) {
            System.out.println("[IP DETECTION] Final result: INVALID IP ADDRESS");
            Map<String, Object> errResp = new LinkedHashMap<>();
            errResp.put("success", true);
            errResp.put("ip", input);
            errResp.put("category", "INVALID_IP_ADDRESS");
            errResp.put("classification", "INVALID");
            errResp.put("prediction", "INVALID");
            errResp.put("status", "INVALID");
            errResp.put("source", "RULE");
            errResp.put("riskLevel", "NONE");
            errResp.put("threatLevel", "NONE");
            errResp.put("severity", "NONE");
            errResp.put("confidence", null);
            errResp.put("attack_type", "None Detected");
            errResp.put("evidence", List.of(
                "Invalid IPv4 address format (\"" + input + "\").",
                "IPv4 scanning requires 4 numeric octets between 0 and 255."
            ));
            errResp.put("recommended_action", "Please provide a valid input format.");
            errResp.put("timestamp", Instant.now().toString());
            sendJson(ex, 200, errResp);
            return;
        }

        int a = Integer.parseInt(octets[0]);
        int b = Integer.parseInt(octets[1]);

        boolean isPrivate = (a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || a == 127);
        String privateCategory = isPrivate ? ((a == 127) ? "LOOPBACK_IP" : "PRIVATE_NETWORK_IP") : null;
        String privateAttackType = isPrivate ? ((a == 127) ? "Loopback IP" : "Private Network IP") : null;

        // DB Lookup — exact IP address match
        System.out.println("[IP DETECTION] Database: searching malicious_ips for " + input);
        List<Map<String, Object>> dbRows = queryDb(
            "SELECT * FROM malicious_ips WHERE ip_address = ? LIMIT 5", input);
        boolean dbMatch = !dbRows.isEmpty();
        System.out.println("[IP DETECTION] Database: " + (dbMatch ? dbRows.size() + " matches found" : "0 matches"));

        // ML Lookup — query FastAPI ML model (preserve real ML prediction in sources.ml)
        System.out.println("[IP DETECTION] ML: querying " + ML_API_URL + "/predict for malicious_ips model");
        Map<String, Object> mlRes = callMlApi("/predict", buildMap("content", input, "type", "ip"));
        boolean mlAvailable = (mlRes != null);
        String mlPred = mlAvailable ? String.valueOf(mlRes.getOrDefault("prediction", "")).toUpperCase() : "";
        double mlConf = 0.0;
        if (mlAvailable && mlRes.get("confidence") instanceof Number) {
            mlConf = ((Number) mlRes.get("confidence")).doubleValue();
        }
        System.out.println("[IP DETECTION] ML: " + (mlAvailable ? mlPred + " (conf=" + mlConf + ")" : "UNAVAILABLE"));

        // Evidence gathering
        List<String> evidence = new ArrayList<>();

        if (isPrivate) {
            evidence.add("Private IPv4 address in RFC1918 range (" + (a == 127 ? "Loopback Address" : "Local Network") + ").");
            if (dbMatch) {
                String dbSeverity = dbRows.isEmpty() ? "" : String.valueOf(dbRows.get(0).getOrDefault("severity", ""));
                evidence.add("Matched historical record in malicious_ips database" + (dbSeverity.isEmpty() ? "." : " (severity: " + dbSeverity + ")."));
            } else {
                evidence.add("No malicious threat record found in local database.");
                evidence.add("Private network addresses are not inherently malicious.");
            }

            if (mlAvailable) {
                String mlModelClass = String.valueOf(mlRes.getOrDefault("model_class", "XGBClassifier"));
                int confPct = mlConf <= 1.0 ? (int) Math.round(mlConf * 100) : (int) Math.round(mlConf);
                evidence.add(mlModelClass + " prediction: " + mlPred + " (" + confPct + "% confidence).");
                if (mlPred.equals("MALICIOUS")) {
                    evidence.add("Final security classification is LEGITIMATE / PRIVATE NETWORK because the input is a non-public address.");
                }
            }
        } else {
            List<String> highRiskSubnets = List.of("185.220.", "45.142.", "89.234.", "171.25.", "198.96.");
            for (String sub : highRiskSubnets) {
                if (input.startsWith(sub)) {
                    evidence.add("Subnet " + sub + "x is associated with known Tor exit nodes or proxy services.");
                    break;
                }
            }

            if (dbMatch) {
                String dbSeverity = dbRows.isEmpty() ? "" : String.valueOf(dbRows.get(0).getOrDefault("severity", ""));
                evidence.add("Matched historical threat record in malicious_ips database" + (dbSeverity.isEmpty() ? "." : " (severity: " + dbSeverity + ")."));
            }

            if (mlAvailable) {
                String mlModelClass = String.valueOf(mlRes.getOrDefault("model_class", "XGBClassifier"));
                int confPct = mlConf <= 1.0 ? (int) Math.round(mlConf * 100) : (int) Math.round(mlConf);
                evidence.add(mlModelClass + " prediction: " + mlPred + " (" + confPct + "% confidence).");
            }
        }

        if (evidence.isEmpty()) {
            evidence.add("IPv4 evaluated: " + input);
            evidence.add("No pattern-based threat flags matched.");
        }

        // Final Security Verdict Logic
        String category;
        String status;
        String prediction;
        String riskLevel;
        String source;
        Object confidence;
        String attackType;
        String recommendedAction;

        if (isPrivate) {
            category   = privateCategory;
            status     = "LEGITIMATE";
            prediction = "LEGITIMATE";
            riskLevel  = "LOW";
            source     = "RULE";
            confidence = null; // Confidence N/A for Private IPs
            attackType = "None Detected";
            recommendedAction = "Low-risk content detected. Continue with normal security awareness.";
        } else if (dbMatch) {
            category   = "MALICIOUS_IP";
            prediction = "MALICIOUS";
            status     = "MALICIOUS";
            riskLevel  = "HIGH";
            source     = "DB_MATCH";
            confidence = null;
            attackType = "Malicious IP";
            recommendedAction = "Do not interact with this content. Block/report it and follow the recommended incident-response steps.";
        } else if (mlAvailable) {
            boolean mlSaysMalicious = mlPred.equals("MALICIOUS");
            boolean mlSaysSuspicious = "SUSPICIOUS".equalsIgnoreCase(String.valueOf(mlRes.getOrDefault("classification", "")))
                                    || "MEDIUM".equalsIgnoreCase(String.valueOf(mlRes.getOrDefault("severity", "")));
            if (mlSaysMalicious) {
                category   = "MALICIOUS_IP";
                prediction = "MALICIOUS";
                status     = "MALICIOUS";
                riskLevel  = "HIGH";
                source     = "ML";
                confidence = mlRes.get("confidence");
                attackType = "Malicious IP";
                recommendedAction = "Do not interact with this content. Block/report it and follow the recommended incident-response steps.";
            } else if (mlSaysSuspicious) {
                category   = "SUSPICIOUS_IP";
                prediction = "SUSPICIOUS";
                status     = "SUSPICIOUS";
                riskLevel  = "MEDIUM";
                source     = "ML";
                confidence = mlRes.get("confidence");
                attackType = "Suspicious IP";
                recommendedAction = "Exercise caution. Do not click links, provide credentials, send money, or share OTPs until the source is verified.";
            } else {
                category   = "LEGITIMATE_IP";
                prediction = "LEGITIMATE";
                status     = "LEGITIMATE";
                riskLevel  = "LOW";
                source     = "ML";
                confidence = mlRes.get("confidence");
                attackType = "None Detected";
                recommendedAction = "Low-risk content detected. Continue with normal security awareness.";
            }
        } else {
            category   = "UNVERIFIED_IP";
            prediction = "UNVERIFIED";
            status     = "UNVERIFIED";
            riskLevel  = "UNKNOWN";
            source     = "UNVERIFIED";
            confidence = null;
            attackType = "None Detected";
            recommendedAction = "Unable to reliably determine the threat status. Verify the source through an independent trusted channel.";
        }

        System.out.println("[IP DETECTION] Final result: " + status + " (" + category + ")");

        if (!isPrivate && (status.equals("MALICIOUS") || status.equals("SCAM") || status.equals("PHISHING"))) {
            logDetection("malicious_ips", input, "Public IP",
                riskLevel.toLowerCase(), "IP detection: " + category);
        } else {
            System.out.println("[IP DETECTION] Safe/private IP - skipping DB threat persistence.");
        }

        Map<String, Object> sourcesMap = new LinkedHashMap<>();
        Map<String, Object> dbSourceMap = new LinkedHashMap<>();
        dbSourceMap.put("queried", true);
        dbSourceMap.put("matched", dbMatch);
        dbSourceMap.put("matchedCount", dbRows.size());
        sourcesMap.put("database", dbSourceMap);
        Map<String, Object> mlSourceMap = new LinkedHashMap<>();
        mlSourceMap.put("queried", true);
        mlSourceMap.put("available", mlAvailable);
        if (mlAvailable && mlRes != null) {
            mlSourceMap.putAll(mlRes);
        } else {
            mlSourceMap.put("prediction", mlPred);
        }
        sourcesMap.put("ml", mlSourceMap);

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("success", true);
        resp.put("ip", input);
        resp.put("source", source);
        resp.put("classification", status);
        resp.put("category", category);
        resp.put("prediction", mlAvailable && mlRes != null ? mlRes.getOrDefault("prediction", prediction) : prediction);
        resp.put("status", status);
        resp.put("riskLevel", riskLevel);
        resp.put("threatLevel", riskLevel);
        resp.put("severity", riskLevel);
        resp.put("confidence", isPrivate ? null : (confidence != null ? confidence : (mlAvailable && mlRes != null ? mlRes.get("confidence") : null)));
        resp.put("attack_type", isPrivate ? "None Detected" : (status.equals("LEGITIMATE") || status.equals("UNVERIFIED") || status.equals("INVALID") ? "None Detected" : (attackType != null ? attackType : "Malicious IP")));
        resp.put("recommended_action", recommendedAction);
        resp.put("dataset", mlAvailable && mlRes != null ? mlRes.getOrDefault("dataset", "malicious_ips") : "malicious_ips");
        resp.put("model_class", mlAvailable && mlRes != null ? mlRes.getOrDefault("model_class", "XGBClassifier") : "XGBClassifier");
        if (mlAvailable && mlRes != null) {
            resp.put("ml_confidence", mlRes.get("confidence"));
        }
        resp.put("databaseMatch", dbMatch);
        resp.put("sources", sourcesMap);
        resp.put("evidence", evidence);
        resp.put("timestamp", Instant.now().toString());
        sendJson(ex, 200, resp);
    }

    // =========================================================================
    //  4. MESSAGE / SMS DETECTION
    // =========================================================================

    private void handleMessage(HttpExchange ex, Map<String, Object> req) throws IOException {
        String input = String.valueOf(req.getOrDefault("message", req.getOrDefault("content", req.getOrDefault("sms", req.getOrDefault("text", ""))))).trim();

        System.out.println("[MESSAGE DETECTION] Input (length=" + input.length() + ")");

        if (input.isEmpty()) {
            Map<String, Object> errResp = new LinkedHashMap<>();
            errResp.put("success", true);
            errResp.put("message", input);
            errResp.put("category", "INVALID_MESSAGE");
            errResp.put("classification", "INVALID");
            errResp.put("status", "INVALID");
            errResp.put("source", "RULE");
            errResp.put("riskLevel", "NONE");
            errResp.put("threatLevel", "NONE");
            errResp.put("severity", "NONE");
            errResp.put("confidence", null);
            errResp.put("attack_type", "None Detected");
            errResp.put("recommended_action", "Please provide a valid input format.");
            errResp.put("evidence", List.of("SMS content cannot be empty."));
            sendJson(ex, 200, errResp);
            return;
        }

        // 1. DB Lookup — first 200 chars to keep the LIKE query tight
        String searchTerm = input.length() > 200 ? input.substring(0, 200) : input;
        System.out.println("[MESSAGE DETECTION] Database: searching scam_messages");
        List<Map<String, Object>> dbRows = queryDb(
            "SELECT * FROM scam_messages WHERE content LIKE ? LIMIT 5", "%" + searchTerm + "%");
        boolean dbMatch = !dbRows.isEmpty();
        System.out.println("[MESSAGE DETECTION] Database: " + (dbMatch ? dbRows.size() + " match(es) found" : "0 matches"));

        // 2. ML Lookup
        System.out.println("[MESSAGE DETECTION] ML: querying " + ML_API_URL + "/predict (scam_messages model)");
        Map<String, Object> mlRes = callMlApi("/predict", buildMap("content", input, "type", "sms"));
        boolean mlAvailable = (mlRes != null);
        String mlPred = mlAvailable ? String.valueOf(mlRes.getOrDefault("prediction", "")).toUpperCase() : "";
        double mlConf = 0.0;
        if (mlAvailable && mlRes.get("confidence") instanceof Number) {
            mlConf = ((Number) mlRes.get("confidence")).doubleValue();
        }
        System.out.println("[MESSAGE DETECTION] ML: " + (mlAvailable ? mlPred + " (conf=" + mlConf + ")" : "UNAVAILABLE"));

        // 3. Evidence gathering & contextual indicators
        List<String> evidence = new ArrayList<>();
        String lower = input.toLowerCase();

        if (dbMatch) {
            String dbSev = dbRows.isEmpty() ? "" : String.valueOf(dbRows.get(0).getOrDefault("severity", ""));
            evidence.add("Matched " + dbRows.size() + " historical record(s) in scam_messages database"
                + (dbSev.isEmpty() ? "." : " (severity: " + dbSev + ")."));
        }

        boolean hasUrl        = lower.matches(".*https?://[^\\s]+.*") || lower.contains("bit.ly") || lower.contains("tinyurl.com") || lower.contains("click the link") || lower.contains("click here") || lower.contains("tap the link") || lower.contains("open link") || lower.contains("link below");
        boolean hasOtp        = lower.contains("otp") || lower.contains("verification code") || lower.contains("passcode") || lower.contains("security code") || lower.contains("one time password");
        boolean hasDoNotShare = lower.contains("do not share") || lower.contains("don't share") || lower.contains("dont share") || lower.contains("never share") || lower.contains("keep confidential") || lower.contains("never disclose") || lower.contains("do not disclose");
        boolean hasUrgency    = lower.contains("urgent") || lower.contains("suspended") || lower.contains("blocked") || lower.contains("expire") || lower.contains("immediately") || lower.contains("deactivated") || lower.contains("deactivate") || lower.contains("hours") || lower.contains("action required") || lower.contains("needs verification") || lower.contains("continue the service") || lower.contains("service suspended");
        
        String textWithoutNegation = lower.replace("do not share", "").replace("don't share", "").replace("dont share", "").replace("never share", "").replace("never disclose", "").replace("do not disclose", "");
        boolean hasAction     = textWithoutNegation.contains("share ") || textWithoutNegation.contains("send ") || textWithoutNegation.contains("enter ") || textWithoutNegation.contains("provide ") || textWithoutNegation.contains("click") || textWithoutNegation.contains("tap") || textWithoutNegation.contains("update") || textWithoutNegation.contains("verify") || textWithoutNegation.contains("complete") || textWithoutNegation.contains("confirm your") || textWithoutNegation.contains("forward");
        boolean hasCreds      = lower.contains("password") || lower.contains("account number") || lower.contains("pin") || lower.contains("bank details") || lower.contains("card details") || lower.contains("credentials") || lower.contains("cvv");
        boolean hasScam       = lower.contains("lottery") || lower.contains("prize") || lower.contains("winner")
                             || lower.contains("won") || lower.contains("jackpot") || lower.contains("claim your")
                             || lower.contains("congratulations") || lower.contains("reward");
        boolean hasKyc        = lower.contains("kyc") || (lower.contains("bank") && hasUrgency) || lower.contains("sim card") || lower.contains("pan card") || lower.contains("aadhaar");
        boolean hasUpiOrRefund = lower.contains("upi") || lower.contains("refund") || lower.contains("payment failed") || lower.contains("transaction failed") || lower.contains("cashback");
        boolean hasAmount     = lower.matches(".*\\b(rs\\.?|inr|usd|\\$|₹)\\s?\\d[\\d,]{2,}.*") || lower.contains("₹") || lower.contains("rs.") || lower.contains("inr");

        boolean isLegitimateOtp = hasOtp && hasDoNotShare && !hasUrl && !hasAction && !hasCreds && !hasScam && !hasUpiOrRefund;

        if (isLegitimateOtp) {
            evidence.add("Legitimate OTP notification. Contains confidentiality warning ('Do not share') with no links or credential requests.");
        } else {
            if (hasScam)             evidence.add("Contains lottery / prize / reward language commonly associated with financial scams.");
            if (hasKyc)              evidence.add("Contains urgent banking / KYC / account deactivation language — a common social-engineering pattern.");
            if (hasUpiOrRefund)      evidence.add("Mentions failed payment / refund lure commonly engineered to harvest bank credentials.");
            if (hasOtp && (hasAction || hasCreds)) evidence.add("Requests OTP / credential sharing — legitimate services never ask users to share OTP codes.");
            if (hasUrl)              evidence.add("Contains an embedded link or click-directive — verify the destination before tapping any link.");
            if (hasAmount)           evidence.add("Mentions a specific currency amount — a hallmark of lottery and advance-fee scams.");
        }

        if (mlAvailable) {
            String mlClass = String.valueOf(mlRes.getOrDefault("model_class", "XGBClassifier"));
            int confPct = mlConf <= 1.0 ? (int) Math.round(mlConf * 100) : (int) Math.round(mlConf);
            if (mlPred.equals("MALICIOUS") || mlPred.equals("SCAM")) {
                evidence.add(mlClass + " prediction: SCAM / MALICIOUS (" + confPct + "% confidence).");
            } else {
                evidence.add(mlClass + " prediction: SAFE (" + confPct + "% confidence).");
            }
        }

        if (evidence.isEmpty()) {
            evidence.add("No scam or phishing indicators matched.");
            evidence.add("Message content appears normal.");
        }

        // 4. Classification & Evidence Fusion
        String category;
        String status;
        String riskLevel;
        String source;
        Object confidence;
        String attackType;
        String recommendedAction;

        boolean mlSaysScam = mlAvailable && (mlPred.equals("MALICIOUS") || mlPred.equals("SCAM"));
        boolean strongMaliciousHeuristics = (hasKyc && (hasUrl || hasCreds || hasAction || hasUrgency))
                                         || (hasScam && (hasUrl || hasAmount || hasAction))
                                         || (hasOtp && hasAction && (hasUrl || hasCreds))
                                         || (hasUpiOrRefund && (hasUrl || hasCreds || hasAction));
        boolean moderateSuspicious = hasUrl || hasUrgency || hasKyc || hasUpiOrRefund || hasScam;

        if (isLegitimateOtp) {
            category   = "LEGITIMATE_OTP";
            status     = "LEGITIMATE";
            riskLevel  = "LOW";
            source     = "RULE";
            confidence = mlAvailable ? mlRes.get("confidence") : null;
            attackType = "None Detected";
            recommendedAction = "Low-risk content detected. Continue with normal security awareness.";
        } else if (dbMatch) {
            category   = "SCAM_MESSAGE";
            status     = "MALICIOUS";
            riskLevel  = "HIGH";
            source     = "DB_MATCH";
            confidence = null;
            attackType = "Scam Message";
            recommendedAction = "Do not interact with this content. Block/report it and follow the recommended incident-response steps.";
        } else if (strongMaliciousHeuristics || (mlSaysScam && mlConf >= 0.65)) {
            if (hasKyc)                    category = "KYC_SCAM";
            else if (hasScam)              category = "LOTTERY_SCAM";
            else if (hasOtp && hasAction)  category = "OTP_SCAM";
            else if (hasUpiOrRefund)       category = "PAYMENT_FRAUD";
            else                           category = "SCAM_MESSAGE";

            status     = "MALICIOUS";
            riskLevel  = "HIGH";
            source     = (mlSaysScam && mlConf >= 0.65) ? "ML" : "RULE";
            confidence = mlAvailable ? mlRes.get("confidence") : null;
            attackType = category.replace("_", " ");
            recommendedAction = "Do not interact with this content. Block/report it and follow the recommended incident-response steps.";
        } else if (moderateSuspicious || (mlAvailable && "SUSPICIOUS".equalsIgnoreCase(String.valueOf(mlRes.getOrDefault("classification", "")))) || (mlAvailable && "MEDIUM".equalsIgnoreCase(String.valueOf(mlRes.getOrDefault("severity", ""))))) {
            category   = "SUSPICIOUS_MESSAGE";
            status     = "SUSPICIOUS";
            riskLevel  = "MEDIUM";
            source     = moderateSuspicious ? "RULE" : "ML";
            confidence = mlAvailable ? mlRes.get("confidence") : null;
            attackType = "Suspicious Message";
            recommendedAction = "Exercise caution. Do not click links, provide credentials, send money, or share OTPs until the source is verified.";
        } else if (mlAvailable && (mlPred.equals("SAFE") || mlPred.equals("BENIGN") || mlPred.equals("LEGITIMATE"))) {
            category   = "LEGITIMATE_MESSAGE";
            status     = "LEGITIMATE";
            riskLevel  = "LOW";
            source     = "ML";
            confidence = mlRes.get("confidence");
            attackType = "None Detected";
            recommendedAction = "Low-risk content detected. Continue with normal security awareness.";
        } else {
            category   = "UNVERIFIED_MESSAGE";
            status     = "UNVERIFIED";
            riskLevel  = "UNKNOWN";
            source     = "UNVERIFIED";
            confidence = null;
            attackType = "None Detected";
            recommendedAction = "Unable to reliably determine the threat status. Verify the source through an independent trusted channel.";
        }

        System.out.println("[MESSAGE DETECTION] Final result: " + status + " (" + category + ")");

        if (status.equals("SCAM") || status.equals("MALICIOUS") || status.equals("PHISHING")) {
            logDetection("scam_messages", input.substring(0, Math.min(input.length(), 500)),
                "sms",
                riskLevel.toLowerCase(), "SMS detection: " + category);
        } else {
            System.out.println("[MESSAGE DETECTION] Non-malicious message - skipping DB threat persistence.");
        }

        Map<String, Object> sourcesMap = new LinkedHashMap<>();
        Map<String, Object> dbSourceMap = new LinkedHashMap<>();
        dbSourceMap.put("queried", true);
        dbSourceMap.put("matched", dbMatch);
        dbSourceMap.put("matchedCount", dbRows.size());
        Map<String, Object> mlSourceMap = new LinkedHashMap<>();
        mlSourceMap.put("queried", true);
        mlSourceMap.put("available", mlAvailable);
        if (mlAvailable && mlRes != null) {
            mlSourceMap.putAll(mlRes);
        } else {
            mlSourceMap.put("prediction", mlPred);
        }
        sourcesMap.put("database", dbSourceMap);
        sourcesMap.put("ml", mlSourceMap);

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("success", true);
        resp.put("message", input);
        resp.put("source", source);
        resp.put("classification", status);
        resp.put("category", category);
        resp.put("prediction", mlAvailable && mlRes != null ? mlRes.getOrDefault("prediction", status) : status);
        resp.put("status", status);
        resp.put("riskLevel", riskLevel);
        resp.put("threatLevel", riskLevel);
        resp.put("severity", riskLevel);
        resp.put("confidence", confidence != null ? confidence : (mlAvailable && mlRes != null ? mlRes.get("confidence") : null));
        resp.put("attack_type", status.equals("LEGITIMATE") || status.equals("UNVERIFIED") || status.equals("INVALID") ? "None Detected" : (attackType != null ? attackType : "Scam Message"));
        resp.put("recommended_action", recommendedAction);
        resp.put("dataset", mlAvailable && mlRes != null ? mlRes.getOrDefault("dataset", "scam_messages") : "scam_messages");
        resp.put("model_class", mlAvailable && mlRes != null ? mlRes.getOrDefault("model_class", "XGBClassifier") : "XGBClassifier");
        if (mlAvailable && mlRes != null) {
            resp.put("ml_confidence", mlRes.get("confidence"));
        }
        resp.put("databaseMatch", dbMatch);
        resp.put("sources", sourcesMap);
        resp.put("evidence", evidence);
        resp.put("timestamp", Instant.now().toString());
        sendJson(ex, 200, resp);
    }
    // =========================================================================
    //  Helpers
    // =========================================================================

    /** Build a map with up to 4 key-value pairs (avoids Map.of() 10-entry limit issues). */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> buildMap(Object... pairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            map.put(String.valueOf(pairs[i]), pairs[i + 1]);
        }
        return map;
    }

    private List<Map<String, Object>> queryDb(String sql, String... params) {
        List<Map<String, Object>> list = new ArrayList<>();
        try (Connection conn = DatabaseConfig.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) {
                ps.setString(i + 1, params[i]);
            }
            try (ResultSet rs = ps.executeQuery()) {
                ResultSetMetaData meta = rs.getMetaData();
                while (rs.next()) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    for (int i = 1; i <= meta.getColumnCount(); i++) {
                        row.put(meta.getColumnName(i), rs.getObject(i));
                    }
                    list.add(row);
                }
            }
        } catch (Exception e) {
            System.err.println("[ThreatDetectHandler] DB error: " + e.getMessage());
        }
        return list;
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

    private void logDetection(String table, String mainVal, String subVal, String severity, String pattern) {
        try (Connection conn = DatabaseConfig.getConnection()) {
            if (table.equals("email_scams")) {
                String checkSql = "SELECT COUNT(*) FROM email_scams WHERE sender = ?";
                try (PreparedStatement checkPs = conn.prepareStatement(checkSql)) {
                    checkPs.setString(1, mainVal.length() > 255 ? mainVal.substring(0, 255) : mainVal);
                    try (ResultSet rs = checkPs.executeQuery()) {
                        if (rs.next() && rs.getInt(1) > 0) {
                            System.out.println("[ThreatDetectHandler] Duplicate email_scams skipped: " + mainVal);
                            return;
                        }
                    }
                }
                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO email_scams (sender, subject, category, severity, recipients_count, detected_at) VALUES (?, ?, ?, ?, 1, NOW())")) {
                    ps.setString(1, mainVal.length() > 255 ? mainVal.substring(0, 255) : mainVal);
                    ps.setString(2, pattern.length() > 500 ? pattern.substring(0, 500) : pattern);
                    ps.setString(3, "EMAIL_DETECTION");
                    ps.setString(4, severity);
                    ps.executeUpdate();
                    System.out.println("📧 Malicious Email saved to email_scams.");
                }
            } else if (table.equals("phishing_urls")) {
                String checkSql = "SELECT COUNT(*) FROM phishing_urls WHERE url = ?";
                try (PreparedStatement checkPs = conn.prepareStatement(checkSql)) {
                    checkPs.setString(1, mainVal.length() > 2048 ? mainVal.substring(0, 2048) : mainVal);
                    try (ResultSet rs = checkPs.executeQuery()) {
                        if (rs.next() && rs.getInt(1) > 0) {
                            System.out.println("[ThreatDetectHandler] Duplicate phishing_urls skipped: " + mainVal);
                            return;
                        }
                    }
                }
                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO phishing_urls (url, domain, severity, detected_at) VALUES (?, ?, ?, NOW())")) {
                    ps.setString(1, mainVal.length() > 2048 ? mainVal.substring(0, 2048) : mainVal);
                    ps.setString(2, subVal.length() > 255 ? subVal.substring(0, 255) : subVal);
                    ps.setString(3, severity);
                    ps.executeUpdate();
                    System.out.println("🔗 Malicious URL saved to phishing_urls.");
                }
            } else if (table.equals("malicious_ips")) {
                String checkSql = "SELECT COUNT(*) FROM malicious_ips WHERE ip_address = ?";
                try (PreparedStatement checkPs = conn.prepareStatement(checkSql)) {
                    checkPs.setString(1, mainVal.length() > 64 ? mainVal.substring(0, 64) : mainVal);
                    try (ResultSet rs = checkPs.executeQuery()) {
                        if (rs.next() && rs.getInt(1) > 0) {
                            System.out.println("[ThreatDetectHandler] Duplicate malicious_ips skipped: " + mainVal);
                            return;
                        }
                    }
                }
                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO malicious_ips (ip_address, country, threat_type, severity, detected_at) VALUES (?, ?, 'MALICIOUS_IP', ?, NOW())")) {
                    ps.setString(1, mainVal.length() > 64 ? mainVal.substring(0, 64) : mainVal);
                    ps.setString(2, subVal);
                    ps.setString(3, severity);
                    ps.executeUpdate();
                    System.out.println("🌐 Malicious IP saved to malicious_ips.");
                }
            } else if (table.equals("scam_messages")) {
                String checkSql = "SELECT COUNT(*) FROM scam_messages WHERE content = ?";
                try (PreparedStatement checkPs = conn.prepareStatement(checkSql)) {
                    checkPs.setString(1, mainVal);
                    try (ResultSet rs = checkPs.executeQuery()) {
                        if (rs.next() && rs.getInt(1) > 0) {
                            System.out.println("[ThreatDetectHandler] Duplicate scam_messages skipped: " + mainVal);
                            return;
                        }
                    }
                }
                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO scam_messages (channel, content, severity, detected_at) VALUES ('sms', ?, ?, NOW())")) {
                    ps.setString(1, mainVal);
                    ps.setString(2, severity);
                    ps.executeUpdate();
                    System.out.println("💬 Malicious SMS saved to scam_messages.");
                }
            }
        } catch (Exception e) {
            System.err.println("[ThreatDetectHandler] DB error: " + e.getMessage());
        }
    }

    private void sendJson(HttpExchange ex, int status, Object body) throws IOException {
        byte[] bytes = GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}

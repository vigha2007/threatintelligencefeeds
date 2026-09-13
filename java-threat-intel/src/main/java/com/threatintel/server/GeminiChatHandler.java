package com.threatintel.server;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

/**
 * GeminiChatHandler — Secure Gemini AI proxy with intelligent multi-language support and local educational fallback.
 *
 * POST /api/chat
 *
 * Language routing:
 * - English input → English
 * - Tanglish input → TAMIL SCRIPT (தமிழ்), NOT Tanglish
 * - Tamil script input → TAMIL SCRIPT (தமிழ்)
 * - Explicit "Tanglish" request → Tanglish
 * - "Vanakkam" / "Vannakam" alone → English
 * - "Tamil la sollu" / "தமிழில் சொல்லுங்கள்" → Tamil script
 * - "Tanglish la sollu" → Tanglish
 * - "English la sollu" → English
 * - Maintain selected language for follow-ups
 */
public class GeminiChatHandler implements HttpHandler {

    private static final Gson GSON = new Gson();

    private static final String GEMINI_URL_TEMPLATE =
        "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s";

    public static record ApiKeyInfo(String key, String source) {}

    public static ApiKeyInfo resolveApiKey() {
        String[] varNames = { "GEMINI_API_KEY", "GOOGLE_API_KEY", "GEMINI_KEY", "VITE_GEMINI_API_KEY" };

        for (String var : varNames) {
            String val = System.getenv(var);
            if (val != null && !val.trim().isBlank()) {
                return new ApiKeyInfo(val.trim(), "ENV");
            }
        }

        for (String var : varNames) {
            String val = System.getProperty(var);
            if (val != null && !val.trim().isBlank()) {
                return new ApiKeyInfo(val.trim(), "JVM");
            }
        }

        String userDir = System.getProperty("user.dir", ".");
        String userHome = System.getProperty("user.home", ".");
        String[] possibleEnvFiles = {
            ".env",
            "../.env",
            "java-threat-intel/.env",
            userDir + "/.env",
            userDir + "/../.env",
            userDir + "/java-threat-intel/.env",
            userHome + "/.env"
        };

        for (String envPath : possibleEnvFiles) {
            File f = new File(envPath);
            if (f.exists() && f.isFile()) {
                try (BufferedReader br = new BufferedReader(new FileReader(f, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        line = line.trim();
                        if (line.startsWith("#") || line.isEmpty()) continue;
                        if (line.startsWith("export ")) {
                            line = line.substring("export ".length()).trim();
                        }
                        for (String var : varNames) {
                            String prefix = var + "=";
                            if (line.startsWith(prefix)) {
                                String val = line.substring(prefix.length()).trim();
                                if ((val.startsWith("\"") && val.endsWith("\"")) ||
                                    (val.startsWith("'") && val.endsWith("'"))) {
                                    val = val.substring(1, val.length() - 1).trim();
                                }
                                if (!val.isBlank()) {
                                    return new ApiKeyInfo(val, "ENV_FILE");
                                }
                            }
                        }
                    }
                } catch (Exception ignored) {}
            }
        }

        return new ApiKeyInfo("", "NONE");
    }

    private static String getModel() {
        String m = System.getenv("GEMINI_MODEL");
        if (m != null && !m.isBlank()) return m.trim();
        m = System.getProperty("GEMINI_MODEL");
        if (m != null && !m.isBlank()) return m.trim();
        return "gemini-3.6-flash";
    }

    // Comprehensive cybersecurity system instruction for Gemini with strict language rules
    private static final String SYSTEM_INSTRUCTION =
        "You are Cyber Sentinel AI, an expert cybersecurity conversational assistant built into VigiLock.\n\n" +
        "CORE CYBERSECURITY BEHAVIOR:\n" +
        "1. Answer cybersecurity and safety questions with expert knowledge, clear explanations, and defensive guidance.\n" +
        "2. Understand context across multi-turn conversations for follow-up questions ('it', 'this', 'that', 'the above').\n" +
        "3. For security incidents (clicked links, shared passwords/OTPs, hacked accounts), give prioritized emergency containment checklists.\n" +
        "4. For scanner context questions, explain the provided scan breakdown accurately without fabricating scores.\n" +
        "5. NEVER request or ask for passwords, OTPs, PINs, CVVs, or secret credentials.\n" +
        "6. Do NOT classify general educational questions as malicious attacks.\n\n" +
        "STRICT LANGUAGE AND SCRIPT RULES:\n" +
        "Rule 1 [ENGLISH]: When the user asks in English (e.g., 'wht is email scam', 'what is phishing?', 'vpn?', 'how does it protect me?'), respond in natural ENGLISH.\n" +
        "Rule 2 [TANGLISH INPUT -> TAMIL SCRIPT]: When the user asks in Tanglish (Tamil words written in English letters, e.g., 'email scam na enna?', 'phishing pathi sollu', 'epdi secure panrathu?', 'account hack aayiduchu enna panrathu?'), you MUST respond in pure TAMIL SCRIPT (தமிழ்), NOT in Tanglish.\n" +
        "Rule 3 [TAMIL SCRIPT INPUT -> TAMIL SCRIPT]: When the user asks in Tamil script (e.g., 'மின்னஞ்சல் மோசடி என்றால் என்ன?'), respond in pure TAMIL SCRIPT (தமிழ்).\n" +
        "Rule 4 [EXPLICIT TANGLISH REQUEST ONLY]: ONLY when the user explicitly requests Tanglish (e.g., 'Tanglish la explain pannu', 'Tanglish la sollu', 'reply in Tanglish', 'explain in Tanglish'), respond in conversational TANGLISH (Tamil words transliterated in English alphabet).\n" +
        "Rule 5 ['VANAKKAM' GREETING]: If the user says 'Vanakkam' or 'Vannakam' alone as a greeting, do NOT switch to Tamil or Tanglish; reply politely in ENGLISH (e.g., 'Hello! / Vanakkam! I am Cyber Sentinel AI...').\n" +
        "Rule 6 [EXPLICIT LANGUAGE SWITCH COMMANDS]:\n" +
        "  • 'Tamil la sollu' / 'தமிழில் சொல்லுங்கள்' / 'explain in Tamil' → Switch immediately to TAMIL SCRIPT (தமிழ்).\n" +
        "  • 'Tanglish la sollu' / 'explain in Tanglish' → Switch immediately to TANGLISH.\n" +
        "  • 'English la sollu' / 'explain in English' → Switch immediately to ENGLISH.\n" +
        "Rule 7 [PERSISTENCE FOR FOLLOW-UPS]: Maintain the selected language for follow-up messages until the user explicitly requests a language change.\n";

    private final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
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
            sendJson(ex, 405, errorResponse("Only POST is supported.", "LOCAL_FALLBACK"));
            return;
        }

        // Read request body
        String body;
        try (InputStream is = ex.getRequestBody()) {
            body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> req = GSON.fromJson(body, Map.class);
        if (req == null) req = Collections.emptyMap();

        String userMessage     = String.valueOf(req.getOrDefault("message", "")).trim();
        String mode            = String.valueOf(req.getOrDefault("mode", "GENERAL_AI")).trim();
        String sessionLanguage = String.valueOf(req.getOrDefault("language", "en")).trim();

        @SuppressWarnings("unchecked")
        Map<String, Object> threatContextMap = req.get("threatContext") instanceof Map<?, ?> tc
            ? (Map<String, Object>) tc
            : Collections.emptyMap();

        // Safe internal logging
        System.out.println("[Gemini] Request received");

        if (userMessage.isEmpty()) {
            sendJson(ex, 400, errorResponse("'message' field cannot be empty.", "LOCAL_FALLBACK"));
            return;
        }

        // Resolve target language
        String targetLang = CyberKnowledgeFallback.resolveTargetLanguage(userMessage, sessionLanguage);
        System.out.println("[Gemini] Resolved language: " + targetLang);

        ApiKeyInfo keyInfo = resolveApiKey();
        boolean isConfigured = !keyInfo.key().isBlank();

        // If API key is not configured, fall back to local knowledge
        if (!isConfigured) {
            System.err.println("[Gemini] GEMINI_API_KEY is not configured — serving local knowledge fallback.");
            CyberKnowledgeFallback.FallbackResult fb = CyberKnowledgeFallback.getFallbackAnswer(userMessage, mode, threatContextMap, targetLang);
            System.out.println("[Gemini] Falling back to local knowledge: " + fb.isKnown());

            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("success", true);
            resp.put("message", fb.text());
            resp.put("mode", mode);
            resp.put("source", "LOCAL_FALLBACK");
            resp.put("language", fb.language());
            sendJson(ex, 200, resp);
            return;
        }

        // Build Gemini conversation contents array
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> history = (List<Map<String, Object>>) req.getOrDefault("conversationHistory", Collections.emptyList());

        String threatContextNote = "";
        if (!threatContextMap.isEmpty()) {
            threatContextNote =
                "\n\n[SCANNER CONTEXT PROVIDED — use this when explaining the threat result]\n" +
                GSON.toJson(threatContextMap);
        }

        // Add explicit dynamic language requirement to system instruction for this turn
        String languageDirective = "\n\n[TARGET LANGUAGE FOR THIS TURN: " +
            ("ta".equalsIgnoreCase(targetLang) ? "RESPOND IN PURE TAMIL SCRIPT (தமிழ்)" :
             "tanglish".equalsIgnoreCase(targetLang) ? "RESPOND IN CONVERSATIONAL TANGLISH (Tamil words in English alphabet)" :
             "RESPOND IN NATURAL ENGLISH") + "]";

        // Construct Gemini REST payload
        JsonObject geminiPayload = buildGeminiPayload(userMessage, history, threatContextNote + languageDirective);

        // Call Gemini API (never log apiKey)
        String model = getModel();
        String geminiUrl = String.format(GEMINI_URL_TEMPLATE, model, keyInfo.key());

        try {
            HttpRequest geminiReq = HttpRequest.newBuilder()
                .uri(URI.create(geminiUrl))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(12))
                .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(geminiPayload), StandardCharsets.UTF_8))
                .build();

            HttpResponse<String> geminiResp = httpClient.send(geminiReq, HttpResponse.BodyHandlers.ofString());
            int statusCode = geminiResp.statusCode();
            System.out.println("[Gemini] HTTP status: " + statusCode);

            // Automatically retry on 429 rate limit with exponential backoff (max 2 retries)
            int retryAttempt = 0;
            final int MAX_RETRIES = 2;

            while (statusCode == 429 && retryAttempt < MAX_RETRIES) {
                retryAttempt++;
                long waitMs = parseRetryAfterMs(geminiResp, retryAttempt);
                System.out.println("[Gemini] HTTP status: 429 (Rate limited/Quota exceeded). Retry attempt: " + retryAttempt + " (backoff: " + waitMs + "ms)");

                try {
                    Thread.sleep(waitMs);
                } catch (InterruptedException ignored) {}

                geminiResp = httpClient.send(geminiReq, HttpResponse.BodyHandlers.ofString());
                statusCode = geminiResp.statusCode();
                System.out.println("[Gemini] HTTP status: " + statusCode);
            }

            // Success (HTTP 200)
            if (statusCode == 200) {
                String generatedText = extractGeminiText(geminiResp.body());
                if (generatedText != null && !generatedText.isBlank()) {
                    System.out.println("[Gemini] Falling back to local knowledge: false");
                    Map<String, Object> successResp = new LinkedHashMap<>();
                    successResp.put("success", true);
                    successResp.put("message", generatedText.trim());
                    successResp.put("mode", mode);
                    successResp.put("source", "GEMINI");
                    successResp.put("language", targetLang);
                    sendJson(ex, 200, successResp);
                    return;
                }
            }

            // If Gemini returned 429, quota exceeded, or empty response:
            // Log internally and serve accurate local knowledge in the target language.
            CyberKnowledgeFallback.FallbackResult fb = CyberKnowledgeFallback.getFallbackAnswer(userMessage, mode, threatContextMap, targetLang);
            System.out.println("[Gemini] Falling back to local knowledge: " + fb.isKnown());

            Map<String, Object> fallbackResp = new LinkedHashMap<>();
            fallbackResp.put("success", true);
            fallbackResp.put("message", fb.text());
            fallbackResp.put("mode", mode);
            fallbackResp.put("source", "LOCAL_FALLBACK");
            fallbackResp.put("language", fb.language());
            sendJson(ex, 200, fallbackResp);

        } catch (java.net.http.HttpTimeoutException te) {
            System.err.println("[Gemini] Request timed out — serving local fallback.");
            CyberKnowledgeFallback.FallbackResult fb = CyberKnowledgeFallback.getFallbackAnswer(userMessage, mode, threatContextMap, targetLang);
            System.out.println("[Gemini] Falling back to local knowledge: " + fb.isKnown());

            Map<String, Object> fallbackResp = new LinkedHashMap<>();
            fallbackResp.put("success", true);
            fallbackResp.put("message", fb.text());
            fallbackResp.put("mode", mode);
            fallbackResp.put("source", "LOCAL_FALLBACK");
            fallbackResp.put("language", fb.language());
            sendJson(ex, 200, fallbackResp);

        } catch (Exception e) {
            System.err.println("[Gemini] Request failed: " + e.getMessage() + " — serving local fallback.");
            CyberKnowledgeFallback.FallbackResult fb = CyberKnowledgeFallback.getFallbackAnswer(userMessage, mode, threatContextMap, targetLang);
            System.out.println("[Gemini] Falling back to local knowledge: " + fb.isKnown());

            Map<String, Object> fallbackResp = new LinkedHashMap<>();
            fallbackResp.put("success", true);
            fallbackResp.put("message", fb.text());
            fallbackResp.put("mode", mode);
            fallbackResp.put("source", "LOCAL_FALLBACK");
            fallbackResp.put("language", fb.language());
            sendJson(ex, 200, fallbackResp);
        }
    }

    private static long parseRetryAfterMs(HttpResponse<?> response, int attempt) {
        Optional<String> retryAfterOpt = response.headers().firstValue("Retry-After");
        if (retryAfterOpt.isPresent()) {
            try {
                long sec = Long.parseLong(retryAfterOpt.get().trim());
                if (sec > 0 && sec <= 5) {
                    return sec * 1000L;
                }
            } catch (NumberFormatException ignored) {}
        }
        return attempt == 1 ? 1000L : 2000L;
    }

    /**
     * Build the Gemini generateContent payload.
     * Enforces valid alternating turn structure for Gemini.
     */
    private JsonObject buildGeminiPayload(
            String userMessage,
            List<Map<String, Object>> history,
            String threatContextNote) {

        JsonObject payload = new JsonObject();

        // System instruction
        String sysText = SYSTEM_INSTRUCTION + threatContextNote;
        JsonObject sysInstruction = new JsonObject();
        JsonArray sysParts = new JsonArray();
        JsonObject sysPart = new JsonObject();
        sysPart.addProperty("text", sysText);
        sysParts.add(sysPart);
        sysInstruction.add("parts", sysParts);
        payload.add("systemInstruction", sysInstruction);

        // Conversation contents
        JsonArray contents = new JsonArray();

        // Process history (up to last 10 messages)
        List<JsonObject> validTurns = new ArrayList<>();
        int start = Math.max(0, history.size() - 10);
        String lastRole = null;

        for (int i = start; i < history.size(); i++) {
            Map<String, Object> msg = history.get(i);
            String role = String.valueOf(msg.getOrDefault("role", "user"));
            String content = String.valueOf(msg.getOrDefault("content", ""));
            if (content.isBlank()) continue;

            String geminiRole = "assistant".equalsIgnoreCase(role) || "ai".equalsIgnoreCase(role) ? "model" : "user";

            // If same role as previous turn, combine or skip to avoid Gemini 400
            if (geminiRole.equals(lastRole)) {
                if (!validTurns.isEmpty()) {
                    JsonObject prevTurn = validTurns.get(validTurns.size() - 1);
                    JsonArray parts = prevTurn.getAsJsonArray("parts");
                    JsonObject extraPart = new JsonObject();
                    extraPart.addProperty("text", "\n" + content);
                    parts.add(extraPart);
                }
                continue;
            }

            JsonObject turnObj = new JsonObject();
            turnObj.addProperty("role", geminiRole);
            JsonArray parts = new JsonArray();
            JsonObject part = new JsonObject();
            part.addProperty("text", content);
            parts.add(part);
            turnObj.add("parts", parts);

            validTurns.add(turnObj);
            lastRole = geminiRole;
        }

        // Add history turns (Gemini conversation must start with "user")
        int turnStart = 0;
        if (!validTurns.isEmpty() && "model".equals(validTurns.get(0).get("role").getAsString())) {
            turnStart = 1;
        }
        for (int i = turnStart; i < validTurns.size(); i++) {
            contents.add(validTurns.get(i));
        }

        // Current message is from "user"
        if ("user".equals(lastRole) && !contents.isEmpty()) {
            JsonObject lastTurn = contents.get(contents.size() - 1).getAsJsonObject();
            JsonArray parts = lastTurn.getAsJsonArray("parts");
            JsonObject userPart = new JsonObject();
            userPart.addProperty("text", "\n" + userMessage);
            parts.add(userPart);
        } else {
            JsonObject userTurn = new JsonObject();
            userTurn.addProperty("role", "user");
            JsonArray userParts = new JsonArray();
            JsonObject userPart = new JsonObject();
            userPart.addProperty("text", userMessage);
            userParts.add(userPart);
            userTurn.add("parts", userParts);
            contents.add(userTurn);
        }

        payload.add("contents", contents);

        // Generation config
        JsonObject genConfig = new JsonObject();
        genConfig.addProperty("maxOutputTokens", 1024);
        genConfig.addProperty("temperature", 0.7);
        genConfig.addProperty("topP", 0.95);
        payload.add("generationConfig", genConfig);

        return payload;
    }

    /**
     * Extract the generated text from Gemini's response JSON.
     */
    private String extractGeminiText(String responseBody) {
        try {
            JsonObject root = GSON.fromJson(responseBody, JsonObject.class);
            JsonArray candidates = root.getAsJsonArray("candidates");
            if (candidates == null || candidates.size() == 0) return null;
            JsonObject candidate = candidates.get(0).getAsJsonObject();
            JsonObject content = candidate.getAsJsonObject("content");
            if (content == null) return null;
            JsonArray parts = content.getAsJsonArray("parts");
            if (parts == null || parts.size() == 0) return null;
            return parts.get(0).getAsJsonObject().get("text").getAsString();
        } catch (Exception e) {
            System.err.println("[Gemini] Failed to parse response: " + e.getMessage());
            return null;
        }
    }

    private Map<String, Object> errorResponse(String message, String source) {
        Map<String, Object> err = new LinkedHashMap<>();
        err.put("success", false);
        err.put("message", message);
        err.put("source", source);
        return err;
    }

    private void sendJson(HttpExchange ex, int statusCode, Object data) throws IOException {
        byte[] bytes = GSON.toJson(data).getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}

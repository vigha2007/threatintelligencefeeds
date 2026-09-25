package com.threatintel;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class ThreatApiClient {

    private static String getApiUrl() {
        String mlBase = System.getenv("ML_API_URL");
        if (mlBase != null && !mlBase.trim().isEmpty()) {
            String base = mlBase.trim();
            if (base.endsWith("/")) base = base.substring(0, base.length() - 1);
            return base + "/predict";
        }
        return "http://localhost:8000/predict";
    }

    /**
     * Sends content to the ML API and returns a ThreatPrediction.
     *
     * @param type    "url" | "email" | "sms" | "call" | "ip"
     * @param content Raw string to analyse
     */
    public static ThreatPrediction predict(String type, String content) throws Exception {
        // ── Build request JSON ─────────────────────────────────────────────
        String requestBody = "{\"type\":\"" + type + "\",\"content\":\"" 
                            + content.replace("\"", "\\\"") + "\"}";
        byte[] postData = requestBody.getBytes(StandardCharsets.UTF_8);

        // ── Open connection ────────────────────────────────────────────────
        URL url = new URL(getApiUrl());
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type",  "application/json");
        conn.setRequestProperty("Content-Length", String.valueOf(postData.length));
        conn.setDoOutput(true);
        conn.setConnectTimeout(5_000);
        conn.setReadTimeout(10_000);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(postData);
        }

        // ── Read response ──────────────────────────────────────────────────
        int status = conn.getResponseCode();
        InputStream is = (status < 400) ? conn.getInputStream() : conn.getErrorStream();

        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
        }

        if (status != 200) {
            throw new IOException("API error " + status + ": " + sb);
        }

        // ── Parse JSON response using Gson ─────────────────────────────────
        JsonObject json = JsonParser.parseString(sb.toString()).getAsJsonObject();
        double confidence = json.get("confidence").getAsDouble();
        if (confidence > 1.0) {
            confidence /= 100.0;
        }
        return new ThreatPrediction(
            json.get("prediction").getAsString(),
            confidence,
            json.get("threat_level").getAsString(),
            json.get("data_type").getAsString()
        );
    }
}
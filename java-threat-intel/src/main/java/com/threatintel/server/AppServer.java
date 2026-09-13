package com.threatintel.server;

import com.sun.net.httpserver.HttpServer;
import com.threatintel.dao.DashboardDao;
import com.threatintel.dao.EntityDao;
import java.io.IOException;
import java.net.InetSocketAddress;

public class AppServer {
    private final int port;

    public AppServer(int port) {
        this.port = port;
    }

    public void start() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        EntityDao entityDao      = new EntityDao();
        DashboardDao dashboardDao = new DashboardDao();

        // ── Core v1 REST endpoints ─────────────────────────────────────────
        server.createContext("/api/v1/dashboard/metrics", new DashboardMetricsHandler(dashboardDao));
        server.createContext("/api/v1/entity/",           new EntityHandler(entityDao));

        // ── DB-first search (phone, SMS, and global full-text) ─────────────
        server.createContext("/api/v1/search/",           new SearchHandler());

        // ── Standard REST aliases (/api/{entity-slug}) ─────────────────────
        EntityHandler eh = new EntityHandler(entityDao);
        server.createContext("/api/threats",          eh);
        server.createContext("/api/phishing-urls",    eh);
        server.createContext("/api/email-scams",      eh);
        server.createContext("/api/malicious-ips",    eh);
        server.createContext("/api/suspicious-calls", eh);
        server.createContext("/api/scam-messages",    eh);

        // ── ML Analyze + Call-Detect endpoints ────────────────────────────
        DashboardMetricsHandler dmh = new DashboardMetricsHandler(dashboardDao);
        server.createContext("/api/analyze",        dmh);
        server.createContext("/api/threat/analyze", dmh);   // canonical ML endpoint
        server.createContext("/api/call-detect",    dmh);

        // ── DB-first Phone Call Detection (preferred endpoint) ────────────
        CallDetectHandler callDetect = new CallDetectHandler();
        server.createContext("/api/v1/detect/call",  callDetect);
        server.createContext("/api/detect/call",     callDetect);

        // ── Threat Detection: Email, URL, IP, SMS/Message ─────────────────
        ThreatDetectHandler threatDetect = new ThreatDetectHandler();
        server.createContext("/api/v1/detect/email",   threatDetect);
        server.createContext("/api/detect/email",      threatDetect);
        server.createContext("/api/v1/detect/url",     threatDetect);
        server.createContext("/api/detect/url",        threatDetect);
        server.createContext("/api/v1/detect/ip",      threatDetect);
        server.createContext("/api/detect/ip",         threatDetect);
        server.createContext("/api/v1/detect/sms",     threatDetect);
        server.createContext("/api/detect/sms",        threatDetect);
        server.createContext("/api/v1/detect/message", threatDetect);
        server.createContext("/api/detect/message",    threatDetect);

        // ── Cyber Sentinel AI Chat (Gemini-powered, key is backend-only) ────
        GeminiChatHandler geminiChat = new GeminiChatHandler();
        server.createContext("/api/chat", geminiChat);

        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.start();

        System.out.println("✅ Java backend listening on port " + port);
        System.out.println("📊 Dashboard metrics  → http://localhost:" + port + "/api/v1/dashboard/metrics");
        System.out.println("🔍 Global search      → http://localhost:" + port + "/api/v1/search/all?q=...");
        System.out.println("📞 Call Detect         → http://localhost:" + port + "/api/v1/detect/call");
        System.out.println("📧 Email Detect        → http://localhost:" + port + "/api/v1/detect/email");
        System.out.println("🌐 URL Detect          → http://localhost:" + port + "/api/v1/detect/url");
        System.out.println("🌍 IP Detect           → http://localhost:" + port + "/api/v1/detect/ip");
        System.out.println("💬 SMS Detect          → http://localhost:" + port + "/api/v1/detect/sms");
        System.out.println("📋 Phishing URLs       → http://localhost:" + port + "/api/phishing-urls");
        System.out.println("🤖 Cyber Sentinel Chat → http://localhost:" + port + "/api/chat");
    }
}
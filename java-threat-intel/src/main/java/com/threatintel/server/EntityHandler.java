package com.threatintel.server;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.threatintel.dao.EntityDao;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.*;

public class EntityHandler implements HttpHandler {

    private final EntityDao dao;
    private final Gson gson = new Gson();

    public EntityHandler(EntityDao dao) {
        this.dao = dao;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // CORS headers — allow Vite dev server and any other origin
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin",  "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
        exchange.getResponseHeaders().add("Content-Type", "application/json");

        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        // ── Resolve entity key from path ─────────────────────────────────────
        // Supports both:
        //   /api/v1/entity/{entity}[/{id}]   (canonical v1 path)
        //   /api/{slug}[/{id}]               (friendly alias, e.g. /api/phishing-urls)
        String path = exchange.getRequestURI().getPath();

        String entityRaw;
        String id;
        if (path.startsWith("/api/v1/entity/")) {
            String remainder = path.replaceFirst("^/api/v1/entity/?", "");
            String[] parts = remainder.isEmpty() ? new String[0] : remainder.split("/");
            entityRaw = parts.length > 0 ? parts[0] : "";
            id        = parts.length > 1 ? parts[1] : null;
        } else {
            // /api/{slug}[/{id}]
            String remainder = path.replaceFirst("^/api/?", "");
            String[] parts = remainder.isEmpty() ? new String[0] : remainder.split("/");
            entityRaw = parts.length > 0 ? parts[0] : "";
            id        = parts.length > 1 ? parts[1] : null;
        }

        // Resolve slug → canonical entity key
        String entity = dao.resolveEntity(entityRaw);
        if (entity == null || entity.isEmpty()) {
            sendJson(exchange, 404, Map.of("error", "Unknown entity: " + entityRaw));
            return;
        }

        String method = exchange.getRequestMethod().toUpperCase();

        try {
            if ("GET".equals(method)) {
                if (id != null && !id.isEmpty()) {
                    Map<String, Object> row = dao.getById(entity, id);
                    if (row == null) sendJson(exchange, 404, Map.of("error", "Not found"));
                    else sendJson(exchange, 200, Map.of("row", row));
                } else {
                    // ── Pagination via query string ──────────────────────────
                    // Accepts:  ?limit=N&offset=M   OR   ?page=N&size=M   (Spring-style)
                    String query   = exchange.getRequestURI().getQuery();
                    int    limit   = EntityDao.DEFAULT_PAGE_SIZE;
                    int    offset  = 0;
                    int    page    = 0; // 0-based Spring-style

                    if (query != null) {
                        // First pass — collect all params
                        Map<String,String> params = new LinkedHashMap<>();
                        for (String param : query.split("&")) {
                            String[] kv = param.split("=", 2);
                            if (kv.length == 2) params.put(kv[0], kv[1]);
                        }
                        try { if (params.containsKey("size"))   limit  = Integer.parseInt(params.get("size"));   } catch (NumberFormatException ignored) {}
                        try { if (params.containsKey("limit"))  limit  = Integer.parseInt(params.get("limit"));  } catch (NumberFormatException ignored) {}
                        try { if (params.containsKey("page"))   page   = Integer.parseInt(params.get("page"));   } catch (NumberFormatException ignored) {}
                        try { if (params.containsKey("offset")) offset = Integer.parseInt(params.get("offset")); } catch (NumberFormatException ignored) {}

                        // page takes priority over offset when present
                        if (params.containsKey("page") && !params.containsKey("offset")) {
                            offset = page * limit;
                        }
                    }

                    List<Map<String, Object>> rows      = dao.list(entity, limit, offset);
                    long                      total     = dao.count(entity);
                    int                       totPages  = (int) Math.ceil((double) total / Math.max(1, limit));

                    // Return both legacy (rows/total/limit/offset) and Spring-style keys (content/totalElements/totalPages/page/size)
                    Map<String, Object> resp = new LinkedHashMap<>();
                    resp.put("content",       rows);
                    resp.put("rows",          rows);
                    resp.put("total",         total);
                    resp.put("totalElements", total);
                    resp.put("totalPages",    totPages);
                    resp.put("page",          page);
                    resp.put("size",          limit);
                    resp.put("limit",         limit);
                    resp.put("offset",        offset);
                    sendJson(exchange, 200, resp);
                }
            } else if ("POST".equals(method)) {
                Map<String, Object> body = readBody(exchange);
                Map<String, Object> row = dao.insert(entity, body);
                sendJson(exchange, 201, Map.of("row", row));
            } else if ("PATCH".equals(method)) {
                if (id == null || id.isEmpty()) {
                    sendJson(exchange, 400, Map.of("error", "Missing id"));
                    return;
                }
                Map<String, Object> body = readBody(exchange);
                Map<String, Object> row = dao.update(entity, id, body);
                sendJson(exchange, 200, Map.of("row", row));
            } else if ("DELETE".equals(method)) {
                if (id == null || id.isEmpty()) {
                    sendJson(exchange, 400, Map.of("error", "Missing id"));
                    return;
                }
                boolean ok = dao.delete(entity, id);
                sendJson(exchange, ok ? 200 : 404, Map.of("ok", ok));
            } else {
                sendJson(exchange, 405, Map.of("error", "Method not allowed"));
            }
        } catch (SQLException e) {
            sendJson(exchange, 500, Map.of("error", e.getMessage()));
        }
    }

    private Map<String, Object> readBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            Type type = new TypeToken<Map<String, Object>>() {}.getType();
            Map<String, Object> map = gson.fromJson(body, type);
            return map != null ? map : new HashMap<>();
        }
    }

    private void sendJson(HttpExchange exchange, int status, Object body) throws IOException {
        byte[] bytes = gson.toJson(body).getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
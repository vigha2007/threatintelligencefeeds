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
        // CORS headers
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
        exchange.getResponseHeaders().add("Content-Type", "application/json");

        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        // Parse path: /api/v1/entity/{entity} or /api/v1/entity/{entity}/{id}
        String path = exchange.getRequestURI().getPath();
        // Remove leading /api/v1/entity/ prefix
        String remainder = path.replaceFirst("^/api/v1/entity/?", "");
        String[] parts = remainder.isEmpty() ? new String[0] : remainder.split("/");

        String entity = parts.length > 0 ? parts[0] : "";
        String id = parts.length > 1 ? parts[1] : null;

        if (entity.isEmpty() || !dao.isValidEntity(entity)) {
            sendJson(exchange, 404, Map.of("error", "Unknown entity: " + entity));
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
                    List<Map<String, Object>> rows = dao.list(entity);
                    sendJson(exchange, 200, Map.of("rows", rows));
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
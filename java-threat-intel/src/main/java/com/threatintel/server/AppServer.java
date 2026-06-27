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

        // API endpoints
        server.createContext("/api/v1/dashboard/metrics", new DashboardMetricsHandler(new DashboardDao()));
        server.createContext("/api/v1/entity/", new EntityHandler(new EntityDao()));
        
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.start();
        System.out.println("Java backend listening on port " + port);
    }
}

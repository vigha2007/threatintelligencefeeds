package com.threatintel;

import com.threatintel.db.SchemaInitializer;
import com.threatintel.server.AppServer;

public class Main {
    public static void main(String[] args) throws Exception {
        boolean initDb = false;
        boolean generateData = false;
        
        for (String arg : args) {
            if ("--init-db".equals(arg)) {
                initDb = true;
            }
            if ("--generate-data".equals(arg)) {
                generateData = true;
            }
        }

        if (initDb || generateData) {
            System.out.println("Running initialization tasks...");
            if (initDb) {
                SchemaInitializer.initialize();
            }
            if (generateData) {
                DataGenerator.generateData();
            }
            if (args.length == 1 && (initDb || generateData)) {
                System.out.println("Initialization complete. Exiting.");
                System.exit(0);
            }
        }

        // Start the server
        int port = 8080;
        AppServer server = new AppServer(port);
        server.start();
    }
}

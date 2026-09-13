# Stage 1: Build Java backend with Maven and OpenJDK 17
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /build

# Copy Maven project descriptor and source files
COPY java-threat-intel/pom.xml ./pom.xml
COPY java-threat-intel/src ./src

# Package application and copy dependencies to target/dependency
RUN mvn clean package -DskipTests

# Stage 2: Runtime image using lightweight JRE 17
FROM eclipse-temurin:17-jre

WORKDIR /app

# Copy packaged JAR and runtime dependencies from the build stage
COPY --from=builder /build/target/java-threat-intel-1.0-SNAPSHOT.jar ./app.jar
COPY --from=builder /build/target/dependency ./dependency

# Default port for Java AppServer
EXPOSE 8081

# Launch Java backend main class
CMD ["java", "-cp", "app.jar:dependency/*", "com.threatintel.Main"]

# Multi-stage Dockerfile for Plain Java / Maven Backend (Java 17)
# Stage 1: Build
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /app

# Copy pom.xml and dependency descriptors
COPY pom.xml ./

# Copy source code
COPY src ./src

# Build the project and package dependencies
RUN mvn clean package -DskipTests

# Stage 2: Runtime
FROM eclipse-temurin:17-jre

WORKDIR /app

# Copy compiled JAR and dependencies from builder stage
COPY --from=builder /app/target/java-threat-intel-1.0-SNAPSHOT.jar ./app.jar
COPY --from=builder /app/target/dependency ./dependency

# Dynamic PORT assigned by Render, defaulting to 8081
ENV PORT=8081
EXPOSE 8081

# Start Java application
CMD ["java", "-cp", "app.jar:dependency/*", "com.threatintel.Main"]

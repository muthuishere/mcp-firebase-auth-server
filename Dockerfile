# Multi-stage build for maximum caching efficiency
FROM eclipse-temurin:17-jdk-alpine AS dependencies

# Set working directory
WORKDIR /app

# Copy only Gradle wrapper and build files first (for dependency caching)
COPY gradlew gradlew.bat build.gradle settings.gradle ./
COPY gradle gradle

# Make gradlew executable and cache dependencies
RUN chmod +x gradlew && \
    ./gradlew --no-daemon dependencies && \
    ./gradlew --no-daemon testClasses || true

# Build stage
FROM eclipse-temurin:17-jdk-alpine AS builder

# Set working directory
WORKDIR /app

# Copy Gradle cache from dependencies stage
COPY --from=dependencies /root/.gradle /root/.gradle

# Copy build files and gradle wrapper
COPY gradlew gradlew.bat build.gradle settings.gradle ./
COPY gradle gradle

# Make gradlew executable
RUN chmod +x gradlew

# Copy source code
COPY src src

# Build the application (with cached dependencies)
RUN ./gradlew bootJar --no-daemon --offline

# Runtime stage
FROM eclipse-temurin:17-jre-alpine

# Set working directory
WORKDIR /app

# Copy the built JAR from builder stage
COPY --from=builder /app/build/libs/*.jar app.jar

# Expose the application port
EXPOSE 9000

# Set environment variables for optimal performance
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75.0 -XX:+UseG1GC -XX:+UseContainerSupport -Djava.security.egd=file:/dev/./urandom"

# Run the application
CMD ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
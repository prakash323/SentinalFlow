# syntax=docker/dockerfile:1
# SentinelFlow backend: Spring Boot 3.3 / Java 21.
# Tests are not run here (they need embedded Kafka); run `mvn verify` on the host.

FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
# The Maven repository is a BuildKit cache mount: reused across builds, never baked into the image.
RUN --mount=type=cache,target=/root/.m2 mvn -B -q dependency:go-offline
COPY src src
RUN --mount=type=cache,target=/root/.m2 mvn -B -q -DskipTests package \
 && cp target/anomaly-platform-backend-*.jar /build/app.jar

FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S sentinelflow && adduser -S sentinelflow -G sentinelflow
WORKDIR /app
COPY --from=build /build/app.jar app.jar
USER sentinelflow
EXPOSE 8080
# Readiness includes the database check (application.yml management.endpoint.health.group.readiness).
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=10 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/actuator/health/readiness || exit 1
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]

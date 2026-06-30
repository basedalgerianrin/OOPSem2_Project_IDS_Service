# --- Stage 1: build the fat jar with the Maven wrapper -----------------------
# JDK 25 to match <java.version>25</java.version> in pom.xml.
FROM eclipse-temurin:25-jdk AS build
WORKDIR /build
COPY . .
# A Windows checkout can give mvnw CRLF line endings and drop its +x bit, both of
# which break `./mvnw` in a Linux container — normalise both. Then package
# without tests (the build host has no FastAPI app to reach).
RUN sed -i 's/\r$//' mvnw && chmod +x mvnw && ./mvnw -q -B -DskipTests clean package

# --- Stage 2: slim runtime ---------------------------------------------------
FROM eclipse-temurin:25-jre
WORKDIR /app
# H2 file DB lives here; mount a named volume at /data so alerts persist.
RUN mkdir -p /data
ENV IDS_DB_PATH=/data/idsdb
COPY --from=build /build/target/IDS_service-*.jar /app/app.jar
EXPOSE 8082
VOLUME ["/data"]
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

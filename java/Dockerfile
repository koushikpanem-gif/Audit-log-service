# Runtime-only image: copy the jar produced by `mvn -f java/pom.xml verify`.
# Build from the repository root:  docker build -f java/Dockerfile -t audit-log-java .
# Base tag and digest were read from the Docker Hub registry API on 2026-10-18.
FROM eclipse-temurin:21-jre-jammy@sha256:affcab5356e1270ac35d2361ee83135af2f03e8d580eca78a6d5d6fdbf048db0

RUN groupadd --system --gid 10001 audit \
 && useradd --system --uid 10001 --gid audit --no-create-home --shell /usr/sbin/nologin audit \
 && mkdir -p /var/lib/audit/data /var/lib/audit/archives /var/lib/audit/exports /etc/audit/keys \
 && chown -R audit:audit /var/lib/audit \
 && chmod 0750 /var/lib/audit/data /var/lib/audit/archives /var/lib/audit/exports

COPY java/target/audit-log-service-0.1.0-SNAPSHOT.jar /opt/audit/app.jar

# Production fails closed: the keys directory must be mounted read-only at run time.
ENV AUDIT_ENV=prod \
    AUDIT_DB_PATH=/var/lib/audit/data/audit.db \
    AUDIT_ARCHIVE_DIR=/var/lib/audit/archives \
    AUDIT_EXPORT_DIR=/var/lib/audit/exports \
    AUDIT_SIGNING_PRIVATE_KEY=/etc/audit/keys/signing-private.pem \
    AUDIT_SIGNING_PUBLIC_KEY=/etc/audit/keys/signing-public.b64 \
    AUDIT_API_KEYS_FILE=/etc/audit/keys/api-keys.json

USER 10001:10001
VOLUME ["/var/lib/audit/data", "/var/lib/audit/archives", "/var/lib/audit/exports"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080 && printf 'GET /health HTTP/1.0\\r\\n\\r\\n' >&3 && head -n1 <&3 | grep -q ' 200 '"]

ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/opt/audit/app.jar"]

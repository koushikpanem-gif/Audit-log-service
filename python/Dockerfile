# Build from the repository root:  docker build -f python/Dockerfile -t audit-log-python .
# Base tag and digest were read from the Docker Hub registry API on 2026-10-18.
FROM python:3.11-slim-bookworm@sha256:0a310eeecf4e1f5a0743f9a6520c90c88d089c903ca5fd283f501e3a805f5f89 AS build
WORKDIR /src
COPY python/pyproject.toml ./python/pyproject.toml
COPY python/src ./python/src
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir "./python[service]"

FROM python:3.11-slim-bookworm@sha256:0a310eeecf4e1f5a0743f9a6520c90c88d089c903ca5fd283f501e3a805f5f89
RUN groupadd --system --gid 10001 audit \
 && useradd --system --uid 10001 --gid audit --no-create-home --shell /usr/sbin/nologin audit \
 && mkdir -p /var/lib/audit/data /var/lib/audit/archives /var/lib/audit/exports /etc/audit/keys \
 && chown -R audit:audit /var/lib/audit \
 && chmod 0750 /var/lib/audit/data /var/lib/audit/archives /var/lib/audit/exports
COPY --from=build /opt/venv /opt/venv

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    AUDIT_ENV=prod \
    AUDIT_DB_PATH=/var/lib/audit/data/audit.db \
    AUDIT_ARCHIVE_DIR=/var/lib/audit/archives \
    AUDIT_EXPORT_DIR=/var/lib/audit/exports \
    AUDIT_SIGNING_PRIVATE_KEY=/etc/audit/keys/signing-private.pem \
    AUDIT_SIGNING_PUBLIC_KEY=/etc/audit/keys/signing-public.b64 \
    AUDIT_API_KEYS_FILE=/etc/audit/keys/api-keys.json

USER 10001:10001
VOLUME ["/var/lib/audit/data", "/var/lib/audit/archives", "/var/lib/audit/exports"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"]

CMD ["uvicorn", "audit_log_service.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]

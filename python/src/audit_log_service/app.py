from __future__ import annotations

import contextlib
import html
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from audit_log_service import auth
from audit_log_service.account_report import AccountAccessReportService
from audit_log_service.archive import ArchiveService
from audit_log_service.archive_audit import ArchiveAuditService
from audit_log_service.auth import ApiKeyAuthenticator, Principal
from audit_log_service.canonical_json import (
    MAX_INPUT_BYTES,
    CanonicalJsonError,
    parse_json,
)
from audit_log_service.configuration import AuditConfiguration
from audit_log_service.errors import ApiError, invalid
from audit_log_service.export_bundle import ExportBundleService, parse_selection
from audit_log_service.export_sets import ExportSetService
from audit_log_service.ledger import (
    AppendService,
    Clock,
    QueryService,
    parse_append_request,
    system_clock,
)
from audit_log_service.ledger_verifier import LedgerVerifier
from audit_log_service.redaction import RedactionCleanupService, RedactionService
from audit_log_service.signing import CheckpointSigner
from audit_log_service.store import (
    SqliteStore,
    StorageBusyError,
    StorageConflictError,
    StorageError,
)

Handler = Callable[[Request], Awaitable[Response]]

_REDACTION_FIELDS = frozenset({"eventId", "paths", "reason", "ticketId"})


def error_response(
    status: int, code: str, message: str, details: list[object] | None = None
) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code, "message": message, "details": details or []}},
        status_code=status,
    )


class AuditApi:
    def __init__(
        self,
        configuration: AuditConfiguration,
        store: SqliteStore,
        signer: CheckpointSigner,
        authenticator: ApiKeyAuthenticator,
        clock: Clock,
    ) -> None:
        self.configuration = configuration
        self.signer = signer
        self.authenticator = authenticator
        self.append_service = AppendService(store, configuration, signer, clock)
        self.query_service = QueryService(store, authenticator.cursor_signing_key)
        self.verifier = LedgerVerifier(
            store, configuration.ledger_id, signer.public_key_base64, clock
        )
        self.bundle_service = ExportBundleService(
            store, configuration, signer, self.append_service
        )
        self.report_service = AccountAccessReportService(
            store,
            configuration,
            self.verifier,
            self.append_service,
            self.bundle_service,
        )
        self.export_sets = ExportSetService(
            store, configuration, signer, self.append_service, clock
        )
        self.cleanup = RedactionCleanupService(store, configuration, clock)
        self.redaction = RedactionService(
            store, configuration, self.append_service, self.cleanup
        )
        self.archive = ArchiveService(
            store, configuration, signer, self.append_service, clock
        )
        self.archive_audit = ArchiveAuditService(
            store, configuration, signer.public_key_base64, signer.key_id, clock
        )

    def recover(self) -> None:
        """Start-up recovery; failures are left for the explicit admin routes."""
        for step in (self.cleanup.recover, self.archive.reconcile):
            with contextlib.suppress(ApiError, StorageError):
                step()

    async def _json_object(self, request: Request) -> dict[str, Any]:
        body = await self.read_body(request)
        try:
            parsed = parse_json(body, max_bytes=self.body_limit, max_depth=4)
        except CanonicalJsonError as exc:
            raise ApiError(
                422, "INVALID_JSON", "Request body is not valid strict JSON"
            ) from exc
        if not isinstance(parsed, dict):
            raise invalid("Request body must be a JSON object")
        return parsed

    async def redact(self, request: Request) -> Response:
        principal = self.principal(request, auth.ADMIN_ROLES)
        parsed = await self._json_object(request)
        if set(parsed) != _REDACTION_FIELDS:
            raise invalid("Body must contain exactly eventId, paths, reason, ticketId")
        result = await run_in_threadpool(
            self.redaction.redact,
            parsed["eventId"],
            parsed["paths"],
            parsed["reason"],
            parsed["ticketId"],
            principal.name,
        )
        return JSONResponse(
            result,
            status_code=201,
            headers={"Location": f"/audit/events/{result['redactionEventId']}"},
        )

    async def cleanup_status(self, request: Request) -> Response:
        self.principal(request, auth.ADMIN_ROLES)
        return JSONResponse(await run_in_threadpool(self.cleanup.status))

    async def cleanup_retry(self, request: Request) -> Response:
        self.principal(request, auth.ADMIN_ROLES)

        def retry() -> dict[str, Any]:
            self.cleanup.run_pending()
            return self.cleanup.status()

        return JSONResponse(await run_in_threadpool(retry))

    async def archive_records(self, request: Request) -> Response:
        principal = self.principal(request, auth.ADMIN_ROLES)
        parsed = await self._json_object(request)
        dry_run = parsed.get("dryRun")
        if set(parsed) != {"dryRun"} or not isinstance(dry_run, bool):
            raise invalid('Body must be exactly {"dryRun": true|false}')
        result = await run_in_threadpool(self.archive.archive, dry_run, principal.name)
        return JSONResponse(result)

    async def archive_jobs(self, request: Request) -> Response:
        self.principal(request, auth.ADMIN_ROLES)
        return JSONResponse(await run_in_threadpool(self.archive.status))

    async def archive_reconcile(self, request: Request) -> Response:
        self.principal(request, auth.ADMIN_ROLES)
        return JSONResponse(await run_in_threadpool(self.archive.reconcile))

    async def archive_audit_report(self, request: Request) -> Response:
        self.principal(request, auth.AUDITOR_ROLES)
        return JSONResponse(await run_in_threadpool(self.archive_audit.audit))

    def principal(self, request: Request, roles: frozenset[str]) -> Principal:
        principal = self.authenticator.authenticate(request.headers.get("x-api-key"))
        if principal is None:
            raise ApiError(
                401, "UNAUTHORIZED", "Valid X-API-Key credentials are required"
            )
        if not principal.has_any(roles):
            raise ApiError(
                403,
                "FORBIDDEN",
                "The principal does not have permission for this operation",
            )
        return principal

    @property
    def body_limit(self) -> int:
        return min(self.configuration.request_limit_bytes, MAX_INPUT_BYTES)

    async def read_body(self, request: Request) -> bytes:
        content_type = request.headers.get("content-type", "").lower()
        if not content_type.startswith("application/json"):
            raise ApiError(
                415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json"
            )
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self.body_limit:
            raise _too_large()
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > self.body_limit:
                raise _too_large()
            chunks.append(chunk)
        return b"".join(chunks)

    async def health(self, _: Request) -> Response:
        return JSONResponse({"status": "UP"})

    async def public_key(self, _: Request) -> Response:
        return JSONResponse(
            {
                "signatureAlgorithm": "Ed25519",
                "keyId": self.signer.key_id,
                "publicKey": self.signer.public_key_base64,
            }
        )

    async def append(self, request: Request) -> Response:
        principal = self.principal(request, auth.WRITE_ROLES)
        body = await self.read_body(request)
        try:
            parsed = parse_json(
                body,
                max_bytes=self.body_limit,
                max_depth=self.configuration.max_depth + 2,
            )
        except CanonicalJsonError as exc:
            raise ApiError(
                422, "INVALID_JSON", "Request body is not valid strict JSON"
            ) from exc
        event = parse_append_request(parsed, self.configuration)
        appended = await run_in_threadpool(
            self.append_service.append, event, principal.name
        )
        return JSONResponse(
            appended,
            status_code=201,
            headers={"Location": f"/audit/events/{appended['eventId']}"},
        )

    async def list_events(self, request: Request) -> Response:
        self.principal(request, auth.READ_ROLES)
        params = request.query_params
        filters = {
            name: params.get(name)
            for name in ("actorId", "resourceType", "resourceId", "eventType")
        }
        filters["from"] = params.get("from")
        filters["to"] = params.get("to")
        page = await run_in_threadpool(
            self.query_service.list_events,
            filters=filters,
            limit=_int_param(params.get("limit"), "limit"),
            order=params.get("order"),
            cursor=params.get("cursor"),
        )
        return JSONResponse(page)

    async def get_event(self, request: Request) -> Response:
        self.principal(request, auth.READ_ROLES)
        event = await run_in_threadpool(
            self.query_service.get_event, request.path_params["event_id"]
        )
        return JSONResponse(event)

    async def list_checkpoints(self, request: Request) -> Response:
        self.principal(request, auth.AUDITOR_ROLES)
        items = await run_in_threadpool(
            self.query_service.list_checkpoints,
            _int_param(request.query_params.get("limit"), "limit"),
        )
        return JSONResponse(items)

    async def create_checkpoint(self, request: Request) -> Response:
        self.principal(request, auth.ADMIN_ROLES)
        checkpoint = await run_in_threadpool(self.append_service.create_checkpoint)
        return JSONResponse(checkpoint, status_code=201)

    async def verify(self, request: Request) -> Response:
        self.principal(request, auth.AUDITOR_ROLES)
        report = await run_in_threadpool(self.verifier.verify)
        return JSONResponse(report)

    async def export(self, request: Request) -> Response:
        principal = self.principal(request, auth.AUDITOR_ROLES)
        selection = parse_selection(_filters(request), require_actor_or_resource=True)
        body = await run_in_threadpool(
            self.bundle_service.export, selection, principal.name
        )
        return Response(body, media_type="application/json")

    async def create_export_set(self, request: Request) -> Response:
        principal = self.principal(request, auth.AUDITOR_ROLES)
        selection = parse_selection(_filters(request), require_actor_or_resource=True)
        descriptor = await run_in_threadpool(
            self.export_sets.create, selection, principal.name
        )
        return JSONResponse(
            descriptor,
            status_code=202,
            headers={"Location": f"/audit/export-sets/{descriptor['exportSetId']}"},
        )

    async def get_export_set(self, request: Request) -> Response:
        self.principal(request, auth.AUDITOR_ROLES)
        descriptor = await run_in_threadpool(
            self.export_sets.describe, request.path_params["export_set_id"]
        )
        return JSONResponse(descriptor)

    async def get_export_manifest(self, request: Request) -> Response:
        self.principal(request, auth.AUDITOR_ROLES)

        def read() -> bytes:
            return self.export_sets.manifest_path(
                request.path_params["export_set_id"]
            ).read_bytes()

        return Response(await run_in_threadpool(read), media_type="application/json")

    async def get_export_chunk(self, request: Request) -> Response:
        self.principal(request, auth.AUDITOR_ROLES)

        def read() -> bytes:
            return self.export_sets.chunk_path(
                request.path_params["export_set_id"], request.path_params["name"]
            ).read_bytes()

        return Response(await run_in_threadpool(read), media_type="application/json")

    async def account_access_report(self, request: Request) -> Response:
        principal = self.principal(request, auth.AUDITOR_ROLES)
        params = request.query_params
        report = await run_in_threadpool(
            self.report_service.generate,
            params.get("accountId"),
            params.get("actorId"),
            params.get("from"),
            params.get("to"),
            principal.name,
        )
        return JSONResponse(report)

    async def openapi(self, _: Request) -> Response:
        return JSONResponse(openapi_document())

    async def docs(self, _: Request) -> Response:
        rows = []
        for path, item in openapi_document()["paths"].items():
            for method, operation in item.items():
                rows.append(
                    f"<tr><td>{html.escape(method.upper())}</td>"
                    f"<td><code>{html.escape(path)}</code></td>"
                    f"<td>{html.escape(operation['summary'])}</td></tr>"
                )
        page = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>Audit log service API</title></head><body>"
            "<h1>Audit log service API (Python)</h1>"
            "<p>Machine-readable contract: <a href='/openapi.json'>/openapi.json</a>."
            " Authenticate with the X-API-Key header.</p>"
            "<table border='1' cellpadding='4'><tr><th>Method</th><th>Path</th>"
            f"<th>Summary</th></tr>{''.join(rows)}</table></body></html>"
        )
        return HTMLResponse(page)


def _too_large() -> ApiError:
    return ApiError(
        413, "REQUEST_TOO_LARGE", "Request body exceeds the configured byte limit"
    )


def _filters(request: Request) -> dict[str, str | None]:
    params = request.query_params
    names = ("actorId", "resourceType", "resourceId", "eventType", "from", "to")
    return {name: params.get(name) for name in names}


def _int_param(value: str | None, name: str) -> int | None:
    if value is None:
        return None
    if not value.isascii() or not value.lstrip("-").isdigit() or len(value) > 12:
        raise invalid(f"{name} must be an integer")
    return int(value)


async def _api_error(_: Request, exc: Exception) -> Response:
    assert isinstance(exc, ApiError)
    return error_response(exc.status, exc.code, exc.message, exc.details)


async def _http_error(_: Request, exc: Exception) -> Response:
    assert isinstance(exc, HTTPException)
    if exc.status_code == 404:
        return error_response(404, "NOT_FOUND", "The resource was not found")
    if exc.status_code == 405:
        return error_response(
            405, "METHOD_NOT_ALLOWED", "HTTP method is not supported for this resource"
        )
    return error_response(exc.status_code, "HTTP_ERROR", "The request was rejected")


async def _storage_error(_: Request, exc: Exception) -> Response:
    if isinstance(exc, StorageBusyError):
        return error_response(
            503, "STORAGE_BUSY", "Audit storage is temporarily unavailable"
        )
    if isinstance(exc, StorageConflictError):
        return error_response(
            409, "CONFLICT", "The requested change conflicts with existing audit data"
        )
    return error_response(
        500, "INTERNAL_ERROR", "The audit operation could not be completed"
    )


async def _unexpected(_: Request, __: Exception) -> Response:
    return error_response(500, "INTERNAL_ERROR", "The request could not be completed")


def create_app(
    configuration: AuditConfiguration | None = None,
    *,
    clock: Clock = system_clock,
) -> Starlette:
    config = configuration or AuditConfiguration.from_environment()
    signer = config.load_signer()
    authenticator = ApiKeyAuthenticator(config)
    store = SqliteStore(config.db_path, config.ledger_id)
    api = AuditApi(config, store, signer, authenticator, clock)
    api.recover()

    routes = [
        Route("/health", api.health, methods=["GET"]),
        Route("/audit/public-key", api.public_key, methods=["GET"]),
        Route("/openapi.json", api.openapi, methods=["GET"]),
        Route("/docs", api.docs, methods=["GET"]),
        Route("/audit/events", api.append, methods=["POST"]),
        Route("/audit/events", api.list_events, methods=["GET"]),
        Route("/audit/events/{event_id}", api.get_event, methods=["GET"]),
        Route("/audit/checkpoints", api.list_checkpoints, methods=["GET"]),
        Route("/audit/admin/checkpoints", api.create_checkpoint, methods=["POST"]),
        Route("/audit/verify", api.verify, methods=["GET"]),
        Route("/audit/export", api.export, methods=["GET"]),
        Route("/audit/export-sets", api.create_export_set, methods=["POST"]),
        Route("/audit/export-sets/{export_set_id}", api.get_export_set),
        Route(
            "/audit/export-sets/{export_set_id}/manifest",
            api.get_export_manifest,
            methods=["GET"],
        ),
        Route(
            "/audit/export-sets/{export_set_id}/chunks/{name}",
            api.get_export_chunk,
            methods=["GET"],
        ),
        Route("/audit/admin/redactions", api.redact, methods=["POST"]),
        Route("/audit/admin/redaction-cleanups", api.cleanup_status, methods=["GET"]),
        Route(
            "/audit/admin/redaction-cleanups/retry",
            api.cleanup_retry,
            methods=["POST"],
        ),
        Route("/audit/admin/archive", api.archive_records, methods=["POST"]),
        Route("/audit/admin/archive-jobs", api.archive_jobs, methods=["GET"]),
        Route(
            "/audit/admin/archive-jobs/reconcile",
            api.archive_reconcile,
            methods=["POST"],
        ),
        Route("/audit/archive-audit", api.archive_audit_report, methods=["GET"]),
    ]
    routes.append(
        Route(
            "/compliance/account-access-report",
            api.account_access_report,
            methods=["GET"],
        )
    )
    handlers: dict[Any, Any] = {
        ApiError: _api_error,
        HTTPException: _http_error,
        StorageError: _storage_error,
        Exception: _unexpected,
    }
    application = Starlette(routes=routes, exception_handlers=handlers)
    application.state.api = api
    return application


def openapi_document() -> dict[str, Any]:
    error = {"$ref": "#/components/schemas/Error"}

    def operation(summary: str, role: str, *statuses: int) -> dict[str, Any]:
        responses: dict[str, Any] = {"200": {"description": "Success"}}
        for status in statuses:
            responses[str(status)] = {
                "description": "See the error code",
                "content": {"application/json": {"schema": error}},
            }
        return {
            "summary": f"{summary} ({role})",
            "security": [] if role == "public" else [{"apiKeyAuth": []}],
            "responses": responses,
        }

    paths: dict[str, Any] = {
        "/health": {"get": operation("Liveness", "public")},
        "/audit/public-key": {"get": operation("Checkpoint public key", "public")},
        "/audit/events": {
            "post": operation(
                "Append an audit event", "writer", 401, 403, 413, 422, 503
            ),
            "get": operation(
                "Query audit events (cursor paging)", "reader", 401, 403, 422, 503
            ),
        },
        "/audit/events/{eventId}": {
            "get": operation("Get one retained event", "reader", 401, 403, 404, 503)
        },
        "/audit/checkpoints": {
            "get": operation("List signed checkpoints", "auditor", 401, 403, 422)
        },
        "/audit/admin/checkpoints": {
            "post": operation("Create a checkpoint", "admin", 401, 403, 409, 503)
        },
        "/audit/verify": {
            "get": operation("Verify the whole ledger", "auditor", 401, 403, 503)
        },
        "/audit/export": {
            "get": operation("Signed v1 export bundle", "auditor", 401, 403, 422, 503)
        },
        "/audit/export-sets": {
            "post": operation(
                "Create a signed export set", "auditor", 401, 403, 422, 429, 503
            )
        },
        "/audit/export-sets/{exportSetId}": {
            "get": operation("Describe an export set", "auditor", 401, 403, 404)
        },
        "/audit/export-sets/{exportSetId}/manifest": {
            "get": operation(
                "Download the signed manifest", "auditor", 401, 403, 404, 409, 410
            )
        },
        "/audit/export-sets/{exportSetId}/chunks/{name}": {
            "get": operation("Download one chunk", "auditor", 401, 403, 404, 409, 410)
        },
        "/audit/admin/redactions": {
            "post": operation(
                "Redact payload values", "admin", 401, 403, 404, 409, 422, 503
            )
        },
        "/audit/admin/redaction-cleanups": {
            "get": operation("Redaction cleanup status", "admin", 401, 403)
        },
        "/audit/admin/redaction-cleanups/retry": {
            "post": operation("Retry redaction cleanup", "admin", 401, 403)
        },
        "/audit/admin/archive": {
            "post": operation(
                "Archive expired records (dryRun supported)",
                "admin",
                401,
                403,
                409,
                422,
                500,
                503,
            )
        },
        "/audit/admin/archive-jobs": {
            "get": operation("Archive job status", "admin", 401, 403)
        },
        "/audit/admin/archive-jobs/reconcile": {
            "post": operation("Reconcile archive jobs", "admin", 401, 403, 409)
        },
        "/audit/archive-audit": {
            "get": operation("Audit archive files", "auditor", 401, 403, 503)
        },
    }
    paths["/compliance/account-access-report"] = {
        "get": operation(
            "Account-access report (one snapshot; capped at 10000 records)",
            "auditor",
            401,
            403,
            422,
            503,
        )
    }
    return {
        "openapi": "3.0.3",
        "info": {"title": "Audit log service (Python)", "version": "0.1.0"},
        "paths": paths,
        "components": {
            "securitySchemes": {
                "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "required": ["error"],
                    "properties": {
                        "error": {
                            "type": "object",
                            "required": ["code", "message", "details"],
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                                "details": {"type": "array", "items": {}},
                            },
                        }
                    },
                }
            },
        },
    }

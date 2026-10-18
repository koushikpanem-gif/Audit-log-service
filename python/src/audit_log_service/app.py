from __future__ import annotations

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
from audit_log_service.auth import ApiKeyAuthenticator, Principal
from audit_log_service.canonical_json import (
    MAX_INPUT_BYTES,
    CanonicalJsonError,
    parse_json,
)
from audit_log_service.configuration import AuditConfiguration
from audit_log_service.errors import ApiError, invalid
from audit_log_service.ledger import (
    AppendService,
    Clock,
    QueryService,
    parse_append_request,
    system_clock,
)
from audit_log_service.signing import CheckpointSigner
from audit_log_service.store import (
    SqliteStore,
    StorageBusyError,
    StorageConflictError,
    StorageError,
)

Handler = Callable[[Request], Awaitable[Response]]

# Routes in the contract that later actions implement. They authenticate and
# authorize like the real routes, then report that they are not built.
_UNBUILT: tuple[tuple[str, str, frozenset[str], str], ...] = (
    ("GET", "/audit/verify", auth.AUDITOR_ROLES, "Ledger verification"),
    ("GET", "/audit/export", auth.AUDITOR_ROLES, "Signed export"),
    ("POST", "/audit/admin/redactions", auth.ADMIN_ROLES, "Redaction"),
    ("POST", "/audit/admin/archive", auth.ADMIN_ROLES, "Archiving"),
    (
        "GET",
        "/compliance/account-access-report",
        auth.AUDITOR_ROLES,
        "The account-access report",
    ),
)


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

    def unbuilt(self, roles: frozenset[str], feature: str) -> Handler:
        async def handler(request: Request) -> Response:
            self.principal(request, roles)
            raise ApiError(
                501,
                "NOT_IMPLEMENTED",
                f"{feature} is not implemented in the Python service yet",
            )

        return handler

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
    ]
    routes.extend(
        Route(path, api.unbuilt(roles, feature), methods=[method])
        for method, path, roles, feature in _UNBUILT
    )
    handlers: dict[Any, Any] = {
        ApiError: _api_error,
        HTTPException: _http_error,
        StorageError: _storage_error,
        Exception: _unexpected,
    }
    return Starlette(routes=routes, exception_handlers=handlers)


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
    }
    for method, path, roles, feature in _UNBUILT:
        role = "admin" if roles == auth.ADMIN_ROLES else "auditor"
        paths[path] = {
            method.lower(): operation(
                f"{feature} - always 501 in this build", role, 401, 403, 501
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

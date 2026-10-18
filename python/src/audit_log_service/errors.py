from __future__ import annotations

from collections.abc import Sequence


class ApiError(Exception):
    """An error that maps directly to the public error shape."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: Sequence[object] = (),
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = list(details)


def invalid(message: str) -> ApiError:
    return ApiError(422, "INVALID_INPUT", message)

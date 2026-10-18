from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route


async def health(_: Request) -> Response:
    return JSONResponse({"status": "UP"})


def create_app() -> Starlette:
    return Starlette(routes=[Route("/health", health)])


app = create_app()

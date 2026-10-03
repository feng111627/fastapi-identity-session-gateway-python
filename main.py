import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import load_settings
from app.errors import AuthError, ErrorCode
from app.routes import admin_router, auth_router, resource_router
from app.seed import seed_demo_users
from app.service import AuthService
from app.store import Store

_STATUS_BY_CODE = {
    ErrorCode.NOT_AUTHENTICATED: 401,
    ErrorCode.TOKEN_INVALID: 401,
    ErrorCode.TOKEN_EXPIRED: 401,
    ErrorCode.SESSION_REVOKED: 401,
    ErrorCode.REFRESH_INVALID: 401,
    ErrorCode.REFRESH_EXPIRED: 401,
    ErrorCode.REFRESH_REUSED: 401,
    ErrorCode.BAD_CREDENTIALS: 401,
    ErrorCode.FORBIDDEN: 403,
}


def create_app(settings=None) -> FastAPI:
    settings = settings or load_settings()
    store = Store()
    seed_demo_users(store)
    service = AuthService(store, settings)

    app = FastAPI(title="identity-session-gateway")
    app.state.settings = settings
    app.state.store = store
    app.state.service = service

    @app.exception_handler(AuthError)
    async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(
            status_code=_STATUS_BY_CODE.get(exc.code, 401),
            content={"detail": {"code": exc.code.value, "message": exc.message}},
        )

    app.include_router(auth_router)
    app.include_router(resource_router)
    app.include_router(admin_router)

    @app.get("/")
    def read_root():
        return {"Hello": "World"}

    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)

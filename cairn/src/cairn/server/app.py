from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from cairn import __version__
from cairn.server import auth_db, db, product_db
from cairn.server.middleware.auth import require_auth
from cairn.server.routers import (
    auth,
    activity,
    business_graph,
    export,
    findings,
    hints,
    intents,
    maintenance,
    projects,
    quality,
    report_enrichments,
    review_tasks,
    settings,
    sources,
    templates,
    timeline,
    tool_scans,
    vulnerabilities,
    workers,
)

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.configure(db.DEFAULT_DB)
    auth_db.configure_auth_db()
    product_db.configure_product_db()
    yield


app = FastAPI(
    title="Rabbit Code Audit",
    description="Fact-graph based collaborative source code audit system",
    version=__version__,
    lifespan=lifespan,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    )
    if request.url.path.startswith("/api/") or request.url.path.startswith("/settings"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response

# Authentication router (login/register/logout/me/password). Its own endpoints
# are exempt from auth so users can obtain a session.
app.include_router(auth.router)

# Existing routers are protected via the shared ``require_auth`` dependency
# applied at include time, WITHOUT modifying the router modules themselves.
#
# ``require_auth`` is a dual-auth dependency: it accepts either a browser session
# cookie or the dispatcher's ``X-Cairn-Internal-Token`` header. Protected routers
# are closed by default; local/test compatibility can be explicitly enabled with
# ``CAIRN_AUTH_OPEN_MODE=1``. See ``cairn.server.middleware.auth`` for details.
_protected = [Depends(require_auth)]

app.include_router(settings.router, dependencies=_protected)
app.include_router(maintenance.router, dependencies=_protected)
app.include_router(projects.router, dependencies=_protected)
app.include_router(quality.router, dependencies=_protected)
app.include_router(sources.router, dependencies=_protected)
app.include_router(hints.router, dependencies=_protected)
app.include_router(intents.router, dependencies=_protected)
app.include_router(export.router, dependencies=_protected)
app.include_router(findings.router, dependencies=_protected)
app.include_router(vulnerabilities.router, dependencies=_protected)
app.include_router(report_enrichments.router, dependencies=_protected)
app.include_router(review_tasks.router, dependencies=_protected)
app.include_router(tool_scans.router, dependencies=_protected)
app.include_router(workers.router, dependencies=_protected)
app.include_router(templates.router, dependencies=_protected)
app.include_router(timeline.router, dependencies=_protected)
app.include_router(activity.router, dependencies=_protected)
app.include_router(business_graph.router, dependencies=_protected)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

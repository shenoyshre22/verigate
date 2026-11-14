"""Lambda entry point: runs the team's FastAPI app (backend/app/main.py) behind API Gateway.

main.py is owned by the module authors and is not edited here. Routers that main.py does not
include yet are added below, but only when their paths are not already registered, so this stays
correct (no duplicate routes) once main.py includes them itself, with or without a prefix.
"""
import importlib
import logging

from mangum import Mangum

from backend.app.main import app

log = logging.getLogger(__name__)

# (module path, a path the router serves). The reporting router is optional and may not exist yet.
EXTRA_ROUTERS = [
    ("backend.modules.decision_engine.api", "/decision/evaluate"),
    ("backend.modules.reporting.api", "/reports/explain"),
    # Shreya's liveness router. By its own design it answers 503 until the host app overrides
    # get_authenticated_user_id and get_ownership_store, so mounting it never opens anything.
    ("backend.modules.face_authentication.liveness.routes", "/face-auth/liveness/session"),
]


def served_paths(routes, prefix: str = "") -> list:
    """Every served path, duplicates kept. Handles flattened routes (older FastAPI) and the
    lazily included routers of newer FastAPI (original_router + include_context.prefix)."""
    out = []
    for r in routes:
        path = getattr(r, "path", None)
        if isinstance(path, str):
            out.append(prefix + path)
            continue
        inner = getattr(r, "original_router", None)
        if inner is not None:
            ctx = getattr(r, "include_context", None)
            out.extend(served_paths(inner.routes, prefix + (getattr(ctx, "prefix", "") or "")))
    return out


def _has_route(fastapi_app, suffix: str) -> bool:
    from fastapi.openapi.utils import get_openapi

    paths = set(served_paths(fastapi_app.routes))
    try:  # public API as a second opinion, without touching app.openapi_schema's cache
        paths |= set(get_openapi(title="probe", version="0", routes=fastapi_app.routes)["paths"])
    except Exception:  # noqa: BLE001 - the route walk alone is still a valid answer
        pass
    return any(p.endswith(suffix) for p in paths)


def include_missing_routers(fastapi_app, routers=EXTRA_ROUTERS) -> list:
    added = []
    for module_path, marker in routers:
        if _has_route(fastapi_app, marker):
            continue  # main.py already serves it
        try:
            module = importlib.import_module(module_path)
        except ModuleNotFoundError as e:
            if e.name != module_path:
                raise  # the module exists but one of its own imports is broken: fail loudly
            continue
        fastapi_app.include_router(module.router)
        added.append(module_path)
    if added:
        log.info("handler included routers not yet in main.py: %s", added)
    return added


include_missing_routers(app)
handler = Mangum(app, lifespan="off")

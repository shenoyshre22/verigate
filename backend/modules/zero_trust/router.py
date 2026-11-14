"""Standalone access-decision router. Mount it from the owning application when approved."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import StrictStr, ValidationError
from starlette.concurrency import run_in_threadpool

from .engine import ZeroTrustDecisionEngine, ZeroTrustDecisionResult
from .schemas import AccessRequest, DomainModel


class APIErrorDetail(DomainModel):
    code: StrictStr
    message: StrictStr


class APIErrorResponse(DomainModel):
    error: APIErrorDetail


def get_zero_trust_engine(request: Request) -> ZeroTrustDecisionEngine | None:
    """Resolve the engine from app state; tests and hosts can override this dependency."""

    return getattr(request.app.state, "zero_trust_decision_engine", None)


router = APIRouter()


@router.post(
    "/api/v1/access/decide",
    response_model=ZeroTrustDecisionResult,
    responses={
        400: {"model": APIErrorResponse, "description": "Malformed JSON request"},
        422: {"model": APIErrorResponse, "description": "Invalid access request"},
        503: {"model": APIErrorResponse, "description": "Decision engine unavailable"},
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": AccessRequest.model_json_schema()}},
        }
    },
)
async def decide_access(
    request: Request,
    engine: ZeroTrustDecisionEngine | None = Depends(get_zero_trust_engine),
):
    """Evaluate a caller's request; trusted evidence and campus records are server-side only."""

    try:
        raw_request = await request.json()
    except Exception:
        return _error(400, "INVALID_JSON", "Request body must be valid JSON.")

    try:
        access_request = AccessRequest.model_validate(raw_request)
    except ValidationError:
        return _error(422, "INVALID_ACCESS_REQUEST", "Request does not match the access contract.")

    if engine is None:
        return _error(503, "DECISION_ENGINE_UNAVAILABLE", "Access decisions are temporarily unavailable.")

    try:
        raw_result = await run_in_threadpool(engine.evaluate, access_request)
        result = ZeroTrustDecisionResult.model_validate(raw_result)
    except Exception:
        # Never expose provider errors, rejected payloads, or internal exception details.
        return _error(503, "DECISION_UNAVAILABLE", "A safe access decision could not be completed.")
    return result


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    payload = APIErrorResponse(error=APIErrorDetail(code=code, message=message))
    return JSONResponse(status_code=status_code, content=payload.model_dump(mode="json"))

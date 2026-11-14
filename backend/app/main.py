"""FastAPI application entry point for VERIGATE."""

from fastapi import FastAPI

from backend.modules.face_authentication.router import router as face_authentication_router
from backend.modules.face_recognition.router import router as face_recognition_router

app = FastAPI(
    title="VERIGATE Backend",
    description="Zero-Trust multimodal identity verification backend.",
    version="0.1.0",
)

app.include_router(face_authentication_router)
app.include_router(face_recognition_router)


@app.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    """Return a lightweight service health response."""

    return {"status": "ok"}

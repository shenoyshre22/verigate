"""FastAPI application entry point for VERIGATE."""

from fastapi import FastAPI

app = FastAPI(
    title="VERIGATE Backend",
    description="Zero-Trust multimodal identity verification backend.",
    version="0.1.0",
)


@app.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    """Return a lightweight service health response."""

    return {"status": "ok"}

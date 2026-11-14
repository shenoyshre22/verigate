"""Lambda entry point: runs the team's FastAPI app (backend/app/main.py) behind API Gateway.

This file only wraps the app; it does not change any routes. Routes are owned by the module authors.
"""
from mangum import Mangum

from backend.app.main import app

handler = Mangum(app, lifespan="off")

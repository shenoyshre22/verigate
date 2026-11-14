"""The Lambda handler serves the decision routes exactly once, with or without main.py including them."""
import importlib.util
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI

HANDLER = Path(__file__).resolve().parents[3] / "aws" / "lambda" / "handler.py"


def load_handler():
    spec = importlib.util.spec_from_file_location("verigate_lambda_handler", HANDLER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def handler_module():
    return load_handler()


def count(app, path):
    module = sys.modules["verigate_lambda_handler"]
    return module.served_paths(app.routes).count(path)


def test_route_walk_counts_duplicates(handler_module):
    from backend.modules.decision_engine.api import router

    app = FastAPI()
    app.include_router(router)
    app.include_router(router)
    assert count(app, "/decision/evaluate") == 2  # proves count() would catch a double include


def test_handler_serves_decision_routes_exactly_once(handler_module):
    app = handler_module.app
    assert count(app, "/decision/evaluate") == 1
    assert count(app, "/decision/offline-sync") == 1
    assert count(app, "/health") == 1


def test_reimporting_handler_does_not_duplicate(handler_module):
    module = load_handler()  # same app object from backend.app.main
    assert count(module.app, "/decision/evaluate") == 1
    assert count(module.app, "/decision/offline-sync") == 1


def test_skips_router_main_already_includes_with_prefix(handler_module):
    from backend.modules.decision_engine.api import router

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")  # what Shreya may do in main.py
    assert handler_module.include_missing_routers(app) == []
    assert count(app, "/decision/evaluate") == 0 and count(app, "/api/v1/decision/evaluate") == 1


def test_missing_optional_router_is_skipped(handler_module):
    app = FastAPI()
    added = handler_module.include_missing_routers(app, [("backend.modules.reporting.api", "/reports/explain")])
    assert added == []

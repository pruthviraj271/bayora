"""
Entrypoint for the Bayora Systems Python Backend Server.
Can be run directly via `python3 -m backend.app.main` or `uvicorn backend.app.main:app`.
"""
from __future__ import annotations

import os
from .api import create_bayora_app
from .compat import run_http_server


app = create_bayora_app(
    db_path=os.environ.get("BAYORA_DB_PATH", "bayora.db"),
    seed_demo_data=os.environ.get("BAYORA_SKIP_SEED", "0") != "1",
)


if __name__ == "__main__":
    port = int(os.environ.get("BAYORA_BACKEND_PORT", "8000"))
    host = os.environ.get("BAYORA_BACKEND_HOST", "127.0.0.1")
    print(f"[Bayora Control Plane] Starting Python backend on http://{host}:{port} ...")
    run_http_server(app, host=host, port=port)

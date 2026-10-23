"""
Bayora Systems — Isolated Blue Team Worker Service (blue-net + control-net).
Configures defensive guards via the Control Plane. Isolated from red-net.
"""
from __future__ import annotations

import json
import os
import urllib.request


CONTROL_PLANE_URL = os.environ.get("BAYORA_CONTROL_PLANE_URL", "http://control-plane:8000")
ACTOR_ID = os.environ.get("BAYORA_BLUE_ACTOR", "blue-worker-node@blue.bayora")


def submit_defense_via_control_plane(test_id: str, defense_name: str, rule_type: str, secret_rule: str) -> dict:
    req = urllib.request.Request(
        f"{CONTROL_PLANE_URL}/api/tests/{test_id}/defenses",
        data=json.dumps(
            {
                "defense_name": defense_name,
                "rule_type": rule_type,
                "defense_config_secret": secret_rule,
            }
        ).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Bayora-Role": "BLUE_TEAM",
            "X-Bayora-Actor": ACTOR_ID,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))

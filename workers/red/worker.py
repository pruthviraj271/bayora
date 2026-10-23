"""
Bayora Systems — Isolated Red Team Worker Service (red-net + control-net).
Cannot reach blue-worker directly (no shared network without internal isolation;
red-worker is attached ONLY to red-net and control-net, and control-net firewall
policy rejects direct peer-to-peer worker traffic).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


CONTROL_PLANE_URL = os.environ.get("BAYORA_CONTROL_PLANE_URL", "http://control-plane:8000")
ACTOR_ID = os.environ.get("BAYORA_RED_ACTOR", "red-worker-node@red.bayora")


def submit_payload_via_control_plane(test_id: str, category: str, severity: str, payload_text: str) -> dict:
    req = urllib.request.Request(
        f"{CONTROL_PLANE_URL}/api/tests/{test_id}/payloads",
        data=json.dumps(
            {
                "category": category,
                "severity_tier": severity,
                "payload_text": payload_text,
            }
        ).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Bayora-Role": "RED_TEAM",
            "X-Bayora-Actor": ACTOR_ID,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))

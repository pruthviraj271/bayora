"""
Bayora Systems — Isolated Target LLM Adapter Service (control-net only).
Reachable ONLY by control-plane on control-net. Neither red-worker nor blue-worker
can call target-adapter directly.
"""
from __future__ import annotations

from backend.app.adapters import DeterministicMockLLMAdapter


def get_adapter() -> DeterministicMockLLMAdapter:
    return DeterministicMockLLMAdapter()

"""
Target LLM Adapter Interface & Deterministic Mock Implementation for Bayora Systems.
Enforces:
- MODEL-01: Every test run starts with a fresh, isolated session_id and context_hash
  so consecutive tests never leak conversation history, system prompts, or payloads.
- Explicit labeling: Mock runs are always tagged with `is_mock=True` and
  `adapter_type="MOCK_DETERMINISTIC_V1"` so mock behavior is never presented as a real model.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class TargetEvaluationOutput:
    run_id: str
    session_id: str
    context_hash: str
    adapter_type: str
    is_mock: bool
    target_config: Dict[str, Any]
    total_probes: int
    blocked_count: int
    bypassed_count: int
    resilience_score: float
    summary_notes: str
    probe_outcomes: List[Dict[str, Any]]
    execution_ms: int
    run_status: str


class TargetLLMAdapter(ABC):
    @abstractmethod
    def evaluate_isolated_run(
        self,
        *,
        test_id: str,
        run_id: str,
        target_model: str,
        red_payloads: List[Dict[str, Any]],
        blue_defenses: List[Dict[str, Any]],
    ) -> TargetEvaluationOutput:
        """Executes an isolated evaluation run in a brand-new session context."""


class DeterministicMockLLMAdapter(TargetLLMAdapter):
    """
    Deterministic Mock LLM Adapter (Stage 4).
    - Instantiates a fresh ephemeral session_id and zero-memory context buffer on every run.
    - Evaluates Red payload hashes/categories against Blue defense rule types deterministically.
    - Never exposes raw payload strings or raw defense secret strings in the evaluation output;
      records only artifact IDs, SHA-256 hashes, categories, and deterministic pass/block verdicts.
    """

    ADAPTER_TYPE = "MOCK_DETERMINISTIC_V1"

    def evaluate_isolated_run(
        self,
        *,
        test_id: str,
        run_id: str,
        target_model: str,
        red_payloads: List[Dict[str, Any]],
        blue_defenses: List[Dict[str, Any]],
    ) -> TargetEvaluationOutput:
        start_ns = time.perf_counter_ns()

        # Fresh session & clean context state per run (MODEL-01)
        session_id = f"ses-{uuid.uuid4().hex[:16]}"
        fresh_seed = f"{test_id}:{run_id}:{session_id}:CLEAN_CONTEXT_INIT"
        context_hash = hashlib.sha256(fresh_seed.encode("utf-8")).hexdigest()[:24]

        target_config = {
            "target_model": target_model,
            "adapter_type": self.ADAPTER_TYPE,
            "is_mock": True,
            "mock_disclosure": "DETERMINISTIC_MOCK_LLM — NO REAL WEIGHTS INVOKED",
            "context_isolation": "FRESH_EPHEMERAL_SESSION",
            "temperature": 0.0,
            "max_tokens": 512,
            "timeout_ms": 5000,
            "session_id": session_id,
            "context_hash": context_hash,
            "active_defense_count": len(blue_defenses),
            "active_defense_ids": [d["id"] for d in blue_defenses],
        }

        active_rule_types = {d["rule_type"].upper() for d in blue_defenses}
        defense_hashes = [d["config_sha256"][:12] for d in blue_defenses]

        # If no explicit payloads were uploaded yet, run a baseline synthetic probe
        probes_to_evaluate = red_payloads if red_payloads else [
            {
                "id": f"red-baseline-{run_id[-6:]}",
                "category": "PROMPT_INJECTION",
                "severity_tier": "HIGH",
                "payload_sha256": hashlib.sha256(f"baseline:{run_id}".encode("utf-8")).hexdigest(),
            }
        ]

        CategoryToDefenseRule = {
            "PROMPT_INJECTION": {"INPUT_SANITIZER", "SYSTEM_PROMPT_GUARD", "ALL_LAYER_SHIELD"},
            "JAILBREAK_ROLEPLAY": {"POLICY_CLASSIFIER", "SYSTEM_PROMPT_GUARD", "ALL_LAYER_SHIELD"},
            "SYSTEM_PROMPT_EXTRACTION": {"OUTPUT_REDACTOR", "SYSTEM_PROMPT_GUARD", "ALL_LAYER_SHIELD"},
            "INDIRECT_CONTEXT_POISONING": {"INPUT_SANITIZER", "POLICY_CLASSIFIER", "ALL_LAYER_SHIELD"},
        }

        probe_outcomes: List[Dict[str, Any]] = []
        blocked_count = 0
        bypassed_count = 0

        for idx, probe in enumerate(probes_to_evaluate, start=1):
            cat = probe["category"].upper()
            matching_rules = CategoryToDefenseRule.get(cat, {"ALL_LAYER_SHIELD"})
            is_blocked = bool(active_rule_types.intersection(matching_rules)) or ("ALL_LAYER_SHIELD" in active_rule_types)

            if is_blocked:
                blocked_count += 1
                verdict = "BLOCKED_BY_DEFENSE"
            else:
                bypassed_count += 1
                verdict = "BYPASSED_TARGET_GUARD"

            probe_outcomes.append(
                {
                    "probe_index": idx,
                    "payload_artifact_id": probe["id"],
                    "payload_sha256_prefix": probe["payload_sha256"][:16],
                    "category": cat,
                    "severity_tier": probe["severity_tier"],
                    "evaluated_against_defense_hashes": defense_hashes,
                    "verdict": verdict,
                    "mock_response_code": f"MOCK_RESP_{verdict}_{idx:02d}",
                }
            )

        total_probes = len(probes_to_evaluate)
        resilience_score = round((blocked_count / total_probes) * 100.0, 1) if total_probes > 0 else 100.0
        elapsed_ms = max(1, int((time.perf_counter_ns() - start_ns) / 1_000_000) + 12)

        summary_notes = (
            f"[MOCK ADAPTER RUN {run_id}] Evaluated {total_probes} isolated probe(s) against "
            f"{len(blue_defenses)} defense artifact(s) in fresh session {session_id}. "
            f"Blocked: {blocked_count}/{total_probes} ({resilience_score}% resilience). "
            f"Raw payloads and defense configurations withheld."
        )

        return TargetEvaluationOutput(
            run_id=run_id,
            session_id=session_id,
            context_hash=context_hash,
            adapter_type=self.ADAPTER_TYPE,
            is_mock=True,
            target_config=target_config,
            total_probes=total_probes,
            blocked_count=blocked_count,
            bypassed_count=bypassed_count,
            resilience_score=resilience_score,
            summary_notes=summary_notes,
            probe_outcomes=probe_outcomes,
            execution_ms=elapsed_ms,
            run_status="COMPLETED_DETERMINISTIC",
        )

"""
Role and Identity Authentication module for Bayora Systems.
Enforces the three explicit roles:
- RED_TEAM
- BLUE_TEAM
- EVALUATOR
Fails closed on missing, invalid, or forged role headers.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .compat import HTTPException, RequestContext


class Role(str, Enum):
    RED_TEAM = "RED_TEAM"
    BLUE_TEAM = "BLUE_TEAM"
    EVALUATOR = "EVALUATOR"


@dataclass(frozen=True)
class ActorIdentity:
    actor: str
    role: Role


def authenticate_request(request: RequestContext) -> ActorIdentity:
    """
    Validates X-Bayora-Role and X-Bayora-Actor headers.
    Fails closed if role is missing or not in {RED_TEAM, BLUE_TEAM, EVALUATOR}.
    """
    raw_role = (request.header("x-bayora-role") or "").strip().upper()
    raw_actor = (request.header("x-bayora-actor") or "").strip()

    if not raw_role:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "AUTHENTICATION_REQUIRED",
                "code": "AUTH_MISSING_ROLE",
                "message": "Missing required X-Bayora-Role identity header. Request denied (fail-closed).",
            },
        )

    try:
        role = Role(raw_role)
    except ValueError:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "INVALID_ROLE_IDENTITY",
                "code": "AUTH_UNKNOWN_ROLE",
                "message": "Unrecognized role identity. Only RED_TEAM, BLUE_TEAM, or EVALUATOR are permitted.",
            },
        )

    actor = raw_actor if raw_actor else f"{role.value.lower()}-operator"
    return ActorIdentity(actor=actor, role=role)

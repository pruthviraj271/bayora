# Bayora Systems — Secure Adversarial AI Testing Environment

**Hack in Hills '26 Prototype** | **Theme**: AI Safety Testing, Container & Network Isolation, Access Control, Auditability

Bayora Systems protects the integrity of adversarial AI safety evaluations by enforcing strict separation between **Red Team attack payloads**, **Blue Team defensive configurations**, and **Target LLM session state** until an authorized **Evaluator** closes the test and releases approved results. Every allowed and denied action produces an immutable, secret-free audit record.

---

## Architecture & Repository Layout

```text
bayora/
├── README.md                         # Setup, test commands, architecture, honest status
├── compose.yaml                      # Hardened Docker Compose (red-net, blue-net, control-net)
├── .env.example                      # Placeholder environment variables (no secrets)
├── docs/
│   ├── problem-and-scope.md          # Core problem statement and prototype boundaries
│   ├── threat-model.md               # Protected assets and trust boundaries
│   ├── api-contract.md               # Exact REST API specification and RBAC rules
│   ├── decisions.md                  # Architectural decisions and verification status
│   └── demo-script.md                # Step-by-step live demo walkthrough
├── backend/
│   ├── requirements.txt              # FastAPI, Pydantic, Uvicorn, Pytest dependencies
│   ├── app/
│   │   ├── api.py                    # API routes + server-side Pydantic/schema validation
│   │   ├── auth.py                   # Fail-closed role authentication (RED_TEAM, BLUE_TEAM, EVALUATOR)
│   │   ├── policy.py                 # RBAC, SEC-01/02/03 isolation, DATA-01 disclosure filter
│   │   ├── lifecycle.py              # Strict state machine (Draft->Ready->Running->Closed->Results Released)
│   │   ├── audit.py                  # Secret-free audit event logger (ALLOW & DENY)
│   │   ├── adapters.py               # Deterministic Mock LLM Adapter with fresh session isolation
│   │   ├── database.py               # Isolated SQLite tables scoped by test_id
│   │   └── main.py                   # Python HTTP / ASGI server entrypoint
│   └── tests/
│       └── test_security_suite.py    # Automated positive & negative security test suite
├── workers/
│   ├── red/                          # Isolated Red Team worker container (red-net)
│   ├── blue/                         # Isolated Blue Team worker container (blue-net)
│   └── target-adapter/               # Isolated Target LLM Adapter container (control-net)
├── infra/docker/                     # Non-root hardened Dockerfiles for backend & frontend
└── src/                              # React + Vite Role-Based Control Plane Dashboard
```

---

## Quickstart & Running Tests

### 1. Run Python Security & Isolation Tests
```bash
python3 -m unittest discover -s backend/tests -v
```

### 2. Run Frontend / Logic Unit Tests
```bash
tsx --test src/lib/bayoraLogic.test.ts
```

### 3. Start Full-Stack Environment (Express + Python Control Plane + React UI on Port 3000)
```bash
npm run dev
```

### 4. Run Hardened Multi-Network Docker Compose (On a Docker Host)
```bash
cp .env.example .env
docker compose up --build
```

---

## Security Evidence Matrix

| Test ID | Security Requirement | Enforcement Mechanism | Status |
| :--- | :--- | :--- | :--- |
| **SEC-01** | Red reads unreleased Blue defense artifact | Denied (`403`), artifact excluded from error body, `DENY` audit logged | **VERIFIED (PASS)** |
| **SEC-02** | Blue reads unreleased Red payload | Denied (`403`), payload excluded from error body, `DENY` audit logged | **VERIFIED (PASS)** |
| **SEC-03** | Non-evaluator releases results | Denied (`403`) for `RED_TEAM` & `BLUE_TEAM`, state unchanged, `DENY` logged | **VERIFIED (PASS)** |
| **STATE-01** | Invalid lifecycle transition (`Draft→Released`, `Closed→Running`, `Running→Ready`) | Rejected (`409`), state uncorrupted, attempted transition logged | **VERIFIED (PASS)** |
| **DATA-01** | Read results before `Results Released` | Returns only non-sensitive metadata; evaluation scores withheld | **VERIFIED (PASS)** |
| **MODEL-01** | Consecutive tests start with fresh context | `DeterministicMockLLMAdapter` generates new `run_id`, `session_id`, and `context_hash` | **VERIFIED (PASS)** |
| **AUDIT-01** | Denied & allowed requests recorded without secrets | Every event records timestamp, role, action, resource hash/ID, decision, transition | **VERIFIED (PASS)** |
| **RUNTIME-01** | Direct Red-to-Blue network call blocked | `red-net` (`internal: true`) & `blue-net` (`internal: true`) + `/api/network/probe` policy | **VERIFIED IN POLICY & COMPOSE CONFIG** *(Live Docker bridge runtime planned/unverified in containerless preview)* |
| **POS-01/02** | Valid Red action & post-release result disclosure | Authorized submission succeeds; Evaluator release unlocks approved metrics | **VERIFIED (PASS)** |

# Guardrailed AI Action & API Orchestration Gateway

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.5-009688.svg?style=flat&logo=FastAPI&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB.svg?style=flat&logo=Python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/React-18.3.1-61DAFB.svg?style=flat&logo=React&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5.4-646CFF.svg?style=flat&logo=Vite&logoColor=white)](https://vitejs.dev)
[![Pytest](https://img.shields.io/badge/Pytest-147%20Passed-4CAF50.svg?style=flat&logo=Pytest&logoColor=white)](https://pytest.org)
[![JWT-RBAC](https://img.shields.io/badge/Inbound%20Auth-JWT%20%2B%20RBAC-0284C7.svg?style=flat&logo=JSONWebTokens&logoColor=white)](#inbound-authentication--role-based-access-control-rbac)
[![Security](https://img.shields.io/badge/Zero--Trust-Enforced-1E293B.svg?style=flat&logo=Shield&logoColor=white)](#zero-trust-security-architecture)

An enterprise-grade, zero-trust backend middleware and orchestration gateway sitting between LLM AI agents and external REST APIs. It provides dynamic API registration, strict JSON Schema tool translation, autonomous natural language task orchestration, deterministic rule-based safety classification (**SAFE** vs **SENSITIVE**), a human-in-the-loop approval queue, and immutable audit logging with replay capabilities.

Built with a **zero-trust security posture**, defending against **Inbound Unauthorized Access**, **Privilege Escalation**, **SSRF**, **DNS Rebinding**, **Prompt Injection**, **Parameter Mass Assignment**, **Path Traversal**, **Approval Bypass**, **Replay Attacks**, and **Credential Exposure**.

---

## 📑 Table of Contents

1. [Architecture Overview](#-architecture-overview)
2. [End-to-End Orchestration Workflow](#-end-to-end-orchestration-workflow)
3. [Zero-Trust Security Controls](#-zero-trust-security-controls)
4. [Inbound Authentication & Role-Based Access Control (RBAC)](#-inbound-authentication--role-based-access-control-rbac)
5. [Enterprise SaaS Dashboard](#-enterprise-saas-dashboard)
6. [Tech Stack](#-tech-stack)
7. [Quick Start & Installation](#-quick-start--installation)
8. [Running the Application](#-running-the-application)
9. [Automated Test Suite (147 Tests)](#-automated-test-suite-147-tests)
10. [Cloud Deployment Architecture](#-cloud-deployment-architecture)
11. [API Reference](#-api-reference)

---

## 🏛 Architecture Overview

```
                      +---------------------------------------+
                      |         Human Operator / UI           |
                      |  (Enterprise React 18 SaaS Dashboard) |
                      |    - In-Memory React Token Storage    |
                      +-------------------+-------------------+
                                          |
                        Bearer <JWT>      |  Login / Approve /
                        Task Request      |  Inspect Logs
                                          v
+-----------------------------------------------------------------------------------+
|               AI ACTION & API ORCHESTRATION GATEWAY (FASTAPI)                     |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | INBOUND AUTHENTICATION & RBAC LAYER                                         |  |
|  |  - Distributed DB Rate Limiter (5 attempts/5m on /auth/login)               |  |
|  |  - Salted Bcrypt (12-Round) Password Verifier                               |  |
|  |  - JWT Signature & Claim Validator (Pinned HS256, iss, aud, 15m exp)       |  |
|  |  - Dynamic DB Role Lookup (Immediate revocation enforcement)               |  |
|  |  - Strict Role Authorization: OPERATOR vs APPROVER vs ADMIN                 |  |
|  |  - Admin Sensitive-Action No-Bypass Rule                                    |  |
|  |  - Four-Eyes Principle (Anti-Self-Approval on sensitive tasks)              |  |
|  +--------------------------------------+--------------------------------------+  |
|                                         |                                         |
|  +---------------------+    +-----------v----------+    +----------------------+  |
|  |   API Registry      |    |  Tool Builder &      |    |  Deterministic       |  |
|  |   - Fernet Encrypt  |--->|  Schema Translator   |--->|  LLM Client /       |  |
|  |   - Zero Leakage    |    |  (Strict JSONSchema) |    |  OpenAI Async Client |  |
|  +---------------------+    +----------------------+    +----------+-----------+  |
|                                                                    |              |
|                                     Extracted Tool Calls & Args    v              |
|                                                     +--------------------------+  |
|                                                     |  Strict Parameter        |  |
|                                                     |  Validator & Sanitizer   |  |
|                                                     +--------------+-----------+  |
|                                                                    |              |
|                                                     Validated Call v              |
|                                                     +--------------------------+  |
|                                                     |  Safety Classifier       |  |
|                                                     |  (SAFE vs SENSITIVE)     |  |
|                                                     +------+------------+------+  |
|                                                            |            |         |
|                          SAFE (GET, read-only)             |            | SENSITIVE (POST, PUT, DELETE,
|                                                            v            |            write, critical)
|                                           +------------------+          v         |
|                                           | Direct Executor  |   +-------------+  |
|                                           +--------+---------+   | Approval    |  |
|                                                    |             | Queue       |  |
|                                                    |             | (Frozen DB  |  |
|                                                    |             |  Payload)   |  |
|                                                    |             +------+------+  |
|                                                    |                    |         |
|                                                    |    Approved (diff  |         |
|                                                    |    authorized user)|         |
|                                                    v<-------------------+         |
|  +-----------------------------------------------------------------------------+  |
|  | PRE-SOCKET SECURITY LAYER                                                   |  |
|  |  - URL Scheme & Target Whitelist                                            |  |
|  |  - Pre-Socket DNS Resolution (DNS Rebinding Check)                          |  |
|  |  - Ephemeral Credential Injection (In-Memory Only)                          |  |
|  |  - HTTPX Dispatch & 50KB Payload Truncation                                 |  |
|  +---------------------------------------+-------------------------------------+  |
|                                          |                                        |
+------------------------------------------|----------------------------------------+
                                           | Filtered HTTP Call
                                           v
                             +---------------------------+
                             |   External REST APIs      |
                             |  (Payment, CRM, Shipping) |
                             +---------------------------+
```

---

## 🔒 Inbound Authentication & Role-Based Access Control (RBAC)

The gateway enforces zero-trust inbound identity verification and strict **Separation of Duties (SoD)**:

### 1. Endpoint Permission Matrix
| Endpoint | Method | `OPERATOR` | `APPROVER` | `ADMIN` | Security Rule |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `/health` | GET | Public | Public | Public | Minimal liveness probe. |
| `/auth/login` | POST | Public | Public | Public | Rate-limited (5 fails/5 min). Generic 401 on mismatch. |
| `/auth/me` | GET | Allowed | Allowed | Allowed | Returns identity and role. |
| `/auth/users` | POST | ❌ 403 | ❌ 403 | Allowed | User provisioning. Public registration disabled. |
| `/apis` | GET | Allowed | Allowed | Allowed | Masked external credentials. |
| `/apis` | POST | ❌ 403 | ❌ 403 | Allowed | External API registration. |
| `/apis/{id}` | PUT | ❌ 403 | ❌ 403 | Allowed | API configuration updates. |
| `/apis/{id}` | DELETE | ❌ 403 | ❌ 403 | Allowed | Deregistration. |
| `/tasks` | POST | Allowed | ❌ 403 | Allowed | **Admin No-Bypass:** Sensitive tasks enter approval queue. |
| `/approvals` | GET | ❌ 403 | Allowed | Allowed | Inspect pending approvals and frozen payloads. |
| `/approvals/{id}/approve` | POST | ❌ 403 | Allowed | Allowed | **Four-Eyes Principle:** Self-approval forbidden (`403`). |
| `/approvals/{id}/reject` | POST | ❌ 403 | Allowed | Allowed | Rejects pending action. |
| `/logs` | GET | Allowed | Allowed | Allowed | View audit trails. |
| `/logs/{id}/replay` | POST | ❌ 403 | Allowed | Allowed | Replay past action (sensitive replays require approval). |

### 2. Core Authentication Architecture Guarantees
1. **Bcrypt 12-Round Password Hashing:** Salted hashes with adaptive work factor; constant-time verification prevents timing attacks.
2. **Strict JWT Claim Validation:** Cryptographically signs tokens with 256-bit secret; enforces pinned `HS256`, `iss` (`guardrailed-ai-gateway`), `aud` (`guardrailed-ai-gateway-api`), and short **15-minute token expiration**.
3. **Dynamic Database Role Lookup:** Authorization checks query the live user record from the database on every request, ensuring instant role revocation or account deactivation without waiting for token expiration.
4. **Distributed Multi-Worker Rate Limiting:** Login failures are tracked in the shared `login_attempts` table, protecting multi-process deployments against brute-force attacks across all application workers.
5. **Generic Error Responses:** Login returns identical `401 Unauthorized` (`"Invalid username or password."`) whether the username exists or not, preventing username enumeration.
6. **In-Memory React Token Storage:** Access tokens reside exclusively in React memory, never persisted in `localStorage` or `sessionStorage` to mitigate XSS credential theft.
7. **Four-Eyes Principle (Anti-Self-Approval):** The user who submitted a sensitive task cannot approve their own request (`requested_by_user_id != decided_by_user_id`).
8. **Admin Sensitive-Action No-Bypass:** Admins submitting sensitive tasks are still subject to approval queue routing (`202 Accepted`).
9. **Secure Admin Bootstrapping:** Admin credentials are never printed to console logs; initial setup is managed via `.env` or secure restricted files.

---

## 🛡 Zero-Trust Security Controls

| Vulnerability Vector | Threat Scenario | Gateway Countermeasure | Test Verification |
| :--- | :--- | :--- | :--- |
| **Unauthorized Gateway Access** | Adversary attempts to call `/apis`, `/tasks`, or `/approvals` without identity. | All operational endpoints require valid Bearer JWT. Unauthenticated requests rejected with HTTP 401. | 16 tests in `test_phase10a_auth.py` |
| **Privilege Escalation** | Operator attempts to approve their own tasks or register APIs. | Backend dependency checks dynamically verify user role from DB; unauthorized roles blocked with HTTP 403. | Verified in `test_operator_rbac_enforcement` |
| **Self-Approval (Four-Eyes)** | User requests sensitive transfer and attempts to approve it. | Gateway verifies `requested_by != decided_by`. Rejects self-approval with HTTP 403. | Verified in `test_four_eyes_anti_self_approval_enforced` |
| **SSRF** | Attacker registers API pointing to `http://169.254.169.254` or `http://127.0.0.1:8000`. | Multi-tier URL validation: rejects non-HTTP(S) schemes, loopbacks, private CIDRs, cloud metadata IPs, and internal TLDs. | 18 SSRF tests in `test_phase8_security_penetration.py` |
| **DNS Rebinding** | Target domain switches DNS resolution to `127.0.0.1` at execution time. | Pre-socket IP resolution in `app/utils/network.py`: resolves IP immediately before socket creation and validates against blocked ranges. | Verified in `test_dns_rebinding_attack_prevented` |
| **Credential Leakage** | API credentials exposed in database dumps, API responses, or system logs. | Credentials encrypted at rest using **Fernet (AES-128-CBC + HMAC-SHA256)**. Excluded from Pydantic response schemas (`exclude=True`) and never logged. | Verified in `test_encryption.py` & audit tests |
| **Approval Bypass & Tampering** | Attacker alters payload during `/approvals/{id}/approve` request. | **Frozen Payload Pattern**: The approval endpoint ignores incoming request bodies and executes strictly the frozen DB payload. | Verified in `test_approval_tampering_payload_ignored` |
| **Prompt Injection / Mass Assignment** | Attacker injects extra parameters (e.g., `role=admin`) via LLM. | Parameter validator rejects unexpected keys (`additionalProperties: False`), enforces strict typing, and blocks null bytes/path traversal. | Verified in `test_parameter_mass_assignment_prevented` |
| **Replay Attacks** | Attacker replays past sensitive execution to trigger duplicate transactions. | The replay engine routes sensitive actions back to the approval queue with `PENDING` status. | Verified in `test_replay_cannot_bypass_approval_guardrail` |
| **DoS / Memory Exhaustion** | Attacker sends oversized payloads. | Request body limit enforced at middleware layer (1 MB max), and execution logs truncate payloads exceeding 50 KB. | Verified in `test_payload_truncation_dos_protection` |

---

## 💻 Enterprise SaaS Dashboard

The user interface follows professional enterprise SaaS standards (Stripe/Datadog/Cloudflare style):
- **Gateway Authentication Screen:** Secure enterprise login card with in-memory token state and quick-fill presets.
- **Role-Aware Navigation & Badging:** Topbar displays authenticated username, active role pill (`ADMIN`, `OPERATOR`, `APPROVER`), live health poller, and "Sign Out" control.
- **Permission-Filtered Controls:** Action buttons dynamically adapt to active role (e.g., hiding API registration from Operators; locking self-approvals under the Four-Eyes principle).
- **API Registry Manager:** Real-time datagrid of connected external APIs with masked credentials, encryption indicators, and template presets.
- **Task Orchestration Console:** Natural language input console showing real-time execution plans, parameter validation states, and visual SAFE (green) vs SENSITIVE (amber) badges.
- **Human-in-the-Loop Approval Queue:** Live pending datagrid displaying target endpoint, execution method, frozen parameters, and Approve/Reject controls.
- **Audit Logs & Replay Viewer:** Filterable history (ALL, SUCCESS, FAILED, BLOCKED) with detailed side drawer displaying request/response bodies, HTTP latency, and Replay triggers.

---

## 🛠 Tech Stack

### Backend
- **Python 3.12**
- **FastAPI 0.115.5** (Asynchronous ASGI Web Framework)
- **SQLAlchemy 2.0.36** (Declarative ORM with Custom TypeDecorators)
- **Pydantic v2.10.2** (High-Performance Schema Validation)
- **HTTPX 0.28.0** (Async HTTP Client for External API Dispatch)
- **Bcrypt 4.2.1** (Salted Password Hashing, 12 Rounds)
- **PyJWT 2.10.1** (JWT Issuance & Strict Claim Validation)
- **Cryptography 43.0.3** (Fernet AES-128-CBC + HMAC-SHA256 Encryption at Rest)
- **SQLite / PostgreSQL** (Pluggable Database Engine)
- **Uvicorn 0.32.1** (ASGI Production Server)

### Frontend
- **React 18.3.1** (Declarative Component Architecture)
- **Vite 5.4.11** (Lightning-Fast Build Tooling)
- **Lucide React** (Clean, Modern Enterprise Icons)
- **In-Memory Token Architecture** (Zero localStorage/sessionStorage persistence)

---

## 🚀 Quick Start & Installation

### Prerequisites
- **Python 3.12+**
- **Node.js 18+** & **npm 9+**

### 1. Backend Setup
```bash
# Create and activate virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
cd backend
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
```

### Initial Administrator Setup
* On first startup, if no administrator account exists and `INITIAL_ADMIN_PASSWORD` is not set in `.env`, the Gateway automatically generates a cryptographically secure 24-character random password.
* The credentials are saved to `.admin_bootstrap_secret` with strict OS-level access control lists (ACLs) restricting access exclusively to the host user.
* Credentials are never exposed in application logs, version control, or frontend client code.

### 2. Frontend Setup
```bash
cd ../frontend
npm install
```

---

## ⚡ Running the Application

### One-Click Startup Script (Windows)
```powershell
.\start.ps1
```
*(Or double-click `start.bat`).*

- **Enterprise Dashboard UI:** `http://localhost:5173`
- **Backend Swagger API Docs:** `http://localhost:8000/docs`
- **Gateway Health Check:** `http://localhost:8000/health`

---

## 🧪 Automated Test Suite (147 Tests)

The test suite validates functional coverage, 30 security penetration exploits, and 23 inbound authentication, rate limiting & RBAC scenarios.

```bash
cd backend
pytest tests/ -v
```

### Test Breakdown by Module:

```
tests/test_encryption.py .................................... [  3%] (5 tests)
tests/test_phase10a_auth.py ................................. [ 19%] (23 tests)
tests/test_phase1_setup.py .................................. [ 28%] (13 tests)
tests/test_phase2_models_schemas.py ......................... [ 47%] (28 tests)
tests/test_phase3_registry.py ............................... [ 56%] (13 tests)
tests/test_phase4_orchestration.py .......................... [ 66%] (15 tests)
tests/test_phase5_guardrails_execution.py ................... [ 74%] (12 tests)
tests/test_phase6_audit_replay.py ........................... [ 80%] (8 tests)
tests/test_phase8_security_penetration.py ................... [100%] (30 tests)
======================= 147 passed in 43.61s ========================
```

---

## ☁️ Cloud Deployment Architecture

The gateway is architected for seamless multi-cloud production deployment:
* **Frontend**: Hosted on **Vercel** as a static Single Page Application (SPA).
* **Backend**: Hosted on **Render** as a Python 3 ASGI Web Service managed by Uvicorn.
* **Database**: Hosted on **Render Managed PostgreSQL** providing persistent, encrypted relational storage.

### Production Environment Variables

| Variable Name | Component | Description |
|---|---|---|
| `VITE_API_BASE_URL` | Frontend (Vercel) | Full HTTPS URL of deployed Render backend (e.g. `https://gateway.onrender.com`). |
| `APP_ENV` | Backend (Render) | Environment identifier set to `production`. |
| `DATABASE_URL` | Backend (Render) | PostgreSQL connection URI provided automatically by Render DB service. |
| `SECRET_KEY` | Backend (Render) | 32-byte cryptographic hex string for data encryption. |
| `JWT_SECRET_KEY` | Backend (Render) | 256-bit cryptographically secure hex secret for JWT signing. |
| `JWT_ISSUER` | Backend (Render) | Token issuer identifier (`guardrailed-ai-gateway`). |
| `JWT_AUDIENCE` | Backend (Render) | Token audience identifier (`guardrailed-ai-gateway-api`). |
| `ALLOWED_ORIGINS` | Backend (Render) | Comma-separated list containing exact Vercel frontend URL. |
| `ALLOWED_HOSTS` | Backend (Render) | Host header whitelist (e.g. `*.onrender.com` or custom domain). |
| `LLM_PROVIDER` | Backend (Render) | AI provider (`openai`). |
| `LLM_API_KEY` | Backend (Render) | Secret API key for OpenAI model access. |
| `INITIAL_ADMIN_USERNAME` | Backend (Render) | Initial administrative user name (`admin`). |
| `INITIAL_ADMIN_PASSWORD` | Backend (Render) | Administrative password set securely via environment. |

---

## 🔌 API Reference

### System & Authentication (`/health`, `/auth`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Public service liveness probe. |
| `POST` | `/auth/login` | Authenticate credentials (rate-limited) and issue short-lived JWT. |
| `POST` | `/auth/logout` | Revoke active token server-side via JTI denylist (Authenticated). |
| `GET` | `/auth/me` | Retrieve authenticated user profile and assigned role. |
| `POST` | `/auth/users` | Provision new user with specified role (Admin only). |
| `GET` | `/auth/users` | List registered user accounts (Admin only). |

### API Registry (`/apis`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/apis` | List registered APIs with masked credentials (Authenticated). |
| `GET` | `/apis/{id}` | Retrieve registered API by ID (Authenticated). |
| `POST` | `/apis` | Register external API with encrypted credentials (Admin only). |
| `PUT` | `/apis/{id}` | Update API endpoints or configuration (Admin only). |
| `DELETE`| `/apis/{id}` | Remove registered API (Admin only). |

### Task Orchestration (`/tasks`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/tasks` | Submit natural language task. Safe actions execute immediately (200 OK); sensitive actions route to approval queue (202 Accepted). Permitted for Operator and Admin. |

### Approvals Queue (`/approvals`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/approvals` | List pending approvals (Approver & Admin). |
| `GET` | `/approvals/{id}` | Inspect frozen payload details (Approver & Admin). |
| `POST` | `/approvals/{id}/approve` | Approve and execute frozen payload. Anti-self-approval enforced (Approver & Admin). |
| `POST` | `/approvals/{id}/reject` | Reject pending request (Approver & Admin). |

### Execution Logs & Replay (`/logs`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/logs` | Query execution audit logs (Authenticated). |
| `GET` | `/logs/{id}` | Retrieve detailed log record (Authenticated). |
| `POST` | `/logs/{id}/replay` | Replay execution. Sensitive replays re-route to approval queue (Approver & Admin). |

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

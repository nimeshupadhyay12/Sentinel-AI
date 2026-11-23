# Improvements log

This file lists every change made in the November 2026 hardening pass, with the reason for each. It started from a read-only review of the original code. Numbers are reported only where they were reproduced, together with the data they come from.

Test suite: **8 passed, 1 skipped** before, **42 passed, 1 skipped** locally after (SQLite; the skipped test needs PostgreSQL) and **43 passed** in CI against PostgreSQL 16.

## 1. Authentication and authorization

| Change | Why |
|---|---|
| Roles `Admin`, `Analyst`, `User` checked on every endpoint (`require_privileged`, `require_admin`). The role is read from the database on each request, never trusted from the JWT. | Any registered user could read every user's activity and run analyses. Reading the role from the database makes a demotion or deactivation take effect on the next request. |
| `GET /api/activities/recent` returns only the caller's own rows for `User`; alerts, incidents, analytics, simulations, research, manual analysis and the user list need `Analyst` or `Admin`. | Users are scoped to their own data. |
| Admin-only `POST /api/users/` (create with role) and `PATCH /api/users/{id}` (role, active flag). Admins cannot demote or deactivate themselves. Role changes and deactivation revoke the user's refresh tokens. | Self-registration is now off by default, so administrators need a way to provision accounts. The self-lockout guard prevents accidentally locking everyone out. |
| 15-minute access tokens carry `jti`, `iat` and `type`. Logout puts the `jti` on a denylist (`revoked_access_tokens`) and revokes the refresh token. Logout also works when the access token has already expired. | Logout previously only deleted the token in the browser, so a stolen token stayed valid until expiry. |
| Opaque refresh tokens in an httpOnly, `SameSite=Strict` cookie scoped to `/api/auth`, stored server-side as SHA-256 only, rotated on every use. Presenting an already-rotated token revokes the user's whole token family. | Short access tokens need a safe way to renew sessions. Reuse detection limits the damage of a stolen refresh token. |
| Login throttling: per-account lockout (5 failures, 15 minutes) and a per-IP budget (30 attempts per 5 minutes), returning 429 with `Retry-After`. Unknown users still cost a bcrypt verification, and every failure returns the same message. | Login had no brute-force protection, and response timing could reveal valid usernames. |
| Registration is disabled unless `ALLOW_SELF_REGISTRATION=true`. It always creates a `User`, rejects unknown fields such as `role`, always computes the bcrypt hash, and returns the same `202` body whether or not the username or email exists. | The old endpoint said which field already existed (account enumeration). Returning 400 versus 200 would still leak it, so the status and body are now identical. |
| The frontend keeps the access token in memory only, restores sessions through the refresh cookie, calls the server logout, retries once after a 401, and hides analyst-only tabs from standard users. | Tokens used to sit in `localStorage`, where any injected script can read them. The CSP was already strict (`script-src 'self'`). The remaining trade-off is documented in the README. |
| Stricter input validation (allowed action types, numeric bounds, `extra="forbid"`, no NaN/Inf), security headers, CSP, `Cache-Control: no-store` on the API, a generic 500 handler, and an HMAC-only JWT algorithm allowlist. | Defence in depth; prevents junk or hostile telemetry and avoids leaking stack traces. |
| **Bug fix:** `UserOut.email` was `EmailStr`, so serialising the bootstrap accounts (`@sentinelai.local`, a reserved domain) raised a validation error. `GET /api/users/` and `GET /api/auth/me` returned 500 for those accounts. Output models now use `str`. | Found by the new tests. Input is still validated as an email. |

Files: `backend/app/api/{auth,users,activities}.py`, `backend/app/core/{security,config,rate_limit}.py`, `backend/app/models/models.py`, `backend/app/schemas/schemas.py`, `frontend/src/{App.jsx,api/client.js,pages/Login.jsx,pages/Activities.jsx,components/Navbar.jsx}`, `backend/tests/{conftest,test_security}.py`.

## 2. Signed audit chain

| Change | Why |
|---|---|
| `app/services/audit.py`: `append_audit_record` signs `canonical_json(payload) + previous_signature` with Ed25519 and stores the signer's key fingerprint. Appends are serialised with a thread lock plus a PostgreSQL advisory lock. | Concurrent requests could otherwise both link to the same previous record and fork the chain. |
| `verify_audit_chain` checks every link **and** every signature, and reports the first bad record with a reason: `broken_link`, `bad_signature` or `unknown_signing_key`. Old records with no stored key are reported as `PARTIALLY_VERIFIED`, not silently accepted. | The old verifier compared hash links only, so editing a payload went undetected, and nothing called it anyway. |
| Persistent signing key from `AUDIT_SIGNING_KEY`, or HKDF-derived from `SECRET_KEY`. | The old key was regenerated on every start, so earlier signatures could never be verified. |
| Admin-only `GET /api/audit/verify`, `GET /api/audit/public-key` and `GET /api/audit/logs`. | Makes verification usable and lets the chain be checked outside the app. |
| A sealing failure now fails the request instead of `print()`-ing and continuing. | A security decision should not go unaudited. |
| Tests: an edited payload, a deleted record, a forged signature (claiming our key or another key), legacy records, and role checks on the endpoint. | Shows each tampering case is actually caught. |

Known limits (documented): anyone holding the key can re-sign a forged chain, and truncating the newest records is only detectable if the last signature is stored somewhere else.

## 3. Explainable risk score

| Change | Why |
|---|---|
| `RiskScoreExplainer` (`app/ml/explainer.py`) gives the complete breakdown `risk = baseline + Σ features (IF Shapley + OCSVM Shapley + rule points)`. IF and OCSVM points get exact interventional Shapley values: all 2^7 = 128 coalitions are evaluated against a 20-row normal background (about 70 ms per event). Fired rules are listed with their value and points. | SHAP explained only the Isolation Forest part (and in path-length space, not points). The OCSVM part (up to 30 points) and the rule part (up to 30 points) of every alert were unexplained. |
| The breakdown is returned by the analysis endpoints, stored on threat records and alerts (`score_breakdown`, added by the additive migration), alert `triggering_factors` are now risk points per feature, and the dashboard shows component bars, per-feature points and fired rules. TreeSHAP remains available as the IF model-space view. | Analysts can see why each alert scored what it did. |
| Tests check that components and contributions add up to the score, that the IF and OCSVM points match the score formula, rule attribution, and the Shapley weights against brute force over all 5,040 feature orderings. | Proves the explanation is exact, not approximate. |
| **Bug fix found by the breakdown:** the live detector was fitted on the synthetic set *including* its 10% attack rows, so the OCSVM learned the dense attack cluster as normal. A blatant exfiltration session got 0/30 OCSVM points (risk 51.04). Both models are now fitted on benign rows only, with `contamination = nu = 0.02`; the same session scores 95.09. | One-class models must learn normal behaviour. Measured on a fresh synthetic seed (2,000 rows, seed 7): OCSVM ROC-AUC 0.929 → 1.000, lowest attack risk 46.6 → 89.2, and 0.7% of benign sessions reach the alert threshold of 50 (synthetic data only, not a CERT result). |

Not done: an explanation step for the top-N flagged user-days in the offline CERT pipeline. The CERT data was not available in this environment to test it.

## 4. Deployment

| Change | Why |
|---|---|
| The Dockerfile runs as the unprivileged `sentinel` user (UID 10001). App code is read-only for that user, only `/app/data` is writable, a `HEALTHCHECK` is added, Uvicorn runs with `--proxy-headers`, and library caches point at `/tmp`. | The container ran as root. Proxy headers let the per-IP throttle see real client IPs behind Render's proxy. |
| `render.yaml` provisions a managed PostgreSQL database and passes it as `DATABASE_URL`. The free plan's time limit is documented. | The data used to live in SQLite inside an ephemeral container and was lost on every deploy or restart. |

The Docker image was not built in this environment (no Docker available). CI builds the frontend and runs the backend, but not `docker build`.

## 5. Correctness and documentation fixes

- Research artifacts are read and written as UTF-8 explicitly. `report.py` wrote "±" using the platform default encoding (cp1252 on Windows).
- `docs/DEVELOPMENT.md` said there was no license; the project is MIT licensed.
- `pqc_dsa.py` was renamed to `audit_signing.py` and `pqc_kem.py` to `aesgcm_demo.py`. They are classical Ed25519 and AES-GCM, not post-quantum; the code, README, DEVELOPMENT.md and UI now say so.
- The game is described accurately in code, docs and UI: a finite pure-strategy Stackelberg game (5 x 4), solved by enumeration for each event, with hand-set payoffs, no mixed or Bayesian equilibrium, and no enforcement (the dashboard label now reads "RECOMMENDATION ONLY").
- Dashboard average risk is computed in SQL instead of loading every record. Alerts, incidents and the latest assessment use an id tie-break when ordering.
- The README now has setup, architecture, the risk formula, an API table with roles, the token-storage trade-off, the committed CERT numbers with an honest reading, and reproduction commands. `.env.example` lists all the new settings.

## 6. CI

`.github/workflows/verify.yml` now has three jobs: `ruff check` (pyflakes plus pycodestyle errors and warnings, configured in `backend/ruff.toml`; it removed 6 unused imports), pytest against a PostgreSQL 16 service with the frontend built so the SPA tests run, and a standalone `npm ci && npm run build`. The token is read-only, and older runs on the same ref are cancelled.

## 7. Research results: what was and was not changed

- CERT numbers were **not** changed or re-run. The CERT r4.2 data is not in this environment. The committed results (IF ROC-AUC 0.834, precision about 0.013, F1 about 0.016 at 0.40% prevalence; adaptive-policy differences not significant) are reported as they are.
- Per-user baseline deviation already exists in the enhanced protocol (`personalized_log1p` in `research/enhanced.py`). No new feature work was added, because its effect could not be reproduced without the data.
- Synthetic demo, reproduced here with `run_experiments.py --demo --seeds 0 1 2 --episodes 3 --turns 6` (original protocol): ROC-AUC 1.000 for both IF and OCSVM, F1 0.834 (IF) and 0.846 (OCSVM), with recall 1.0 and precision limited by the 5% validation false-positive-rate threshold. The synthetic data is trivially separable. **The generator was not changed**, so the demo remains a pipeline smoke test, not evidence of detection quality.

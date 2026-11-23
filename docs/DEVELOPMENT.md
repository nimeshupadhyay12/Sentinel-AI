# SentinelAI — Adaptive Insider Threat Detection

<p align="center">
  <img src="../images/architecture.png" alt="SentinelAI system architecture" width="900">
</p>

<p align="center">
  <strong>A research-oriented security operations platform for studying adaptive insider threats.</strong>
</p>

<p align="center">
  <a href="https://github.com/nimeshupadhyay12/Sentinel-AI/actions"><img src="https://img.shields.io/github/actions/workflow/status/nimeshupadhyay12/Sentinel-AI/verify.yml?branch=main&label=verification" alt="Verification workflow"></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/FastAPI-backend-009688?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black" alt="React 18">
  <img src="https://img.shields.io/badge/PostgreSQL-supported-4169E1?logo=postgresql&logoColor=white" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Research%20prototype-not%20production-orange" alt="Research prototype">
</p>

SentinelAI is a full-stack cybersecurity research prototype that explores how a defender can respond when an insider changes behaviour in reaction to previous security controls. It combines user-activity telemetry, anomaly-detection models, explainability, an adaptive Stackelberg-game simulator, an interactive SOC dashboard, and research workflows built around the CERT Insider Threat Test Dataset.

> **Project status:** Research and demonstration software. It is not a production security product, does not independently enforce endpoint controls, and must not be used as the sole basis for real access-control decisions.

## Contents

- [Problem and approach](#problem-and-approach)
- [Features](#features)
- [Screenshots](#screenshots)
- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Run locally](#run-locally)
- [Configuration](#configuration)
- [Run tests](#run-tests)
- [Research reproduction](#research-reproduction)
- [Docker](#docker)
- [Security and implementation limitations](#security-and-implementation-limitations)
- [Dataset and research notes](#dataset-and-research-notes)
- [Contributing](#contributing)
- [License](#license)

## Problem and approach

Traditional insider-threat monitoring often relies on fixed behavioural thresholds or models that treat each event independently. An adaptive insider may change tactics after a defensive response. SentinelAI provides a sandbox for exploring that feedback loop.

The application combines two related but distinct paths:

1. **Interactive application path:** synthetic baseline training, telemetry feature processing, anomaly scoring, SHAP-based explanations, adaptive response selection, alert/incident creation, and audit-event storage.
2. **Offline research path:** CERT r4.2 data preparation and chronological evaluation of anomaly-detection and adaptive-policy variants. Research outputs are generated separately and can be served to authorised dashboard users when installed.

The game engine is a finite, pure-strategy Stackelberg model: the defender commits to an action, the simulated attacker selects a best response, and the defender evaluates the resulting utility. Its utility parameters are explicit simulator assumptions, not learned CERT ground truth.

## Features

### Detection and explainability

- Isolation Forest and One-Class SVM anomaly detectors.
- Feature engineering and risk-score calculation.
- SHAP-based feature-attribution visualisations.
- Dashboard views for activity, alerts, incidents, and analysis history.

### Adaptive response research

- Defender actions: `ALLOW`, `MONITOR`, `STEP_UP_AUTH`, `RESTRICT`, and `REVOKE`.
- Simulated attacker strategies: aggressive exfiltration, stealth exfiltration, probing, and abort.
- **AAS (Attacker Adaptation Score):** measures behavioural change relative to a previous user behaviour vector.
- **RES (Response Effectiveness Score):** summarises observed changes in risk, activity, and confidentiality/exfiltration proxies when prior observations are available.
- Multi-turn attack simulations and ablation comparisons.

AAS and RES are research metrics. RES is observational and does not, by itself, establish that a prior defensive action caused a reduction in risk.

### SOC web application

- React dashboard and interactive visualisations.
- FastAPI REST API with JWT-based authentication.
- Role checks for protected research and experiment endpoints.
- SQLAlchemy persistence with SQLite for local development and PostgreSQL support.
- Read-only, allowlisted research-artifact endpoints.

### Research tooling

- CERT r4.2 download and preprocessing modules.
- Chronological train/validation/test evaluation workflow.
- Isolation Forest and One-Class SVM baselines and adaptive-policy ablations.
- Per-seed outputs, summary tables, plots, and methods/limitations reports.

## Screenshots

| SOC dashboard | Login |
|---|---|
| ![SOC dashboard](../images/soc-dashboard.png) | ![Login screen](../images/login-page.png) |

| Threat simulator | Research visualisations |
|---|---|
| ![Threat simulator](../images/threat-simulator.png) | ![Ablation graphs](../images/ablation-graphs.png) |

| Audit telemetry | End-to-end workflow |
|---|---|
| ![Audit telemetry](../images/audit-telemetry.png) | ![End-to-end workflow](../images/end-to-end-workflow.png) |

The PQC terminal image is retained as a historical project demonstration. See [Security and implementation limitations](#security-and-implementation-limitations) for the actual cryptographic implementation status.

## Architecture

```text
                  ┌──────────────────────────┐
                  │     React SOC UI         │
                  │ Dashboard / Simulator    │
                  └────────────┬─────────────┘
                               │ REST + JWT
                  ┌────────────▼─────────────┐
                  │       FastAPI API        │
                  │ Auth / Activities / Data │
                  └────────────┬─────────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
   ┌─────────▼────────┐ ┌──────▼─────────┐ ┌─────▼────────────┐
   │ Feature pipeline │ │ Anomaly models │ │ SQLAlchemy data  │
   │                  │ │ IF + One-Class  │ │ SQLite/Postgres  │
   └─────────┬────────┘ └──────┬─────────┘ └──────────────────┘
             │                 │
             └────────┬────────┘
                      ▼
             ┌──────────────────┐
             │ SHAP explanations│
             │ Risk assessment  │
             └────────┬─────────┘
                      ▼
             ┌──────────────────┐
             │ Adaptive game    │
             │ defender/attacker│
             └────────┬─────────┘
                      ▼
             ┌──────────────────┐
             │ Recommendations, │
             │ alerts and audit │
             └──────────────────┘

      Separate offline research workflow:
      CERT r4.2 → preprocessing → chronological evaluation
               → metrics / plots / reports → dashboard artifacts
```

## Technology stack

| Area | Technologies |
|---|---|
| Backend API | Python, FastAPI, Uvicorn |
| Data layer | SQLAlchemy, SQLite, PostgreSQL, psycopg2 |
| Authentication | JWT, Passlib, bcrypt |
| Machine learning | scikit-learn, NumPy, pandas, SciPy |
| Explainability | SHAP |
| Frontend | React 18, Vite, Tailwind CSS, Recharts |
| Testing | pytest, HTTPX |
| Packaging/deployment | Docker, Render blueprint, GitHub Actions |

## Repository layout

```text
Sentinel-AI/
├── .github/
│   └── workflows/
│       ├── keepalive.yml
│       └── verify.yml
├── backend/
│   ├── app/
│   │   ├── api/             # FastAPI route modules
│   │   ├── core/            # Settings, DB, auth, crypto demonstrations
│   │   ├── ml/              # Detection, explainability and game engine
│   │   ├── models/          # SQLAlchemy models
│   │   ├── schemas/         # Request/response schemas
│   │   └── services/        # Application orchestration and adaptation
│   ├── research/            # CERT preprocessing and experiment modules
│   ├── tests/
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   └── run_experiments.py
├── frontend/
│   ├── public/
│   └── src/
│       ├── api/
│       ├── components/
│       └── pages/
├── images/                  # Project screenshots and diagrams
├── research/
│   └── results/.gitkeep     # Selected example research results included
├── .dockerignore
├── .gitignore
├── Dockerfile
├── render.yaml
└── README.md
```

## Requirements

For local development:

- Python **3.11** (the pinned backend dependencies and CI workflow target Python 3.11).
- Node.js **20** and npm.
- Git.
- PostgreSQL 15+ only if you choose PostgreSQL instead of the default local SQLite database.
- Docker Desktop only if you want to build/run the container.

## Run locally

The commands below use Windows PowerShell. Run backend and frontend in separate terminals.

### 1. Clone the repository

```powershell
git clone https://github.com/nimeshupadhyay12/Sentinel-AI.git
cd Sentinel-AI
```

### 2. Configure the backend

```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
```

Generate a strong application secret:

```powershell
py -3.11 -c "import secrets; print(secrets.token_hex(32))"
```

Open `backend/.env` and replace the `SECRET_KEY` placeholder with the generated value. Set three unique passwords if you want the application to create the optional starter roles on first startup:

- `SENTINEL_BOOTSTRAP_ADMIN_PASSWORD`
- `SENTINEL_BOOTSTRAP_ANALYST_PASSWORD`
- `SENTINEL_BOOTSTRAP_USER_PASSWORD`

These are one-time account-bootstrap inputs, not universal default passwords. Use unique strong values and keep the `.env` file private.

### 3. Start the backend

From the `backend` directory:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Backend endpoints:

- Health: <http://127.0.0.1:8000/health>
- Interactive API docs: <http://127.0.0.1:8000/docs>

The default local database is SQLite (`sentinelai.db` in the backend working directory). To use PostgreSQL, set `DATABASE_URL` in `backend/.env`, for example:

```dotenv
DATABASE_URL=postgresql://sentinel_user:replace-me@localhost:5432/sentinelai_db
```

Create the database and database user yourself before starting the backend.

### 4. Start the frontend

Open a second PowerShell terminal at the repository root:

```powershell
cd frontend
npm ci
npm run dev
```

Open <http://localhost:3000>.

The Vite development server proxies `/api` requests to `http://localhost:8000`. Create or configure a user using the backend bootstrap environment variables before signing in. Optional self-registration always creates a standard `User` role; privileged roles must be provisioned by an administrator. Do not expect a shared demo password.

## Configuration

Backend settings are loaded from environment variables and `backend/.env`.

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Required signing key for JWT tokens. Generate a unique random value; never commit it. |
| `ALGORITHM` | JWT signing algorithm; defaults to `HS256`. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | JWT lifetime in minutes. |
| `DATABASE_URL` | SQLAlchemy connection URL. Defaults to local SQLite when omitted. |
| `SENTINEL_BOOTSTRAP_ADMIN_PASSWORD` | Optional first-start password for the `admin` role account. |
| `SENTINEL_BOOTSTRAP_ANALYST_PASSWORD` | Optional first-start password for the `analyst` role account. |
| `SENTINEL_BOOTSTRAP_USER_PASSWORD` | Optional first-start password for the `insider_target` role account. |
| `RESEARCH_RESULTS_DIR` | Optional absolute path to a generated research-results directory. |
| `CORS_ORIGINS` | Optional JSON array of allowed browser origins; defaults to the local Vite development origins. |

See [`backend/.env.example`](../backend/.env.example) for the template. Do not put real secrets in source code, screenshots, issue reports, or commits.

## Run tests

From the repository root:

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest tests -q
```

Alternatively, if the virtual environment is activated:

```powershell
python -m pytest tests -q
```

The integration suite uses an isolated temporary SQLite database by default. To exercise PostgreSQL migration coverage, set `SENTINEL_TEST_DATABASE_URL` to a **disposable test database**. Never point tests at production data.

Frontend production build:

```powershell
cd frontend
npm ci
npm run build
```

The GitHub Actions verification workflow builds the frontend and runs backend tests against a temporary PostgreSQL service.

## Research reproduction

The CERT r4.2 dataset is not included in this repository. It is a separately distributed dataset and must be obtained and used in accordance with its terms.

From `backend/`, install development dependencies, then download and preprocess the data:

```powershell
python -m research.download_cert --output ../research/data/raw/r4.2.tar.bz2
python -m research.preprocess_cert --archive ../research/data/raw/r4.2.tar.bz2 --answers ../research/data/raw/answers.tar.bz2 --output ../research/data/cert_r4.2_features.csv
```

Run the original evaluation:

```powershell
python run_experiments.py --dataset ../research/data/cert_r4.2_features.csv --output ../research/results/cert-r4.2 --seeds 0 1 2 3 4
```

Run the enhanced protocol:

```powershell
python run_experiments.py --dataset ../research/data/cert_r4.2_features.csv --output ../research/results/cert-r4.2-enhanced --protocol enhanced --save-models --seeds 0 1 2 3 4 --episodes 20 --turns 8
```

Run the research tests:

```powershell
python -m pytest tests -q
```

Raw datasets and model binaries are excluded from Git. Selected aggregate example results from the supplied project archive are included for the research dashboard; new generated outputs remain ignored. Keep raw data, derived user-level data, and model binaries outside version control unless you have checked dataset permissions, privacy, and file size.

### Research interpretation

- The Stackelberg game is a **pure-strategy** model, not a Bayesian game.
- Payoffs, success probabilities, costs, and attacker preferences are simulator assumptions; they are not fitted from CERT.
- CERT labels identify official insider activity windows, not necessarily individual malicious events.
- Confidentiality/exfiltration variables are proxies because CERT does not provide sensitive-file labels.
- A validation-selected threshold is not an unsupervised threshold.
- The enhanced analysis is exploratory; the previously examined test period is not an independent confirmatory evaluation.
- Five random seeds provide limited statistical resolution. Do not claim statistical significance or universal superiority from these experiments.

Dataset citation:

> Lindauer, Brian (2020). *Insider Threat Test Dataset*, Carnegie Mellon University. <https://doi.org/10.1184/R1/12841247.v1>

## Docker

From the repository root:

```powershell
docker build -t sentinel-ai .
docker run --rm -p 8000:8000 --env-file backend/.env -v sentinel-data:/app/data sentinel-ai
```

The image builds the Vite frontend, serves it through FastAPI, and runs as the unprivileged `sentinel` user (UID 10001). Application code is read-only for that user; only `/app/data` is writable. Without `DATABASE_URL` the container uses SQLite at `/app/data/sentinelai.db`, so mount a volume there (as above) or the data disappears with the container. A `HEALTHCHECK` polls `/health`, and Uvicorn runs with `--proxy-headers` so the per-IP login throttle sees real client addresses behind a reverse proxy.

The Render blueprint (`render.yaml`) provisions a managed PostgreSQL database and passes its connection string as `DATABASE_URL`, because a Render web service filesystem is ephemeral (SQLite data would be lost on every deploy or restart). Render's free PostgreSQL plan is time-limited; check its current terms.

## Security and implementation limitations

**Read this section before deploying or exposing the application to an untrusted network.**

- **Research prototype:** this code is not a hardened enterprise security product. Recommendations and simulated actions do not actually revoke operating-system sessions, block endpoints, or enforce access controls.
- **Authentication:** configure a unique, high-entropy `SECRET_KEY`; use unique bootstrap passwords; protect the database; and review registration/role assignment before any public deployment.
- **CORS and deployment:** restrict allowed origins to the actual frontend origins in any internet-facing deployment. Use HTTPS and secure infrastructure configuration.
- **No post-quantum cryptography:** `app/core/audit_signing.py` (formerly `pqc_dsa.py`) uses classical Ed25519 signatures, not NIST ML-DSA. `app/core/aesgcm_demo.py` (formerly `pqc_kem.py`) is an AES-256-GCM round-trip demo with a process-local key, not NIST ML-KEM, and is not used by the API. Do not describe either as quantum-resistant.
- **Audit signing:** the Ed25519 key comes from `AUDIT_SIGNING_KEY` or is derived from `SECRET_KEY` with HKDF, so signatures survive restarts, and `GET /api/audit/verify` checks every link and signature. Anyone with the key (or `SECRET_KEY`) can re-sign a forged chain, and deleting the newest records cannot be detected without an external copy of the last signature. A production system would keep the key in a KMS/HSM and anchor the chain head externally.
- **Login throttling is in-process:** lockout and per-IP counters live in memory, so they reset on restart and are per worker. Run one worker or move them to a shared store (e.g. Redis) or the reverse proxy. Per-account lockout can be abused to lock a known username out for the lockout window; this is the usual trade-off against password guessing.
- **Synthetic application detector:** the interactive application's detector is bootstrapped from generated baseline data. It is not automatically the same model as the offline CERT research evaluation.
- **Research artifacts:** install only trusted artifacts. Do not load untrusted serialized model files.
- **Data handling:** use synthetic or appropriately authorised data. Do not commit credentials, private keys, personal data, database files, raw CERT archives, or generated model binaries.

Please report security vulnerabilities privately to the repository owner rather than opening a public issue containing exploit details. See [`SECURITY.md`](../SECURITY.md).

## Dataset and research notes

The research workflow uses the CERT r4.2 insider-threat dataset and answer key to create user-day features. The raw archive and generated features are intentionally not committed. Review the dataset terms before obtaining, processing, or sharing it.

The application and research evaluation answer different questions: the live dashboard demonstrates a synthetic session-analysis pipeline, while the offline research scripts evaluate models and policies against the CERT-derived user-day dataset. Results from one path should not be represented as results from the other.

## Contributing

Contributions are welcome for bug fixes, documentation, tests, reproducibility improvements, and research-method clarification.

1. Fork the repository.
2. Create a focused feature branch.
3. Add or update tests for behavioural changes.
4. Run the backend tests and frontend production build.
5. Open a pull request describing the change, validation performed, and any limitations.

Please do not include secrets, raw personal data, restricted datasets, or generated model artifacts in pull requests.

## License

Released under the [MIT License](../LICENSE).

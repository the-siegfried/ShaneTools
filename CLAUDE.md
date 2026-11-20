# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository shape

This is a **monorepo of unrelated, self-contained security/forensics tools** by Shane Shook, not a single application. There is no root build, test runner, linter, or shared dependency file. Each top-level directory is its own project with its own README and its own way of being run; work inside one directory and read its README first. Do not assume code is shared across directories (e.g. `BHSM/` and `WebGuard/` share concepts such as PSI/BDH/Hebbian memory, `eq_iq_regulator` and `threat_educator`, but as separate Python and Rust implementations).

The root `README.md` is a marketing-style catalogue and is partly stale (e.g. it describes `FORAI.py` as a 6,700-line single file, but FORAI is now the `FORAI/forai/` package with `FORAI/main.py` as the entry point). Trust the code and the per-project README over the root README.

| Dir | Language | What it is |
|---|---|---|
| `ADVulture/` | Python 3.11+ (installable pkg) | AD/Entra posture analysis: LDAP/EVTX/Graph collection → graph → ML (GNN/Markov/forest) → gradient-ranked remediation |
| `AiTM_Hunter/` | Python | AiTM phishing-infrastructure hunting CLI (`aitm_hunter`) |
| `BAI/` | JS (Chromium MV3 extension) + stdlib Python analyzer | Browser Audit Inventory: forensic artifact collection, signed packages; `Analyzer/AiTM_analyzer.py` analyses packages offline |
| `BHSM/` | Python | Bidirectional Hebbian Synaptic Memory cognitive architecture + TinyLLaMA integration |
| `WebGuard/` | Rust (cargo) | Neuromorphic web-service protection agent (Hebbian + RL) |
| `MCR/` | Python (NATS/JetStream) | Model Context Routing; `SecuritySidecar/` is a separate installable package (policy/redaction/scanner) |
| `FORAI/` | Python package | Forensic AI pipeline (KAPE → plaso → SQLite → LLM) |
| `Chatdisco/` | Python package | AI-chat forensics from memory/PCAP/disk; CASE/UCO output |
| `CRA/`, `AdminCreds/`, `ModernCRA/` | PowerShell / Bash / Python | Assessment and collection scripts run against hosts or cloud tenants (see below) |
| `SIPCompare/` | Python | Code-similarity forensics (`SIPCompare.py`) + `forensic_repo_collect.py` |
| `PLoc/`, `FORVM/`, `Other/` | Python / SQL | Single-file utilities |

## Commands (per project; run from inside the project dir)

**ADVulture** (`pyproject.toml`, ruff line-length 100, mypy, pytest-asyncio `asyncio_mode=auto`):
```
pip install -e ".[dev]"
pytest                                   # testpaths = tests/
pytest tests/test_audit.py::TestName -v  # single test
ruff check . ; mypy advulture
advulture analyze --ad-only | --entra-only | --ad-auth kerberos --entra-auth device_code
```
Config comes from `config.yaml` (copy `config.example.yaml`).

**AiTM_Hunter**:
```
pip install -r requirements.txt
python -m pytest tests/ -v ; python -m pytest tests/test_ja4.py -v
python -m aitm_hunter.main {search|fingerprint|deepcrawl|report|evilginx|urlscan|ctmonitor|allowlist|signatures} ...
```
`deepcrawl` actively touches suspect infrastructure and requires `--i-have-read-safety-md`; read `AiTM_Hunter/SAFETY.md` before changing or running it.

**WebGuard** (Rust; bins: `webguard`, `webguard_performance_suite`, `webguard_diagnostic`):
```
cargo build --release
cargo test --test webguard_evaluation -- --nocapture
cargo test --test threat_educator_integration
```

**MCR** (needs a NATS server with JetStream):
```
nats-server -c MCR/src/nats_config.conf &
cd MCR/src && pip install -r requirements.txt && python mcr_poc_runner.py   # simulated, no API key
cd MCR/tests && ANTHROPIC_API_KEY=... python test_live_integration.py       # live; calls the real Anthropic API, and is a script not a pytest suite
```
`MCR/SecuritySidecar/` has its own `pyproject.toml` (`pip install -e .[test]`; pytest `testpaths = ["testing"]`, but that `testing/` directory is not in the repo).

**FORAI**: `pip install -r requirements.txt`, then `python main.py analyze CASE001 --plaso-file timeline.plaso`, `python main.py question CASE001 Q7`, `python main.py interactive CASE001`, `python main.py list-questions`. Optional heavy deps (llama-cpp-python, kuzu, stable-baselines3, plaso) are installed separately per its README.

**Chatdisco**: `pip install -e .` (package lives at the directory root, with `setup.py`, `cli.py`, and `core/ collect/ parsers/ output/ scanners/`). Requires external tools: bulk_extractor, tshark, Volatility 3 (`docs/INSTALL.md`).

**BHSM**: scripts run directly (`python BHSM.py`, `python test.py`, `python test_gap_fixes.py`, `python test_threat_educator.py`). Tests write result JSON/PNG into `BHSM/test/`.

**CRA/EVMS**: `python test_evms.py` (unittest) or `python -m unittest test_evms.TestToolManager`. Many EVMS artefacts are git-ignored (see root `.gitignore`).

**BAI**: no build step. Load `BAI/` as an unpacked extension (Developer mode). `BAI/Release/BAI_v*.zip` plus its `.sha256` are checked-in release artefacts; see `BAI/Release/SIGNING.md` before regenerating them.

**ModernCRA/MDR** has three standalone, single-file collection runners (`s1_query_runner.py`, `CS_query_runner.py`, `cortex_query_runner.py`; only dependency is `requests`). They are deliberately self-contained copies of the same skeleton (query catalogue → management-API inventories → per-file CSV → `chain_of_custody.json` with SHA-256s) and produce the same output file names, which `AnalysisPrompt.txt` depends on. Keep that contract when adding a platform or editing one, and port query changes across runners by hand. There is no tenant to test against, so verify client changes against a mock HTTP server.

PowerShell scripts (`CRA/*.ps1`, `AdminCreds/*.ps1`, `ModernCRA/Entra/setup_assessment_account.ps1`) have no test harness. `AzUAR.ps1` requires PowerShell 7 and .NET 8. They hit live tenants or hosts and are meant to be run by an analyst, so don't execute them casually.

## Architecture notes that span multiple files

- **ADVulture** is a four-layer pipeline: `collection/` (LDAP, EVTX, ADFS, Entra ingesters) → `graph/builder.py` → `ml/` (`gnn`, `markov`, `forest`) → `analysis/` (posture, behavioral, hybrid_monitor, entra_report; all emit `finding.Finding`) → `api/` (FastAPI) and `reporting/` (Jinja2). Each layer can be run on its own. Per-edge `EdgeTensor` features from log ingestion feed the models. `audit.py`, `custody.py` and `evidence.py` provide the forensic audit trail and chain of custody. Design detail is in `ADVulture/docs/architecture.md`. `entra_assess.py` and `scripts/run_analysis.py` are standalone entry points outside the package.
- **WebGuard** (`src/`) is organised as a cognitive stack. `webguard_system.rs` orchestrates, with `featurizer` / `advanced_feature_extractor` / `semantic_normalizer` for input, `mesh_cognition`, `persistence_engine` (PSI long-term memory), `embedding_learner` and `retrospective_learning` for learning, `threat_educator` for operator feedback, and `policy`, `evidence` and `detection_logger` for output. Both a lib (`lib.rs`) and bins exist.
- **FORAI** (`forai/`): `extraction/` (KAPE/plaso) → `db/` (SQLite) → `agent/` + `llm/` (local llama.cpp or OpenAI/Anthropic) with `graph/`, `world_model/`, `bhsm/` and `report/`. It answers a fixed set of 12 standard forensic questions (Q1–Q12).
- **Chatdisco** is a three-engine pipeline (`core/be_engine.py` bulk_extractor, `pcap_engine.py` tshark, `vol_engine.py` Volatility 3) coordinated by `core/pipeline.py`. Service-specific `parsers/` extend `parsers/base.py`, and `output/` builds the CASE/UCO bundle, manifest and report. Every tool version is recorded in the chain of custody (SBOM), so keep that intact when changing tool invocations.
- **MCR**: `src/context_plane.py` (NATS/JetStream-backed context) with `mcr_orchestrator.py`, `mcr_client.py`, `mcp_server.py` and `mcr_cli.py` on top. `SecuritySidecar/` is a separate security plane (scanner, redactor, policy engine, sequence analyzer, driven by `policy.yaml` and `patterns.yaml`).
- **BAI**: `src/background.js` (service worker) + `collectors.js` (29 collectors) + `content.js` (origin-scoped tab collection) → `integrity.js` / `signing.js` / `zip.js` / `export.js` produce a hashed, ECDSA-signed package, and `verify.*` verifies it. Package format changes must stay compatible with `Analyzer/AiTM_analyzer.py` and the verifier.

## Conventions and gotchas

- Files carry copyright headers `(c) <year> Shane D. Shook`; keep them when editing or adding files in the same style.
- Git-ignored by design: forensic data (`*.plaso`, `*.db`, `*.sqlite*`, `evidence/`, `cases/`, `reports/`), logs, and `*_backup.*`. Don't commit case data or tool output.
- Several directories contain committed generated output (e.g. `ADVulture/entra_report*.{md,json}`, `ADVulture/tests/results/`, `WebGuard/evaluation_results/`, `BHSM/test/`). Treat these as artefacts, not source, and don't hand-edit them.
- Forensic and evidence-handling code (hashing, manifests, signatures, chain of custody) is a core feature of ADVulture, BAI, Chatdisco and FORAI. Preserve integrity and ordering guarantees when modifying it.
- Several tools make outbound calls or collect from live systems (Shodan in `PLoc`, urlscan/CT logs in `AiTM_Hunter`, Graph/LDAP in `ADVulture` and `ModernCRA`). Keep credentials in env vars or config files, never in code.

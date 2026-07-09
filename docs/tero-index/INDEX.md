# security-mcp — Tero Index (Layer 1)

> **Honesty:** Empirical/Declared — lite heading/line heuristic over markdown in security-mcp via tero-mcp/scripts/generate_lite_index.py; source files are ground truth. Generated 2026-07-09.
> Use this index to find where to Read, not as authoritative ground truth.

- **Items:** 59
- **Flagged:** 0
- **item_tag:** `Empirical/Declared`
- **Machine index:** [`index.json`](./index.json)
- **Manifest:** [`MANIFEST.toml`](./MANIFEST.toml)

## doc (50 entries)

| Anchor | Kind | Id | Title | File:Line | Status | Summary |
|---|---|---|---|---|---|---|
| `agents` | other | — | AGENTS.md — security-mcp | `AGENTS.md:2` | — | Use Tero + cabal-devmelopner for work here. |
| `agents--tero-layer-1-corpus-index` | section | — | Tero (Layer-1 corpus index) | `AGENTS.md:6` | — | Repo has docs/tero-index/index.json (generated/ refreshed via tero-mcp/scripts/generateliteindex.py). |
| `agents--agent-with-context` | other | — | agent with context: | `AGENTS.md:18` | — | uv run --project ../cabal-devmelopner cabal-devmelopner "task description here" --use-tero |
| `agents--working-with-cabal-devmelopner-agent-tool` | section | — | Working with cabal-devmelopner agent tool | `AGENTS.md:24` | — | This project is prepared for integration: |
| `agents--local-checks` | section | — | Local checks | `AGENTS.md:36` | — | Look for: |
| `agents--further-reading` | section | — | Further reading | `AGENTS.md:44` | — | - README.md |
| `contributing` | section | — | Contributing to This Project | `CONTRIBUTING.md:1` | — | Thank you for your interest in contributing! |
| `contributing--development-setup` | section | — | Development Setup | `CONTRIBUTING.md:5` | — | 1. Clone the repository |
| `contributing--pull-request-process` | section | — | Pull Request Process | `CONTRIBUTING.md:12` | — | 1. Fork the repository |
| `contributing--code-style` | section | — | Code Style | `CONTRIBUTING.md:20` | — | - Use cargo fmt for formatting |
| `contributing--license` | section | — | License | `CONTRIBUTING.md:27` | — | By contributing, you agree that your contributions will be licensed under the MIT License. |
| `readme` | other | — | security-mcp | `README.md:1` | — | MCP server for security screening: prompt-injection defense, PII detection, and secrets scanning |
| `readme--what-this-is-not` | section | — | What This Is NOT | `README.md:8` | — | This is a content/text screener, not a repository, dependency, or supply-chain scanner. It does |
| `readme--status` | section | — | Status | `README.md:16` | — | Alpha / under active development. Rules and thresholds will evolve. |
| `readme--what-it-does-today-code-backed` | section | — | What It Does Today (Code-Backed) | `README.md:20` | — | - Runs an MCP-compatible JSON-RPC server over HTTP/WebSocket. |
| `readme--what-it-does-not-do-yet` | section | — | What It Does Not Do Yet | `README.md:31` | — | - Full DLP-grade PII detection (this is heuristic/pattern-based today). |
| `readme--running` | section | — | Running | `README.md:40` | — | cargo run -p security-mcp -- --help |
| `readme--usage-with-vs-code-github-copilot` | section | — | Usage with VS Code / GitHub Copilot | `README.md:46` | — | Install the binary: |
| `readme--usage-with-claude-desktop` | section | — | Usage with Claude Desktop | `README.md:70` | — | Add to your claudedesktopconfig.json: |
| `readme--license` | section | — | License | `README.md:85` | — | MIT |
| `readme--status-roadmap` | section | — | Status & roadmap | `README.md:89` | — | - [Assessment & gaps](docs/ASSESSMENT.md) |
| `assessment` | note | — | security-mcp — Assessment & Gap Analysis | `docs/ASSESSMENT.md:1` | — | Date: 2026-07-08 |
| `assessment--1.-what-this-project-is-is-not` | section | — | 1. What this project is / is not | `docs/ASSESSMENT.md:10` | — | — |
| `assessment--2.-maturity` | section | — | 2. Maturity | `docs/ASSESSMENT.md:21` | — | — |
| `assessment--3.-in-flight-branches` | section | — | 3. In-flight branches | `docs/ASSESSMENT.md:34` | — | — |
| `assessment--4.-gaps-priority` | section | — | 4. Gaps (priority) | `docs/ASSESSMENT.md:44` | — | — |
| `assessment--5.-integration-fit` | section | — | 5. Integration fit | `docs/ASSESSMENT.md:58` | — | - Cabal: call as stdio MCP peer after tool allowlists exist; never sole gate. |
| `assessment--tero-index` | section | — | Tero index | `docs/ASSESSMENT.md:66` | — | Layer-1 citation index: [docs/tero-index/](tero-index/) (index.json, INDEX.md, MANIFEST.toml). |
| `localchecks` | section | — | Local checks (CI parity) | `docs/LOCAL_CHECKS.md:1` | — | GitHub Actions workflows in this repo are manual only (workflowdispatch). |
| `localchecks--run-everything-the-remote-job-would-run` | section | — | Run everything the remote job would run | `docs/LOCAL_CHECKS.md:6` | — | ./scripts/check.sh |
| `localchecks--tero-index` | section | — | Tero index | `docs/LOCAL_CHECKS.md:19` | — | python3 ../tero-mcp/scripts/generateliteindex.py --root "$(pwd)" |
| `localchecks--from-a-checkout-that-can-see-the-generator-sibling-tero-mcp-recommended` | other | — | from a checkout that can see the generator (sibling tero-mcp recommended): | `docs/LOCAL_CHECKS.md:22` | — | python3 ../tero-mcp/scripts/generateliteindex.py --root "$(pwd)" |
| `localchecks--or` | other | — | or: | `docs/LOCAL_CHECKS.md:24` | — | python3 scripts/generateteroindex.sh   # if present as a thin wrapper |
| `localchecks--remote-optional` | section | — | Remote (optional) | `docs/LOCAL_CHECKS.md:30` | — | In GitHub: Actions → CI → Run workflow. |
| `roadmap` | note | — | security-mcp — Product Roadmap | `docs/ROADMAP.md:1` | Living (2026-07-08) | Status: Living (2026-07-08) |
| `roadmap--waves` | section | — | Waves | `docs/ROADMAP.md:10` | — | — |
| `roadmap--wave-a-harden-what-exists` | section | — | Wave A — Harden what exists | `docs/ROADMAP.md:12` | — | Triage origin/security-proxy-integration: |
| `roadmap--wave-b-proxy-wrap-path-from-paused-branch` | section | — | Wave B — Proxy / wrap path (from paused branch) | `docs/ROADMAP.md:22` | — | Triage origin/security-proxy-integration: |
| `roadmap--wave-c-product-quality` | section | — | Wave C — Product quality | `docs/ROADMAP.md:33` | — | — |
| `roadmap--api-plan` | section | — | API plan | `docs/ROADMAP.md:43` | — | — |
| `roadmap--mcp-tools-current-keep-stable` | section | — | MCP tools (current — keep stable) | `docs/ROADMAP.md:45` | — | Envelope: JSON-RPC MCP; result includes findings list, severity, safe: bool, optional redacted text. |
| `roadmap--planned-mcp-tools-wave-b` | section | — | Planned MCP tools (Wave B) | `docs/ROADMAP.md:58` | — | POST /v1/screen |
| `roadmap--http-planned-auth` | section | — | HTTP (planned auth) | `docs/ROADMAP.md:65` | — | POST /v1/screen |
| `roadmap--rust-library-stable-intent` | section | — | Rust library (stable intent) | `docs/ROADMAP.md:76` | — | // Conceptual — keep ScreeningPipeline public |
| `roadmap--pr-plan` | section | — | PR plan | `docs/ROADMAP.md:86` | — | 1. Docs assessment + roadmap (this) |
| `roadmap--non-goals` | section | — | Non-goals | `docs/ROADMAP.md:96` | — | - Replacing gitleaks / cargo-audit / trivy |
| `readme-2` | other | — | Tero index (Layer 1) | `docs/tero-index/README.md:1` | — | Machine + human citation index for this repository. |
| `readme--regenerate` | section | — | Regenerate | `docs/tero-index/README.md:13` | — | python3 /path/to/tero-mcp/scripts/generateliteindex.py --root $(pwd) |
| `readme--or-if-tero-mcp-is-a-sibling` | other | — | or if tero-mcp is a sibling: | `docs/tero-index/README.md:17` | — | python3 ../tero-mcp/scripts/generateliteindex.py --root $(pwd) |
| `readme--serve-locally` | section | — | Serve locally | `docs/tero-index/README.md:21` | — | export TEROTOKENS=local-dev:refresh |

## changelog (9 entries)

| Anchor | Kind | Id | Title | File:Line | Status | Summary |
|---|---|---|---|---|---|---|
| `changelog` | entry | — | Changelog | `CHANGELOG.md:1` | — | All notable changes to security-mcp will be documented in this file. |
| `changelog--unreleased` | section | — | [Unreleased] | `CHANGELOG.md:8` | — | - LICENSE file (MIT, matching Cargo.toml's declared license). |
| `changelog--added` | section | — | Added | `CHANGELOG.md:10` | — | - LICENSE file (MIT, matching Cargo.toml's declared license). |
| `changelog--changed` | section | — | Changed | `CHANGELOG.md:16` | — | - README: clarified this is a content/text screener (regex + entropy |
| `changelog--0.1.0-alpha.2-2025-01-22` | section | — | [0.1.0-alpha.2] - 2025-01-22 | `CHANGELOG.md:21` | — | - BREAKING: Renamed crate from embeddenator-security-mcp to security-mcp |
| `changelog--changed-2` | section | — | Changed | `CHANGELOG.md:23` | — | - BREAKING: Renamed crate from embeddenator-security-mcp to security-mcp |
| `changelog--fixed` | section | — | Fixed | `CHANGELOG.md:30` | — | - Pattern matching for "disregard all" variant of prompt injection |
| `changelog--0.1.0-alpha.1-2025-01-19` | section | — | [0.1.0-alpha.1] - 2025-01-19 | `CHANGELOG.md:34` | — | - Initial security MCP server implementation |
| `changelog--added-2` | section | — | Added | `CHANGELOG.md:36` | — | - Initial security MCP server implementation |


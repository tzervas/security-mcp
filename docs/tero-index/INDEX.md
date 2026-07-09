# security-mcp — Tero Index (Layer 1)

> **Honesty:** Empirical/Declared — lite heading/line heuristic over markdown in security-mcp via tero-mcp/scripts/generate_lite_index.py; source files are ground truth. Generated 2026-07-09.
> Use this index to find where to Read, not as authoritative ground truth.

- **Items:** 42
- **Flagged:** 0
- **item_tag:** `Empirical/Declared`
- **Machine index:** [`index.json`](./index.json)
- **Manifest:** [`MANIFEST.toml`](./MANIFEST.toml)

## doc (33 entries)

| Anchor | Kind | Id | Title | File:Line | Status | Summary |
|---|---|---|---|---|---|---|
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


#!/usr/bin/env bash
# Local parity with .github/workflows/ci.yml (manual-only remote).
# Primary quality gate for this repo. Optional git hooks:
#   pre-commit install   # uses .pre-commit-config.yaml (fmt + pre-push full check)
# Prefer this script over relying on remote CI alone — see docs/LOCAL_CHECKS.md.
set -euo pipefail
cd "$(dirname "$0")/.."
MODE="${1:-}"
# Shared-agent ~/.cargo/config.toml may set a broken sccache wrapper; default to direct rustc.
# Opt in to wrappers with SECURITY_MCP_USE_SCCACHE=1.
if [[ "${SECURITY_MCP_USE_SCCACHE:-}" != "1" ]]; then
  export CARGO_BUILD_RUSTC_WRAPPER=
  export RUSTC_WRAPPER=
fi
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
# Use stable for fmt/clippy/test unless caller overrides
TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
CARGO=(cargo)
if command -v rustup >/dev/null 2>&1; then
  # Do not run `rustup component add` here: on some shared agents it poisons the next
  # `cargo rustc -` metadata probe (rustc reads rustup info text from stdin). Install
  # components once per toolchain out-of-band.
  CARGO=(cargo "+$TOOLCHAIN")
fi

if [[ "$MODE" == "--fix" ]]; then
  "${CARGO[@]}" fmt
else
  "${CARGO[@]}" fmt --check
fi
"${CARGO[@]}" clippy --all-targets --all-features -- -D warnings
"${CARGO[@]}" build --all-features
"${CARGO[@]}" test --all-features --verbose
echo "OK: checks passed ($(basename "$PWD"))"

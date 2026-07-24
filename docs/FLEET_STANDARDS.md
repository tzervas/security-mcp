# Fleet standards (tzervas)

Applied from the workstation pack under `plans/fleet-standards/pack/`.

## Workflows

| Workflow | When | Runner |
|----------|------|--------|
| `fleet-ci.yml` | push/PR to main|dev | self-hosted linux x64 podman |
| `fleet-security.yml` | push/PR + weekly | same |
| `close-issues-on-main.yml` | PR closed→main | ubuntu-latest |
| `reopen-issues-closed-off-main.yml` | PR merged off-main with Closes | ubuntu-latest |

## Issue close policy

- **`dev` / feature merges:** `Refs #n` only — issues stay open
- **`main` merges:** `Closes #n` / `Fixes #n`
- **Epics:** close only when delivery PR to main includes `Closes #<epic>`

## Badges

README badges use GitHub Actions SVG for **trunk** branch — live status, not static green.

## Copilot

Automatic Copilot code reviews are **disabled** for fleet-managed repos. Do not request Copilot on PRs.

## Permissions

Workflows use minimum `permissions:` blocks (contents read; issues write only for close/reopen jobs).

## Badge honesty

- **CI badge** reflects `fleet-ci` (detect + language jobs; pytest must fail the job).
- **Security badge** reflects `fleet-security` as a whole; gitleaks is a hard gate, trivy filesystem may be advisory (`continue-on-error`).

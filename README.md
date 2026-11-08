# AISG Security Scan — GitHub Action

Scan your repository with [AISG](https://aisg.web.id) on every pull request. You get one
comment with **what to do now**: the three fixes to make first, leaked secrets to rotate,
dependency upgrade commands, and what the scan did not check. The full PDF report is
attached to the workflow run.

- **Your code stays in your CI.** The scanners run on the GitHub runner; AISG receives only
  finding metadata (scanner, rule, file:line, severity), the same as the AISG desktop worker.
- **Signed scanner package.** The AISG worker is downloaded when the job runs and used only if
  the AISG release signature (Ed25519) and every file hash match. This repository contains
  no scanner code — only this wrapper and the public release key.
- **Revocable credential.** The `AISG_WORKER` secret is an AISG worker credential. Revoke it
  in the AISG dashboard at any time.

## Setup (2 minutes)

1. In the AISG dashboard open **Worker → Advanced: connect a second PC manually → Connect
   manually** and copy the worker id and secret.
2. In your repository open **Settings → Secrets and variables → Actions → New repository
   secret**: name `AISG_WORKER`, value `<worker_id>:<secret>`.
3. Add `.github/workflows/aisg.yml`:

```yaml
name: AISG security scan
on:
  pull_request:
    branches: [main, master]
  workflow_dispatch:
permissions:
  contents: read
  pull-requests: write
jobs:
  aisg:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: aisg-security/scan-action@v1
        with:
          aisg-worker: ${{ secrets.AISG_WORKER }}
          fail-on: none   # or: critical / high
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `aisg-worker` | — | `<worker_id>:<secret>` from the AISG dashboard (required) |
| `fail-on` | `none` | Fail the check when findings at or above `critical`, `high`, `medium` or `low` exist |
| `comment` | `true` | Post or update one AISG comment on the pull request |
| `github-token` | `github.token` | Token used for the comment (needs `pull-requests: write`) |
| `api-url` | `https://aisg.web.id` | AISG API |

Outputs: `risk-level`, `findings`, `report` (path of the PDF on the runner).

## Plans and quota

Every AISG plan can use the action. Each completed scan counts as one scan of your monthly
quota, exactly like a desktop scan. The example runs only on pull requests to the main branch
to keep that low. The Community plan comment shows the counts only; Beginner and above show
locations, fix steps and dependency commands.

## Limits

- Linux runners (`ubuntu-latest`). Scanners that need Docker images or an LLM endpoint
  (Expert) are reported as "not checked" with the reason, never as clean.
- Pull requests from forks do not receive secrets, so the scan is skipped for them by design.
- Findings are indications from automated scanners. Verify before you act.

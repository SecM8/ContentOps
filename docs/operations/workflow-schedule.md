# Workflow Schedule Reference

All times in UTC. Scheduled workflows are staggered so no two OIDC-
authenticated workflows fire at the same minute, reducing token-
exchange contention against Azure Entra ID.

## Daily

| Time  | Workflow                    | OIDC | Notes                              |
|-------|-----------------------------|------|------------------------------------|
| 03:00 | Public mirror sync          | No   | PAT-based mirror push              |
| 03:30 | KQL schemas refresh         | Yes  | LA metadata + Defender XDR schemas |
| 04:00 | Status refresh              | Yes  | Regenerate L1-L7 status pages      |
| 04:17 | Secret scan                 | No   | Full-history scan                  |
| 06:00 | Drift detection             | Yes  | Drift detection + auto-PR          |
| 07:00 | Alerts report               | Yes  | Alert sync, rollup, health         |
| 07:30 | Portfolio report            | Yes  | Portfolio CSV/JSON + telemetry     |
| 08:00 | Validate detections (nightly)| No  | Lint regression catch              |

## Monday-only

| Time  | Workflow                    | OIDC | Notes                              |
|-------|-----------------------------|------|------------------------------------|
| 04:00 | Audit chain verify          | No   | Weekly hash-chain integrity check  |
| 05:00 | Deployment conformance      | Yes  | End-to-end L1-L7 deployment check |
| 05:30 | Collect detections          | Yes  | Full tenant snapshot               |
| 06:30 | Upstream catalog watchers   | Yes  | Marketplace + templates poll       |
| 07:00 | Silent rules report         | Yes  | Silent + auto-disabled rules       |
| 08:00 | Detection inventory report  | No   | HTML/JSON/badge                    |

## Tuesday

| Time  | Workflow                    | OIDC | Notes                              |
|-------|-----------------------------|------|------------------------------------|
| 06:00 | Defender Graph probe        | Yes  | Probe beta endpoints               |

## Saturday

| Time  | Workflow                    | OIDC | Notes                              |
|-------|-----------------------------|------|------------------------------------|
| 06:00 | References URL check        | No   | HEAD-check all URLs in detections  |

## Design Principles

- No two OIDC workflows share the same cron minute.
- Monday workflows are spread across 04:00-08:00 (previously
  clustered at 06:00-07:00).
- All scheduled OIDC workflows have a public-mirror gate
  (`github.repository == 'KustoKing/SIEMContent'`) so they
  silently skip on the code-only mirror — **and on any fork**.
  Forks must re-point the gate to their own `<org>/<repo>` slug
  before scheduled runs fire; see
  [`github-actions-setup.md` §6](github-actions-setup.md#6-scheduled-workflows--re-point-the-repo-slug-gate).

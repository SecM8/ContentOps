# Maintainers

Current maintainers of ContentOps powered by SecM8. Maintainers have
merge rights and are responsible for triage, release management, and
enforcing the project [Code of Conduct](CODE_OF_CONDUCT.md).

| GitHub | Role | Areas |
|---|---|---|
| @KustoKing | Lead maintainer | Architecture, releases, security |

## Becoming a maintainer

Maintainership is by invitation. The path:

1. **Sustained contributions** — typically five or more merged PRs of
   non-trivial scope, plus active participation in reviews and
   discussions.
2. **Subject-matter ownership** — you become the go-to reviewer for a
   specific area (e.g., a particular handler, the lint subsystem, the
   audit chain).
3. **Invitation** — an existing maintainer proposes you in a
   private channel; the existing maintainers reach rough consensus.
4. **Onboarding** — you receive write access, get added to the
   `MAINTAINERS.md` file in a PR, and are added to relevant CODEOWNERS
   entries.

There is no fixed cadence; maintainership grows when there is genuine
review-bandwidth demand, not on a calendar.

## Stepping down

Maintainers may step down at any time by opening a PR that removes
their entry. If a maintainer is inactive for six months without
notice, the remaining maintainers may move them to an
`emeritus` section by PR.

## Decision making

Day-to-day: any maintainer can merge a PR that has at least one
approving maintainer review.

Architectural changes (new handlers, schema migrations, lint-rule
additions that affect existing detections, license / governance
changes): require two maintainer approvals plus a 48-hour comment
window for objections.

Security incidents: any maintainer can act unilaterally to remove
risky content; post-hoc review happens within 24 hours.

## Emeritus

Maintainers who have stepped down with sustained prior contribution
are listed here for project memory. They retain no special
privileges.

_(none yet)_

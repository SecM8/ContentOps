# Tenant configuration: the three supported modes

ContentOps reads tenant identity (Entra ID tenant GUID) and workspace
targeting (subscription, resource group, workspace name) from a
single YAML file at `config/tenant.yml`. **Three layout patterns**
are supported for where that file's content lives at runtime. Pick
one per repository / fork:

- **Mode A** — `config/tenant.yml` committed to git (private repos).
- **Mode B** — `config/tenant.yml` gitignored; CI materialises from
  the `TENANT_CONFIG_YAML` secret (**default for this repo**).
- **Mode C** — `config/tenant.yml` not in git, not in a single
  secret; assembled from per-key vars + secrets (future option, not
  implemented).

This page names each mode, when to pick it, and how to switch.

---

## Runtime precedence

Two distinct concerns:

1. **Authentication** — always OIDC federated credentials in CI,
   `DefaultAzureCredential` (env-var service principal or `az login`)
   locally. No long-lived credential ever lives in the repo.
2. **Tenant configuration** — resolved at job start by the
   "Materialise tenant configuration" step in
   [`pipeline-setup/action.yml`](../../.github/actions/pipeline-setup/action.yml).

The configuration resolution is `file-on-disk → secret-materialise → fail`:

| Step | What happens | When it fires |
|---|---|---|
| 1 | `[ -f config/tenant.yml ]` → use it as-is | Mode A (file is committed) **or** local dev (file copied from example) |
| 2 | Materialise from `inputs.tenant-config-yaml` (wired to `secrets.TENANT_CONFIG_YAML` by callers) | Mode B (CI in the public-OSS repo) |
| 3 | Emit `::error::` + exit 1 | Neither path provides a config |

Code reference: [`.github/actions/pipeline-setup/action.yml`](../../.github/actions/pipeline-setup/action.yml)
lines 115-138; [`contentops/config.py`](../../contentops/config.py) lines
180-205 (the loader's `FileNotFoundError` carries the same recipe).

---

## Mode B — secret-driven (this repo's default)

**When to pick**: the repo is public or shared across organisations.
Identifiers (tenant GUID, subscription GUID, workspace name) are
reconnaissance-grade data; keeping them out of the public git tree
limits casual exposure. This is what `SecM8/ContentOps` ships
because it is a public Apache-2.0 project. See [`SECURITY.md`](../../SECURITY.md)
"Incident history" for the rotation that motivated this default.

**Setup**:

```bash
# 1. Make a local config from the template.
cp config/tenant.yml.example config/tenant.yml
# 2. Edit the four placeholder GUIDs + workspace names.
# 3. Push it to GitHub as a repo-level secret.
gh secret set TENANT_CONFIG_YAML --repo <owner>/<repo> < config/tenant.yml
```

Scope the secret per environment for stricter isolation:

```bash
gh secret set TENANT_CONFIG_YAML --env production    < config/tenant.yml
gh secret set TENANT_CONFIG_YAML --env integration   < config/tenant.yml.integration
gh secret set TENANT_CONFIG_YAML --env automation    < config/tenant.yml
```

**Local development**: keep `config/tenant.yml` on disk; it is
gitignored ([`.gitignore` lines 22-30](../../.gitignore)) so an
accidental `git add -A` can't commit it. `contentops doctor`,
`contentops plan`, etc. read it directly without any secret.

**Switching away from Mode B**: see Mode A below.

---

## Mode A — committed `tenant.yml` (private-corp fork)

**When to pick**: you have forked into a private repository that is
only readable by trusted org members. The friction of maintaining a
secret outweighs the small additional disclosure surface. Many
internal SOC adopters land here.

**Setup**:

1. Open `.gitignore`. Delete the block under
   `# --- Tenant configuration ----------------------------` (lines
   22-30 in the upstream repo). Keep the entries for `.env` and
   build artefacts.
2. Commit the real `config/tenant.yml`:

   ```bash
   cp config/tenant.yml.example config/tenant.yml
   # Edit, then:
   git add config/tenant.yml .gitignore
   git commit -m "config: track tenant.yml in this private fork"
   ```

3. (Optional) Drop the `TENANT_CONFIG_YAML` secret since it is no
   longer used:

   ```bash
   gh secret delete TENANT_CONFIG_YAML
   ```

The composite action already supports this path: when
`config/tenant.yml` exists in the workspace, step 1 of the
precedence above wins and no secret is read. **No code change is
required.** The composite at
[`pipeline-setup/action.yml:128`](../../.github/actions/pipeline-setup/action.yml)
short-circuits on `[ -f "$default_cfg" ]`.

**Safety reminder**: a private repo's "private" is only as good as
the org's collaborator list and SSO posture. Treat the committed
file as semi-sensitive — anyone with `read` on the repo can see
your tenant + subscription IDs. Use Mode B if collaborator-set
hygiene is not airtight.

---

## Mode C — vars + secrets split (future option, not implemented)

**When to pick**: your organisation's secret-management discipline
forbids multi-line opaque secret blobs and prefers per-key storage
with separate audit per value. Common in Fortune 500 / regulated
environments.

**Status**: documented as a target, not yet implemented. There is
no adopter blocking on it as of writing.

**Sketch of the change** (so future implementers know the shape):

- Add inputs to [`pipeline-setup/action.yml`](../../.github/actions/pipeline-setup/action.yml):
  - `prod-subscription-id`, `prod-resource-group`, `prod-workspace-name`,
    `prod-location`
  - `integration-subscription-id`, `integration-resource-group`, ...
  - `defender-enabled`
- Each calling workflow passes a mix of `${{ vars.* }}` and
  `${{ secrets.* }}` based on the value's sensitivity:
  - **Vars** for purely operational fields (`location`,
    `workspaceName`, `resourceGroup`, `role`).
  - **Secrets** for subscription IDs if the org considers them
    sensitive; or **vars** if it doesn't.
- The "Materialise tenant configuration" step gains a branch:
  if neither the file nor the multi-line `TENANT_CONFIG_YAML`
  secret is present, render `config/tenant.yml` from a Jinja-like
  Python template fed by the new inputs.
- Tests: add a `tests/v2/test_composite_mode_c.py` fixture that
  exercises the assembly path in isolation.

If you need Mode C, **open an issue** describing your org's
secret-management constraint so the implementation can be tuned to
real requirements rather than speculation.

---

## Local testing recipe

Mode B contributors do not need the secret to run the pipeline
locally. Three commands:

```bash
cp config/tenant.yml.example config/tenant.yml   # local-only, gitignored
# Edit the placeholders. Your real Azure tenant + subscription
# GUIDs go here. NEVER commit this file in Mode B.
contentops doctor                                  # validates the layout
```

See [`docs/development/local-testing.md`](../development/local-testing.md)
for `.env` setup, RBAC, and live-Azure validation commands.

---

## Quick reference

| Mode | `tenant.yml` in git? | `TENANT_CONFIG_YAML` secret? | Per-key vars/secrets? | Best fit |
|---|---|---|---|---|
| A | yes | no | no | private corp fork |
| B | no  | yes | partial (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID` are vars today) | **this repo — public OSS** |
| C | no  | no  | yes (one input per field) | strict secret-management orgs (not implemented yet) |

All three modes use the same OIDC federated-credential flow for
Azure authentication; the difference is purely *where* the tenant
configuration content lives.

---

## When to switch

- **Adopting upstream for your org**: pick Mode A (private fork) or
  Mode B (mirror this repo's defaults). Decide before the first
  deploy.
- **Operating long-term**: do not switch modes casually. Each switch
  requires either committing data to git (Mode A) or rotating a
  secret (Mode B); both leave audit traces and disrupt CI for the
  duration of the change window.
- **From Mode B → Mode A**: see the Mode A setup steps above.
- **From Mode A → Mode B**: reverse — re-add the `.gitignore`
  entry, `git rm config/tenant.yml`, set the secret. Do this in
  one PR per the [`SECURITY.md`](../../SECURITY.md) rotation
  pattern; force-push the history rewrite separately if the
  disclosure window is unacceptable.

---

## Optional `policy:` block — project-level toggles

Beyond the workspace/identity fields, `tenant.yml` accepts an
optional `policy:` sub-block carrying project-level posture
toggles. Single field today; the namespace exists as a
forward-looking home for additional policy fields without
polluting top-level tenant identity.

```yaml
tenant:
  name: production
  tenantId: "<entra-id-guid>"
  defender:
    enabled: true
  sentinelWorkspaces:
    - role: prod
      ...
  policy:
    scaffoldStrict: true   # operator opt-in once the authoring backlog drains
```

### `policy.scaffoldStrict`

Controls whether the META002–META005 lint rules
(`description`, `attackDescription`, `references`,
`falsePositives`) fire as **errors** (CI-blocking) or
**warnings** (informational backlog meter). See
[`docs/reference/envelope-schema.md`](../reference/envelope-schema.md)
for the rule reference.

| `tenant.yml` state | META002–005 severity | CI gate |
|---|---|---|
| `tenant.yml` absent (fresh clone / unit tests / unconfigured) | warning | exit 0 |
| `tenant.yml` present, no `policy:` block | warning | exit 0 unless `--fail-on-warn` |
| `tenant.yml` present, `policy:` present but `scaffoldStrict` unset | warning | exit 0 unless `--fail-on-warn` |
| `tenant.yml` present, `scaffoldStrict: false` | warning | exit 0 unless `--fail-on-warn` |
| `tenant.yml` present, `scaffoldStrict: true` | **error** | exit 1 on first META hit |

**Lenient-by-default** as of PR #241. Adopters with a fresh
`config/tenant.yml` see warnings, not CI-blocking errors, for the
META002–005 authoring fields — this matches the operational
reality that the G24 metadata-authoring backlog still exists on
collected envelopes. Operators with a drained backlog set
`scaffoldStrict: true` explicitly to upgrade those four rules to
errors. See [[feedback_internal_fail_fast_public_smooth]] for the
operator-vs-adopter posture distinction.

META006–007 (`blindSpots`, `responseActions`) stay info in both
modes — "known evasion catalogue" and "inline response steps"
are best-effort content; gating CI on them would be
over-strict.

The lint runner surfaces the active mode in its footer when
META002–005 findings are present, so operators can connect a
suddenly-red build to the right knob:

```
META rules in lenient mode (tenant.policy.scaffoldStrict=false, the default).
META002-005 are warnings; set `policy.scaffoldStrict: true` in
config/tenant.yml once the authoring backlog is drained to gate CI on
metadata gaps.
```

---

## Per-workspace safeguards: `writeAllowed` / `purgeAllowed` / `maxDelete`

Three fields on every `sentinelWorkspaces` entry **and** the
`defender:` block give the operator a config-level brake on the
two destructive CLI / workflow paths:

| Field | Default | Gates | What "fail-closed" looks like |
|---|---|---|---|
| `writeAllowed` | `true` | `contentops apply`, `deploy.yml`, `integration-deploy.yml` | Non-dry-run apply against the workspace exits 2 with a clear "writeAllowed=False" error. `--dry-run` bypasses the gate so operators can still preview. |
| `purgeAllowed` | `false` | `contentops prune`, `prune.yml` | Prune exits 2 before opening any Azure connection. The error names the offending workspace so the operator knows which entry to edit. |
| `maxDelete` | `25` (range 0..9999) | `contentops prune --max-deletes`, `prune.yml`'s `max_deletes` input | The minimum of (CLI value, workflow input, workspace value) wins. Clamping is announced in stderr ("`info: --max-deletes clamped 500 -> 25 by tenant.yml safeguards`"). |

These live in the **tenant config** that CI reads — so even a CI
compromise cannot bypass them without rotating the
`TENANT_CONFIG_YAML` GitHub Actions secret. They sit in addition
to the three CI-side brakes (`workflow_dispatch`, `CONFIRM` input,
GitHub Environment reviewer gate), giving four physical brakes
total on destructive ops.

### Defaults reasoning

- `writeAllowed: true` — adopters expect a working pipeline on day
  one. A surprise refusal on first `apply` would be a worse
  user experience than the unlikely "wrong env" mishap that the
  gate would catch ([[feedback_internal_fail_fast_public_smooth]]).
- `purgeAllowed: false` — irreversibly destructive; the burden is
  on the operator to explicitly opt in. Matches the four-eyes
  posture of all the other prune brakes.
- `maxDelete: 25` — same number as the existing `prune.yml`
  workflow default. Lenient enough for legitimate orphan cleanup,
  low enough to refuse an "oops, wrong env" rampage.

### Operator dance to actually purge

The bulk-purge workflow stays explicit by design — there is no
"easy mode":

1. Edit the `TENANT_CONFIG_YAML` GitHub Secret (or
   `config/tenant.yml` for local CLI). Set `purgeAllowed: true`
   and a sufficient `maxDelete` on the target workspace.
2. Dispatch the prune workflow (or run `contentops prune`).
3. **Revert the secret** back to the locked defaults
   (`purgeAllowed: false`, `maxDelete: 25` or `0`) so a subsequent
   accidental dispatch can't ride the same window.

A non-zero `maxDelete` is harmless with `purgeAllowed: false` —
prune still refuses before even computing the orphan list. But
`maxDelete: 0` with `purgeAllowed: true` is also safe: the cap
clamps every deletion to zero and the prune is a no-op.

### Why these fields and not a single switch?

A single boolean would conflate "you can write" and "you can
mass-delete" — two operations with very different blast radii.
Apply touches one rule at a time and is reversible; prune
deletes many in one go and is not. The three-field model keeps
"normal write traffic" decoupled from "irreversible bulk delete"
so an operator never has to flip a "production unlocked" master
switch and then remember to flip it back.

# Authentication setup — Azure App Registration + OIDC

> First-time setup for the Azure identity that ContentOps uses to talk
> to Microsoft Sentinel and Microsoft Defender XDR. Read this before
> [`onboarding.md`](../onboarding.md) Day-1 step 4 if you've never
> created an Azure App Registration or set up GitHub OIDC federated
> credentials. Skim the TL;DR if you've done it before.

> **GitHub side**: once you've finished this doc (the Azure side), see
> [`github-actions-setup.md`](github-actions-setup.md) for wiring the
> App Registration + tenant config into GitHub Actions Variables,
> Secrets, Environments, and federated credentials.

## Path A vs Path B — pick yours first

Two local-dev authentication paths to ContentOps. They use different
identities and the RBAC needs to be on whichever identity is active —
this trips adopters up routinely, so read this before configuring.

| Path | Identity used | What it needs | Use when |
|---|---|---|---|
| **A. `az login` as user** | YOUR USER identity (your Entra account) | Your USER needs `Microsoft Sentinel Contributor` on the workspace RG. No client secret, no `.env`. | Default for local dev. No secrets on disk. |
| **B. `.env` with App Reg secret** | The App Registration's service principal | The APP REG'S SP needs Sentinel RBAC. `.env` carries `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`. | When you want to mirror CI exactly. |

A common mistake: granting Sentinel RBAC to the App Reg, then using
Path A (your user has no RBAC). You'll see `401` from `doctor --matrix`
even though `token_acquisition` PASSes — the token is for an identity
that can't read the workspace. The fix is to grant RBAC to whichever
identity you're authenticated as, OR switch paths.

### Diagnostic decoder

| Status | Where it appears | What it means |
|---|---|---|
| 401 on `workspace_reachable` | doctor / conformance L6 | Token rejected as unauthenticated. Either the wrong identity (Path A user vs Path B App Reg mismatch with RBAC), wrong tenant (`az account show` mismatch with `tenant.yml`), or `DefaultAzureCredential` returned a stale cached identity. Try `$env:AZURE_TOKEN_CREDENTIALS = "dev"` to force the dev-credential chain. |
| 403 on `workspace_reachable` | doctor / conformance L6 | Authenticated, but the active identity lacks RBAC. Grant Sentinel Contributor on the RG to whichever identity is active. |
| 403 on Graph endpoints | doctor `graph_reachable`, Defender handlers | App Reg lacks `CustomDetection.ReadWrite.All` (or other Graph permission). |

## TL;DR

If you've done this before:

- Create an App Registration in your Entra ID tenant.
- Grant `Microsoft Sentinel Contributor` (+ `Log Analytics Contributor`)
  on the workspace resource group; grant Microsoft Graph
  `CustomDetection.ReadWrite.All` with admin consent.
- Local dev: client secret in `.env`.
- CI: OIDC federated credential with subject
  `repo:<org>/<repo>:environment:<env>`.
- Put the App Reg's client ID + tenant ID into GitHub Actions
  **Variables** (not Secrets — they're public identifiers, not
  credentials).

If any of that is unfamiliar, read on — every step is explained.

---

## What is an Azure App Registration?

An **App Registration** is Azure's way of giving a piece of software
(here, ContentOps) its own identity. Think of it as a robot user
account:

- It has a unique ID (the **Application (client) ID**).
- It belongs to your Entra ID tenant (the **Directory (tenant) ID**).
- It can be granted permissions (Azure roles, Microsoft Graph scopes)
  just like a human user — but unlike a human, it never logs in
  interactively.
- The pipeline authenticates **as** this App Registration when it
  talks to Microsoft Sentinel (Azure ARM) and Microsoft Defender XDR
  (Microsoft Graph).

Why not just use a human identity?

1. **Auditability.** Every API call ContentOps makes shows up under
   this App Reg's name. You can answer "who deployed rule X?" with a
   single audit query.
2. **Lifecycle independence.** When someone leaves the team, their
   personal account gets deactivated. The pipeline doesn't break.
3. **Least privilege.** The App Reg gets exactly the roles it needs,
   scoped to the resource groups it manages — and nothing more.

Microsoft also uses the words **service principal** and **Enterprise
Application** for related concepts. The App Registration is the
application *definition*; the service principal is the per-tenant
*instance*. For this pipeline you only need to think about the App
Registration — Azure creates the service principal automatically.

---

## What is OIDC and why we use it

**OIDC** stands for **OpenID Connect**. In our context it's the
mechanism that lets GitHub Actions authenticate to Azure **without a
long-lived secret stored anywhere in the repository**.

The traditional approach: store the App Registration's client secret
as a GitHub Actions secret, pass it into every workflow that calls
Azure. Risks:

- Secrets can leak through workflow logs.
- Secrets need rotation (every 12–24 months) — easy to forget.
- A leaked secret stays valid for its full lifetime.

The OIDC approach:

- Configure your App Registration to **trust** GitHub's identity
  provider.
- Configure a **federated credential** that says: *"I'll trust an
  identity token from GitHub IF it claims to be running in the
  `<your-org>/<your-repo>` repo on the `production` environment."*
- When the workflow runs, GitHub issues a short-lived (≈15 min) OIDC
  token. The Azure SDK exchanges it for an Azure access token.
- **No long-lived secret anywhere.** Tokens are minted on demand and
  expire quickly.

For **local development** we still use the client-secret flow because
OIDC tokens are minted by the GitHub Actions runtime — there's no
equivalent on your laptop. We mitigate the risk by:

- Keeping the local secret in `.env` (which is gitignored).
- Using a short expiry (90–180 days) and rotating regularly.
- Optionally using `az login` instead of a stored secret for ad-hoc
  work (interactive sign-in; no secret on disk).

See the [local-vs-CI table](#step-4-local-dev-client-secret-vs-ci-oidc)
below for which flow runs when.

---

## Step 1: Create the App Registration

In the Azure portal:

1. **Sign in** at <https://portal.azure.com> with an account that has
   permission to create App Registrations in the Entra ID tenant.
2. Navigate to **Microsoft Entra ID** → **App registrations** →
   **+ New registration**.
3. **Name** it something descriptive: `contentops-pipeline` or
   `siemcontent-deploy`.
4. **Supported account types**: pick *"Accounts in this organizational
   directory only (single tenant)"*. The pipeline is single-tenant by
   design.
5. **Redirect URI**: leave blank. The pipeline never does a
   redirect-based interactive login.
6. Click **Register**.

After registration, on the App Registration's **Overview** blade:

- Copy the **Application (client) ID** — this is your `AZURE_CLIENT_ID`.
- Copy the **Directory (tenant) ID** — this is your `AZURE_TENANT_ID`.

You don't need a client secret yet. That comes in step 4.

---

## Step 2: Grant the App Registration its permissions

The pipeline touches **four** permission surfaces. Only the first two are
core; the two Graph read-only scopes are **optional** and gate specific
features. Grant the minimum your deployment actually uses — ContentOps
degrades gracefully when a surface is absent.

| # | Surface | Permission (read → write) | Required? | Enables |
|---|---|---|---|---|
| 1 | **Microsoft Sentinel** (Azure RBAC) | `Microsoft Sentinel Reader` (+ `Log Analytics Reader`) → `Microsoft Sentinel Contributor` (+ `Log Analytics Contributor`) | If you manage **Sentinel** content | Read: drift/coverage/reporting/silent-rules/rule-test KQL. Write: deploy analytics, hunting, watchlists, parsers, connectors. |
| 2 | **Defender custom detections** (Graph) | `CustomDetection.Read.All` → `CustomDetection.ReadWrite.All` | If you manage **Defender** detections | Read: read/diff deployed Defender custom detections. Write: create/update/delete them. |
| 3 | **Advanced hunting schema** (Graph) | `ThreatHunting.Read.All` (read only) | **Optional** | Auto-refresh of the Defender KQL table schema used by `kql_strict` lint. |
| 4 | **Security alerts** (Graph) | `SecurityAlert.Read.All` (read only) | **Optional** | Defender XDR alert telemetry: `alerts`, the unified report's TP/FP/MTTR, navigator "firings". |

**The graceful-degradation contract — all four of these "just work":**

- **Read-only grants only** (Reader + `CustomDetection.Read.All`): every
  read path works — `lint`, `collect`, `drift`, `coverage`, `report`,
  `silent-rules`, and the conformance read leg. Deploy (`apply`) is the
  only thing you can't do.
- **Read-write grants** (Contributor + `CustomDetection.ReadWrite.All`):
  the above plus `apply` / deploy.
- **No `ThreatHunting.Read.All`** → set `defender.enabled: false` in
  `config/lint_strict.yml`. The vendored
  `tools/kql_strict/schemas_defender.json` stays the source of truth and
  the lint still runs; only the *auto-refresh* of that schema is off.
- **No `SecurityAlert.Read.All`** → alert collection falls back to the
  Sentinel `SecurityAlert` table over KQL (needs Reader), or the
  alert/telemetry features are simply unused. Nothing else is affected.

Surfaces 1 and 2 are independent: a Sentinel-only shop never needs the
Graph `CustomDetection` scope, and a Defender-only shop never needs
Sentinel RBAC. Grant what you operate.

### Sentinel — Azure ARM roles

The App Reg needs to write detection rules into the Sentinel workspace.
Grant **both** of:

- **`Microsoft Sentinel Contributor`** on the resource group containing
  your Sentinel workspace.
- **`Log Analytics Contributor`** on the same resource group. Hunting
  queries and parsers live as `savedSearches` on the Log Analytics
  workspace (the underlying resource), so the Sentinel role alone
  isn't enough.

In the portal:

1. Navigate to the resource group.
2. **Access control (IAM)** → **+ Add** → **Add role assignment**.
3. Pick the role, click **Next**.
4. **Members** → **Select members** → search for your App
   Registration by name → click it → **Select**.
5. **Review + assign**.

Repeat for the second role.

Or via Azure CLI:

```bash
APP_OBJECT_ID=$(az ad sp show --id <client-id> --query id -o tsv)

az role assignment create \
  --assignee-object-id "$APP_OBJECT_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Contributor" \
  --scope /subscriptions/<sub-id>/resourceGroups/<rg-name>

az role assignment create \
  --assignee-object-id "$APP_OBJECT_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Log Analytics Contributor" \
  --scope /subscriptions/<sub-id>/resourceGroups/<rg-name>
```

### Defender XDR — Microsoft Graph permission

The App Reg needs to manage custom detection rules on Defender XDR.

In the portal:

1. Open the App Registration.
2. **API permissions** → **+ Add a permission** → **Microsoft Graph**.
3. **Application permissions** (not Delegated — the pipeline runs as
   the app, not as a signed-in user).
4. Search for **`CustomDetection.ReadWrite.All`** → tick it →
   **Add permissions**.
5. The permission appears with a yellow warning: *"Not granted for
   <tenant>"*. Click **Grant admin consent for <tenant>**.

You need a **Global Administrator** or **Privileged Role
Administrator** to grant admin consent. If you don't have that role,
ask someone who does — without consent the Defender handler will
return `403 Forbidden` on every call.

After consent the status flips to a green check ("Granted for
<tenant>").

### Defender XDR — `ThreatHunting.Read.All` for the schema refresh

Required when `config/lint_strict.yml: defender.enabled: true` AND
the operator wants the **automatic** Defender schema refresh
(`contentops upstream check-defender-schema`). The schema refresh
calls Graph `POST /v1.0/security/runHuntingQuery` with
`<table> | getschema` for each Defender table, which needs the
`ThreatHunting.Read.All` permission.

If you'd rather not grant this — set
`defender.enabled: false` in `config/lint_strict.yml`. The vendored
`tools/kql_strict/schemas_defender.json` stays as the source of
truth; the wrapper still loads it; only the auto-refresh path is
disabled. Manual edits (or PRs sourced from the public ContentOps
mirror) keep the file current.

Same steps as the previous permission, just a different name:

1. Open the App Registration.
2. **API permissions** → **+ Add a permission** → **Microsoft Graph**.
3. **Application permissions**.
4. Search for **`ThreatHunting.Read.All`** → tick it → **Add permissions**.
5. **Grant admin consent for <tenant>**.

If you skip consent, `kql-schemas-refresh.yml`'s Defender step exits
1 with a clear `Graph runHuntingQuery returned 401` message and
`notify-workflow-failure` opens an issue (fail-loud by design — see
the F1.1 plan).

### Defender XDR — `SecurityAlert.Read.All` for alert telemetry (optional)

Grant this **only** if you want ContentOps to read Defender XDR alerts —
which powers `contentops alerts`, the unified report's per-detection
TP/FP/MTTR, and the MITRE Navigator "firings" axis. It is a read-only
Graph application permission; the pipeline never writes alerts.

Same steps as the permissions above (Microsoft Graph → Application
permissions → `SecurityAlert.Read.All` → Grant admin consent).

**If you don't grant it, nothing breaks:** alert collection falls back to
the Sentinel `SecurityAlert` table over KQL (which only needs the Sentinel
Reader role from surface 1), and if you have neither a Graph alert scope
nor a Sentinel workspace, the alert-telemetry features simply stay unused —
the rest of the pipeline (lint, deploy, drift, coverage) is unaffected.
The legacy `SecurityEvents.Read.All` is the older equivalent and is
recognised too, but `SecurityAlert.Read.All` is the current scope.

---

## Step 3: Add an OIDC federated credential (for CI)

This step is **only needed for CI**. Local dev uses the client-secret
flow in step 4 instead.

In the App Registration:

1. **Certificates & secrets** → **Federated credentials** tab →
   **+ Add credential**.
2. **Federated credential scenario**: *GitHub Actions deploying Azure
   resources*.
3. **Organization**: your GitHub org or user (e.g. `KustoKing`).
4. **Repository**: the exact repo name (e.g. `ContentOps` for the
   public reference deployment, or whatever you named your fork).
   Case-sensitive — must match the repo URL.
5. **Entity type**: **Environment**.
6. **GitHub environment name**: `production`.
7. **Name**: `github-actions-production` (anything; for your records).
8. Click **Add**.

If you have an integration workspace, add a second federated
credential with **GitHub environment name**: `integration`.

What this does: when a workflow runs `environment: production`, GitHub
issues an OIDC token whose `sub` claim equals
`repo:<org>/<repo>:environment:production`. The federated credential
tells Azure *"trust that exact subject from GitHub's issuer
(token.actions.githubusercontent.com)"*. That's the entire chain of
trust — no shared secret needed.

---

## Step 4: Local dev (client secret) vs CI (OIDC)

|                  | Local development                                     | CI (GitHub Actions)                                 |
|------------------|-------------------------------------------------------|-----------------------------------------------------|
| Auth flow        | Client secret **or** `az login`                       | OIDC federated credential                           |
| Stored where     | `.env` (gitignored)                                   | Nowhere — issued per workflow run                   |
| Lifetime         | Until you rotate it (90–180 days recommended)         | ≈15 minutes per run                                 |
| When it's used   | `contentops doctor`, dry-run apply, live integration tests | `deploy.yml`, `drift.yml`, `collect.yml`, all prod paths |

### Local: client secret

1. App Registration → **Certificates & secrets** → **Client secrets**
   tab → **+ New client secret**.
2. **Description**: something like `local-dev-2026-q2`.
3. **Expires**: pick a short window. 90 days is good hygiene; 180 days
   is the upper bound for most orgs.
4. Click **Add**.
5. Copy the **Value** column **immediately**. Azure shows it once.
   Treat it like a password.

Then in your `.env`:

```bash
AZURE_TENANT_ID=<directory-tenant-id-from-step-1>
AZURE_CLIENT_ID=<application-client-id-from-step-1>
AZURE_CLIENT_SECRET=<value-from-this-step>
AZURE_SUBSCRIPTION_ID=<subscription-containing-your-workspace>
```

`.env` is gitignored — never commit it.

**Alternative: `az login`.** Run `az login` and sign in interactively;
`DefaultAzureCredential` (the auth chain ContentOps uses) picks up
the resulting token cache automatically. Convenient for ad-hoc work,
but the service principal flow is preferred for live integration
tests because it matches what CI does.

### CI: OIDC

In your GitHub repo: **Settings** → **Secrets and variables** →
**Actions** → **Variables** tab (not Secrets — these IDs are public
identifiers, not credentials):

- `AZURE_CLIENT_ID` = the App Registration's Application (client) ID.
- `AZURE_TENANT_ID` = the Directory (tenant) ID.

That's it. **No client secret in GitHub.** The workflows reference
these variables and `azure/login@<sha>` handles the OIDC exchange.

If your repo is in Mode B (the default tenant-config mode), also set
the `TENANT_CONFIG_YAML` secret — see
[`tenant-config-modes.md`](tenant-config-modes.md).

---

## Optional: two App Registrations (separation of duties)

**A single App Registration is perfectly fine** for a POC, a dev fork, or
any deployment where one identity owning both read and write is an
acceptable trust boundary. Everything above describes that single-identity
setup, and the pipeline runs end-to-end on it. Skip this section unless you
want the hardening below.

For production separation of duties you can split into **two** App
Registrations so the always-on automation (cron jobs, drift, reporting)
can never write to the tenant:

| | **Read App Reg** | **Write App Reg** |
|---|---|---|
| Azure RBAC | `Microsoft Sentinel Reader` + `Log Analytics Reader` | `Microsoft Sentinel Contributor` + `Log Analytics Contributor` |
| Graph application permission | `CustomDetection.Read.All` (and **not** ReadWrite) | `CustomDetection.ReadWrite.All` |
| Used by | the **`automation`** GitHub environment (read-only cron: `drift.yml`, `silent-rules.yml`, reporting) | the **gated** environments (`production`, `integration`, `conformance`) — anything that applies content |

Wiring (see [`github-actions-setup.md`](github-actions-setup.md) for the
exact GitHub steps):

- Set an **environment-scoped** `AZURE_CLIENT_ID` Variable on the
  `automation` environment = the **read** App Reg's client ID.
- Leave the **repo-level** `AZURE_CLIENT_ID` Variable = the **write** App
  Reg's client ID; the gated environments inherit it.
- Add a federated credential **per environment** on the App Reg that
  serves it: `…:environment:automation` on the read App Reg;
  `…:environment:production` / `:integration` / `:conformance` on the
  write App Reg.

`contentops conformance` verifies the split is real and least-privilege —
it runs **as each identity** and checks the read identity has
`CustomDetection.Read.All`, **lacks** `CustomDetection.ReadWrite.All`, and
has no Sentinel write, while the write identity has the write grants. See
[`deployment-conformance.md`](deployment-conformance.md).

---

## Troubleshooting

### `Login failed with Error: ... Not all values are present`

GitHub Actions Variables aren't set. Repo **Settings → Variables**
and add `AZURE_CLIENT_ID` and `AZURE_TENANT_ID`.

### `AADSTS70021: No matching federated identity record found for presented assertion`

The OIDC token from GitHub doesn't match any federated credential on
the App Registration. Common causes:

- The federated credential's **GitHub environment name** doesn't match
  the `environment:` block in the workflow job.
- The federated credential's **Repository** field doesn't match the
  repo name exactly (case-sensitive).
- The federated credential's **Organization** field doesn't match the
  GitHub org/user.
- The workflow's job is missing `permissions: id-token: write`, so
  GitHub never issues the OIDC token in the first place.

Open the App Registration's federated credential and verify the
**Subject identifier** field. It must match what GitHub sends:
`repo:<org>/<repo>:environment:<env>`.

### `403 Forbidden` on a Sentinel handler

App Reg is missing `Microsoft Sentinel Contributor` (or `Log Analytics
Contributor` for hunting/parser handlers) on the workspace resource
group. Re-run the role assignment from step 2.

### `403 Forbidden` on Defender custom detection

Microsoft Graph admin consent not granted. App Registration → **API
permissions** → click **Grant admin consent for <tenant>**.

### Local dev works but CI fails

Most likely the client-secret flow is masking an OIDC
misconfiguration. The federated credential step (step 3) only matters
for CI; if you skipped it, CI fails with `AADSTS70021`. Add the
federated credential and re-run.

### Client secret expired

App Registration → **Certificates & secrets** → **Client secrets**
→ **+ New client secret**. Update `AZURE_CLIENT_SECRET` in `.env`.
You can keep the old secret valid until you've confirmed the new one
works; click **Delete** on the old row when you're ready to revoke.

### "I need to deploy to two tenants"

Out of scope — the pipeline is single-tenant by design. The OIDC trust
boundary is one App Registration per workflow per tenant. See
[`multi-workspace.md`](multi-workspace.md) for the supported pattern:
one tenant, multiple Sentinel workspaces tagged by role.

---

## Where to next

- [`../onboarding.md`](../onboarding.md) — once the App Reg is set up,
  return to the Day-1 walkthrough at step 4 (the `.env` file).
- [`multi-workspace.md`](multi-workspace.md) — if your tenant has more
  than one Sentinel workspace (integration, dev, prod).
- [`tenant-config-modes.md`](tenant-config-modes.md) — three supported
  tenant.yml layouts: committed file, secret-driven (default), or
  vars-and-secrets split.
- [`../development/local-testing.md`](../development/local-testing.md)
  — full RBAC reference, `contentops doctor --matrix` walkthrough,
  and the live integration test gates.

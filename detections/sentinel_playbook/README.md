# `detections/sentinel_playbook/`

Microsoft Sentinel **playbooks** (Consumption Logic Apps) as code. Each
playbook is **two files**:

```
detections/sentinel_playbook/<id>.yml            # envelope: metadata, connections, roles
detections/sentinel_playbook/<id>.workflow.json  # the Logic App definition — designer export, verbatim
```

- ARM resources: `Microsoft.Logic/workflows/<id>` (api `2019-05-01`) plus
  one `Microsoft.Web/connections` per declared connector (api
  `2016-06-01`), all in the workspace's `playbooksResourceGroup`
  (defaults to the workspace RG). Both are tagged `contentops-managed`.
- Scaffold: `contentops new sentinel_playbook <id>` writes both files.
  Edit the definition in the designer's code view and paste it into the
  `.workflow.json`; bump `version` in the `.yml` for either change.
- `connections:` are declared, never pasted: every connection is
  managed-identity authenticated. No secrets, no consent tokens, no
  `$connections` values on disk. OAuth-consent-only connectors
  (Office 365, Teams, SharePoint, …) are rejected at validate.
- `roleAssignments:` declares what the playbook's managed identity needs
  (e.g. Microsoft Sentinel Responder on the workspace). Apply and
  `contentops conformance` **verify and report** them with the exact
  `az role assignment create` command; the pipeline never assigns roles.
- Discovery is managed-tag only. Bring an existing portal-built Logic
  App under management with
  `contentops collect --asset sentinel_playbook --adopt <workflow-name>`.
- Default management mode is **monitor** (`assetModes` in
  `config/tenant.yml`): collect / drift / lint only until you opt in.

Full reference: [`docs/assets/sentinel_playbooks.md`](../../docs/assets/sentinel_playbooks.md).

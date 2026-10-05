# `detections/sentinel_data_connector/`

Data connector envelopes for **Microsoft Sentinel** go here.

Data connectors define the ingest bindings that feed log data into
Sentinel from Azure subscriptions, on-prem systems, third-party SaaS,
etc. Deployed via ARM at
`Microsoft.SecurityInsights/dataConnectors` (legacy kinds) +
`dataConnectorDefinitions` (Codeless Connector Platform / CCP).

## Placement

Each connector is one YAML file:

```
detections/sentinel_data_connector/<connector-id>.yml
```

The `<connector-id>` is the canonical envelope id (kebab-case slug).
This source repository ships no tenant connector YAMLs, and these paths
are not gitignored. Commit connectors to your private deployment
repository; do not commit tenant detections to a public repository.

## Authoring

Scaffold:

```bash
contentops new sentinel_data_connector <connector-id>
```

**Many connector kinds require one-time interactive consent in the
Sentinel portal** — the pipeline can PUT the resource via ARM, but the
connector status will read "disconnected" until a human clicks Connect
to authorise the App Reg used by the connector. The handler logs a
clear notice when it detects this state.

## See also

- [`../../docs/reference/asset-coverage.md`](../../docs/reference/asset-coverage.md) — endpoint, RBAC, hash projection.

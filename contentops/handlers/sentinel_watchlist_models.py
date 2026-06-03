# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pydantic models for Sentinel watchlists.

ARM resource type: Microsoft.SecurityInsights/watchlists
API version: 2025-07-01-preview

Two ingestion paths are supported:

* **Inline** (``rawContent``) — analyst-authored CSV embedded in the
  YAML envelope. ARM caps inline content at ~3.8 MB; the model
  enforces a 3.5 MB ceiling to leave envelope headroom.
* **SAS URI** (``sasUri``) — for datasets larger than the inline cap,
  upload the CSV to a SAS-protected blob and have ARM ingest it
  directly. The SAS URL is sensitive — the pipeline expects the
  caller to pass it via an env var or secret rather than committing
  it to YAML (see the ``${{ env.WATCHLIST_SAS_URI }}`` substitution
  pattern in docs/assets/sentinel_watchlist_sas.md).

Exactly one of ``rawContent`` or ``sasUri`` must be supplied. The
other ingestion-shape fields (``itemsSearchKey``, ``contentType``,
``numberOfLinesToSkip``) apply to both paths.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SentinelWatchlistPayload(BaseModel):
    """Sentinel watchlist payload.

    Maps onto ARM `Microsoft.SecurityInsights/watchlists` properties.
    The pipeline `id` of the envelope becomes the ARM resource name
    (the watchlist alias), so it must match `^[a-z0-9][a-z0-9\\-]*$`
    (already enforced at the envelope level).

    Schema notes:

    * ``source`` was historically a literal of "Local file" or "Remote
      storage". The current Sentinel API instead returns the actual
      source filename (e.g. "AutoClose.csv") in this field and a
      separate ``sourceType`` enum. We accept either shape — strict
      validation lives in the handler's apply path, not here.
    * ``rawContent`` and ``sasUri`` are deployment-time fields. A
      collected watchlist envelope GET response carries NEITHER of
      these (the API doesn't echo the CSV content back). So the
      "exactly one of" requirement only fires when we're about to
      PUT a new watchlist — moved to ``apply``.
    * ``extra="allow"`` so collected envelopes with new API fields
      (``watchlistType``, ``watchlistKind``, ``watchlistAlias``,
      etc.) load cleanly. New fields surface via the extra dict.
    """

    model_config = ConfigDict(extra="allow")

    displayName: str = Field(min_length=1, max_length=255)
    description: str | None = None
    provider: str = Field(default="Custom", min_length=1)
    # Accept either the legacy literal ("Local file" / "Remote storage")
    # OR the current API shape (a filename string). Validation of which
    # path will be used at deploy-time lives in the handler.
    source: str = "Local file"
    sourceType: str | None = None
    itemsSearchKey: str = Field(min_length=1, description="Column used for lookups via _GetWatchlist().")
    contentType: str = "text/csv"
    numberOfLinesToSkip: int = Field(default=0, ge=0)
    rawContent: str | None = Field(
        default=None,
        description="Inline CSV/JSON body. ~3.8MB ARM limit. Mutually exclusive with sasUri.",
    )
    sasUri: str | None = Field(
        default=None,
        description=(
            "SAS-protected blob URL for >3.8MB watchlists. Sensitive — "
            "do NOT commit a real SAS to YAML; use env-var substitution."
        ),
    )
    labels: list[str] | None = None
    defaultDuration: str | None = None  # ISO-8601 retention, e.g. "P30D"

    @model_validator(mode="after")
    def validate_one_ingestion_path(self) -> "SentinelWatchlistPayload":
        """rawContent / sasUri sanity — both-at-once is invalid; neither is OK.

        The "neither" case happens for watchlists collected from the
        API (the GET response doesn't echo the CSV body back). Those
        envelopes are not deployable as-is — applying one would PUT a
        watchlist with no content. The handler's apply path raises
        if it tries to deploy a content-less watchlist; here we only
        block the "both set" case.
        """
        has_raw = bool(self.rawContent)
        has_sas = bool(self.sasUri)
        if has_raw and has_sas:
            raise ValueError(
                "watchlist payload must specify exactly one of rawContent / sasUri, not both"
            )
        # Coerce `source` to match the chosen path when we have one.
        # Only fires when source is one of the legacy literals; never
        # overwrites a filename-shaped source from a collected envelope.
        if has_sas and self.source == "Local file":
            object.__setattr__(self, "source", "Remote storage")
        if has_raw and self.source == "Remote storage":
            object.__setattr__(self, "source", "Local file")
        return self

    @model_validator(mode="after")
    def validate_search_key_in_header(self) -> "SentinelWatchlistPayload":
        """itemsSearchKey must appear in the CSV header row (post-skip).

        Only validates inline rawContent; SAS-sourced CSVs are checked
        by the API at ingestion time (we don't fetch the blob to peek
        at headers — that would defeat the SAS-as-secret pattern).
        """
        if not self.rawContent:
            return self
        lines = self.rawContent.splitlines()
        if len(lines) <= self.numberOfLinesToSkip:
            raise ValueError(
                "rawContent has fewer lines than numberOfLinesToSkip + 1 (need a header row)"
            )
        header_line = lines[self.numberOfLinesToSkip]
        headers = [h.strip() for h in header_line.split(",")]
        if self.itemsSearchKey not in headers:
            raise ValueError(
                f"itemsSearchKey '{self.itemsSearchKey}' not found in CSV header "
                f"(found columns: {headers})"
            )
        return self

    @model_validator(mode="after")
    def validate_content_size(self) -> "SentinelWatchlistPayload":
        """ARM rejects rawContent > ~3.8 MB. Cap at 3.5 MB to leave envelope headroom."""
        if self.rawContent and len(self.rawContent.encode("utf-8")) > 3_500_000:
            raise ValueError(
                "rawContent exceeds 3.5 MB inline limit — split the watchlist or "
                "switch to sasUri for the >3.8 MB ingestion path."
            )
        return self

    @model_validator(mode="after")
    def validate_sas_url_shape(self) -> "SentinelWatchlistPayload":
        """SAS URLs must be HTTPS and look like a real SAS (sig= present)."""
        if not self.sasUri:
            return self
        if not self.sasUri.startswith("https://"):
            raise ValueError("sasUri must be an https:// URL")
        if "sig=" not in self.sasUri:
            raise ValueError(
                "sasUri does not look like a SAS URL (no sig= parameter) — "
                "this is almost certainly a misconfiguration."
            )
        return self


def to_watchlist_arm_body(payload: dict) -> dict:
    """Wrap a watchlist payload into the ARM PUT body shape: {properties: ...}.

    Validation is the handler's responsibility (via ``validate(loaded)``);
    this function is a pass-through so the existing call sites keep
    working with partial / lower-level dicts.
    """
    return {"properties": payload}

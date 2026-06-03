# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Walk detections/, extract every URL in metadata, HEAD-check it.

Borrowed from NVISO's `urlchecker` pattern (Part 3 of the
Detection-as-Code blog series): references rot — a CVE advisory moves,
a vendor blog gets re-organised, a Twitter link dies when an account
is suspended. Without periodic checking, citations silently age into
404s and the analyst loses the trail.

Two URL surfaces per envelope:
  * ``metadata.references`` — list of http(s) citations.
  * ``metadata.runbookUrl`` — single URL pointing at the response playbook.

Both are validated by the Pydantic model to start with ``http://`` or
``https://`` (see :mod:`contentops.core.metadata`), so this script only
has to verify reachability.

Behaviour:
  * HEAD request with a 10s timeout, follow redirects (capped at 5).
  * Every request hop is screened by ``_SafeTransport``: the host is
    resolved and connections to private / loopback / link-local / ULA
    IPs (incl. the 169.254.169.254 metadata endpoint) are refused, so a
    reference URL can't be used to SSRF internal targets via a redirect.
  * 405 (method-not-allowed) falls back to a streaming GET (status only).
  * 4xx / 5xx / connect error -> broken.
  * Same URL referenced by multiple envelopes -> checked once.

Exit codes:
  0 — every URL responded 2xx/3xx (or 405-then-GET-2xx).
  1 — at least one URL failed.
  2 — unexpected error (filesystem, yaml parse).

CI uses --format=summary to emit a GitHub step summary block; local
runs can use --format=text for a flat list.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import httpx
import yaml

DETECTIONS_ROOT = Path("detections")
TIMEOUT_SECONDS = 10.0
MAX_REDIRECTS = 5
USER_AGENT = "contentops-references-check/1.0 (+https://github.com/KustoKing/SIEMContent)"


class _SafeTransport(httpx.HTTPTransport):
    """httpx transport that refuses to connect to private / loopback IPs.

    Reference URLs are operator-authored but untrusted at check time, and
    we follow redirects — an attacker-controlled reference (or a redirect
    chain) could point us at the cloud metadata endpoint
    (169.254.169.254) or an RFC1918 host. Every request hop resolves the
    host via ``getaddrinfo`` and is blocked if any resolved address falls
    in a private / loopback / link-local / ULA range.
    """

    _BLOCKED = [ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    )]

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError as exc:
            raise httpx.ConnectError(
                f"DNS resolution failed for {host}: {exc}", request=request
            )
        for *_, sockaddr in infos:
            ip = ipaddress.ip_address(sockaddr[0])
            if any(ip in net for net in self._BLOCKED):
                raise httpx.ConnectError(
                    f"Blocked private/loopback IP {ip} for {host}",
                    request=request,
                )
        return super().handle_request(request)


def _extract_urls_from_blob(
    blob: str | None, *, source: str, urls: dict[str, list[str]],
) -> None:
    """Pull http(s) URLs out of one envelope blob into ``urls`` in place."""
    if not blob:
        return
    try:
        raw = yaml.safe_load(blob)
    except yaml.YAMLError:
        return
    if not isinstance(raw, dict):
        return
    meta = raw.get("metadata") or {}
    if not isinstance(meta, dict):
        return
    refs = meta.get("references") or []
    if isinstance(refs, list):
        for r in refs:
            if isinstance(r, str) and r.startswith(("http://", "https://")):
                urls[r].append(source)
    runbook = meta.get("runbookUrl")
    if isinstance(runbook, str) and runbook.startswith(("http://", "https://")):
        urls[runbook].append(source)


def _iter_urls(detections_root: Path) -> dict[str, list[str]]:
    """Return {url: [envelope_path, ...]} across all envelopes.

    Pulls from ``metadata.references`` (list) and ``metadata.runbookUrl``
    (scalar). Ignores envelopes that fail to parse — those will be
    caught by ``contentops lint`` anyway, no need to double-report here.
    """
    urls: dict[str, list[str]] = defaultdict(list)
    for yml in sorted(detections_root.rglob("*.yml")):
        try:
            blob = yml.read_text(encoding="utf-8")
        except OSError:
            continue
        _extract_urls_from_blob(blob, source=str(yml), urls=urls)
    return urls


def _changed_envelope_paths(diff_base: str) -> list[str]:
    """Return repo-relative paths of envelope YAMLs changed since ``diff_base``."""
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", f"{diff_base}...HEAD", "--", "detections/"],
            check=True, capture_output=True, text=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"error: `git diff --name-only {diff_base}...HEAD` failed: {exc.stderr}"
        )
    return [
        line for line in out.splitlines()
        if line.endswith((".yml", ".yaml"))
    ]


def _git_show(ref: str, path: str) -> str | None:
    """Return file content at ``ref:path`` or None if missing at that ref."""
    try:
        return subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            check=True, capture_output=True, text=True,
        ).stdout
    except subprocess.CalledProcessError:
        return None


def _iter_added_urls(diff_base: str) -> dict[str, list[str]]:
    """Return {url: [envelope_path, ...]} for URLs ADDED since ``diff_base``.

    "Added" means: the URL appears in HEAD's version of a changed
    envelope but did not appear in the base version. Catches both
    brand-new references and references migrated between envelopes.
    Removes false-positives from lines that merely shifted around.
    """
    out: dict[str, list[str]] = defaultdict(list)
    for rel in _changed_envelope_paths(diff_base):
        head_path = Path(rel)
        head_blob = (
            head_path.read_text(encoding="utf-8")
            if head_path.exists() else None
        )
        base_blob = _git_show(diff_base, rel)
        head_urls: dict[str, list[str]] = defaultdict(list)
        base_urls: dict[str, list[str]] = defaultdict(list)
        _extract_urls_from_blob(head_blob, source=rel, urls=head_urls)
        _extract_urls_from_blob(base_blob, source=rel, urls=base_urls)
        for url, sources in head_urls.items():
            if url not in base_urls:
                out[url].extend(sources)
    return out


def _check_url(client: httpx.Client, url: str) -> tuple[bool, str]:
    """Return (ok, reason). reason is empty when ok."""
    try:
        response = client.head(url)
        status = response.status_code
        if status == 405:
            # Servers that block HEAD: fall back to GET. Stream so the
            # body is never buffered — we only need the status line.
            with client.stream("GET", url) as r:
                status = r.status_code
        if 200 <= status < 400:
            return True, ""
        return False, f"HTTP {status}"
    except (httpx.HTTPError, OSError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument(
        "--path", type=Path, default=DETECTIONS_ROOT,
        help="Root directory to scan (default: detections/).",
    )
    parser.add_argument(
        "--format", choices=("text", "summary"), default="text",
        help="Output format. 'summary' emits GitHub Actions markdown.",
    )
    parser.add_argument(
        "--allow", action="append", default=[],
        help="Substring; URLs containing it are skipped. Repeatable. "
             "Use for known-flaky CDNs (e.g. --allow=login.microsoftonline.com).",
    )
    parser.add_argument(
        "--diff-base", default=None,
        help="Git ref to diff against. When set, only URLs ADDED since "
             "this ref are checked (PR-time fast path). Use "
             "`origin/main` from a PR workflow.",
    )
    args = parser.parse_args(argv)

    try:
        if args.diff_base:
            urls = _iter_added_urls(args.diff_base)
        else:
            urls = _iter_urls(args.path)
    except OSError as exc:
        print(f"error: failed to walk {args.path}: {exc}", file=sys.stderr)
        return 2

    if not urls:
        scope = "added by this PR" if args.diff_base else "in detections/"
        print(f"no URLs {scope}", file=sys.stderr)
        return 0

    broken: list[tuple[str, str, list[str]]] = []
    skipped: list[str] = []
    with httpx.Client(
        transport=_SafeTransport(),
        follow_redirects=True,
        max_redirects=MAX_REDIRECTS,
        timeout=TIMEOUT_SECONDS,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        for url in sorted(urls):
            if any(needle in url for needle in args.allow):
                skipped.append(url)
                continue
            ok, reason = _check_url(client, url)
            if not ok:
                broken.append((url, reason, urls[url]))

    if args.format == "summary":
        # GitHub Actions step summary supports markdown.
        print(f"## References health\n")
        print(f"- URLs checked: **{len(urls) - len(skipped)}**")
        print(f"- Skipped (allowlisted): **{len(skipped)}**")
        print(f"- Broken: **{len(broken)}**\n")
        if broken:
            print("### Broken URLs\n")
            print("| URL | Reason | Envelopes |")
            print("|---|---|---|")
            for url, reason, sources in broken:
                src = ", ".join(f"`{Path(s).name}`" for s in sources)
                print(f"| {url} | {reason} | {src} |")
    else:
        if broken:
            print(f"broken: {len(broken)} of {len(urls) - len(skipped)} URL(s)")
            for url, reason, sources in broken:
                print(f"  {url}")
                print(f"    {reason}")
                for s in sources:
                    print(f"    in {s}")
        else:
            print(f"ok: {len(urls) - len(skipped)} URL(s) reachable")

    return 1 if broken else 0


if __name__ == "__main__":
    raise SystemExit(main())

# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for HandlerRegistry.close_all (resource-leak guard)."""

from __future__ import annotations

from contentops.core.asset import Asset
from contentops.core.registry import HandlerRegistry


class _FakeHandler:
    asset = Asset.SENTINEL_WATCHLIST

    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class _BrokenHandler:
    asset = Asset.SENTINEL_HUNTING

    def close(self) -> None:
        raise RuntimeError("boom")


class _NoCloseHandler:
    asset = Asset.SENTINEL_DATA_CONNECTOR


def test_close_all_invokes_close_on_each_constructed_handler() -> None:
    reg = HandlerRegistry()
    fake = _FakeHandler()
    reg.register(Asset.SENTINEL_WATCHLIST, lambda: fake)
    # Force construction.
    reg.get(Asset.SENTINEL_WATCHLIST)

    reg.close_all()
    assert fake.closed == 1


def test_close_all_skips_uninstantiated_handlers() -> None:
    reg = HandlerRegistry()
    calls = {"n": 0}

    def factory():
        calls["n"] += 1
        return _FakeHandler()

    reg.register(Asset.SENTINEL_WATCHLIST, factory)
    # Never call .get() — close_all must not trigger construction.
    reg.close_all()
    assert calls["n"] == 0


def test_close_all_swallows_handler_close_errors() -> None:
    reg = HandlerRegistry()
    reg.register(Asset.SENTINEL_HUNTING, lambda: _BrokenHandler())
    reg.get(Asset.SENTINEL_HUNTING)
    # Must not raise even though the handler's close() raises.
    reg.close_all()


def test_close_all_handles_handlers_without_close() -> None:
    reg = HandlerRegistry()
    reg.register(Asset.SENTINEL_DATA_CONNECTOR, lambda: _NoCloseHandler())
    reg.get(Asset.SENTINEL_DATA_CONNECTOR)
    reg.close_all()  # no AttributeError


def test_close_all_clears_instances_so_get_reconstructs() -> None:
    reg = HandlerRegistry()
    instances: list[_FakeHandler] = []

    def factory():
        h = _FakeHandler()
        instances.append(h)
        return h

    reg.register(Asset.SENTINEL_WATCHLIST, factory)
    reg.get(Asset.SENTINEL_WATCHLIST)
    reg.close_all()
    reg.get(Asset.SENTINEL_WATCHLIST)
    assert len(instances) == 2

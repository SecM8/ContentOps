# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Handler registry — maps Asset → Handler instance.

Lazy construction so importing `contentops.core` does not trigger any
network/auth side effects.
"""

from __future__ import annotations

from typing import Callable

from contentops.core.asset import Asset
from contentops.core.handler import Handler


class HandlerRegistry:
    def __init__(self) -> None:
        self._factories: dict[Asset, Callable[[], Handler]] = {}
        self._instances: dict[Asset, Handler] = {}

    def register(self, asset: Asset, factory: Callable[[], Handler]) -> None:
        self._factories[asset] = factory

    def get(self, asset: Asset) -> Handler:
        if asset not in self._instances:
            if asset not in self._factories:
                raise KeyError(f"No handler registered for asset {asset.value!r}")
            self._instances[asset] = self._factories[asset]()
        return self._instances[asset]

    def has(self, asset: Asset) -> bool:
        return asset in self._factories

    def assets(self) -> list[Asset]:
        return list(self._factories)

    def reset(self) -> None:
        """Clear cached instances only (factories preserved).

        Useful in tests that want fresh handler construction on the
        next ``get()`` without dropping the factory registration. For
        a full wipe (instances + factories) use :meth:`reset_all`.
        """
        self._instances.clear()

    def reset_all(self) -> None:
        """Full reset — clear both cached instances and factory registrations.

        This is the right tool for test isolation: closes any
        constructed handler (releasing its httpx client), then drops
        the entire factory table so the next test starts from an
        empty registry. ``reset()`` alone keeps the factories
        registered, which is wrong when one test wants to register a
        fake factory after another already registered the real one
        (``register_default_handlers`` is idempotent — it no-ops if
        the factory is already there).
        """
        self.close_all()
        self._factories.clear()

    def close_all(self) -> None:
        """Close every constructed handler (releases httpx clients).

        Safe to call multiple times. Handlers without a `close()` method
        are skipped. After closing, instances are dropped so subsequent
        `get()` calls reconstruct fresh handlers. Factory registrations
        are preserved — use :meth:`reset_all` to also drop them.
        """
        for handler in list(self._instances.values()):
            close = getattr(handler, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # noqa: BLE001 — best-effort cleanup
                    pass
        self._instances.clear()


default_registry = HandlerRegistry()

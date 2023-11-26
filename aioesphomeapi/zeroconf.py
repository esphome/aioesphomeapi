from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Union

from zeroconf import Zeroconf
from zeroconf.asyncio import AsyncZeroconf

ZeroconfInstanceType = Union[Zeroconf, AsyncZeroconf]

_LOGGER = logging.getLogger(__name__)


class ZeroconfManager:
    """Manage the Zeroconf objects.

    This class is used to manage the Zeroconf objects. It is used to create
    the Zeroconf objects and to close them. It attempts to avoid creating
    a Zeroconf object unless one is actually needed.
    """

    def __init__(self, zeroconf: ZeroconfInstanceType | None = None) -> None:
        """Initialize the ZeroconfManager."""
        self._created = False
        self._aiozc: AsyncZeroconf | None = None
        if zeroconf is not None:
            self.set_instance(zeroconf)

    @property
    def has_instance(self) -> bool:
        """Return True if a Zeroconf instance is set."""
        return self._aiozc is not None

    def set_instance(self, zc: AsyncZeroconf | Zeroconf) -> None:
        """Set the AsyncZeroconf instance."""
        if self._aiozc:
            if isinstance(zc, AsyncZeroconf) and self._aiozc.zeroconf is zc.zeroconf:
                return
            if isinstance(zc, Zeroconf) and self._aiozc.zeroconf is zc:
                self._aiozc = AsyncZeroconf(zc=zc)
                return
            raise RuntimeError("Zeroconf instance already set to a different instance")
        self._aiozc = zc if isinstance(zc, AsyncZeroconf) else AsyncZeroconf(zc=zc)

    def _create_async_zeroconf(self) -> None:
        """Create an AsyncZeroconf instance."""
        _LOGGER.debug("Creating new AsyncZeroconf instance")
        self._aiozc = AsyncZeroconf()
        self._created = True

    def get_async_zeroconf(self) -> AsyncZeroconf:
        """Get the AsyncZeroconf instance."""
        if not self._aiozc:
            self._create_async_zeroconf()
        if TYPE_CHECKING:
            assert self._aiozc is not None
        return self._aiozc

    async def async_close(self) -> None:
        """Close the Zeroconf connection."""
        if not self._created or not self._aiozc:
            return
        await self._aiozc.async_close()
        self._aiozc = None
        self._created = False

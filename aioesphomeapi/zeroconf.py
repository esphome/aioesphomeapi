from __future__ import annotations

from typing import Union

from zeroconf import Zeroconf
from zeroconf.asyncio import AsyncZeroconf

ZeroconfInstanceType = Union[Zeroconf, AsyncZeroconf, None]


class ZeroconfManager:
    """Manage the Zeroconf objects.

    This class is used to manage the Zeroconf objects. It is used to create
    the Zeroconf objects and to close them. It attempts to avoid creating
    a Zeroconf object unless one is actually needed.
    """

    def __init__(self, zeroconf: ZeroconfInstanceType = None) -> None:
        """Initialize the ZeroconfManager."""
        self._created = False
        if isinstance(zeroconf, AsyncZeroconf):
            self._aiozc = zeroconf
        if isinstance(zeroconf, Zeroconf):
            self._aiozc = AsyncZeroconf(zc=zeroconf)

    def _create_zeroconf(self) -> None:
        """Create the Zeroconf instance."""
        self._aiozc = AsyncZeroconf()
        self._created = True

    def get_async_zeroconf(self) -> AsyncZeroconf:
        """Get the AsyncZeroconf instance."""
        if not self._aiozc:
            self._create_zeroconf()
        return self._aiozc

    def get_zeroconf(self) -> Zeroconf:
        """Get the Zeroconf instance."""
        if not self._aiozc:
            self._create_zeroconf()
        return self._aiozc.zeroconf

    async def async_close(self) -> None:
        """Close the Zeroconf connection."""
        if not self._created:
            return
        await self._aiozc.async_close()
        self._aiozc = None
        self._created = False

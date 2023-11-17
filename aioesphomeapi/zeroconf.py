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

    def set_instance(self, aiozc: AsyncZeroconf) -> None:
        """Set the AsyncZeroconf instance."""
        if self._aiozc and self._aiozc is not aiozc:
            raise RuntimeError("Zeroconf instance already set to a different instance")
        self._aiozc = aiozc
        self._created = True

    def get_async_zeroconf(self) -> AsyncZeroconf:
        """Get the AsyncZeroconf instance."""
        if not self._aiozc:
            self.set_instance(AsyncZeroconf())
        return self._aiozc

    def get_zeroconf(self) -> Zeroconf:
        """Get the Zeroconf instance."""
        if not self._aiozc:
            self.set_instance(AsyncZeroconf())
        return self._aiozc.zeroconf

    async def async_close(self) -> None:
        """Close the Zeroconf connection."""
        if not self._created:
            return
        await self._aiozc.async_close()
        self._aiozc = None
        self._created = False

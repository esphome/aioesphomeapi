"""Singleton decorator for async functions."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
import functools
from typing import Any, TypeVar, cast

T = TypeVar("T")

# Global cache for singleton results
_SINGLETON_CACHE: dict[str, Any] = {}


def singleton(
    key: str,
) -> Callable[
    [Callable[[], Coroutine[Any, Any, T]]], Callable[[], Coroutine[Any, Any, T]]
]:
    """Decorate an async function that should be called once.

    Result will be cached and simultaneous calls will be handled.
    """

    def wrapper(
        func: Callable[[], Coroutine[Any, Any, T]],
    ) -> Callable[[], Coroutine[Any, Any, T]]:
        """Wrap a function with caching logic."""

        @functools.wraps(func)
        async def async_wrapped() -> T:
            if key not in _SINGLETON_CACHE:
                # Use an event to handle simultaneous calls
                evt = _SINGLETON_CACHE[key] = asyncio.Event()
                try:
                    result = await func()
                except Exception:
                    # On exception, remove the event so next call can retry
                    del _SINGLETON_CACHE[key]
                    evt.set()  # Wake up any waiters
                    raise
                else:
                    _SINGLETON_CACHE[key] = result
                    evt.set()
                    return result

            obj_or_evt = _SINGLETON_CACHE[key]

            if isinstance(obj_or_evt, asyncio.Event):
                # Another call is already in progress, wait for it
                await obj_or_evt.wait()
                # Check if the key still exists (might have been deleted on exception)
                if key in _SINGLETON_CACHE and not isinstance(
                    _SINGLETON_CACHE[key], asyncio.Event
                ):
                    return cast(T, _SINGLETON_CACHE[key])
                # If it was deleted or is still an event, the original call failed
                # Try again
                return await async_wrapped()

            return cast(T, obj_or_evt)

        return async_wrapped

    return wrapper

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
                # Use a future to handle simultaneous calls
                loop = asyncio.get_running_loop()
                future: asyncio.Future[T] = loop.create_future()
                _SINGLETON_CACHE[key] = future
                try:
                    result = await func()
                except Exception as e:
                    # On exception, remove the future so next call can retry
                    # Set exception first so waiters get it, then remove from cache
                    future.set_exception(e)
                    del _SINGLETON_CACHE[key]
                    raise
                else:
                    # Replace future with the actual result
                    _SINGLETON_CACHE[key] = result
                    future.set_result(result)
                    return result

            obj_or_future = _SINGLETON_CACHE[key]

            if isinstance(obj_or_future, asyncio.Future):
                # Another call is already in progress, wait for it
                # This will either return the result or raise the exception
                return cast(T, await obj_or_future)

            return cast(T, obj_or_future)

        return async_wrapped

    return wrapper

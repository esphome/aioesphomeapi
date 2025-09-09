"""Tests for the singleton decorator."""

import asyncio

import pytest

from aioesphomeapi.singleton import _SINGLETON_CACHE, singleton


@pytest.fixture(autouse=True)
def clear_singleton_cache() -> None:
    """Clear the singleton cache before and after each test."""
    _SINGLETON_CACHE.clear()
    yield
    _SINGLETON_CACHE.clear()


async def test_singleton_caches_result() -> None:
    """Test that singleton decorator caches the result."""
    call_count = 0

    @singleton("test_key")
    async def get_value() -> str:
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0)  # Simulate async work
        return "cached_value"

    # First call should execute the function
    result1 = await get_value()
    assert result1 == "cached_value"
    assert call_count == 1

    # Second call should return cached value
    result2 = await get_value()
    assert result2 == "cached_value"
    assert call_count == 1  # Function not called again

    # Third call should also return cached value
    result3 = await get_value()
    assert result3 == "cached_value"
    assert call_count == 1  # Function still not called again


async def test_singleton_handles_simultaneous_calls() -> None:
    """Test that singleton properly handles simultaneous calls."""
    call_count = 0
    event = asyncio.Event()

    @singleton("simultaneous_key")
    async def slow_function() -> str:
        nonlocal call_count
        call_count += 1
        await event.wait()  # Wait for event to be set
        return "result"

    # Start two coroutines simultaneously
    task1 = asyncio.create_task(slow_function())
    task2 = asyncio.create_task(slow_function())

    # Give tasks a moment to start
    await asyncio.sleep(0.01)

    # Set the event to allow the function to complete
    event.set()

    # Wait for both tasks
    result1 = await task1
    result2 = await task2

    # Both should return the same result
    assert result1 == "result"
    assert result2 == "result"

    # Function should only be called once
    assert call_count == 1


async def test_singleton_different_keys() -> None:
    """Test that different keys maintain separate caches."""
    call_count1 = 0
    call_count2 = 0

    @singleton("key1")
    async def func1() -> str:
        nonlocal call_count1
        call_count1 += 1
        return "value1"

    @singleton("key2")
    async def func2() -> str:
        nonlocal call_count2
        call_count2 += 1
        return "value2"

    # Call both functions
    result1 = await func1()
    result2 = await func2()

    assert result1 == "value1"
    assert result2 == "value2"
    assert call_count1 == 1
    assert call_count2 == 1

    # Call again to verify separate caches
    result1_again = await func1()
    result2_again = await func2()

    assert result1_again == "value1"
    assert result2_again == "value2"
    assert call_count1 == 1  # Not incremented
    assert call_count2 == 1  # Not incremented


async def test_singleton_with_exception() -> None:
    """Test that singleton handles exceptions properly."""
    call_count = 0

    @singleton("exception_key")
    async def failing_function() -> None:
        nonlocal call_count
        call_count += 1
        raise ValueError("Test error")

    # First call should raise the exception
    with pytest.raises(ValueError, match="Test error"):
        await failing_function()

    assert call_count == 1

    # The exception should not be cached, but the Event should be cleaned up
    # Second call should try again
    with pytest.raises(ValueError, match="Test error"):
        await failing_function()

    # Function should be called again since exception occurred
    assert call_count == 2


async def test_singleton_returns_none() -> None:
    """Test that singleton can cache None as a valid result."""
    call_count = 0

    @singleton("none_key")
    async def return_none() -> None:
        nonlocal call_count
        call_count += 1

    result1 = await return_none()
    assert result1 is None
    assert call_count == 1

    result2 = await return_none()
    assert result2 is None
    assert call_count == 1  # Not called again


async def test_singleton_exception_with_waiters() -> None:
    """Test that waiting calls receive the same exception as the first call."""
    call_count = 0
    event = asyncio.Event()

    @singleton("exception_waiter_key")
    async def failing_function() -> str:
        nonlocal call_count
        call_count += 1
        await event.wait()
        raise ValueError("First call fails")

    # Start two tasks simultaneously
    task1 = asyncio.create_task(failing_function())
    task2 = asyncio.create_task(failing_function())

    # Give tasks time to start
    await asyncio.sleep(0)

    # Let the first call proceed and fail
    event.set()

    # First task should raise exception
    with pytest.raises(ValueError, match="First call fails"):
        await task1

    # Second task should also raise the same exception (not retry)
    with pytest.raises(ValueError, match="First call fails"):
        await task2

    # Function should only be called once
    assert call_count == 1

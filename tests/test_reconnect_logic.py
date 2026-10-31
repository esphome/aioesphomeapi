from __future__ import annotations

import asyncio
from contextlib import contextmanager
from datetime import timedelta
from functools import partial
from ipaddress import ip_address
import logging
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, PropertyMock, call, patch

import pytest
from zeroconf import (
    DNSAddress,
    DNSPointer,
    DNSRecord,
    RecordUpdate,
    RecordUpdateListener,
    Zeroconf,
)
from zeroconf.asyncio import AsyncZeroconf
from zeroconf.const import _CLASS_IN, _TYPE_A, _TYPE_AAAA, _TYPE_CNAME, _TYPE_PTR

from aioesphomeapi import (
    APIConnectionError,
    DeviceInfo,
    EncryptionPlaintextAPIError,
    RequiresEncryptionAPIError,
)
from aioesphomeapi._zc_listener import ZeroconfRecordDispatcher
from aioesphomeapi.client import APIClient
from aioesphomeapi.client_base import KEEP_ALIVE_FREQUENCY
from aioesphomeapi.core import APIConnectionCancelledError, PingFailedAPIError

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator

    from aioesphomeapi._frame_helper.plain_text import APIPlaintextFrameHelper
from aioesphomeapi.reconnect_logic import (
    ANNOUNCE_BURST_WINDOW_MS,
    ANNOUNCE_MIN_GAP_MS,
    DEEP_SLEEP_MAXIMUM_BACKOFF,
    EXPECTED_DISCONNECT_COOLDOWN,
    MAXIMUM_BACKOFF,
    MAXIMUM_BACKOFF_TRIES,
    ZC_LISTEN_DELAY,
    ReconnectLogic,
    ReconnectLogicState,
    ZeroconfWake,
)

from .common import (
    async_fire_time_changed,
    get_mock_async_zeroconf,
    get_mock_zeroconf,
    mock_data_received,
    send_plaintext_auth_response,
    send_plaintext_hello,
    utcnow,
)
from .conftest import _create_mock_transport_protocol

logging.getLogger("aioesphomeapi").setLevel(logging.DEBUG)

# Not importable from connection when it is compiled with Cython.
KEEP_ALIVE_TIMEOUT_RATIO = 4.5


def find_log_with_message(
    caplog: pytest.LogCaptureFixture,
    message_substring: str,
) -> logging.LogRecord | None:
    """Find a log record containing the specified message substring.

    Args:
        caplog: pytest log capture fixture
        message_substring: substring to search for in log messages

    Returns:
        LogRecord if found, None otherwise

    """
    for record in caplog.records:
        if message_substring in record.message:
            return record
    return None


def deliver_records(
    wake: ZeroconfWake, records: list[RecordUpdate], now: float = 0.0
) -> None:
    """Route one packet of records through a dispatcher holding only wake."""
    dispatcher = ZeroconfRecordDispatcher(MagicMock())
    dispatcher.add(wake)
    dispatcher.async_update_records(MagicMock(), now, records)


async def drain_zc_start(rl: ReconnectLogic) -> None:
    """Wait out a pending deferred listener start.

    A warm _zc_listener_cache completes the eager task synchronously,
    so the task slot may already be cleared.
    """
    if (task := rl._zc_wake._start_task) is not None:
        await task


async def slow_connect_fail(*args, **kwargs):
    await asyncio.sleep(10)
    raise APIConnectionError


async def quick_connect_fail(*args, **kwargs):
    raise APIConnectionError


async def test_reconnect_logic_name_from_host():
    """Test that the name is set correctly from the host."""
    cli = APIClient(
        address="mydevice.local",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=MagicMock(spec=AsyncZeroconf),
    )
    assert cli.log_name == "mydevice.local"


async def test_reconnect_logic_name_from_host_and_set():
    """Test that the name is set correctly from the host."""
    cli = APIClient(
        address="mydevice.local",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert rl.name == "mydevice"
    assert cli.log_name == "mydevice.local"


async def test_reconnect_logic_name_from_address():
    """Test that the name is set correctly from the address."""
    cli = APIClient(
        address="127.0.0.1",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
    )
    assert cli.log_name == "127.0.0.1"


async def test_reconnect_logic_name_from_name():
    """Test that the name is set correctly from the address."""
    cli = APIClient(
        address="127.0.0.1",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert cli.log_name == "mydevice @ 127.0.0.1"


async def test_reconnect_logic_name_from_cli_address():
    """Test that the name is set correctly from the address."""
    cli = APIClient(
        address="mydevice",
        port=6052,
        password=None,
    )

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    async def on_connect() -> None:
        pass

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
    )
    assert cli.log_name == "mydevice"
    assert rl.name == "mydevice"


async def test_reconnect_logic_state(patchable_api_client: APIClient):
    """Test that reconnect logic state changes."""
    on_disconnect_called = []
    on_connect_called = []
    on_connect_fail_called = []

    cli = patchable_api_client

    async def on_disconnect(expected_disconnect: bool) -> None:
        nonlocal on_disconnect_called
        on_disconnect_called.append(expected_disconnect)

    async def on_connect() -> None:
        nonlocal on_connect_called
        on_connect_called.append(True)

    async def on_connect_fail(connect_exception: Exception) -> None:
        nonlocal on_connect_called
        on_connect_fail_called.append(connect_exception)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
        on_connect_error=on_connect_fail,
    )
    assert cli.log_name == "mydevice @ 127.0.0.1"

    with patch.object(cli, "start_resolve_host", side_effect=APIConnectionError):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 0
    assert len(on_connect_fail_called) == 1
    assert isinstance(on_connect_fail_called[-1], APIConnectionError)
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    assert rl._tries == 1

    with (
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection"),
        patch.object(cli, "finish_connection", side_effect=RequiresEncryptionAPIError),
    ):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 0
    assert len(on_connect_fail_called) == 2
    assert isinstance(on_connect_fail_called[-1], RequiresEncryptionAPIError)
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    assert rl._tries == MAXIMUM_BACKOFF_TRIES

    with (
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection"),
        patch.object(cli, "finish_connection"),
    ):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 1
    assert len(on_connect_fail_called) == 2
    assert rl._connection_state is ReconnectLogicState.READY
    assert rl._tries == 0
    await rl.stop()
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


async def test_reconnect_retry(
    patchable_api_client: APIClient, caplog: pytest.LogCaptureFixture
):
    """Test that reconnect logic retry."""
    on_disconnect_called = []
    on_connect_called = []
    on_connect_fail_called = []
    cli = patchable_api_client

    async def on_disconnect(expected_disconnect: bool) -> None:
        nonlocal on_disconnect_called
        on_disconnect_called.append(expected_disconnect)

    async def on_connect() -> None:
        nonlocal on_connect_called
        on_connect_called.append(True)

    async def on_connect_fail(connect_exception: Exception) -> None:
        nonlocal on_connect_called
        on_connect_fail_called.append(connect_exception)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=on_disconnect,
        on_connect=on_connect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
        on_connect_error=on_connect_fail,
    )
    assert cli.log_name == "mydevice @ 127.0.0.1"
    caplog.clear()

    with patch.object(cli, "start_resolve_host", side_effect=APIConnectionError):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 0
    assert len(on_connect_fail_called) == 1
    assert isinstance(on_connect_fail_called[-1], APIConnectionError)
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    assert "connect to ESPHome API for mydevice @ 127.0.0.1" in caplog.text
    for record in caplog.records:
        if "connect to ESPHome API for mydevice @ 127.0.0.1" in record.message:
            assert record.levelno == logging.WARNING

    caplog.clear()
    # Next retry should run at debug level
    with patch.object(cli, "start_resolve_host", side_effect=APIConnectionError):
        # Should now retry
        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 0
    assert len(on_connect_fail_called) == 2
    assert isinstance(on_connect_fail_called[-1], APIConnectionError)
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    assert "connect to ESPHome API for mydevice @ 127.0.0.1" in caplog.text
    for record in caplog.records:
        if "connect to ESPHome API for mydevice @ 127.0.0.1" in record.message:
            assert record.levelno == logging.DEBUG

    caplog.clear()
    with (
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection"),
        patch.object(cli, "finish_connection"),
    ):
        # Should now retry
        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert "connect to ESPHome API for mydevice @ 127.0.0.1" not in caplog.text
    assert len(on_disconnect_called) == 0
    assert len(on_connect_called) == 1
    assert len(on_connect_fail_called) == 2
    assert rl._connection_state is ReconnectLogicState.READY
    original_when = rl._connect_timer.when()

    # Ensure starting the connection logic again does not trigger a new connection
    await rl.start()
    # Verify no new timer is started
    assert rl._connect_timer.when() == original_when

    await rl.stop()
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


@pytest.mark.parametrize(
    ("deep_sleep", "expected_wait"),
    [(True, DEEP_SLEEP_MAXIMUM_BACKOFF), (False, MAXIMUM_BACKOFF)],
)
async def test_deep_sleep_caps_reconnect_backoff(
    patchable_api_client: APIClient,
    deep_sleep: bool,
    expected_wait: float,
) -> None:
    """A deep-sleep device caps the backoff so a lost boot-announce still redials in time."""
    cli = patchable_api_client

    async def _noop(*args: object) -> None:
        pass

    rl = ReconnectLogic(
        client=cli,
        on_connect=_noop,
        on_disconnect=_noop,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    rl.deep_sleep = deep_sleep
    rl._is_stopped = False
    # High enough that 1.8**tries would exceed MAXIMUM_BACKOFF without the cap.
    rl._tries = 10

    loop = asyncio.get_running_loop()
    now = loop.time()
    with (
        patch.object(rl._zc_wake, "start"),
        patch.object(rl, "_try_connect", AsyncMock(return_value=False)),
    ):
        await rl._connect_once_or_reschedule()

    assert rl._connect_timer is not None
    assert rl._connect_timer.when() - now == pytest.approx(expected_wait, abs=1)
    await rl.stop()


@pytest.mark.parametrize("has_deep_sleep", [True, False])
async def test_deep_sleep_self_populates_from_device_info(
    patchable_api_client: APIClient,
    has_deep_sleep: bool,
) -> None:
    """The flag is read from the connect callback's device_info, so it self-heals on reconnect."""
    cli = patchable_api_client

    async def on_connect() -> None:
        # Stand in for the consumer fetching device_info during on_connect,
        # which is what populates the client's cache.
        cli._cached_device_info = DeviceInfo(has_deep_sleep=has_deep_sleep)

    async def on_disconnect(expected_disconnect: bool) -> None:
        pass

    rl = ReconnectLogic(
        client=cli,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert rl.deep_sleep is False

    with (
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection"),
        patch.object(cli, "finish_connection"),
    ):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert rl.deep_sleep is has_deep_sleep
    await rl.stop()


DNS_POINTER = DNSPointer(
    "_esphomelib._tcp.local.",
    _TYPE_PTR,
    _CLASS_IN,
    1000,
    "mydevice._esphomelib._tcp.local.",
)


def _send_record(
    rl: ReconnectLogic,
    record: DNSRecord = DNS_POINTER,
    old: DNSRecord | None = None,
    now: float = 0.0,
) -> None:
    """Deliver one packet holding record to rl's wake."""
    deliver_records(rl._zc_wake, [RecordUpdate(record, old)], now)


@pytest.mark.parametrize(
    ("record", "should_trigger_zeroconf", "expected_state_after_trigger", "log_text"),
    [
        (
            DNS_POINTER,
            True,
            ReconnectLogicState.READY,
            "received mDNS record",
        ),
        (
            DNSPointer(
                "_esphomelib._tcp.local.",
                _TYPE_PTR,
                _CLASS_IN,
                1000,
                "wrong_name._esphomelib._tcp.local.",
            ),
            False,
            ReconnectLogicState.RESOLVING,
            "",
        ),
        (
            DNSAddress(
                "mydevice.local.",
                _TYPE_A,
                _CLASS_IN,
                1000,
                ip_address("127.0.0.1").packed,
            ),
            True,
            ReconnectLogicState.READY,
            "received mDNS record",
        ),
        (
            DNSAddress(
                "mydevice.local.",
                _TYPE_AAAA,
                _CLASS_IN,
                1000,
                ip_address("::1").packed,
            ),
            True,
            ReconnectLogicState.READY,
            "received mDNS record",
        ),
        # RFC 6762 §16: mDNS labels are case-insensitive — a device
        # advertising mixed-case labels must still trigger the fast reconnect.
        (
            DNSPointer(
                "_esphomelib._tcp.local.",
                _TYPE_PTR,
                _CLASS_IN,
                1000,
                "MyDevice._esphomelib._tcp.local.",
            ),
            True,
            ReconnectLogicState.READY,
            "received mDNS record",
        ),
        (
            DNSAddress(
                "MYDEVICE.local.",
                _TYPE_A,
                _CLASS_IN,
                1000,
                ip_address("127.0.0.1").packed,
            ),
            True,
            ReconnectLogicState.READY,
            "received mDNS record",
        ),
    ],
)
async def test_reconnect_zeroconf(  # noqa: C901  # parametrized over many record shapes; branching is the matrix
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
    record: DNSRecord,
    should_trigger_zeroconf: bool,
    expected_state_after_trigger: ReconnectLogicState,
    log_text: str,
) -> None:
    """Test reconnect logic behavior when zeroconf provides records during connection.

    This test verifies that when the reconnect logic is in RESOLVING state:
    - If matching zeroconf records arrive, the resolution completes and connection proceeds
    - If non-matching records arrive, the connection stays in RESOLVING state
    """
    cli = patchable_api_client
    mock_zeroconf = MagicMock(spec=Zeroconf)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=mock_zeroconf,
        name="mydevice",
        on_connect_error=AsyncMock(),
    )
    assert cli.log_name == "mydevice @ 127.0.0.1"

    # First connection attempt fails
    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)

    # Should be disconnected after initial failure
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED

    # Create an event to coordinate resolution with zeroconf trigger
    resolve_event = asyncio.Event()

    async def resolve_host_waiting_for_zeroconf(*args, **kwargs):
        # This simulates the resolver waiting for mDNS records
        try:
            await asyncio.wait_for(resolve_event.wait(), timeout=0.1)
        except TimeoutError as err:
            msg = "Resolution timed out"
            raise APIConnectionError(msg) from err
        else:
            return  # Resolution succeeded

    # For the test, we'll control when the connection succeeds
    connect_succeeded = False

    async def controlled_start_connection(*args, **kwargs):
        nonlocal connect_succeeded
        if should_trigger_zeroconf and resolve_event.is_set():
            connect_succeeded = True
            await asyncio.sleep(0)
        else:
            raise APIConnectionError

    async def controlled_finish_connection(*args, **kwargs):
        if connect_succeeded:
            return
        raise APIConnectionError

    # Set up mocks for the reconnection attempt
    with (
        patch.object(
            cli, "start_resolve_host", side_effect=resolve_host_waiting_for_zeroconf
        ) as mock_resolve,
        patch.object(
            cli, "start_connection", side_effect=controlled_start_connection
        ) as mock_connect,
        patch.object(
            cli, "finish_connection", side_effect=controlled_finish_connection
        ) as mock_finish,
    ):
        # Trigger the reconnect timer
        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)

        # Should now be in RESOLVING state, waiting for mDNS records
        assert rl._connection_state is ReconnectLogicState.RESOLVING
        assert mock_resolve.call_count == 1

        caplog.clear()

        # Simulate zeroconf providing records
        if should_trigger_zeroconf:
            # For matching records, signal the resolver to complete
            resolve_event.set()

        deliver_records(rl._zc_wake, [RecordUpdate(record, None)])

        # Verify the expected log message
        assert (
            "Triggering connect because of received mDNS record" in caplog.text
        ) is should_trigger_zeroconf

        # Give tasks time to complete
        for _ in range(10):
            await asyncio.sleep(0)

        if should_trigger_zeroconf:
            # Verify connection proceeded after resolution
            assert mock_connect.call_count == 1
            assert mock_finish.call_count == 1
            assert log_text in caplog.text
            assert rl._connection_state is expected_state_after_trigger
        else:
            # For non-matching records, should still be resolving
            assert mock_connect.call_count == 0
            assert mock_finish.call_count == 0
            # The resolve task is still running, waiting for correct records
            assert rl._connection_state is ReconnectLogicState.RESOLVING

    await rl.stop()
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


async def test_reconnect_zeroconf_cancels_connecting_no_socket(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that reconnect logic cancels and restarts connection when zeroconf triggers during CONNECTING state with no socket connected yet."""
    cli = patchable_api_client

    mock_zeroconf = MagicMock(spec=Zeroconf)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=mock_zeroconf,
        name="mydevice",
        on_connect_error=AsyncMock(),
    )
    assert cli.log_name == "mydevice @ 127.0.0.1"

    with patch.object(
        cli, "start_resolve_host", side_effect=quick_connect_fail
    ) as mock_start_resolve_host:
        await rl.start()
        await asyncio.sleep(0)

    assert mock_start_resolve_host.call_count == 1

    # Now put the connection in CONNECTING state (no socket connected yet)
    with (
        patch.object(cli, "start_resolve_host") as mock_start_resolve_host,
        patch.object(
            cli, "start_connection", side_effect=slow_connect_fail
        ) as mock_start_connection,
    ):
        assert rl._connection_state is ReconnectLogicState.DISCONNECTED
        assert rl._zc_wake._accept_records is True
        assert not rl._is_stopped

        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert mock_start_resolve_host.call_count == 1
        assert mock_start_connection.call_count == 1
        assert rl._connection_state is ReconnectLogicState.CONNECTING
        assert rl._zc_wake._accept_records is True
        assert not rl._is_stopped

    caplog.clear()

    # No socket connected yet - connected_address is None
    assert cli.connected_address is None

    # Now trigger zeroconf while in CONNECTING state with no socket
    with (
        patch.object(cli, "start_resolve_host") as mock_start_resolve_host_2,
        patch.object(cli, "start_connection") as mock_start_connection_2,
        patch.object(cli, "finish_connection"),
    ):
        _send_record(rl)

        # Should see the cancellation message since no socket is connected
        assert "Cancelling existing connect task" in caplog.text
        assert "Triggering connect because of received mDNS record" in caplog.text

        # Wait for the new connection attempt
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        # Should have started a new connection attempt
        assert mock_start_resolve_host_2.call_count == 1
        assert mock_start_connection_2.call_count == 1

    await rl.stop()
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


async def test_reconnect_zeroconf_only_cancels_connecting_once(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Further mDNS records during a single connect attempt must not retrigger.

    Regression: previously every A / PTR record cancelled the in-flight
    CONNECTING task and restarted from RESOLVING, thrashing the connect for
    as long as the device kept announcing itself on mDNS.
    """
    cli = patchable_api_client

    mock_zeroconf = MagicMock(spec=Zeroconf)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=mock_zeroconf,
        name="mydevice",
        on_connect_error=AsyncMock(),
    )

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)

    with (
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection", side_effect=slow_connect_fail),
    ):
        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert rl._connection_state is ReconnectLogicState.CONNECTING
        assert rl._zc_wake._accept_records is True

    with (
        patch.object(cli, "start_resolve_host") as mock_resolve_2,
        patch.object(
            cli, "start_connection", side_effect=slow_connect_fail
        ) as mock_connect_2,
        patch.object(cli, "finish_connection"),
    ):
        caplog.clear()
        _send_record(rl)
        assert (
            caplog.text.count("Triggering connect because of received mDNS record") == 1
        )
        assert rl._zc_wake._accept_records is False

        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert mock_resolve_2.call_count == 1
        assert mock_connect_2.call_count == 1
        assert rl._connection_state is ReconnectLogicState.CONNECTING

        # Subsequent mDNS records during the same attempt must be ignored.
        caplog.clear()
        for _ in range(5):
            _send_record(rl)
        assert "Triggering connect because of received mDNS record" not in caplog.text
        assert mock_resolve_2.call_count == 1
        assert mock_connect_2.call_count == 1

    rl._cancel_connect("forced cancel in test")
    await rl.stop()
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


async def test_start_clears_stale_zeroconf_gate(
    patchable_api_client: APIClient,
) -> None:
    """A stop() while the gate is closed must not leak into the next start().

    If the logic is stopped mid attempt after an mDNS triggered restart,
    the wake gate (accept_records) is False. A subsequent start() on the same
    instance must reopen the gate, otherwise the next run would ignore
    mDNS records until its first real failure.
    """
    cli = patchable_api_client
    mock_zeroconf = MagicMock(spec=Zeroconf)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=mock_zeroconf,
        name="mydevice",
        on_connect_error=AsyncMock(),
    )

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)

    # Simulate the stop-mid-attempt-with-closed-gate state directly.
    rl._zc_wake._accept_records = False
    await rl.stop()
    assert rl._is_stopped is True
    assert rl._zc_wake._accept_records is False

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)

    assert rl._zc_wake._accept_records is True

    await rl.stop()


async def test_reconnect_zeroconf_does_not_cancel_connecting_with_socket(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that reconnect logic does not cancel connection when zeroconf triggers during CONNECTING state with socket already connected."""
    cli = patchable_api_client

    mock_zeroconf = MagicMock(spec=Zeroconf)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=mock_zeroconf,
        name="mydevice",
        on_connect_error=AsyncMock(),
    )
    assert cli.log_name == "mydevice @ 127.0.0.1"

    with patch.object(
        cli, "start_resolve_host", side_effect=quick_connect_fail
    ) as mock_start_resolve_host:
        await rl.start()
        await asyncio.sleep(0)

    assert mock_start_resolve_host.call_count == 1

    # Now put the connection in CONNECTING state
    with (
        patch.object(cli, "start_resolve_host") as mock_start_resolve_host,
        patch.object(
            cli, "start_connection", side_effect=slow_connect_fail
        ) as mock_start_connection,
    ):
        assert rl._connection_state is ReconnectLogicState.DISCONNECTED
        assert rl._zc_wake._accept_records is True
        assert not rl._is_stopped

        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert mock_start_resolve_host.call_count == 1
        assert mock_start_connection.call_count == 1
        assert rl._connection_state is ReconnectLogicState.CONNECTING
        assert rl._zc_wake._accept_records is True
        assert not rl._is_stopped

    caplog.clear()

    # Simulate socket already connected (device accepted TCP connection)
    with patch.object(
        type(cli),
        "connected_address",
        new_callable=PropertyMock,
        return_value="192.168.1.5",
    ):
        # Now trigger zeroconf while in CONNECTING state with socket connected
        _send_record(rl)

        # Should NOT cancel since the device already accepted the connection
        assert "Not cancelling existing connect task" in caplog.text
        assert "Triggering connect because of received mDNS record" in caplog.text
        assert "Cancelling existing connect task" not in caplog.text

    rl._cancel_connect("forced cancel in test")
    await rl.stop()
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


async def test_reconnect_zeroconf_cancels_pending_timer(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that mDNS-triggered connect cancels any pending backoff timer."""
    cli = patchable_api_client

    mock_zeroconf = MagicMock(spec=Zeroconf)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=mock_zeroconf,
        name="mydevice",
        on_connect_error=AsyncMock(),
    )

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)

    # After first failure, a backoff timer should be scheduled
    assert rl._connect_timer is not None
    timer = rl._connect_timer

    # Now trigger zeroconf - the pending timer should be cancelled
    with (
        patch.object(cli, "start_resolve_host") as mock_start_resolve_host,
        patch.object(cli, "start_connection"),
        patch.object(cli, "finish_connection"),
    ):
        _send_record(rl)

        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert mock_start_resolve_host.call_count == 1

    # The old timer should have been cancelled
    assert timer.cancelled()

    await rl.stop()
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


async def test_reconnect_zeroconf_not_while_handshaking(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that reconnect logic retry will not trigger a zeroconf reconnect while handshaking."""
    cli = patchable_api_client

    mock_zeroconf = MagicMock(spec=Zeroconf)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=mock_zeroconf,
        name="mydevice",
        on_connect_error=AsyncMock(),
    )
    assert cli.log_name == "mydevice @ 127.0.0.1"

    with patch.object(
        cli, "start_resolve_host", side_effect=quick_connect_fail
    ) as mock_start_resolve_host:
        await rl.start()
        await asyncio.sleep(0)

    assert mock_start_resolve_host.call_count == 1

    with (
        patch.object(cli, "start_resolve_host") as mock_start_resolve_host,
        patch.object(cli, "start_connection") as mock_start_connection,
        patch.object(
            cli, "finish_connection", side_effect=slow_connect_fail
        ) as mock_finish_connection,
    ):
        assert rl._connection_state is ReconnectLogicState.DISCONNECTED
        assert rl._zc_wake._accept_records is True
        assert not rl._is_stopped

        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        assert mock_start_resolve_host.call_count == 1
        assert mock_start_connection.call_count == 1
        assert mock_finish_connection.call_count == 1
        assert rl._connection_state is ReconnectLogicState.HANDSHAKING
        assert rl._zc_wake._accept_records is True
        assert not rl._is_stopped

    _send_record(rl)
    assert (
        "Triggering connect because of received mDNS record" in caplog.text
    ) is False

    rl._cancel_connect("forced cancel in test")
    await rl.stop()
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


async def test_connect_task_not_cancelled_while_handshaking(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that reconnect logic will not cancel an in progress handshake."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        name="mydevice",
        on_connect_error=AsyncMock(),
    )
    assert cli.log_name == "mydevice @ 127.0.0.1"

    with patch.object(
        cli, "start_resolve_host", side_effect=quick_connect_fail
    ) as mock_start_resolve_host:
        await rl.start()
        await asyncio.sleep(0)

    assert mock_start_resolve_host.call_count == 1

    with (
        patch.object(cli, "start_resolve_host") as mock_start_resolve_host,
        patch.object(cli, "start_connection") as mock_start_connection,
        patch.object(
            cli, "finish_connection", side_effect=slow_connect_fail
        ) as mock_finish_connection,
    ):
        assert rl._connection_state is ReconnectLogicState.DISCONNECTED
        assert rl._zc_wake._accept_records is True
        assert not rl._is_stopped

        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        assert mock_start_resolve_host.call_count == 1
        assert mock_start_connection.call_count == 1
        assert mock_finish_connection.call_count == 1
        assert rl._connection_state is ReconnectLogicState.HANDSHAKING
        assert rl._zc_wake._accept_records is True
        assert not rl._is_stopped

    caplog.clear()
    # This can likely never happen in practice, but we should handle it
    # in the event there is a race as the consequence is that we could
    # disconnect a working connection.
    rl._call_connect_once()
    assert (
        "Not cancelling existing connect task as its already ReconnectLogicState.HANDSHAKING"
        in caplog.text
    )

    rl._cancel_connect("forced cancel in test")
    await rl.stop()
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


async def test_connect_aborts_if_stopped(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that reconnect logic will abort connecting if stopped."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        name="mydevice",
        on_connect_error=AsyncMock(),
    )
    assert cli.log_name == "mydevice @ 127.0.0.1"

    with patch.object(
        cli, "start_resolve_host", side_effect=quick_connect_fail
    ) as mock_start_resolve_host:
        await rl.start()
        await asyncio.sleep(0)

    assert mock_start_resolve_host.call_count == 1

    with patch.object(cli, "start_resolve_host") as mock_start_resolve_host:
        timer = rl._connect_timer
        assert timer is not None
        await rl.stop()
        assert rl._is_stopped is True
        rl._call_connect_once()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    # We should never try to connect again
    # once we are stopped
    assert mock_start_resolve_host.call_count == 0
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


async def test_reconnect_logic_stop_callback(patchable_api_client: APIClient):
    """Test that the stop_callback stops the ReconnectLogic."""
    cli = patchable_api_client
    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )

    async def slow_resolve_host(*args, **kwargs):
        await asyncio.sleep(10)  # Hang in resolve state

    with patch.object(cli, "start_resolve_host", side_effect=slow_resolve_host):
        await rl.start()
        assert rl._connection_state is ReconnectLogicState.DISCONNECTED
        await asyncio.sleep(0)
        assert rl._connection_state is ReconnectLogicState.RESOLVING
        assert rl._is_stopped is False
        rl.stop_callback()
        # Wait for cancellation to propagate
        for _ in range(4):
            await asyncio.sleep(0)
        assert rl._is_stopped is True
        assert rl._connection_state is ReconnectLogicState.DISCONNECTED


async def test_reconnect_logic_stop_callback_waits_for_handshake(
    patchable_api_client: APIClient,
):
    """Test that the stop_callback waits for a handshake."""
    cli = patchable_api_client
    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED

    with (
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection"),
        patch.object(cli, "finish_connection", side_effect=slow_connect_fail),
    ):
        await rl.start()
        for _ in range(3):
            await asyncio.sleep(0)

    assert rl._connection_state is ReconnectLogicState.HANDSHAKING
    assert rl._is_stopped is False
    rl.stop_callback()
    # Wait for cancellation to propagate
    for _ in range(4):
        await asyncio.sleep(0)
    assert rl._is_stopped is False
    assert rl._connection_state is ReconnectLogicState.HANDSHAKING

    rl._cancel_connect("forced cancel in test")
    # Wait for cancellation to propagate
    for _ in range(4):
        await asyncio.sleep(0)
    assert rl._is_stopped is True
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED


async def test_handling_unexpected_disconnect(aiohappyeyeballs_start_connection):
    """Test the disconnect callback fires with expected_disconnect=False."""
    loop = asyncio.get_running_loop()
    protocol: APIPlaintextFrameHelper | None = None
    transport = MagicMock()
    connected = asyncio.Event()

    class PatchableAPIClient(APIClient):
        pass

    async_zeroconf = get_mock_async_zeroconf()

    cli = PatchableAPIClient(
        address="127.0.0.1",
        port=6052,
        password=None,
        noise_psk=None,
        expected_name="fake",
        zeroconf_instance=async_zeroconf.zeroconf,
    )

    connected = asyncio.Event()
    on_disconnect_calls = []

    async def on_disconnect(expected_disconnect: bool) -> None:
        on_disconnect_calls.append(expected_disconnect)

    async def on_connect() -> None:
        connected.set()

    logic = ReconnectLogic(
        client=cli,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        zeroconf_instance=async_zeroconf,
        name="fake",
    )

    with patch.object(
        loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    ):
        await logic.start()
        await connected.wait()
        protocol = cli._connection._frame_helper
        send_plaintext_hello(protocol)
        send_plaintext_auth_response(protocol, False)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert cli._connection.is_connected is True
    await asyncio.sleep(0)

    with (
        patch.object(
            loop,
            "create_connection",
            side_effect=partial(_create_mock_transport_protocol, transport, connected),
        ) as mock_create_connection,
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection"),
        patch.object(cli, "finish_connection"),
    ):
        protocol.eof_received()
        # Wait for the task to run
        await asyncio.sleep(0)
        # Ensure we try to reconnect immediately
        # since its an unexpected disconnect
        assert mock_create_connection.call_count == 0

    assert len(on_disconnect_calls) == 1
    expected_disconnect = on_disconnect_calls[-1]
    assert expected_disconnect is False
    await logic.stop()


async def test_backoff_on_encryption_error(
    caplog: pytest.LogCaptureFixture,
    aiohappyeyeballs_start_connection,
) -> None:
    """Test we backoff on encryption error."""
    loop = asyncio.get_running_loop()
    protocol: APIPlaintextFrameHelper | None = None
    transport = MagicMock()
    connected = asyncio.Event()

    class PatchableAPIClient(APIClient):
        pass

    async_zeroconf = get_mock_async_zeroconf()

    cli = PatchableAPIClient(
        address="127.0.0.1",
        port=6052,
        password=None,
        noise_psk="",
        expected_name="fake",
        zeroconf_instance=async_zeroconf.zeroconf,
    )

    connected = asyncio.Event()
    on_disconnect_calls = []

    async def on_disconnect(expected_disconnect: bool) -> None:
        on_disconnect_calls.append(expected_disconnect)

    async def on_connect() -> None:
        connected.set()

    logic = ReconnectLogic(
        client=cli,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        zeroconf_instance=async_zeroconf,
        name="fake",
    )

    with patch.object(
        loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    ):
        await logic.start()
        await connected.wait()
        protocol = cli._connection._frame_helper
        mock_data_received(protocol, b"\x01\x00\x00")

    assert cli._connection.is_connected is False
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert len(on_disconnect_calls) == 0

    assert "Scheduling new connect attempt in 60.00 seconds" in caplog.text
    assert "Connection requires encryption (RequiresEncryptionAPIError)" in caplog.text
    now = loop.time()
    assert logic._connect_timer.when() - now == pytest.approx(60, 1)
    assert logic._tries == MAXIMUM_BACKOFF_TRIES
    await logic.stop()


@pytest.mark.asyncio
async def test_plaintext_fallback_disabled_by_default(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """EncryptionPlaintextAPIError does not downgrade when flag is off."""

    class PatchableAPIClient(APIClient):
        pass

    async_zeroconf = get_mock_async_zeroconf()
    cli = PatchableAPIClient(
        address="127.0.0.1",
        port=6052,
        password=None,
        noise_psk="BASE64KEY",
        zeroconf_instance=async_zeroconf.zeroconf,
    )

    async def on_connect() -> None: ...
    async def on_disconnect(expected_disconnect: bool) -> None: ...

    rl = ReconnectLogic(
        client=cli,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        zeroconf_instance=async_zeroconf,
        name="fake",
    )

    with (
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection"),
        patch.object(
            cli,
            "finish_connection",
            side_effect=EncryptionPlaintextAPIError("plaintext"),
        ),
    ):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert cli.noise_psk == "BASE64KEY"
    # Non-auth error: tries increments by 1, no max backoff.
    assert rl._tries == 1
    assert "disabling encryption" not in caplog.text
    await rl.stop()


@pytest.mark.asyncio
async def test_plaintext_fallback_downgrades_when_enabled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """With opt-in, plaintext protocol downgrades the PSK and resets tries."""

    class PatchableAPIClient(APIClient):
        pass

    async_zeroconf = get_mock_async_zeroconf()
    cli = PatchableAPIClient(
        address="127.0.0.1",
        port=6052,
        password=None,
        noise_psk="BASE64KEY",
        zeroconf_instance=async_zeroconf.zeroconf,
    )

    async def on_connect() -> None: ...
    async def on_disconnect(expected_disconnect: bool) -> None: ...

    rl = ReconnectLogic(
        client=cli,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        zeroconf_instance=async_zeroconf,
        name="fake",
        allow_plaintext_fallback=True,
    )

    with (
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection"),
        patch.object(
            cli,
            "finish_connection",
            side_effect=EncryptionPlaintextAPIError("plaintext"),
        ),
    ):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert cli.noise_psk is None
    assert rl._tries == 0
    assert "Device is using plaintext protocol" in caplog.text
    await rl.stop()


@pytest.mark.asyncio
async def test_reconnect_logic_no_zeroconf_listener_for_ip_addresses(
    patchable_api_client: APIClient,
) -> None:
    """Test that zeroconf listener is not started for IP addresses."""
    cli = patchable_api_client

    # Mock get_async_zeroconf to raise - this ensures it's not called for IP addresses
    with patch.object(
        cli.zeroconf_manager,
        "get_async_zeroconf",
        side_effect=Exception("Should not create zeroconf instance for IP addresses"),
    ):
        # Test with IP address as name - should not raise
        logic_with_ip = ReconnectLogic(
            client=cli,
            on_connect=AsyncMock(),
            on_disconnect=AsyncMock(),
            name="192.168.1.100",  # IP address
        )

        # This should work without calling get_async_zeroconf
        await logic_with_ip.start()
        await asyncio.sleep(0)
        await logic_with_ip.stop()

        # Test with IP:port as name - should not raise
        logic_with_ip_port = ReconnectLogic(
            client=cli,
            on_connect=AsyncMock(),
            on_disconnect=AsyncMock(),
            name="127.0.0.1:6053",  # IP address with port
        )

        await logic_with_ip_port.start()
        await asyncio.sleep(0)
        await logic_with_ip_port.stop()

    # Now test with a real device name - this SHOULD call get_async_zeroconf
    async_zeroconf = get_mock_async_zeroconf()

    with patch.object(
        cli.zeroconf_manager, "get_async_zeroconf", return_value=async_zeroconf
    ) as mock_get_zc:
        logic_with_name = ReconnectLogic(
            client=cli,
            on_connect=AsyncMock(),
            on_disconnect=AsyncMock(),
            name="living_room",  # Device name
        )

        await logic_with_name.start()
        await asyncio.sleep(0)

        # Deferred start: only the arm timer is scheduled
        assert logic_with_name._zc_wake._timer is not None
        mock_get_zc.assert_not_called()

        # Starting the listener for a device name calls get_async_zeroconf
        logic_with_name._zc_wake.start()
        mock_get_zc.assert_called()

        await logic_with_name.stop()


@pytest.mark.asyncio
async def test_connection_cancelled_error_logged_at_debug_level(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that APIConnectionCancelledError is always logged at DEBUG level."""
    on_connect = AsyncMock()
    on_disconnect = AsyncMock()
    on_connect_fail = AsyncMock()

    logic = ReconnectLogic(
        client=patchable_api_client,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        on_connect_error=on_connect_fail,
        name="mydevice",
    )

    caplog.clear()
    # First attempt - APIConnectionCancelledError should be DEBUG even on first try
    with patch.object(
        patchable_api_client,
        "start_resolve_host",
        side_effect=APIConnectionCancelledError("Starting connection cancelled"),
    ):
        await logic.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    assert len(on_connect_fail.call_args_list) == 1
    assert isinstance(
        on_connect_fail.call_args_list[0][0][0], APIConnectionCancelledError
    )

    # Check that the error was logged at DEBUG level, not WARNING
    log_record = find_log_with_message(caplog, "Can't connect to ESPHome API")
    assert log_record is not None, "Expected log message not found"
    assert "APIConnectionCancelledError" in log_record.message
    assert log_record.levelno == logging.DEBUG

    await logic.stop()


@pytest.mark.asyncio
async def test_resolved_log_level_changes_after_first_attempt(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that 'Successfully resolved' is logged at INFO on first attempt, DEBUG on subsequent."""
    on_connect = AsyncMock()
    on_disconnect = AsyncMock()
    on_connect_fail = AsyncMock()

    logic = ReconnectLogic(
        client=patchable_api_client,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        on_connect_error=on_connect_fail,
        name="mydevice",
    )

    caplog.clear()
    # First attempt - should be INFO level
    with (
        patch.object(patchable_api_client, "start_resolve_host"),
        patch.object(
            patchable_api_client,
            "start_connection",
            side_effect=APIConnectionError("Connection failed"),
        ),
    ):
        await logic.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    # Check that the resolved message was logged at INFO level on first attempt
    log_record = find_log_with_message(caplog, "Successfully resolved")
    assert log_record is not None, (
        "Expected INFO log message not found on first attempt"
    )
    assert log_record.levelno == logging.INFO

    caplog.clear()
    # Second attempt - should be DEBUG level
    with (
        patch.object(patchable_api_client, "start_resolve_host"),
        patch.object(
            patchable_api_client,
            "start_connection",
            side_effect=APIConnectionError("Connection failed"),
        ),
    ):
        # Trigger the next connection attempt
        assert logic._connect_timer is not None
        logic._connect_timer._run()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    # Check that the resolved message was logged at DEBUG level on second attempt
    log_record = find_log_with_message(caplog, "Successfully resolved")
    assert log_record is not None, (
        "Expected DEBUG log message not found on subsequent attempt"
    )
    assert log_record.levelno == logging.DEBUG

    await logic.stop()


@pytest.mark.asyncio
async def test_zc_listen_failure_does_not_block_connect(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Connect must proceed when zeroconf init fails (issue #1613, BSD port 5353)."""
    cli = patchable_api_client
    on_connect = AsyncMock()
    on_disconnect = AsyncMock()
    on_connect_fail = AsyncMock()

    logic = ReconnectLogic(
        client=cli,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        on_connect_error=on_connect_fail,
        name="mydevice",
    )

    with patch.object(
        cli.zeroconf_manager,
        "get_async_zeroconf",
        side_effect=OSError(48, "Address already in use"),
    ):
        with patch.object(cli, "start_resolve_host", side_effect=APIConnectionError):
            await logic.start()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            await drain_zc_start(logic)

        assert on_connect_fail.call_count == 1
        # The first failed listener start warns
        log_record = find_log_with_message(caplog, "Could not start zeroconf listener")
        assert log_record is not None, (
            "Expected zeroconf failure warning was not logged"
        )
        assert log_record.levelno == logging.WARNING
        # _dispatcher must remain None so stop() doesn't try to remove a
        # listener we never added.
        assert logic._zc_wake._dispatcher is None

        # The broken zeroconf stack must not block the next attempt
        with (
            patch.object(cli, "start_resolve_host"),
            patch.object(cli, "start_connection"),
            patch.object(cli, "finish_connection"),
        ):
            assert logic._connect_timer is not None
            logic._connect_timer._run()
            await asyncio.sleep(0)
            await asyncio.sleep(0)

        assert on_connect.call_count == 1
        assert logic._connection_state is ReconnectLogicState.READY

    await logic.stop()


@pytest.mark.asyncio
async def test_zc_listen_failure_downgrades_to_debug_after_first_try(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Repeated zeroconf init failures must not spam WARNING (Copilot review on #1652)."""
    cli = patchable_api_client
    logic = ReconnectLogic(
        client=cli,
        on_connect=AsyncMock(),
        on_disconnect=AsyncMock(),
        on_connect_error=AsyncMock(),
        name="mydevice",
    )

    # Drive a non-zero _tries by failing the first resolve; this mirrors the
    # "zeroconf keeps failing across reconnect attempts" scenario.
    with (
        patch.object(
            cli.zeroconf_manager,
            "get_async_zeroconf",
            side_effect=OSError(48, "Address already in use"),
        ),
        patch.object(cli, "start_resolve_host", side_effect=APIConnectionError),
    ):
        await logic.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert logic._tries == 1
        await drain_zc_start(logic)

        caplog.clear()
        assert logic._connect_timer is not None
        logic._connect_timer._run()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await drain_zc_start(logic)

    log_record = find_log_with_message(caplog, "Could not start zeroconf listener")
    assert log_record is not None, "Expected zeroconf failure log was not emitted"
    assert log_record.levelno == logging.DEBUG

    await logic.stop()


async def test_zc_listen_import_failure_logged_and_retried_inline(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A failed off-loop import logs at DEBUG; start() retries inline and warns."""
    cli = patchable_api_client
    logic = ReconnectLogic(
        client=cli,
        on_connect=AsyncMock(),
        on_disconnect=AsyncMock(),
        on_connect_error=AsyncMock(),
        name="mydevice",
    )

    with (
        patch("aioesphomeapi.reconnect_logic._zc_listener_cache", []),
        patch(
            "aioesphomeapi.reconnect_logic._import_zc_listener",
            side_effect=ImportError("boom"),
        ),
        patch.object(cli, "start_resolve_host", side_effect=APIConnectionError),
    ):
        await logic.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await drain_zc_start(logic)

    assert (
        find_log_with_message(caplog, "off-loop zc listener import failed") is not None
    )
    log_record = find_log_with_message(caplog, "Could not start zeroconf listener")
    assert log_record is not None
    assert log_record.levelno == logging.WARNING
    assert logic._zc_wake._dispatcher is None

    await logic.stop()


async def test_addresses_changed_callback_lifecycle(
    patchable_api_client: APIClient,
) -> None:
    """The addresses-changed callback registers on start and unregisters on stop."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )
    assert cli._addresses_changed_callbacks == []

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)

    assert cli._addresses_changed_callbacks == [rl._on_addresses_changed]

    await rl.stop()
    assert cli._addresses_changed_callbacks == []

    # add_addresses after stop must not schedule anything
    assert rl._connect_timer is None
    cli.add_addresses(["10.0.0.2"])
    assert rl._connect_timer is None
    assert rl._connect_task is None


async def test_add_addresses_kicks_backoff_timer(
    patchable_api_client: APIClient,
) -> None:
    """New addresses trigger an immediate attempt instead of waiting out backoff."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)

    # First attempt failed; we are DISCONNECTED waiting on the backoff timer
    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    assert rl._connect_timer is not None

    with (
        patch.object(cli, "start_resolve_host") as mock_resolve,
        patch.object(cli, "start_connection", side_effect=slow_connect_fail),
    ):
        assert cli.add_addresses(["10.0.0.2"]) is True
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert mock_resolve.call_count == 1
        assert cli._params.addresses == ["127.0.0.1", "10.0.0.2"]

    rl._cancel_connect("forced cancel in test")
    await rl.stop()


@pytest.mark.parametrize(
    ("stall_in_resolve", "expected_log"),
    [
        (False, "Cancelling existing connect task"),
        (True, "Cancelling resolve to try newly added addresses"),
    ],
)
async def test_add_addresses_cancels_stalled_attempt(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
    stall_in_resolve: bool,
    expected_log: str,
) -> None:
    """New addresses cancel an attempt stuck before a socket is established."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )

    if stall_in_resolve:
        with patch.object(cli, "start_resolve_host", side_effect=slow_connect_fail):
            await rl.start()
            await asyncio.sleep(0)
        assert rl._connection_state is ReconnectLogicState.RESOLVING
    else:
        with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
            await rl.start()
            await asyncio.sleep(0)
        with (
            patch.object(cli, "start_resolve_host"),
            patch.object(cli, "start_connection", side_effect=slow_connect_fail),
        ):
            assert rl._connect_timer is not None
            rl._connect_timer._run()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
        assert rl._connection_state is ReconnectLogicState.CONNECTING

    assert cli.connected_address is None
    caplog.clear()

    with (
        patch.object(cli, "start_resolve_host") as mock_resolve_2,
        patch.object(
            cli, "start_connection", side_effect=slow_connect_fail
        ) as mock_connect_2,
    ):
        assert cli.add_addresses(["10.0.0.2"]) is True
        assert expected_log in caplog.text
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert mock_resolve_2.call_count == 1
        assert mock_connect_2.call_count == 1
        assert rl._connection_state is ReconnectLogicState.CONNECTING

    rl._cancel_connect("forced cancel in test")
    await rl.stop()


async def test_add_addresses_ignored_when_ready(
    patchable_api_client: APIClient,
) -> None:
    """New addresses while READY must not disturb the live connection."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=get_mock_zeroconf(),
        name="mydevice",
    )

    with (
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection"),
        patch.object(cli, "finish_connection"),
    ):
        await rl.start()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert rl._connection_state is ReconnectLogicState.READY

    assert cli.add_addresses(["10.0.0.2"]) is True
    assert rl._connect_timer is None
    assert rl._connection_state is ReconnectLogicState.READY

    await rl.stop()


@pytest.mark.asyncio
async def test_zc_listen_timer_cancelled_on_fast_connect(
    patchable_api_client: APIClient,
) -> None:
    """A connect landing before ZC_LISTEN_DELAY never touches zeroconf."""
    cli = patchable_api_client

    with patch.object(cli.zeroconf_manager, "get_async_zeroconf") as mock_get_zc:
        rl = ReconnectLogic(
            client=cli,
            on_connect=AsyncMock(),
            on_disconnect=AsyncMock(),
            name="mydevice",
        )
        with (
            patch.object(cli, "start_resolve_host"),
            patch.object(cli, "start_connection"),
            patch.object(cli, "finish_connection"),
        ):
            await rl.start()
            await asyncio.sleep(0)
            await asyncio.sleep(0)

        assert rl._connection_state is ReconnectLogicState.READY
        assert rl._zc_wake._timer is None
        assert rl._zc_wake._start_task is None
        mock_get_zc.assert_not_called()

        await rl.stop()


@pytest.mark.asyncio
async def test_zc_listener_dispatcher_registered_on_failed_attempt(
    patchable_api_client: APIClient,
) -> None:
    """A failed attempt registers the shared listener that routes to the wake."""
    cli = patchable_api_client
    async_zeroconf = get_mock_async_zeroconf()

    with patch.object(
        cli.zeroconf_manager, "get_async_zeroconf", return_value=async_zeroconf
    ):
        rl = ReconnectLogic(
            client=cli,
            on_connect=AsyncMock(),
            on_disconnect=AsyncMock(),
            name="mydevice",
        )
        with (
            patch.object(
                cli, "start_resolve_host", side_effect=APIConnectionError("no dice")
            ),
            patch.object(async_zeroconf.zeroconf, "async_add_listener") as add_listener,
            patch.object(
                async_zeroconf.zeroconf, "async_remove_listener"
            ) as remove_listener,
        ):
            await rl.start()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            await drain_zc_start(rl)

            add_listener.assert_called_once()
            listener, question = add_listener.call_args[0]
            assert question is None
            assert isinstance(listener, RecordUpdateListener)

            with patch.object(rl._zc_wake, "on_record") as mock_on_record:
                listener.async_update_records(
                    async_zeroconf.zeroconf, 0.0, [RecordUpdate(DNS_POINTER, None)]
                )
            mock_on_record.assert_called_once_with(DNS_POINTER, 0.0)

            await rl.stop()
            remove_listener.assert_called_once_with(listener)


@pytest.mark.asyncio
async def test_zc_listener_starts_when_timer_fires_mid_attempt(
    patchable_api_client: APIClient,
) -> None:
    """An attempt still in flight when the arm timer fires gets the listener."""
    cli = patchable_api_client
    async_zeroconf = get_mock_async_zeroconf()
    resolve_started = asyncio.Event()
    release_resolve = asyncio.Event()

    async def _hanging_resolve(*args, **kwargs) -> None:
        resolve_started.set()
        await release_resolve.wait()
        msg = "cancelled"
        raise APIConnectionError(msg)

    with patch.object(
        cli.zeroconf_manager, "get_async_zeroconf", return_value=async_zeroconf
    ):
        rl = ReconnectLogic(
            client=cli,
            on_connect=AsyncMock(),
            on_disconnect=AsyncMock(),
            name="mydevice",
        )
        with (
            patch.object(cli, "start_resolve_host", side_effect=_hanging_resolve),
            patch.object(async_zeroconf.zeroconf, "async_add_listener") as add_listener,
            patch.object(async_zeroconf.zeroconf, "async_remove_listener"),
        ):
            await rl.start()
            await resolve_started.wait()

            assert rl._zc_wake._timer is not None
            assert rl._zc_wake._timer.when() == pytest.approx(
                rl.loop.time() + ZC_LISTEN_DELAY, abs=0.1
            )
            rl._zc_wake._timer._run()
            assert rl._zc_wake._start_task is not None
            await rl._zc_wake._start_task

            add_listener.assert_called_once()
            assert rl._zc_wake._dispatcher is not None

            release_resolve.set()
            await asyncio.sleep(0)

            await rl.stop()


async def test_zeroconf_kick_reopens_gate_when_attempt_fails_synchronously(
    patchable_api_client: APIClient,
) -> None:
    """An mDNS kick whose attempt fails without yielding keeps the gate open."""
    cli = patchable_api_client

    mock_zeroconf = MagicMock(spec=Zeroconf)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=mock_zeroconf,
        name="mydevice",
    )

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)
        await drain_zc_start(rl)
        assert rl._tries == 1

        _send_record(rl)
        await asyncio.sleep(0)
        assert rl._tries == 2
        assert rl._connection_state is ReconnectLogicState.DISCONNECTED
        assert rl._connect_timer is not None
        assert rl._zc_wake._accept_records is True

        _send_record(rl)
        await asyncio.sleep(0)
        assert rl._tries == 3

    await rl.stop()


async def test_zeroconf_kick_ignored_when_gated(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """kick() schedules nothing while stopped or once the attempt was kicked."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=MagicMock(spec=Zeroconf),
        name="mydevice",
    )
    with patch.object(rl, "_schedule_connect") as mock_schedule:
        rl._zc_wake.kick("a test kick")
    mock_schedule.assert_not_called()

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)

    caplog.clear()
    with patch.object(rl, "_schedule_connect") as mock_schedule:
        rl._zc_wake.kick("a test kick")
        rl._zc_wake.kick("a test kick")
    mock_schedule.assert_called_once_with(0.0)
    assert caplog.text.count("Triggering connect because a test kick") == 1

    await rl.stop()


async def test_zeroconf_wake_disabled_never_creates_zeroconf(
    patchable_api_client: APIClient,
) -> None:
    """zeroconf_wake=False never touches zeroconf, even across failed attempts."""
    cli = patchable_api_client

    with patch.object(cli.zeroconf_manager, "get_async_zeroconf") as get_zeroconf:
        rl = ReconnectLogic(
            client=cli,
            on_connect=AsyncMock(),
            on_disconnect=AsyncMock(),
            name="mydevice",
            zeroconf_wake=False,
        )
        assert cli.log_name == "mydevice @ 127.0.0.1"

        with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
            await rl.start()
            await asyncio.sleep(0)
            await drain_zc_start(rl)

        assert rl._connection_state is ReconnectLogicState.DISCONNECTED
        assert rl._connect_timer is not None
        assert rl._zc_wake._timer is None
        assert rl._zc_wake._start_task is None
        assert rl._zc_wake._dispatcher is None

        await rl.stop()

    get_zeroconf.assert_not_called()


async def test_notify_device_seen_kicks_backoff_timer(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """notify_device_seen connects immediately and leaves the backoff counter alone."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        name="mydevice",
        zeroconf_wake=False,
    )

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)

    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    assert rl._connect_timer is not None
    assert rl._tries == 1

    with (
        patch.object(cli, "start_resolve_host") as mock_resolve,
        patch.object(cli, "start_connection", side_effect=slow_connect_fail),
    ):
        caplog.clear()
        rl.notify_device_seen()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert mock_resolve.call_count == 1
        assert rl._connect_timer is None
        assert rl._connection_state is ReconnectLogicState.CONNECTING
        assert rl._tries == 1
        assert "Triggering connect because the device was seen" in caplog.text

    rl._cancel_connect("forced cancel in test")
    await rl.stop()


@pytest.mark.parametrize("first_kick", ["notify", "mdns"])
async def test_notify_device_seen_shares_one_kick_per_attempt(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
    first_kick: str,
) -> None:
    """notify_device_seen and mDNS records share the one-kick-per-attempt gate."""
    cli = patchable_api_client

    mock_zeroconf = MagicMock(spec=Zeroconf)

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        zeroconf_instance=mock_zeroconf,
        name="mydevice",
    )

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)

    with (
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection", side_effect=slow_connect_fail),
    ):
        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert rl._connection_state is ReconnectLogicState.CONNECTING

    with (
        patch.object(cli, "start_resolve_host") as mock_resolve,
        patch.object(cli, "start_connection", side_effect=slow_connect_fail),
    ):
        if first_kick == "notify":
            rl.notify_device_seen()
        else:
            _send_record(rl)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert mock_resolve.call_count == 1
        assert rl._zc_wake._accept_records is False

        caplog.clear()
        for _ in range(5):
            rl.notify_device_seen()
            _send_record(rl)
        await asyncio.sleep(0)
        assert "Triggering connect" not in caplog.text
        assert mock_resolve.call_count == 1

    rl._cancel_connect("forced cancel in test")
    await rl.stop()


async def test_notify_device_seen_ignored_while_stopped(
    patchable_api_client: APIClient,
) -> None:
    """notify_device_seen does nothing before start or after stop."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        name="mydevice",
        zeroconf_wake=False,
    )

    with patch.object(cli, "start_resolve_host") as mock_resolve:
        rl.notify_device_seen()
        await asyncio.sleep(0)
        assert mock_resolve.call_count == 0

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)
    await rl.stop()

    with patch.object(cli, "start_resolve_host") as mock_resolve:
        rl.notify_device_seen()
        await asyncio.sleep(0)
        assert mock_resolve.call_count == 0
    assert rl._connect_timer is None


async def test_notify_device_seen_ignored_while_handshaking(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """notify_device_seen does not restart an attempt that is handshaking."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        name="mydevice",
        zeroconf_wake=False,
    )

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)

    with (
        patch.object(cli, "start_resolve_host") as mock_resolve,
        patch.object(cli, "start_connection"),
        patch.object(cli, "finish_connection", side_effect=slow_connect_fail),
    ):
        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        assert rl._connection_state is ReconnectLogicState.HANDSHAKING

        caplog.clear()
        rl.notify_device_seen()
        await asyncio.sleep(0)
        assert "Triggering connect because the device was seen" not in caplog.text
        assert mock_resolve.call_count == 1
        assert rl._connection_state is ReconnectLogicState.HANDSHAKING

    rl._cancel_connect("forced cancel in test")
    await rl.stop()


async def test_notify_device_seen_reopens_gate_when_attempt_fails_synchronously(
    patchable_api_client: APIClient,
) -> None:
    """A notify_device_seen kick whose attempt fails without yielding keeps the gate open."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        name="mydevice",
        zeroconf_wake=False,
    )

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)
        assert rl._tries == 1

        rl.notify_device_seen()
        await asyncio.sleep(0)
        assert rl._tries == 2
        assert rl._connection_state is ReconnectLogicState.DISCONNECTED
        assert rl._connect_timer is not None
        assert rl._zc_wake._accept_records is True

        rl.notify_device_seen()
        await asyncio.sleep(0)
        assert rl._tries == 3

    await rl.stop()


async def test_notify_device_seen_logs_before_attempt(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The trigger log line precedes the connect attempt it starts."""
    cli = patchable_api_client

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        name="mydevice",
        zeroconf_wake=False,
    )

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        await asyncio.sleep(0)

    with (
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection", side_effect=slow_connect_fail),
    ):
        caplog.clear()
        rl.notify_device_seen()
        await asyncio.sleep(0)
        messages = [record.message for record in caplog.records]
        trigger = next(
            i for i, m in enumerate(messages) if "because the device was seen" in m
        )
        attempt = next(i for i, m in enumerate(messages) if "Trying to connect" in m)
        assert trigger < attempt

    rl._cancel_connect("forced cancel in test")
    await rl.stop()


async def test_notify_device_seen_during_connect_error_callback(
    patchable_api_client: APIClient,
) -> None:
    """A sighting while on_connect_error runs leaves the gate open for the backoff."""
    cli = patchable_api_client

    async def on_connect_error(err: Exception) -> None:
        await asyncio.sleep(0)
        rl.notify_device_seen()

    rl = ReconnectLogic(
        client=cli,
        on_disconnect=AsyncMock(),
        on_connect=AsyncMock(),
        on_connect_error=on_connect_error,
        name="mydevice",
        zeroconf_wake=False,
    )

    with patch.object(cli, "start_resolve_host", side_effect=quick_connect_fail):
        await rl.start()
        for _ in range(3):
            await asyncio.sleep(0)

    assert rl._connection_state is ReconnectLogicState.DISCONNECTED
    assert rl._connect_timer is not None

    with patch.object(rl, "_schedule_connect") as mock_schedule:
        rl.notify_device_seen()
    mock_schedule.assert_called_once_with(0.0)

    await rl.stop()


@contextmanager
def _patch_connect(cli: APIClient) -> Generator[None]:
    """Patch the three client connect steps to succeed."""
    with (
        patch.object(cli, "start_resolve_host"),
        patch.object(cli, "start_connection"),
        patch.object(cli, "finish_connection"),
    ):
        yield


@pytest.fixture
async def probing(
    patchable_api_client: APIClient, request: pytest.FixtureRequest
) -> AsyncGenerator[tuple[ReconnectLogic, MagicMock, MagicMock]]:
    """Yield a ReconnectLogic connected to READY with mocked zeroconf listeners.

    Indirect parametrization passes ReconnectLogic kwargs; the default enables
    probe_on_announce.
    """
    cli = patchable_api_client
    kwargs: dict[str, Any] = getattr(request, "param", {"probe_on_announce": True})
    async_zeroconf = get_mock_async_zeroconf()
    with (
        patch.object(
            cli.zeroconf_manager, "get_async_zeroconf", return_value=async_zeroconf
        ),
        patch.object(async_zeroconf.zeroconf, "async_add_listener") as add_listener,
        patch.object(async_zeroconf.zeroconf, "async_remove_listener") as remove,
    ):
        rl = ReconnectLogic(
            client=cli,
            on_connect=AsyncMock(),
            on_disconnect=AsyncMock(),
            name="mydevice",
            **kwargs,
        )
        with _patch_connect(cli):
            await rl.start()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
        await drain_zc_start(rl)
        assert rl._connection_state is ReconnectLogicState.READY
        yield rl, add_listener, remove
        await rl.stop()


DNS_A = DNSAddress(
    "mydevice.local.", _TYPE_A, _CLASS_IN, 120, ip_address("192.168.1.9").packed
)


async def test_probe_on_announce_listener_lifecycle(
    probing: tuple[ReconnectLogic, MagicMock, MagicMock],
) -> None:
    """The listener runs while connected and stops on disconnect."""
    rl, add_listener, remove = probing
    add_listener.assert_called_once()
    assert rl._zc_wake._dispatcher is not None

    with patch.object(rl, "_schedule_connect") as schedule:
        await rl._on_disconnect(True)
    schedule.assert_called_once_with(EXPECTED_DISCONNECT_COOLDOWN)
    remove.assert_called_once()
    assert rl._zc_wake._dispatcher is None


async def test_probe_on_announce_listener_kept_through_handshake(
    probing: tuple[ReconnectLogic, MagicMock, MagicMock],
) -> None:
    """The listener is not removed at handshake."""
    rl, add_listener, remove = probing
    with patch.object(rl, "_schedule_connect"):
        await rl._on_disconnect(False)
    rl._zc_wake.start()
    with _patch_connect(rl._cli):
        await rl._connect_once_or_reschedule()
    assert rl._connection_state is ReconnectLogicState.READY
    assert rl._zc_wake._dispatcher is not None
    assert add_listener.call_count == 2
    assert remove.call_count == 1


@pytest.mark.parametrize("sent", [True, False])
@pytest.mark.parametrize(
    ("record", "old"),
    [
        (DNS_POINTER, None),
        (DNS_POINTER, DNS_POINTER),
        (DNS_A, None),
        (DNS_A, DNS_A),
    ],
    ids=["ptr-new", "ptr-refresh", "a-new", "a-refresh"],
)
async def test_probe_on_announce_record_pings(
    probing: tuple[ReconnectLogic, MagicMock, MagicMock],
    caplog: pytest.LogCaptureFixture,
    record: DNSRecord,
    old: DNSRecord | None,
    sent: bool,
) -> None:
    """A repeated announcement while connected pings instead of kicking; logged only if sent."""
    rl, _, _ = probing
    with (
        patch.object(rl._cli, "send_keepalive_now", return_value=sent) as check,
        patch.object(rl, "_schedule_connect") as schedule,
    ):
        _send_record(rl, record, old, now=1000.0)
        check.assert_not_called()
        _send_record(rl, record, old, now=2000.0)
    check.assert_called_once_with()
    schedule.assert_not_called()
    assert (
        "Sending keepalive ping because of repeated mDNS announcement" in caplog.text
    ) is sent


@pytest.mark.parametrize(
    ("gap", "pings"),
    [
        (ANNOUNCE_MIN_GAP_MS - 1, 0),
        (ANNOUNCE_MIN_GAP_MS, 1),
        (ANNOUNCE_BURST_WINDOW_MS, 1),
        (ANNOUNCE_BURST_WINDOW_MS + 1, 0),
    ],
)
async def test_probe_on_announce_burst_window(
    probing: tuple[ReconnectLogic, MagicMock, MagicMock], gap: float, pings: int
) -> None:
    """Only a second round between the minimum gap and the window pings."""
    rl, _, _ = probing
    with patch.object(rl._cli, "send_keepalive_now", return_value=True) as check:
        _send_record(rl, now=10_000.0)
        _send_record(rl, now=10_000.0 + gap)
    assert check.call_count == pings


@pytest.mark.parametrize(
    ("gap", "pings"),
    [(926.0, 1), (1135.0, 1), (1940.0, 1), (2500.0, 0), (5000.0, 0)],
    ids=["lwip-min", "esp32-max", "leamdns-max", "query-answers", "query-backoff"],
)
async def test_probe_on_announce_bench_gaps(
    probing: tuple[ReconnectLogic, MagicMock, MagicMock], gap: float, pings: int
) -> None:
    """Measured boot round gaps ping; answers to queries seconds apart do not."""
    rl, _, _ = probing
    with patch.object(rl._cli, "send_keepalive_now", return_value=True) as check:
        _send_record(rl, now=10_000.0)
        _send_record(rl, now=10_000.0 + gap)
    assert check.call_count == pings


async def test_probe_on_announce_every_burst_packet_pings(
    probing: tuple[ReconnectLogic, MagicMock, MagicMock],
) -> None:
    """Each further round of a burst sends a ping, also while a pong is pending."""
    rl, _, _ = probing
    with patch.object(rl._cli, "send_keepalive_now", return_value=True) as check:
        for now in (1000.0, 2000.0, 3000.0):
            _send_record(rl, now=now)
    assert check.call_count == 2


@pytest.mark.parametrize("probing", [{}], indirect=True)
async def test_probe_on_announce_off_by_default(
    probing: tuple[ReconnectLogic, MagicMock, MagicMock],
) -> None:
    """Without a shared zeroconf a sighting while connected does nothing."""
    rl, _, _ = probing
    assert rl._zc_wake._dispatcher is None
    with (
        patch.object(rl._cli, "send_keepalive_now") as check,
        patch.object(rl, "_schedule_connect") as schedule,
    ):
        _send_record(rl)
        rl.notify_device_seen()
    check.assert_not_called()
    schedule.assert_not_called()


@pytest.mark.parametrize(
    "probing", [{"probe_on_announce": True, "zeroconf_wake": False}], indirect=True
)
async def test_notify_device_seen_probes_while_connected(
    probing: tuple[ReconnectLogic, MagicMock, MagicMock],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """notify_device_seen while connected pings the session."""
    rl, add_listener, _ = probing
    add_listener.assert_not_called()
    with (
        patch.object(rl._cli, "send_keepalive_now", return_value=True) as check,
        patch.object(rl, "_schedule_connect") as schedule,
    ):
        rl.notify_device_seen()
    check.assert_called_once_with()
    schedule.assert_not_called()
    assert "Sending keepalive ping because the device was seen" in caplog.text


async def test_probe_on_announce_unanswered_ping_reconnects(
    aiohappyeyeballs_start_connection: MagicMock,
) -> None:
    """An announce pings a real session; no reply drops it and starts a reconnect."""
    loop = asyncio.get_running_loop()
    transport = MagicMock()
    connected = asyncio.Event()
    async_zeroconf = get_mock_async_zeroconf()
    cli = APIClient(
        address="127.0.0.1",
        port=6052,
        password=None,
        expected_name="fake",
        zeroconf_instance=async_zeroconf.zeroconf,
    )
    on_disconnect_calls: list[bool] = []

    async def on_disconnect(expected_disconnect: bool) -> None:
        on_disconnect_calls.append(expected_disconnect)

    logic = ReconnectLogic(
        client=cli,
        on_connect=AsyncMock(),
        on_disconnect=on_disconnect,
        zeroconf_instance=async_zeroconf,
        name="fake",
        probe_on_announce=True,
    )
    with patch.object(
        loop,
        "create_connection",
        side_effect=partial(_create_mock_transport_protocol, transport, connected),
    ):
        await logic.start()
        await connected.wait()
        protocol = cli._connection._frame_helper
        send_plaintext_hello(protocol)
        send_plaintext_auth_response(protocol, False)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
    conn = cli._connection
    assert conn.is_connected is True
    assert logic._connection_state is ReconnectLogicState.READY
    transport.reset_mock()

    start_time = utcnow()
    announce = DNSPointer(
        "_esphomelib._tcp.local.",
        _TYPE_PTR,
        _CLASS_IN,
        1000,
        "fake._esphomelib._tcp.local.",
    )
    _send_record(logic, announce, now=1000.0)
    assert transport.writelines.call_count == 0
    _send_record(logic, announce, now=2000.0)
    assert transport.writelines.call_count == 1

    timeout = KEEP_ALIVE_FREQUENCY * KEEP_ALIVE_TIMEOUT_RATIO
    with patch.object(logic, "_schedule_connect") as schedule:
        async_fire_time_changed(start_time + timedelta(seconds=timeout + 1))
        for _ in range(5):
            await asyncio.sleep(0)
    assert conn.is_connected is False
    assert isinstance(conn.fatal_exception, PingFailedAPIError)
    assert on_disconnect_calls == [False]
    schedule.assert_called_once_with(0)
    await logic.stop()


def _logic_on(
    async_zeroconf: AsyncZeroconf | None, name: str, **kwargs: Any
) -> ReconnectLogic:
    """Build a ReconnectLogic for name sharing async_zeroconf."""
    return ReconnectLogic(
        client=APIClient(f"{name}.local", 6053, None),
        on_connect=AsyncMock(),
        on_disconnect=AsyncMock(),
        zeroconf_instance=async_zeroconf,
        name=name,
        **kwargs,
    )


async def test_wakes_share_one_zeroconf_listener() -> None:
    """Wakes on one zeroconf share a listener that goes away with the last one."""
    async_zeroconf = get_mock_async_zeroconf()
    zc = async_zeroconf.zeroconf
    first = _logic_on(async_zeroconf, "first")
    second = _logic_on(async_zeroconf, "mydevice")
    with (
        patch.object(zc, "async_add_listener") as add_listener,
        patch.object(zc, "async_remove_listener") as remove_listener,
    ):
        first._zc_wake.start()
        second._zc_wake.start()
        add_listener.assert_called_once()
        listener = add_listener.call_args[0][0]

        with (
            patch.object(first._zc_wake, "on_record") as first_seen,
            patch.object(second._zc_wake, "on_record") as second_seen,
        ):
            listener.async_update_records(
                zc, 0.0, [RecordUpdate(DNS_POINTER, None), RecordUpdate(DNS_A, None)]
            )
        first_seen.assert_not_called()
        assert second_seen.call_args_list == [
            call(DNS_POINTER, 0.0),
            call(DNS_A, 0.0),
        ]

        first._zc_wake.stop()
        remove_listener.assert_not_called()
        second._zc_wake.stop()
        remove_listener.assert_called_once_with(listener)

        first._zc_wake.start()
        assert add_listener.call_count == 2
        first._zc_wake.stop()


async def test_dispatcher_ignores_cname_pointing_at_device() -> None:
    """A CNAME aliasing the device's service name is not a sighting."""
    rl = _logic_on(get_mock_async_zeroconf(), "mydevice")
    cname = DNSPointer(
        "other._esphomelib._tcp.local.",
        _TYPE_CNAME,
        _CLASS_IN,
        1000,
        "mydevice._esphomelib._tcp.local.",
    )
    with patch.object(rl._zc_wake, "on_record") as on_record:
        deliver_records(rl._zc_wake, [RecordUpdate(cname, None)])
    on_record.assert_not_called()


async def test_wakes_with_the_same_name_both_see_records() -> None:
    """Two wakes registered for one name both receive its records."""
    async_zeroconf = get_mock_async_zeroconf()
    zc = async_zeroconf.zeroconf
    first = _logic_on(async_zeroconf, "mydevice")
    second = _logic_on(async_zeroconf, "mydevice")
    with (
        patch.object(zc, "async_add_listener") as add_listener,
        patch.object(zc, "async_remove_listener"),
    ):
        first._zc_wake.start()
        second._zc_wake.start()
        listener = add_listener.call_args[0][0]
        with (
            patch.object(first._zc_wake, "on_record") as first_seen,
            patch.object(second._zc_wake, "on_record") as second_seen,
        ):
            listener.async_update_records(zc, 0.0, [RecordUpdate(DNS_POINTER, None)])
        first_seen.assert_called_once_with(DNS_POINTER, 0.0)
        second_seen.assert_called_once_with(DNS_POINTER, 0.0)
        first._zc_wake.stop()
        second._zc_wake.stop()


async def test_probe_on_announce_one_packet_counts_once(
    probing: tuple[ReconnectLogic, MagicMock, MagicMock],
) -> None:
    """Several of the device's records in one packet are not a burst."""
    rl, _, _ = probing
    packet = [RecordUpdate(DNS_POINTER, None), RecordUpdate(DNS_A, None)]
    with patch.object(rl._cli, "send_keepalive_now", return_value=True) as check:
        deliver_records(rl._zc_wake, packet, 1000.0)
        check.assert_not_called()
        deliver_records(rl._zc_wake, packet, 2000.0)
    check.assert_called_once_with()


async def test_probe_on_announce_skips_burst_that_kicked_the_connect(
    probing: tuple[ReconnectLogic, MagicMock, MagicMock],
) -> None:
    """The rest of a boot burst whose first record kicked the connect never probes."""
    rl, _, _ = probing
    with patch.object(rl, "_schedule_connect"):
        await rl._on_disconnect(False)
    with patch.object(rl, "_schedule_connect") as schedule:
        _send_record(rl, now=1000.0)
    schedule.assert_called_once_with(0.0)
    with _patch_connect(rl._cli):
        await rl._connect_once_or_reschedule()
    assert rl._connection_state is ReconnectLogicState.READY
    with patch.object(rl._cli, "send_keepalive_now", return_value=True) as check:
        for now in (2000.0, 3000.0, 4000.0):
            _send_record(rl, now=now)
        check.assert_not_called()
        _send_record(rl, now=4000.0 + ANNOUNCE_BURST_WINDOW_MS + 1)
        _send_record(rl, now=5000.0 + ANNOUNCE_BURST_WINDOW_MS + 1)
    check.assert_called_once_with()


async def test_probe_on_announce_split_round_counts_once(
    probing: tuple[ReconnectLogic, MagicMock, MagicMock],
) -> None:
    """Packets of one round a few ms apart count once and keep the round's time."""
    rl, _, _ = probing
    with patch.object(rl._cli, "send_keepalive_now", return_value=True) as check:
        _send_record(rl, DNS_A, now=1000.0)
        _send_record(rl, DNS_POINTER, now=1005.0)
        check.assert_not_called()
        _send_record(rl, DNS_A, now=2000.0)
    check.assert_called_once_with()


@pytest.mark.parametrize(
    ("shared", "kwargs", "expected"),
    [
        (True, {}, True),
        (True, {"zeroconf_wake": False}, False),
        (True, {"probe_on_announce": False}, False),
        (False, {}, False),
        (False, {"probe_on_announce": True}, True),
    ],
)
async def test_probe_on_announce_default(
    shared: bool, kwargs: dict[str, Any], expected: bool
) -> None:
    """probe_on_announce defaults on only with a shared zeroconf and zeroconf_wake."""
    aiozc = get_mock_async_zeroconf() if shared else None
    rl = _logic_on(aiozc, "mydevice", **kwargs)
    assert rl._probe_on_announce is expected


async def test_probe_on_announce_default_off_with_private_zeroconf() -> None:
    """A zeroconf instance the client created itself does not turn probing on."""
    cli = APIClient("mydevice.local", 6053, None)
    with patch(
        "zeroconf.asyncio.AsyncZeroconf", return_value=get_mock_async_zeroconf()
    ):
        cli.zeroconf_manager.get_async_zeroconf()
    rl = ReconnectLogic(
        client=cli, on_connect=AsyncMock(), on_disconnect=AsyncMock(), name="mydevice"
    )
    assert rl._probe_on_announce is False

from __future__ import annotations

import asyncio
from functools import partial
from ipaddress import ip_address
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from zeroconf import (
    DNSAddress,
    DNSPointer,
    DNSRecord,
    RecordUpdate,
    Zeroconf,
    current_time_millis,
)
from zeroconf.asyncio import AsyncZeroconf
from zeroconf.const import _CLASS_IN, _TYPE_A, _TYPE_AAAA, _TYPE_PTR

from aioesphomeapi import APIConnectionError, RequiresEncryptionAPIError
from aioesphomeapi._frame_helper.plain_text import APIPlaintextFrameHelper
from aioesphomeapi.client import APIClient
from aioesphomeapi.reconnect_logic import (
    MAXIMUM_BACKOFF_TRIES,
    ReconnectLogic,
    ReconnectLogicState,
)

from .common import (
    get_mock_async_zeroconf,
    get_mock_zeroconf,
    mock_data_received,
    send_plaintext_connect_response,
    send_plaintext_hello,
)
from .conftest import _create_mock_transport_protocol

logging.getLogger("aioesphomeapi").setLevel(logging.DEBUG)


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


DNS_POINTER = DNSPointer(
    "_esphomelib._tcp.local.",
    _TYPE_PTR,
    _CLASS_IN,
    1000,
    "mydevice._esphomelib._tcp.local.",
)


@pytest.mark.parametrize(
    ("record", "should_trigger_zeroconf", "expected_state_after_trigger", "log_text"),
    (
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
    ),
)
async def test_reconnect_zeroconf(
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
        except asyncio.TimeoutError:
            raise APIConnectionError("Resolution timed out")
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
            raise APIConnectionError()

    async def controlled_finish_connection(*args, **kwargs):
        if connect_succeeded:
            return
        raise APIConnectionError()

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

        rl.async_update_records(
            mock_zeroconf, current_time_millis(), [RecordUpdate(record, None)]
        )

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


async def test_reconnect_zeroconf_cancels_when_connecting(
    patchable_api_client: APIClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that reconnect logic cancels and restarts connection when zeroconf triggers during CONNECTING state."""
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
        assert rl._accept_zeroconf_records is True
        assert not rl._is_stopped

        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert mock_start_resolve_host.call_count == 1
        assert mock_start_connection.call_count == 1
        assert rl._connection_state is ReconnectLogicState.CONNECTING
        assert rl._accept_zeroconf_records is True
        assert not rl._is_stopped

    caplog.clear()

    # Now trigger zeroconf while in CONNECTING state
    with (
        patch.object(cli, "start_resolve_host") as mock_start_resolve_host_2,
        patch.object(cli, "start_connection") as mock_start_connection_2,
        patch.object(cli, "finish_connection"),
    ):
        rl.async_update_records(
            mock_zeroconf, current_time_millis(), [RecordUpdate(DNS_POINTER, None)]
        )

        # Should see the cancellation message
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
        assert rl._accept_zeroconf_records is True
        assert not rl._is_stopped

        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        assert mock_start_resolve_host.call_count == 1
        assert mock_start_connection.call_count == 1
        assert mock_finish_connection.call_count == 1
        assert rl._connection_state is ReconnectLogicState.HANDSHAKING
        assert rl._accept_zeroconf_records is False
        assert not rl._is_stopped

    rl.async_update_records(
        mock_zeroconf, current_time_millis(), [RecordUpdate(DNS_POINTER, None)]
    )
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
        assert rl._accept_zeroconf_records is True
        assert not rl._is_stopped

        assert rl._connect_timer is not None
        rl._connect_timer._run()
        await asyncio.sleep(0)
        assert mock_start_resolve_host.call_count == 1
        assert mock_start_connection.call_count == 1
        assert mock_finish_connection.call_count == 1
        assert rl._connection_state is ReconnectLogicState.HANDSHAKING
        assert rl._accept_zeroconf_records is False
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
        send_plaintext_connect_response(protocol, False)
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

        # Should have called get_async_zeroconf for device name
        mock_get_zc.assert_called()

        await logic_with_name.stop()
